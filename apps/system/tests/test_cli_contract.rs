//! Integration test: CLI contract via subprocess.
//!
//! Real risks this guards against:
//! 1. Exit codes drift from the documented stable values; downstream shell
//!    scripts and initramfs init check exit codes literally.
//! 2. JSON mode leaks non-JSON lines (warnings, errors, banners) onto stdout.
//! 3. Argument errors get exit code 0 by accident (silent failure).
//! 4. `--root` is silently accepted as relative and operates on the wrong
//!    filesystem (the host's `/etc`), which is catastrophic for a recovery
//!    tool invoked from a LiveCD.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_catos-system"))
}

fn run(args: &[&str]) -> (bool, i32, String, String) {
    let out = Command::new(bin_path()).args(args).output().unwrap();
    (
        out.status.success(),
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn no_args_exits_arg_error() {
    let (ok, code, _, stderr) = run(&[]);
    assert!(!ok);
    assert_eq!(code, 2, "stderr: {stderr}");
    // Errors must go to stderr, not stdout.
    assert!(!stderr.is_empty());
}

#[test]
fn unknown_subcommand_exits_arg_error() {
    let (ok, code, _, _) = run(&["frobnicate"]);
    assert!(!ok);
    assert_eq!(code, 2);
}

#[test]
fn unknown_flag_exits_arg_error() {
    let (ok, code, _, _) = run(&["inspect", "--definitely-not-a-flag"]);
    assert!(!ok);
    assert_eq!(code, 2);
}

#[test]
fn missing_root_value_exits_arg_error() {
    let (ok, code, _, _) = run(&["inspect", "--root"]);
    assert!(!ok);
    assert_eq!(code, 2);
}

#[test]
fn relative_root_exits_invalid_root() {
    // Critical safety check: a relative `--root mnt` must NOT be silently
    // interpreted as `/mnt` or `./mnt`. It must error before any probe runs.
    let (ok, code, _, stderr) = run(&["inspect", "--root", "mnt"]);
    assert!(!ok);
    assert_eq!(code, 3, "expected INVALID_ROOT (3); stderr: {stderr}");
}

#[test]
fn nonexistent_root_exits_invalid_root() {
    let (ok, code, _, _) = run(&["inspect", "--root", "/definitely/does/not/exist/xyz"]);
    assert!(!ok);
    assert_eq!(code, 3);
}

#[test]
fn inspect_default_root_succeeds() {
    let (ok, code, stdout, _) = run(&["inspect"]);
    assert!(ok, "exit {code}");
    assert!(stdout.contains("Runtime"));
}

#[test]
fn json_stdout_is_pure_json() {
    let (ok, code, stdout, _) = run(&["inspect", "--json"]);
    assert!(ok, "exit {code}");
    let trimmed = stdout.trim();
    // The very first non-whitespace character must be `{`, and parsing must
    // succeed. Any leading banner / log line would break this.
    assert!(
        trimmed.starts_with('{'),
        "stdout does not start with JSON object; got: {trimmed:?}"
    );
    serde_json::from_str::<serde_json::Value>(trimmed)
        .expect("stdout must be valid JSON in --json mode");
    // No ANSI escapes anywhere on stdout.
    assert!(
        !stdout.contains('\u{001b}'),
        "ANSI escape leaked into JSON stdout"
    );
}

#[test]
fn json_schema_version_is_two() {
    let (_, _, stdout, _) = run(&["inspect", "--json"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["schemaVersion"].as_u64(), Some(2));
}

#[test]
fn json_has_required_top_level_keys() {
    let (_, _, stdout, _) = run(&["inspect", "--json"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    for key in [
        "schemaVersion",
        "programVersion",
        "invocation",
        "targetRoot",
        "runtime",
        "capabilities",
        "target",
        "warnings",
    ] {
        assert!(v.get(key).is_some(), "missing top-level JSON key: {key}");
    }
    // The phase-1 contract enumerates exactly these 16 capability names.
    let cap_names: Vec<&str> = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(cap_names.len(), 16, "expected 16 phase-1 capabilities");
    for required in [
        "read_target_root",
        "read_proc",
        "read_sysfs",
        "read_block_sysfs",
        "access_dev",
        "shell_available",
        "mount_operations_possible",
        "write_efivars_possible",
        "systemd_available",
        "pacman_present_in_target",
        "mkinitcpio_present_in_target",
        "bootloadu_present_in_target",
        "btrfs_tool_available",
        "cryptsetup_available",
        "lsblk_available",
        "mount_tool_available",
    ] {
        assert!(
            cap_names.contains(&required),
            "missing capability {required:?} in JSON output"
        );
    }
}

#[test]
fn json_runtime_has_six_detections() {
    let (_, _, stdout, _) = run(&["environment", "--json"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let runtime = &v["runtime"];
    for key in [
        "is_initramfs",
        "is_chroot",
        "is_live_environment",
        "is_snapshot_boot",
        "has_systemd",
        "root_is_read_only",
    ] {
        let det = &runtime[key];
        assert!(det.is_object(), "runtime.{key} is not an object");
        let status = det["status"].as_str();
        assert!(
            matches!(
                status,
                Some("detected") | Some("not_detected") | Some("unknown")
            ),
            "runtime.{key}.status has invalid value: {status:?}"
        );
    }
}

#[test]
fn help_and_version_exit_zero() {
    let (ok, code, stdout_help, _) = run(&["--help"]);
    assert!(ok);
    assert_eq!(code, 0);
    assert!(stdout_help.contains("USAGE"));
    let (ok, code, stdout_v, _) = run(&["--version"]);
    assert!(ok);
    assert_eq!(code, 0);
    assert!(stdout_v.contains("catos-system"));
}

// ---- sub-command view dispatch (review issue #1) ----
// The original implementation parsed `Command` but never read it, so all
// three sub-commands produced identical output. These tests verify each
// sub-command selects a distinct view of the same underlying report.

fn json_keys(args: &[&str]) -> Vec<String> {
    let (_, _, stdout, _) = run(args);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    v.as_object()
        .expect("top-level object")
        .keys()
        .map(|s| s.to_string())
        .collect()
}

#[test]
fn environment_view_omits_capabilities_and_target() {
    let keys = json_keys(&["environment", "--json"]);
    assert!(keys.contains(&"runtime".to_string()), "missing runtime");
    assert!(
        !keys.contains(&"capabilities".to_string()),
        "environment must not emit capabilities, got: {keys:?}"
    );
    assert!(
        !keys.contains(&"target".to_string()),
        "environment must not emit target, got: {keys:?}"
    );
}

#[test]
fn capabilities_view_omits_runtime_and_target() {
    let keys = json_keys(&["capabilities", "--json"]);
    assert!(keys.contains(&"capabilities".to_string()));
    assert!(
        !keys.contains(&"runtime".to_string()),
        "capabilities must not emit runtime, got: {keys:?}"
    );
    assert!(
        !keys.contains(&"target".to_string()),
        "capabilities must not emit target, got: {keys:?}"
    );
}

#[test]
fn inspect_view_emits_all_three_sections() {
    let keys = json_keys(&["inspect", "--json"]);
    for k in ["runtime", "capabilities", "target"] {
        assert!(
            keys.contains(&k.to_string()),
            "inspect must emit {k}, got: {keys:?}"
        );
    }
}

#[test]
fn three_subcommands_produce_distinct_output() {
    // The whole point of the fix: the three views must NOT be identical.
    let env = json_keys(&["environment", "--json"]);
    let caps = json_keys(&["capabilities", "--json"]);
    let insp = json_keys(&["inspect", "--json"]);
    assert_ne!(
        env, caps,
        "environment and capabilities views are identical"
    );
    assert_ne!(env, insp, "environment and inspect views are identical");
    assert_ne!(caps, insp, "capabilities and inspect views are identical");
}

#[test]
fn all_views_share_unconditional_keys() {
    // schemaVersion, programVersion, invocation, targetRoot, warnings
    // must be present in EVERY view.
    for args in [
        ["environment", "--json"],
        ["capabilities", "--json"],
        ["inspect", "--json"],
    ] {
        let keys = json_keys(&args);
        for k in [
            "schemaVersion",
            "programVersion",
            "invocation",
            "targetRoot",
            "warnings",
        ] {
            assert!(
                keys.contains(&k.to_string()),
                "view {args:?} is missing unconditional key {k}: {keys:?}"
            );
        }
    }
}

#[test]
fn human_environment_view_omits_target_section() {
    let (_, _, stdout, _) = run(&["environment"]);
    assert!(stdout.contains("Runtime"));
    assert!(!stdout.contains("\nTarget\n"));
    assert!(!stdout.contains("\nCapabilities\n"));
}

#[test]
fn human_capabilities_view_omits_runtime_section() {
    let (_, _, stdout, _) = run(&["capabilities"]);
    assert!(stdout.contains("Capabilities"));
    assert!(!stdout.contains("\nRuntime\n"));
    assert!(!stdout.contains("\nTarget\n"));
}

#[test]
fn target_root_absolute_symlinks_do_not_escape_to_host() {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut root = std::env::temp_dir();
    root.push(format!(
        "catos-root-symlink-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(root.join("boot")).unwrap();
    symlink("/etc", root.join("etc")).unwrap();
    symlink("/usr", root.join("usr")).unwrap();

    let root_text = root.to_string_lossy().into_owned();
    let (ok, code, stdout, stderr) = run(&["inspect", "--root", &root_text, "--json"]);
    let _ = fs::remove_dir_all(&root);

    assert!(ok, "exit {code}: {stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(
        value["target"].get("os_release").is_none(),
        "host /etc/os-release escaped through target symlink: {}",
        value["target"]
    );
    assert_ne!(
        value["target"]["is_catos_target"]["status"], "detected",
        "empty target was misidentified as host CatOS"
    );
    let pacman = value["target"]["tool_paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "pacman")
        .unwrap();
    assert_ne!(
        pacman["status"], "available",
        "host /usr/bin/pacman escaped through target symlink"
    );
}
