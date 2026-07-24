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
fn json_schema_version_is_one() {
    let (_, _, stdout, _) = run(&["inspect", "--json"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["schemaVersion"].as_u64(), Some(1));
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
        "run_external_commands",
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
