//! Integration test: verify the multicall contract end-to-end by spawning
//! the actual binary.
//!
//! Real risks this guards against:
//! 1. Someone re-introduces separate binaries instead of one multicall
//!    binary (defeats size budget + initramfs simplicity).
//! 2. argv[0] handling breaks so invoking via a symlink crashes or gives
//!    a wrong invocation field that downstream tooling keys on.
//! 3. Probe results diverge depending on the entry point (must be identical).

use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path() -> PathBuf {
    // Injected by cargo for the `catos-system` binary target.
    PathBuf::from(env!("CARGO_BIN_EXE_catos-system"))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> std::io::Result<Self> {
        let mut builder = std::env::temp_dir();
        builder.push(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&builder)?;
        Ok(Self { path: builder })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Symlink-name -> invocation string. All public entry points share the
/// same physical binary but retain distinct user-facing roles.
const ENTRY_POINTS: &[(&str, &str)] = &[
    ("catos-system", "catos-system"),
    ("catos-update", "catos-update"),
    ("catos-recovery", "catos-recovery"),
    ("catos-doctor", "catos-doctor"),
    ("catos-repair", "catos-repair"),
    ("catos-chroot", "catos-chroot"),
];

#[test]
fn each_symlink_is_recognised_in_help_output() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-multicall").unwrap();

    for (link_name, expected_invocation) in ENTRY_POINTS {
        let link_path = tmp.path.join(link_name);
        symlink(&bin, &link_path).unwrap();
        let output = Command::new(&link_path)
            .arg("--help")
            .output()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", link_path.display()));
        assert!(
            output.status.success(),
            "{} exited with {:?}: stderr={}",
            link_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.starts_with(expected_invocation),
            "help output did not use invocation {expected_invocation}: {stdout}"
        );
    }
}

#[test]
fn core_probe_results_are_identical_across_entry_points() {
    // Public routing change: `catos-recovery` no longer inherits the
    // `catos-system inspect` subcommand. The public recovery surface is
    // `catos-recovery <SUB>` (list/inspect/plan/apply/status/resume/
    // revert), and `catos-recovery inspect` is now the RECOVERY inspect
    // subcommand, not the low-level inspect. The original "identical
    // report" guarantee was a property of the old inherited-surface
    // design that the new contract intentionally removes (see the
    // user-facing spec: "公开接口去掉重复的 `recovery` 层").
    //
    // The property this test re-pins under the new contract:
    //   * `catos-system inspect` still produces the canonical inspection
    //     report (unchanged, schema-stable).
    //   * The recovery engine's `inspect` is reachable through BOTH the
    //     `catos-system recovery inspect` canonical form and the new
    //     `catos-recovery inspect` public form, and both produce the
    //     same structured failure when --root-device is missing. This
    //     proves the recovery parser was not duplicated: the new entry
    //     point reuses the existing engine.
    let bin = bin_path();
    let tmp = TempDir::new("catos-multicall-core").unwrap();

    let system_out = Command::new(&bin)
        .arg("inspect")
        .arg("--json")
        .output()
        .expect("spawn catos-system");
    assert!(
        system_out.status.success(),
        "catos-system inspect failed: {}",
        String::from_utf8_lossy(&system_out.stderr)
    );
    let system_value: serde_json::Value =
        serde_json::from_str(&String::from_utf8(system_out.stdout).unwrap()).unwrap();
    assert_eq!(system_value["schemaVersion"].as_u64(), Some(2));
    assert_eq!(system_value["invocation"].as_str(), Some("catos-system"));

    // Both forms reach the recovery engine. Without --root-device they
    // fail with the same structured `target_changed` error and the same
    // exit code (PROBE_FAILED = 5). This proves the new entry point is a
    // thin re-mapping over the existing parser, not a parallel CLI.
    let canonical_link = tmp.path.join("catos-system");
    symlink(&bin, &canonical_link).unwrap();
    let recovery_link = tmp.path.join("catos-recovery");
    symlink(&bin, &recovery_link).unwrap();

    let canonical_out = Command::new(&canonical_link)
        .args(["recovery", "inspect", "--json"])
        .output()
        .expect("spawn canonical");
    let public_out = Command::new(&recovery_link)
        .args(["inspect", "--json"])
        .output()
        .expect("spawn public");

    assert_eq!(
        canonical_out.status.code(),
        public_out.status.code(),
        "canonical vs public exit codes diverged",
    );
    assert_eq!(
        canonical_out.status.code(),
        Some(5),
        "recovery inspect without --root-device must reach the engine and exit PROBE_FAILED"
    );

    let mut canonical: serde_json::Value =
        serde_json::from_str(&String::from_utf8(canonical_out.stdout).unwrap())
            .expect("canonical JSON");
    let mut public: serde_json::Value =
        serde_json::from_str(&String::from_utf8(public_out.stdout).unwrap()).expect("public JSON");
    // Both envelopes carry their own invocation label (top-level and
    // nested under payload); equalise before comparing so the
    // assertion targets the recovery payload, not the dispatch label.
    for value in [&mut canonical, &mut public] {
        value["invocation"] = serde_json::Value::Null;
        value["payload"]["invocation"] = serde_json::Value::Null;
    }
    assert_eq!(
        canonical.to_string(),
        public.to_string(),
        "catos-system recovery inspect and catos-recovery inspect produced different payloads"
    );
}

#[test]
fn single_physical_binary_backs_all_entry_points() {
    // Guard against regression where someone adds separate `[[bin]]` targets
    // or accidentally produces multiple files. After following symlinks, all
    // recognised paths must report the same dev+ino.
    use std::os::unix::fs::MetadataExt;
    let bin = bin_path();
    let tmp = TempDir::new("catos-multicall-inode").unwrap();

    let mut metas = Vec::new();
    let direct = fs::metadata(&bin).unwrap();
    metas.push((direct.dev(), direct.ino()));
    for (link_name, _) in ENTRY_POINTS {
        let link_path = tmp.path.join(link_name);
        symlink(&bin, &link_path).unwrap();
        let m = fs::metadata(&link_path).unwrap();
        metas.push((m.dev(), m.ino()));
    }
    let first = metas[0];
    for (i, m) in metas.iter().enumerate().skip(1) {
        assert_eq!(
            *m, first,
            "entry point {i} does not share dev/ino with the canonical binary"
        );
    }
}

#[test]
fn doctor_without_arguments_requires_privilege_before_diagnosis() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let bin = bin_path();
    let tmp = TempDir::new("catos-doctor-no-args").unwrap();
    let link = tmp.path.join("catos-doctor");
    symlink(&bin, &link).unwrap();

    let output = Command::new(&link).output().expect("spawn doctor");
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("administrator privileges are required"),
        "stderr={stderr:?}"
    );
}

#[test]
fn doctor_rejects_inspect_and_preflight_parameters() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-doctor-no-subcommands").unwrap();
    let link = tmp.path.join("catos-doctor");
    symlink(&bin, &link).unwrap();

    for args in [["inspect"].as_slice(), ["preflight", "recovery"].as_slice()] {
        let output = Command::new(&link)
            .args(args)
            .output()
            .expect("spawn doctor");
        assert!(
            !output.status.success(),
            "doctor unexpectedly accepted {args:?}"
        );
        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn unknown_argv0_falls_back_to_canonical_name() {
    // Defends against the case where the binary is invoked under an unknown
    // name (e.g. via a renamed copy). The fallback must be `catos-system`,
    // never a crash.
    let bin = bin_path();
    let tmp = TempDir::new("catos-multicall-unknown").unwrap();
    let link = tmp.path.join("totally-unknown-tool");
    symlink(&bin, &link).unwrap();
    let output = Command::new(&link)
        .arg("inspect")
        .arg("--json")
        .output()
        .expect("spawn");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(output.stdout).unwrap()).unwrap();
    assert_eq!(v["invocation"].as_str(), Some("catos-system"));
}

// ===========================================================================
// Invocation-aware routing contract
// ===========================================================================
//
// Each public entry point owns a distinct dispatch surface. These tests
// verify real dispatch (subprocess + exit code + structured output), not
// just help-text wording. The contract they pin:
//
//   * `catos-recovery <SUB>` routes directly to the recovery engine;
//     the redundant `catos-recovery recovery <SUB>` form is rejected.
//   * `catos-repair` exposes only `fs|mount|boot` and routes each to a
//     stable, distinct "not implemented" result. Other names (including
//     `inspect`, `recovery`, `preflight`, `apply`, ...) are rejected.
//   * `catos-update` is recognised (no crash, prints help/version) but
//     does NOT inherit any `catos-system` subcommand. Calling
//     `catos-update inspect` must not run the low-level inspector.
//
// `catos-doctor`'s argumentless behavior is already pinned by the tests
// above; these additions do not regress it.

fn link_to(bin: &std::path::Path, tmp: &TempDir, name: &str) -> std::path::PathBuf {
    let link = tmp.path.join(name);
    symlink(bin, &link).unwrap();
    link
}

/// Run a linked entry point with the given args and return
/// `(success, code, stdout, stderr)`.
fn run_via(link: &std::path::Path, args: &[&str]) -> (bool, i32, String, String) {
    let out = Command::new(link).args(args).output().unwrap();
    (
        out.status.success(),
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// ---------------------------------------------------------------------------
// catos-recovery
// ---------------------------------------------------------------------------

#[test]
fn recovery_list_without_root_device_reaches_recovery_engine() {
    // Real dispatch proof: `catos-recovery list` (no --root-device) MUST
    // reach the recovery list orchestrator, which returns the structured
    // `target_changed`/`requires --root-device` error. That path exits
    // PROBE_FAILED (5), not ARG_ERROR (2). If the routing fell through
    // to the generic parser, `list` would be an unknown subcommand and
    // the exit code would be 2.
    let bin = bin_path();
    let tmp = TempDir::new("catos-recovery-list-dispatch").unwrap();
    let link = link_to(&bin, &tmp, "catos-recovery");
    let (ok, code, stdout, stderr) = run_via(&link, &["list", "--json"]);
    assert!(!ok, "stdout={stdout}, stderr={stderr}");
    assert_ne!(
        code, 2,
        "list must not be rejected as an unknown subcommand; stderr={stderr}"
    );
    assert_eq!(
        code, 5,
        "expected PROBE_FAILED from recovery list orchestrator"
    );
    // The error must come from the recovery layer, not the generic CLI
    // parser: stdout is pure JSON, kind=error, payload.kind is a recovery
    // error kind (target_changed).
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("recovery list failure must be JSON");
    assert_eq!(value["kind"], "error");
    assert_eq!(value["payload"]["kind"], "target_changed");
}

#[test]
fn recovery_doubled_recovery_subcommand_is_rejected() {
    // The legacy redundant form `catos-recovery recovery list` must be
    // rejected. The new public surface drops the duplicated `recovery`
    // layer. Exit code is ARG_ERROR (2) — the same code the generic
    // parser uses for unknown subcommands — but the message must
    // identify the inner `recovery` token as the offender.
    let bin = bin_path();
    let tmp = TempDir::new("catos-recovery-doubled").unwrap();
    let link = link_to(&bin, &tmp, "catos-recovery");
    let (ok, code, _stdout, stderr) = run_via(&link, &["recovery", "list"]);
    assert!(!ok);
    assert_eq!(code, 2, "stderr={stderr}");
    assert!(
        stderr.contains("recovery"),
        "rejection must name the offending `recovery` token: {stderr}"
    );
}

#[test]
fn recovery_subcommands_route_directly() {
    // Every public recovery subcommand MUST route via the new direct
    // surface (no `recovery` prefix). Without --root-device each one
    // exits PROBE_FAILED (5), proving dispatch reached the recovery
    // layer rather than the generic parser (which would exit 2).
    let bin = bin_path();
    let tmp = TempDir::new("catos-recovery-direct").unwrap();
    let link = link_to(&bin, &tmp, "catos-recovery");
    for sub in ["list", "inspect", "plan"] {
        let (ok, code, _stdout, stderr) = run_via(&link, &[sub, "--json"]);
        assert!(!ok, "catos-recovery {sub} unexpectedly succeeded");
        assert_eq!(
            code, 5,
            "catos-recovery {sub} should reach recovery engine (exit 5); stderr={stderr}"
        );
    }
    // Subcommands that require a transaction id also reach the recovery
    // layer but fail one step earlier (transaction id validation). They
    // still must NOT exit 2 (unknown subcommand).
    for sub in ["status", "resume", "revert"] {
        let (ok, code, _stdout, stderr) = run_via(&link, &[sub, "--json"]);
        assert!(!ok, "catos-recovery {sub} unexpectedly succeeded");
        assert_ne!(
            code, 2,
            "catos-recovery {sub} must route to recovery engine, not generic parser; stderr={stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// catos-repair
// ---------------------------------------------------------------------------

#[test]
fn aggregate_menu_reaches_repair_target_selection() {
    let bin = bin_path();
    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn catos-system");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(b"3\n2\n0\n0\n")
        .expect("write menu input");
    let output = child.wait_with_output().expect("wait for catos-system");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CatOS System Tools"), "stdout={stdout}");
    assert!(stdout.contains("Repair Target"), "stdout={stdout}");
    assert!(
        stdout.contains("Choose a detected CatOS installation"),
        "stdout={stdout}"
    );
}

#[test]
fn repair_menu_requires_target_selection_before_execution() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-repair-target-menu").unwrap();
    let link = link_to(&bin, &tmp, "catos-repair");
    let mut child = Command::new(&link)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn catos-repair");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(b"2\n0\n")
        .expect("write menu input");
    let output = child.wait_with_output().expect("wait for catos-repair");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Repair Target"), "stdout={stdout}");
    assert!(
        stdout.contains("Choose a detected CatOS installation"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("Enter a root device manually"),
        "stdout={stdout}"
    );
}

#[test]
fn recovery_menu_requires_target_selection_before_execution() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-recovery-target-menu").unwrap();
    let link = link_to(&bin, &tmp, "catos-recovery");
    let mut child = Command::new(&link)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn catos-recovery");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(b"1\n0\n")
        .expect("write menu input");
    let output = child.wait_with_output().expect("wait for catos-recovery");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Recovery Target"), "stdout={stdout}");
    assert!(
        stdout.contains("Choose a detected CatOS installation"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("Enter a root device manually"),
        "stdout={stdout}"
    );
}

#[test]
fn repair_without_args_opens_an_interactive_menu() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-repair-no-args").unwrap();
    let link = link_to(&bin, &tmp, "catos-repair");
    let (ok, code, stdout, stderr) = run_via(&link, &[]);
    assert!(ok, "exit {code}: {stderr}");
    assert_eq!(code, 0);
    assert!(stdout.contains("Repair"), "stdout={stdout}");
    for action in ["filesystem", "mount layout", "boot setup"] {
        assert!(
            stdout.to_ascii_lowercase().contains(action),
            "repair menu must mention {action}: {stdout}"
        );
    }
}

#[test]
fn repair_domains_route_appropriately() {
    // Current repair behavior:
    //   * `catos-repair fs` is implemented. With no
    //     devices and no explicit selection it refuses with
    //     ARG_ERROR (ambiguous target).
    //   * `catos-repair mount` is implemented. It builds
    //     a structured report and may exit 0 (clean / partially
    //     repaired) or non-zero depending on the host. It MUST NOT
    //     print "not implemented".
    //   * `catos-repair boot` is implemented. It detects
    //     the target's bootloader provider from the target's own
    //     configuration; without a verified target it refuses with
    //     a structured report (ARG_ERROR for ambiguous_target) and
    //     MUST NOT print "not implemented in this stage".
    let bin = bin_path();
    let tmp = TempDir::new("catos-repair-domains").unwrap();
    let link = link_to(&bin, &tmp, "catos-repair");

    let (fs_ok, _fs_code, _fs_stdout, fs_stderr) = run_via(&link, &["fs"]);
    let _ = fs_ok;
    assert!(
        !fs_stderr.to_lowercase().contains("not implemented"),
        "fs must be implemented; stderr={fs_stderr}"
    );

    let (mount_ok, _mount_code, _mount_stdout, mount_stderr) = run_via(&link, &["mount"]);
    let _ = mount_ok;
    assert!(
        !mount_stderr
            .to_lowercase()
            .contains("not implemented in this stage"),
        "mount must be implemented; stderr={mount_stderr}"
    );

    let (boot_ok, _boot_code, _boot_stdout, boot_stderr) = run_via(&link, &["boot"]);
    assert!(
        !boot_stderr
            .to_lowercase()
            .contains("not implemented in this stage"),
        "boot must be implemented; stderr={boot_stderr}"
    );
    // Without a verified target, boot repair refuses — never exits 0
    // on a host without a uniquely identified CatOS root.
    assert!(
        !boot_ok || std::env::var("CATOS_REPAIR_BOOT_TEST_ALLOW_OK").is_ok(),
        "catos-repair boot should refuse without a verified target"
    );
}

#[test]
fn repair_rejects_forbidden_subcommands() {
    // `catos-repair` exposes ONLY fs/mount/boot. Anything else —
    // including names that DO exist on `catos-system`/`catos-recovery`
    // (inspect, recovery, plan, apply, status, resume, preflight) —
    // MUST be rejected before any work happens. This is what keeps the
    // repair surface from accidentally inheriting other entry points'
    // commands.
    let bin = bin_path();
    let tmp = TempDir::new("catos-repair-forbidden").unwrap();
    let link = link_to(&bin, &tmp, "catos-repair");
    for forbidden in [
        "inspect",
        "preflight",
        "recovery",
        "plan",
        "apply",
        "status",
        "resume",
        "revert",
        "storage",
        "target",
        "environment",
        "capabilities",
    ] {
        let (ok, code, _stdout, stderr) = run_via(&link, &[forbidden]);
        assert!(
            !ok,
            "catos-repair {forbidden} unexpectedly succeeded; stderr={stderr}"
        );
        assert_eq!(
            code, 2,
            "forbidden subcommand {forbidden} must exit ARG_ERROR; stderr={stderr}"
        );
    }
    // The composite form `catos-repair recovery list` is also rejected.
    let (ok, code, _stdout, _stderr) = run_via(&link, &["recovery", "list"]);
    assert!(!ok);
    assert_eq!(code, 2);
}

// ---------------------------------------------------------------------------
// catos-update
// ---------------------------------------------------------------------------

#[test]
fn update_help_and_version_are_accepted() {
    // The entry point MUST be recognised: --help and --version exit 0.
    let bin = bin_path();
    let tmp = TempDir::new("catos-update-hv").unwrap();
    let link = link_to(&bin, &tmp, "catos-update");
    for flag in ["--help", "-h", "--version", "-V"] {
        let (ok, code, stdout, _stderr) = run_via(&link, &[flag]);
        assert!(ok, "catos-update {flag} failed");
        assert_eq!(code, 0);
        let text = stdout;
        assert!(
            text.contains("catos-update") || text.contains("catos-system"),
            "catos-update {flag} output must identify the invocation: {text}"
        );
    }
}

#[test]
fn update_does_not_inherit_catos_system_commands() {
    // `catos-update` is recognised as a distinct entry point and MUST
    // NOT expose any `catos-system` subcommand. Each inherited name
    // must exit ARG_ERROR (2) and must NOT produce the inspection report.
    // Without this guard, `catos-update inspect --json` would silently
    // run the diagnostics under a different invocation name.
    let bin = bin_path();
    let tmp = TempDir::new("catos-update-no-inherit").unwrap();
    let link = link_to(&bin, &tmp, "catos-update");
    for sub in [
        "inspect",
        "environment",
        "capabilities",
        "storage",
        "target",
        "recovery",
    ] {
        let (ok, code, stdout, stderr) = run_via(&link, &[sub, "--json"]);
        assert!(
            !ok,
            "catos-update {sub} unexpectedly ran a catos-system command"
        );
        assert_eq!(
            code, 2,
            "catos-update {sub} must exit ARG_ERROR; stderr={stderr}"
        );
        // The stdout must NOT be a low-level inspection report. If it
        // were, the JSON would contain `runtime`/`capabilities` keys.
        if !stdout.trim().is_empty() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
            if let Ok(value) = parsed {
                assert!(
                    value.get("runtime").is_none() && value.get("capabilities").is_none(),
                    "catos-update {sub} produced a inspection report: {value}"
                );
            }
        }
    }
    // The forbidden new update commands (check/apply/status) are also
    // rejected — they don't exist on this entry point.
    for forbidden in ["check", "apply", "status"] {
        let (ok, code, _stdout, _stderr) = run_via(&link, &[forbidden]);
        assert!(!ok, "catos-update {forbidden} must not be implemented yet");
        assert_eq!(code, 2);
    }
}

// ---------------------------------------------------------------------------
// catos-doctor regression: argumentless behavior is unchanged
// ---------------------------------------------------------------------------

#[test]
fn doctor_remains_argumentless_after_routing_changes() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-doctor-routing-regression").unwrap();
    let link = link_to(&bin, &tmp, "catos-doctor");
    if unsafe { libc::geteuid() } != 0 {
        let (ok_no_args, code_no_args, stdout, stderr) = run_via(&link, &[]);
        assert!(!ok_no_args);
        assert_eq!(code_no_args, 4);
        assert!(stdout.is_empty());
        assert!(stderr.contains("administrator privileges are required"));
    }
    for forbidden in [
        "inspect",
        "preflight",
        "recovery",
        "list",
        "fs",
        "mount",
        "boot",
        "check",
        "apply",
        "--json",
        "--root-device",
        "/dev/sda1",
    ] {
        let (ok, code, _stdout, _stderr) = run_via(&link, &[forbidden]);
        assert!(!ok, "catos-doctor {forbidden} unexpectedly succeeded");
        assert_eq!(code, 2);
    }
}

#[test]
fn recovery_subcommand_help_lists_real_required_options() {
    let directory = TempDir::new("recovery-subcommand-help").unwrap();
    let recovery = directory.path.join("catos-recovery");
    symlink(bin_path(), &recovery).unwrap();
    let output = Command::new(&recovery)
        .args(["apply", "--help"])
        .output()
        .expect("run catos-recovery apply --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for required in ["--root-device", "--plan-file", "--plan-id", "--confirm"] {
        assert!(
            stdout.contains(required),
            "missing {required} in apply help: {stdout}"
        );
    }
    assert!(
        !stdout.contains("COMMANDS:\n    list"),
        "apply help fell back to top-level help"
    );
}

// ---------------------------------------------------------------------------
// catos-chroot
// ---------------------------------------------------------------------------

#[test]
fn chroot_help_and_version_are_accepted() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-chroot-hv").unwrap();
    let link = link_to(&bin, &tmp, "catos-chroot");
    for flag in ["--help", "-h", "--version", "-V"] {
        let (ok, code, stdout, _stderr) = run_via(&link, &[flag]);
        assert!(ok, "catos-chroot {flag} failed");
        assert_eq!(code, 0);
        assert!(
            stdout.contains("catos-chroot"),
            "catos-chroot {flag} output must identify the invocation: {stdout}"
        );
    }
}

#[test]
fn chroot_does_not_inherit_catos_system_commands() {
    // `catos-chroot` is its own dispatch surface and MUST NOT expose
    // any `catos-system` subcommand. Every inherited name must exit
    // ARG_ERROR (2) before any external command runs.
    let bin = bin_path();
    let tmp = TempDir::new("catos-chroot-no-inherit").unwrap();
    let link = link_to(&bin, &tmp, "catos-chroot");
    for sub in [
        "inspect",
        "environment",
        "capabilities",
        "storage",
        "target",
        "recovery",
    ] {
        let (ok, code, _stdout, stderr) = run_via(&link, &[sub]);
        assert!(
            !ok,
            "catos-chroot {sub} unexpectedly ran a catos-system command"
        );
        assert_eq!(
            code, 2,
            "catos-chroot {sub} must exit ARG_ERROR; stderr={stderr}"
        );
    }
}

#[test]
fn chroot_rejects_the_removed_non_root_bypass() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-chroot-no-root-bypass").unwrap();
    let link = link_to(&bin, &tmp, "catos-chroot");
    let (ok, code, _stdout, stderr) = run_via(&link, &["--skip-root-check"]);
    assert!(!ok);
    assert_eq!(code, 2, "stderr={stderr}");
    assert!(stderr.contains("unknown option"), "stderr={stderr}");
}

#[test]
fn chroot_unknown_option_is_arg_error() {
    // Unknown flags must be rejected before any device enumeration.
    let bin = bin_path();
    let tmp = TempDir::new("catos-chroot-unknown-flag").unwrap();
    let link = link_to(&bin, &tmp, "catos-chroot");
    let (ok, code, _stdout, stderr) = run_via(&link, &["--definitely-not-a-flag"]);
    assert!(!ok);
    assert_eq!(code, 2, "stderr={stderr}");
    assert!(stderr.contains("unknown option"), "stderr={stderr}");
}

#[test]
fn chroot_help_lists_documented_flags() {
    // Every documented long option must appear in --help output so
    // operators can discover the full surface without reading the
    // source.
    let bin = bin_path();
    let tmp = TempDir::new("catos-chroot-help-surface").unwrap();
    let link = link_to(&bin, &tmp, "catos-chroot");
    let (ok, _code, stdout, _stderr) = run_via(&link, &["--help"]);
    assert!(ok);
    for flag in [
        "--no-auto-mount",
        "--no-systemd-chroot",
        "--show-btrfs-dot-snapshots",
    ] {
        assert!(
            stdout.contains(flag),
            "catos-chroot --help missing {flag}: {stdout}"
        );
    }
    assert!(
        !stdout.contains("--skip-root-check"),
        "testing-only privilege bypass must not be advertised: {stdout}"
    );
}

#[test]
fn public_entry_points_report_usage_problems_in_plain_language() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-plain-usage-errors").unwrap();
    let cases: &[(&str, &[&str])] = &[
        ("catos-system", &["unknown-command"]),
        ("catos-doctor", &["unexpected"]),
        ("catos-chroot", &["--unknown"]),
        ("catos-repair", &["unknown-domain"]),
        ("catos-recovery", &["unknown-command"]),
        ("catos-update", &["--unknown"]),
    ];
    for (name, args) in cases {
        let link = link_to(&bin, &tmp, name);
        let (_, code, _, stderr) = run_via(&link, args);
        assert_eq!(code, 2, "{name} {args:?}: stderr={stderr:?}");
        assert!(
            !stderr.to_ascii_lowercase().contains("argument error"),
            "{name} leaked internal error taxonomy: {stderr:?}"
        );
        assert!(!stderr.trim().is_empty(), "{name} returned no guidance");
    }
}
