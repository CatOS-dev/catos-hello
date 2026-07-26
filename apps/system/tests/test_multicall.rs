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
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

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
    // Stage-1 routing change: `catos-recovery` no longer inherits the
    // `catos-system inspect` subcommand. The public recovery surface is
    // `catos-recovery <SUB>` (list/inspect/plan/apply/status/resume/
    // revert), and `catos-recovery inspect` is now the RECOVERY inspect
    // subcommand, not the phase-1 inspect. The original "identical
    // report" guarantee was a property of the old inherited-surface
    // design that the new contract intentionally removes (see the
    // user-facing spec: "公开接口去掉重复的 `recovery` 层").
    //
    // The property this test re-pins under the new contract:
    //   * `catos-system inspect` still produces the canonical phase-1
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
fn doctor_without_arguments_outputs_diagnosis() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-doctor-no-args").unwrap();
    let link = tmp.path.join("catos-doctor");
    symlink(&bin, &link).unwrap();

    let output = Command::new(&link).output().expect("spawn doctor");
    assert!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Runtime"));
    assert!(stdout.contains("Capabilities"));
    assert!(stdout.contains("Target"));
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
// Phase-1 stage-1: invocation-aware routing contract
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
//     `catos-update inspect` must not run the phase-1 inspector.
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
fn repair_without_args_rejects_and_lists_three_domains() {
    // `catos-repair` (no args) MUST be rejected with ARG_ERROR (2). The
    // usage message MUST name the three domains (fs, mount, boot) so an
    // operator can correct the invocation. This is real dispatch:
    // routing enters the repair handler, NOT the generic parser.
    let bin = bin_path();
    let tmp = TempDir::new("catos-repair-no-args").unwrap();
    let link = link_to(&bin, &tmp, "catos-repair");
    let (ok, code, _stdout, stderr) = run_via(&link, &[]);
    assert!(!ok);
    assert_eq!(code, 2, "stderr={stderr}");
    for domain in ["fs", "mount", "boot"] {
        assert!(
            stderr.contains(domain),
            "no-args usage must mention domain {domain}: {stderr}"
        );
    }
}

#[test]
fn repair_domains_route_appropriately() {
    // After stage 3:
    //   * `catos-repair fs` is implemented (stage 2). With no
    //     devices and no explicit selection it refuses with
    //     ARG_ERROR (ambiguous target).
    //   * `catos-repair mount` is implemented (stage 3). It builds
    //     a structured report and may exit 0 (clean / partially
    //     repaired) or non-zero depending on the host. It MUST NOT
    //     print "not implemented".
    //   * `catos-repair boot` remains a stable "not implemented"
    //     result, exits non-zero, and mentions the domain.
    let bin = bin_path();
    let tmp = TempDir::new("catos-repair-domains").unwrap();
    let link = link_to(&bin, &tmp, "catos-repair");

    let (fs_ok, _fs_code, _fs_stdout, fs_stderr) = run_via(&link, &["fs"]);
    let _ = fs_ok;
    assert!(
        !fs_stderr.to_lowercase().contains("not implemented"),
        "fs must be implemented in stage 2; stderr={fs_stderr}"
    );

    let (mount_ok, _mount_code, _mount_stdout, mount_stderr) = run_via(&link, &["mount"]);
    let _ = mount_ok;
    assert!(
        !mount_stderr
            .to_lowercase()
            .contains("not implemented in this stage"),
        "mount must be implemented in stage 3; stderr={mount_stderr}"
    );

    let (boot_ok, boot_code, _boot_stdout, boot_stderr) = run_via(&link, &["boot"]);
    assert!(!boot_ok, "catos-repair boot unexpectedly succeeded");
    assert!(
        boot_stderr.contains("boot"),
        "stderr must mention domain boot: {boot_stderr}"
    );
    assert!(
        boot_stderr
            .to_lowercase()
            .contains("not implemented in this stage"),
        "stderr must say 'not implemented in this stage' for boot: {boot_stderr}"
    );
    assert_ne!(
        boot_code, 0,
        "unimplemented repair domain must exit non-zero"
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
    // must exit ARG_ERROR (2) and must NOT produce the phase-1 report.
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
        // The stdout must NOT be a phase-1 inspection report. If it
        // were, the JSON would contain `runtime`/`capabilities` keys.
        if !stdout.trim().is_empty() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
            if let Ok(value) = parsed {
                assert!(
                    value.get("runtime").is_none() && value.get("capabilities").is_none(),
                    "catos-update {sub} produced a phase-1 report: {value}"
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
    // Pins the existing doctor contract so the routing refactor does
    // not regress it. Doctor runs the diagnosis with no args; any
    // functional argument is rejected with ARG_ERROR (2).
    let bin = bin_path();
    let tmp = TempDir::new("catos-doctor-routing-regression").unwrap();
    let link = link_to(&bin, &tmp, "catos-doctor");
    let (ok_no_args, code_no_args, stdout, _) = run_via(&link, &[]);
    assert!(ok_no_args);
    assert_eq!(code_no_args, 0);
    for section in ["Runtime", "Capabilities", "Target"] {
        assert!(
            stdout.contains(section),
            "doctor output missing {section}: {stdout}"
        );
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
