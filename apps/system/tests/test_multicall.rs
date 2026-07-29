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
fn public_help_lines_fit_an_eighty_column_terminal() {
    let cases: &[&[&str]] = &[
        &["--help"],
        &["help", "doctor"],
        &["help", "chroot"],
        &["help", "repair"],
        &["help", "repair", "fs"],
        &["help", "repair", "mount"],
        &["help", "repair", "boot"],
        &["help", "recovery"],
        &["help", "recovery", "list"],
        &["help", "recovery", "inspect"],
        &["help", "recovery", "plan"],
        &["help", "recovery", "apply"],
        &["help", "recovery", "status"],
        &["help", "recovery", "resume"],
        &["help", "recovery", "revert"],
        &["help", "recovery", "discard-plan"],
        &["help", "recovery", "purge"],
        &["help", "update"],
        &["advanced", "--help"],
    ];
    for args in cases {
        let output = Command::new(bin_path()).args(*args).output().unwrap();
        assert!(output.status.success(), "help failed for {args:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        for (line_number, line) in stdout.lines().enumerate() {
            assert!(
                line.chars().count() <= 80,
                "help line {} for {args:?} exceeds 80 columns: {line:?}",
                line_number + 1
            );
        }
    }
}

#[test]
fn core_probe_results_are_identical_across_entry_points() {
    // Public routing change: `catos-recovery` no longer inherits the
    // `catos-system inspect` subcommand. The public recovery surface is
    // `catos-recovery <SUB>` (list/inspect/plan/apply/status/resume/revert/
    // discard-plan/purge), and `catos-recovery inspect` is the RECOVERY inspect
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

    // Both forms reach the recovery layer. Without --root-device they
    // fail with the same structured `target_changed` argument error and
    // exit ARG_ERROR (2). This proves the new entry point is a thin
    // re-mapping over the existing parser, not a parallel CLI.
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
        Some(2),
        "recovery inspect without --root-device must be a structured argument error"
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
fn recovery_list_without_root_device_reaches_recovery_layer() {
    // Real dispatch proof: the public `list` token is accepted and rendered
    // through the recovery JSON envelope. The missing required target is a
    // static usage error, so it exits ARG_ERROR rather than PROBE_FAILED.
    let bin = bin_path();
    let tmp = TempDir::new("catos-recovery-list-dispatch").unwrap();
    let link = link_to(&bin, &tmp, "catos-recovery");
    let (ok, code, stdout, stderr) = run_via(&link, &["list", "--json"]);
    assert!(!ok, "stdout={stdout}, stderr={stderr}");
    assert_eq!(code, 2, "stderr={stderr}");
    assert!(stderr.is_empty(), "stderr={stderr}");
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("recovery list failure must be JSON");
    assert_eq!(value["kind"], "error");
    assert_eq!(value["payload"]["kind"], "target_changed");
    assert!(value["payload"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("--root-device")));
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
    // Every public recovery subcommand MUST route via the direct surface.
    // Missing required fields are static argument errors, but the payload
    // must still be the recovery envelope rather than an unknown-command
    // message from the generic parser.
    let bin = bin_path();
    let tmp = TempDir::new("catos-recovery-direct").unwrap();
    let link = link_to(&bin, &tmp, "catos-recovery");
    for sub in [
        "list", "inspect", "plan", "apply", "status", "resume", "revert",
    ] {
        let (ok, code, stdout, stderr) = run_via(&link, &[sub, "--json"]);
        assert!(!ok, "catos-recovery {sub} unexpectedly succeeded");
        assert_eq!(code, 2, "catos-recovery {sub}: stderr={stderr}");
        assert!(stderr.is_empty(), "catos-recovery {sub}: stderr={stderr}");
        let value: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|error| panic!("catos-recovery {sub}: {error}; stdout={stdout}"));
        assert_eq!(value["kind"], "error", "catos-recovery {sub}");
        assert!(value["payload"]["kind"].is_string(), "catos-recovery {sub}");
    }
}

// ---------------------------------------------------------------------------
// catos-repair
// ---------------------------------------------------------------------------

#[test]
fn aggregate_without_a_tty_rejects_the_interactive_menu() {
    let bin = bin_path();
    let output = Command::new(&bin).output().expect("spawn catos-system");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("interactive terminal"), "stderr={stderr}");
}

#[test]
fn role_menus_without_a_tty_fail_instead_of_reporting_success() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-role-menu-no-tty").unwrap();
    for name in ["catos-repair", "catos-recovery"] {
        let link = link_to(&bin, &tmp, name);
        let (ok, code, stdout, stderr) = run_via(&link, &[]);
        assert!(!ok, "{name} unexpectedly succeeded: {stdout}");
        assert_eq!(code, 2, "{name}: stderr={stderr}");
        assert!(stdout.is_empty(), "{name}: stdout={stdout}");
        assert!(
            stderr.contains("interactive terminal"),
            "{name}: stderr={stderr}"
        );
    }
}

#[test]
fn doctor_internal_workflow_requires_a_terminal() {
    let output = Command::new(bin_path())
        .args([
            "doctor",
            "--continue-interactive-menu",
            "workflow",
        ])
        .output()
        .expect("run Doctor workflow without a terminal");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive Doctor workflow requires a terminal"),
        "stderr={stderr}"
    );
}

#[test]
fn aggregate_help_and_errors_preserve_the_aggregate_command_name() {
    let bin = bin_path();
    for (args, expected, forbidden) in [
        (
            ["help", "doctor"].as_slice(),
            "catos-system doctor",
            "catos-doctor",
        ),
        (
            ["help", "repair"].as_slice(),
            "catos-system repair",
            "catos-repair",
        ),
        (
            ["help", "recovery"].as_slice(),
            "catos-system recovery",
            "catos-recovery",
        ),
        (
            ["help", "chroot"].as_slice(),
            "catos-system chroot",
            "catos-chroot",
        ),
        (
            ["help", "update"].as_slice(),
            "catos-system update",
            "catos-update",
        ),
    ] {
        let output = Command::new(&bin).args(args).output().expect("run help");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(expected), "args={args:?}: {stdout}");
        assert!(
            !stdout
                .lines()
                .next()
                .unwrap_or_default()
                .contains(forbidden),
            "args={args:?}: {stdout}"
        );
    }

    for (args, expected_prefix) in [
        (["repair", "nonsense"].as_slice(), "catos-system repair:"),
        (
            ["recovery", "nonsense"].as_slice(),
            "catos-system recovery:",
        ),
        (["chroot", "--nonsense"].as_slice(), "catos-system chroot:"),
        (["update", "--nonsense"].as_slice(), "catos-system update:"),
    ] {
        let output = Command::new(&bin).args(args).output().expect("run error");
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with(expected_prefix), "stderr={stderr}");
    }
}

#[test]
fn direct_write_commands_fail_at_the_privilege_boundary_before_probing() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let bin = bin_path();
    let tmp = TempDir::new("catos-direct-write-elevation").unwrap();
    let repair = link_to(&bin, &tmp, "catos-repair");
    let recovery = link_to(&bin, &tmp, "catos-recovery");

    let (_, repair_code, repair_stdout, repair_stderr) =
        run_via(&repair, &["fs", "/dev/does-not-exist"]);
    assert_eq!(repair_code, 4, "stderr={repair_stderr}");
    assert!(repair_stdout.is_empty());
    assert!(repair_stderr.contains("administrator privileges are required"));

    let (_, recovery_code, recovery_stdout, recovery_stderr) = run_via(
        &recovery,
        &[
            "resume",
            "--root-device",
            "/dev/does-not-exist",
            "--transaction",
            "tx-00000000000000000000000000000004",
        ],
    );
    assert_eq!(recovery_code, 4, "stderr={recovery_stderr}");
    assert!(recovery_stdout.is_empty());
    assert!(recovery_stderr.contains("administrator privileges are required"));

    for args in [
        vec![
            "discard-plan",
            "--root-device",
            "/dev/does-not-exist",
            "--plan-id",
            "tx-00000000000000000000000000000004",
            "--confirm",
            "v2:unused",
        ],
        vec![
            "purge",
            "--root-device",
            "/dev/does-not-exist",
            "--transaction",
            "tx-00000000000000000000000000000004",
            "--confirm",
            "purge-v1:unused",
        ],
    ] {
        let (_, code, stdout, stderr) = run_via(&recovery, &args);
        assert_eq!(code, 4, "args={args:?} stderr={stderr}");
        assert!(stdout.is_empty());
        assert!(stderr.contains("administrator privileges are required"));
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
fn update_full_flow_refuses_noninteractive_stdin_before_listing_updates() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-update-noninteractive").unwrap();
    let link = link_to(&bin, &tmp, "catos-update");
    let (ok, code, stdout, stderr) = run_via(&link, &[]);
    assert!(!ok);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "stdout={stdout:?}");
    assert!(stderr.contains("interactive terminal"), "stderr={stderr:?}");
    assert!(stderr.contains("--check"), "stderr={stderr:?}");
}

#[test]
fn update_help_does_not_advertise_unsupported_noop_flags() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-update-help-surface").unwrap();
    let link = link_to(&bin, &tmp, "catos-update");
    let (ok, code, stdout, stderr) = run_via(&link, &["--help"]);
    assert!(ok, "code={code} stderr={stderr}");
    assert!(!stdout.contains("--devel"), "stdout={stdout}");
    assert!(stdout.contains("interactive terminal"), "stdout={stdout}");
}

#[test]
fn repair_rejects_nonstandard_root_subvolume_before_elevation() {
    let bin = bin_path();
    for domain in ["mount", "boot"] {
        let output = Command::new(&bin)
            .args([
                "repair",
                domain,
                "--root-device",
                "/dev/does-not-exist",
                "--root-subvolume",
                "/@root",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "domain={domain}");
        assert!(output.stdout.is_empty(), "domain={domain}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("supports only"),
            "domain={domain}: {stderr}"
        );
        assert!(
            !stderr.contains("administrator privileges"),
            "domain={domain}: {stderr}"
        );
    }
}

#[test]
fn repair_top_level_help_defers_to_command_specific_options() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-repair-help-surface").unwrap();
    let link = link_to(&bin, &tmp, "catos-repair");
    let (ok, code, stdout, stderr) = run_via(&link, &["--help"]);
    assert!(ok, "code={code} stderr={stderr}");
    assert!(
        stdout.contains("catos-repair <COMMAND> --help"),
        "stdout={stdout}"
    );
    assert!(
        !stdout.contains("--root-device"),
        "top-level help must not imply every domain accepts the same options: {stdout}"
    );
}

#[test]
fn recovery_top_level_help_explains_the_safe_workflow() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-recovery-help-workflow").unwrap();
    let link = link_to(&bin, &tmp, "catos-recovery");
    let (ok, code, stdout, stderr) = run_via(&link, &["--help"]);
    assert!(ok, "code={code} stderr={stderr}");
    assert!(stdout.contains("WORKFLOW:"), "stdout={stdout}");
    assert!(stdout.contains("State-changing"), "stdout={stdout}");
    assert!(
        stdout.contains("List snapshots, pending plans, and recovery transactions"),
        "stdout={stdout}"
    );
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
fn recovery_static_usage_errors_exit_two_and_preserve_json() {
    let directory = TempDir::new("recovery-static-usage").unwrap();
    let recovery = directory.path.join("catos-recovery");
    symlink(bin_path(), &recovery).unwrap();

    for args in [
        vec!["list"],
        vec!["inspect", "--root-device", "/dev/does-not-exist"],
        vec!["status", "--root-device", "/dev/does-not-exist"],
        vec![
            "list",
            "--root-device",
            "/dev/does-not-exist",
            "--esp-device",
            "/dev/vda1",
        ],
    ] {
        let output = Command::new(&recovery).args(&args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "args={args:?} stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new(&recovery)
        .args(["list", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "error");
    assert_eq!(value["payload"]["kind"], "target_changed");
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
    for required in ["--root-device", "--plan-id", "--confirm"] {
        assert!(
            stdout.contains(required),
            "missing {required} in apply help: {stdout}"
        );
    }
    assert!(
        !stdout.contains("--plan-file"),
        "legacy plan-file option leaked into help"
    );
    assert!(
        !stdout.contains("COMMANDS:\n    list"),
        "apply help fell back to top-level help"
    );
    let options = stdout
        .split_once("OPTIONS:\n")
        .expect("apply help must contain an options section")
        .1;
    assert!(
        options.find("--plan-id").unwrap() < options.find("--root-device").unwrap(),
        "action-specific options should precede common target options: {stdout}"
    );
}

#[test]
fn recovery_lifecycle_help_exposes_distinct_confirmation_sources() {
    let directory = TempDir::new("recovery-lifecycle-help").unwrap();
    let recovery = directory.path.join("catos-recovery");
    symlink(bin_path(), &recovery).unwrap();

    let discard = Command::new(&recovery)
        .args(["discard-plan", "--help"])
        .output()
        .unwrap();
    assert!(discard.status.success());
    let discard = String::from_utf8(discard.stdout).unwrap();
    assert!(discard.contains("Pending plan id"));
    assert!(discard.contains("Apply token embedded in that plan"));
    assert!(!discard.contains("Purge token"));

    let purge = Command::new(&recovery)
        .args(["purge", "--help"])
        .output()
        .unwrap();
    assert!(purge.status.success());
    let purge = String::from_utf8(purge.stdout).unwrap();
    assert!(purge.contains("Completed or reverted transaction"));
    assert!(purge.contains("Purge token from"));
    assert!(purge.contains("permanently deletes"));
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
