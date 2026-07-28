//! Integration test: `catos-doctor` CLI contract.
//!
//! Real risks this guards against:
//!
//! 1. Someone introduces a `--json`, `--root-device`, or
//!    `inspect`/`preflight`/`fs`/`mount`/`boot`/`recovery` argument
//!    on `catos-doctor` (spec section 二 is explicit: argumentless
//!    only).
//! 2. The new aggregated Doctor re-introduces the inspection-only
//!    "Runtime / Capabilities / Target" headings.
//! 3. `catos-doctor` inherits any `catos-system` subcommand.
//! 4. A non-interactive unprivileged invocation starts probing and emits a
//!    mostly-empty report instead of failing before diagnosis.

use std::env;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
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

fn link_doctor() -> (TempDir, PathBuf) {
    let tmp = TempDir::new("catos-doctor-contract").unwrap();
    let link = tmp.path.join("catos-doctor");
    symlink(bin_path(), &link).unwrap();
    (tmp, link)
}

#[test]
fn doctor_noninteractive_unprivileged_fails_before_diagnosis() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let (_tmp, link) = link_doctor();
    let output = Command::new(&link).output().expect("spawn doctor");
    assert_eq!(output.status.code(), Some(4));
    assert!(
        output.stdout.is_empty(),
        "stdout must not contain an empty report"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("administrator privileges are required"),
        "stderr={stderr:?}"
    );
    assert!(
        stderr.contains("sudo catos-doctor"),
        "stderr={stderr:?}"
    );
}

#[test]
fn doctor_help_explains_exit_behavior_without_internal_scheme_names() {
    let (_tmp, link) = link_doctor();
    let output = Command::new(&link)
        .arg("--help")
        .output()
        .expect("spawn doctor --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("catos-doctor"));
    assert!(stdout.contains("Exit status is zero when a selected target was"));
    assert!(stdout.contains("diagnosed, even when problems were found"));
    assert!(stdout.contains("target-selection"));
    assert!(stdout.contains("internal pager"));
    assert!(stdout.contains("Enter advances and q quits"));
    assert!(!stdout.to_ascii_lowercase().contains("scheme b"));
    let lower = stdout.to_ascii_lowercase();
    assert!(lower.contains("filesystem"));
    assert!(lower.contains("mount"));
    assert!(lower.contains("boot"));
    assert!(lower.contains("recovery"));
}

#[test]
fn doctor_version_succeeds() {
    let (_tmp, link) = link_doctor();
    let output = Command::new(&link)
        .arg("--version")
        .output()
        .expect("spawn doctor --version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("catos-doctor "));
}

#[test]
fn doctor_rejects_all_functional_arguments() {
    let (_tmp, link) = link_doctor();
    let forbidden = [
        "inspect",
        "preflight",
        "recovery",
        "list",
        "fs",
        "mount",
        "boot",
        "check",
        "apply",
        "status",
        "resume",
        "revert",
        "--json",
        "--root-device",
        "/dev/sda1",
        "--root",
        "/",
        "plan",
        "environment",
        "capabilities",
        "storage",
        "scan",
        "target",
    ];
    for arg in forbidden {
        let output = Command::new(&link)
            .arg(arg)
            .output()
            .unwrap_or_else(|e| panic!("spawn doctor {arg}: {e}"));
        assert_ne!(
            output.status.code(),
            Some(0),
            "doctor unexpectedly accepted {arg:?}"
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "doctor {arg:?} should produce ARG_ERROR (2), got {:?}",
            output.status.code()
        );
    }
}

#[test]
fn doctor_rejects_repeated_or_combined_flags() {
    let (_tmp, link) = link_doctor();
    for argv in [
        ["--help", "--version"],
        ["--json", "--root-device"],
        ["fs", "--json"],
    ] {
        let output = Command::new(&link).args(argv).output().unwrap();
        assert_ne!(output.status.code(), Some(0));
    }
}

#[test]
fn doctor_does_not_inherit_catos_system_subcommands() {
    let (_tmp, link) = link_doctor();
    // The low-level inspection surfaces that catos-system owns MUST NOT appear on
    // catos-doctor. We assert each one returns ARG_ERROR.
    for sub in [
        "environment",
        "capabilities",
        "inspect",
        "storage",
        "target",
    ] {
        let output = Command::new(&link).args([sub, "--json"]).output().unwrap();
        assert_ne!(output.status.code(), Some(0));
    }
}

#[test]
fn doctor_noninteractive_permission_failure_does_not_render_sections() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let (_tmp, link) = link_doctor();
    let output = Command::new(&link).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for section in [
        "Environment",
        "Storage",
        "Filesystem",
        "Mount layout",
        "Boot",
        "Secure Boot",
        "Recovery",
    ] {
        assert!(
            !stdout.contains(section),
            "permission failure rendered {section}: {stdout}"
        );
    }
}

#[test]
fn doctor_does_not_print_legacy_inspection_headings() {
    let (_tmp, link) = link_doctor();
    let output = Command::new(&link).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Doctor replaces the legacy inspection-only output. The
    // previous "Runtime / Capabilities / Target" section trio is
    // gone for good — a regression here would mean someone wired
    // Doctor back to `inspect`.
    assert!(!stdout.contains("Runtime mode"));
    assert!(!stdout.contains("Capabilities:"));
}

#[test]
fn doctor_same_inode_as_other_entry_points() {
    // All five public entry points resolve to the same physical
    // binary. We verify by checking the stat'd inode of each
    // symlink's target (the canonical catos-system binary) matches.
    let tmp = TempDir::new("catos-doctor-inode").unwrap();
    let targets = [
        "catos-system",
        "catos-update",
        "catos-recovery",
        "catos-doctor",
        "catos-repair",
    ];
    let mut inodes = Vec::new();
    for name in targets {
        let link = tmp.path.join(name);
        symlink(bin_path(), &link).unwrap();
        let meta = std::fs::metadata(link).unwrap();
        use std::os::unix::fs::MetadataExt;
        inodes.push(meta.ino());
    }
    let first = inodes[0];
    assert!(
        inodes.iter().all(|ino| *ino == first),
        "entry-point inodes differ: {inodes:?}"
    );
}

#[test]
fn doctor_help_does_not_advertise_inspect_or_preflight() {
    let (_tmp, link) = link_doctor();
    let output = Command::new(&link).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("catos-doctor inspect"),
        "help advertised an `inspect` subcommand: {stdout}"
    );
    assert!(
        !stdout.contains("catos-doctor preflight"),
        "help advertised a `preflight` subcommand: {stdout}"
    );
    assert!(
        !stdout.contains("catos-doctor --json"),
        "help advertised a `--json` flag: {stdout}"
    );
}
