//! Read-only guarantee tests for Doctor's filesystem diagnosis.
//!
//! Real risks this guards against:
//!
//! 1. A future maintainer wires Doctor's fs diagnosis to the repair
//!    flow (`-y`, `--repair`, `-L`, `fsck.fat -a`) instead of the
//!    read-only flows. The spec is explicit: Doctor 不执行
//!    `e2fsck -y`, `xfs_repair -L`, `btrfs check --repair`.
//! 2. Someone reuses the repair runner's `btrfs_flow` instead of the
//!    new `btrfs_check_only`. The repair flow escalates to
//!    `--repair` on detecting corruption; the Doctor variant MUST
//!    NOT.
//! 3. The f2fs read-only flow picks up `-a` instead of `--dry-run`.

use catos_system::fs::command::RecordedRunner;
use catos_system::fs::diagnose::btrfs::check_mounted_readonly;
use catos_system::fs::diagnose::{
    btrfs_check_only, check_only_for, e2fsck_check_only, f2fs_check_only, fat_check_only,
    xfs_check_only, ReadonlyOutcome,
};

const DEVICE: &str = "/dev/sda1";

fn expect_readonly(
    binary: &str,
    argv: &[&str],
    exit_code: i32,
    stdout: impl Into<Vec<u8>>,
    stderr: impl Into<Vec<u8>>,
) -> RecordedRunner {
    RecordedRunner::new().expect_raw(binary, argv.iter().copied(), exit_code, stdout, stderr)
}

fn expected_readonly_call(fstype: &str, device: &str) -> (&'static str, Vec<String>) {
    match fstype {
        "ext2" | "ext3" | "ext4" => (
            "e2fsck",
            vec!["-n".into(), "-C".into(), "0".into(), device.into()],
        ),
        "vfat" | "fat" | "fat32" => ("fsck.fat", vec!["-n".into(), device.into()]),
        "f2fs" => ("fsck.f2fs", vec!["--dry-run".into(), device.into()]),
        "xfs" => ("xfs_repair", vec!["-n".into(), device.into()]),
        "btrfs" => (
            "btrfs",
            vec!["check".into(), "--readonly".into(), device.into()],
        ),
        other => panic!("unsupported test fstype {other}"),
    }
}

#[test]
fn e2fsck_check_only_uses_n_flag_not_y() {
    let runner = expect_readonly("e2fsck", &["-n", "-C", "0", DEVICE], 0, b"clean", b"");
    let _ = e2fsck_check_only(&runner, DEVICE).unwrap();
    let invocations = runner.invocations();
    assert_eq!(invocations[0].binary, "e2fsck");
    let argv = &invocations[0].argv;
    assert!(
        argv.contains(&"-n".to_string()),
        "expected -n flag, got {argv:?}"
    );
    assert!(!argv.contains(&"-y".to_string()), "must not pass -y");
    assert!(
        !argv.contains(&"-p".to_string()),
        "must not pass -p (preen writes)"
    );
    runner.assert_consumed();
}

#[test]
fn e2fsck_check_only_clean_returns_clean_outcome() {
    let runner = expect_readonly("e2fsck", &["-n", "-C", "0", DEVICE], 0, b"clean", b"");
    let result = e2fsck_check_only(&runner, DEVICE).unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::Clean);
    assert_eq!(result.exit_code, 0);
    runner.assert_consumed();
}

#[test]
fn e2fsck_check_only_corruption_returns_corruption_outcome() {
    let runner = expect_readonly("e2fsck", &["-n", "-C", "0", DEVICE], 4, b"errors left", b"");
    let result = e2fsck_check_only(&runner, DEVICE).unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
    runner.assert_consumed();
}

#[test]
fn fat_check_only_uses_n_flag_never_a() {
    let runner = expect_readonly("fsck.fat", &["-n", DEVICE], 0, b"clean", b"");
    let _ = fat_check_only(&runner, DEVICE).unwrap();
    let argv = &runner.invocations()[0].argv;
    assert!(argv.contains(&"-n".to_string()));
    assert!(!argv.contains(&"-a".to_string()));
    assert!(!argv.contains(&"-r".to_string()));
    runner.assert_consumed();
}

#[test]
fn f2fs_check_only_uses_dry_run_never_a_or_y() {
    let runner = expect_readonly("fsck.f2fs", &["--dry-run", DEVICE], 0, b"clean", b"");
    let _ = f2fs_check_only(&runner, DEVICE).unwrap();
    let argv = &runner.invocations()[0].argv;
    assert!(argv.contains(&"--dry-run".to_string()));
    assert!(!argv.contains(&"-a".to_string()));
    assert!(!argv.contains(&"-y".to_string()));
    assert!(!argv.contains(&"-f".to_string()));
    runner.assert_consumed();
}

#[test]
fn xfs_check_only_uses_n_flag_never_l() {
    let runner = expect_readonly("xfs_repair", &["-n", DEVICE], 0, b"clean", b"");
    let _ = xfs_check_only(&runner, DEVICE).unwrap();
    let argv = &runner.invocations()[0].argv;
    assert_eq!(argv, &["-n".to_string(), "/dev/sda1".to_string()]);
    assert!(!argv.contains(&"-L".to_string()));
    runner.assert_consumed();
}

#[test]
fn xfs_check_only_dirty_log_does_not_escalate_to_l() {
    // The repair flow would escalate exit 2 → `-L`. The Doctor
    // variant MUST NOT: under `-n` exit 2 simply means "would have
    // needed -L", which is corruption detected.
    let runner = expect_readonly("xfs_repair", &["-n", DEVICE], 2, b"", b"dirty log");
    let result = xfs_check_only(&runner, DEVICE).unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
    assert_eq!(runner.invocations().len(), 1);
    assert!(!runner.any_invocation_with_flag("-L"));
    runner.assert_consumed();
}

#[test]
fn btrfs_check_only_uses_readonly_never_repair() {
    let runner = expect_readonly("btrfs", &["check", "--readonly", DEVICE], 0, b"", b"");
    let _ = btrfs_check_only(&runner, DEVICE).unwrap();
    let argv = &runner.invocations()[0].argv;
    assert_eq!(
        argv,
        &[
            "check".to_string(),
            "--readonly".to_string(),
            "/dev/sda1".to_string()
        ]
    );
    assert!(!runner.any_invocation_with_flag("--repair"));
    runner.assert_consumed();
}

#[test]
fn btrfs_check_on_controlled_readonly_mount_adds_force_without_repair() {
    let runner = expect_readonly(
        "btrfs",
        &["check", "--readonly", "--force", DEVICE],
        0,
        b"",
        b"",
    );
    let result = check_mounted_readonly(&runner, DEVICE).unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::Clean);
    assert!(runner.any_invocation_with_flag("--readonly"));
    assert!(runner.any_invocation_with_flag("--force"));
    assert!(!runner.any_invocation_with_flag("--repair"));
    runner.assert_consumed();
}

#[test]
fn btrfs_check_only_corruption_does_not_escalate_to_repair() {
    // The repair flow runs `btrfs check --readonly`, then if it
    // reports corruption, runs `btrfs check --repair`. The Doctor
    // variant MUST NOT run `--repair` — it surfaces the corruption
    // in the report instead.
    let runner = expect_readonly("btrfs", &["check", "--readonly", DEVICE], 1, b"errors", b"");
    let result = btrfs_check_only(&runner, DEVICE).unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
    assert_eq!(runner.invocations().len(), 1);
    assert!(!runner.any_invocation_with_flag("--repair"));
    runner.assert_consumed();
}

#[test]
fn btrfs_check_only_checksum_diagnostic_is_corruption_not_clean() {
    let runner = RecordedRunner::new().expect_raw(
        "btrfs",
        ["check", "--readonly", DEVICE],
        0,
        b"checksum verify failed on 30605312 wanted 0x1 found 0x2".to_vec(),
        b"".to_vec(),
    );
    let result = btrfs_check_only(&runner, DEVICE).unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
    assert!(!result.is_clean());
    runner.assert_consumed();
}

#[test]
fn check_only_for_dispatches_known_fstypes() {
    for fstype in [
        "ext2", "ext3", "ext4", "vfat", "fat", "fat32", "f2fs", "xfs", "btrfs",
    ] {
        let (binary, argv) = expected_readonly_call(fstype, DEVICE);
        let runner = RecordedRunner::new().expect_raw(binary, argv, 0, b"", b"");
        let result = check_only_for(fstype, &runner, DEVICE).unwrap();
        assert!(result.is_some(), "expected dispatch for {fstype:?}");
        runner.assert_consumed();
    }
}

#[test]
fn check_only_for_returns_none_for_unsupported_fstype() {
    let runner = RecordedRunner::new();
    assert!(check_only_for("ntfs", &runner, DEVICE).unwrap().is_none());
    assert!(check_only_for("zfs", &runner, DEVICE).unwrap().is_none());
    assert_eq!(runner.invocation_count(), 0);
    runner.assert_consumed();
}

#[test]
fn readonly_flows_report_tool_missing_without_invoking_anything() {
    let runner = RecordedRunner::new().expect_missing("btrfs", ["check", "--readonly", DEVICE]);
    let result = btrfs_check_only(&runner, DEVICE).unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::ToolMissing);
    // Single invocation attempt; no retries, no escalation.
    assert_eq!(runner.invocations().len(), 1);
    runner.assert_consumed();
}

#[test]
fn readonly_flows_record_label_for_audit_trail() {
    let runner = expect_readonly("btrfs", &["check", "--readonly", DEVICE], 0, b"", b"");
    let result = btrfs_check_only(&runner, DEVICE).unwrap();
    assert!(result.label.is_some(), "label must be recorded for audit");
    assert!(result.label.as_deref().unwrap().starts_with("btrfs"));
    runner.assert_consumed();
}

#[test]
fn readonly_flows_argv_is_independent_elements_no_shell() {
    let hostile = "/dev/sda1; rm -rf /";
    let runner = expect_readonly("e2fsck", &["-n", "-C", "0", hostile], 0, b"", b"");
    let _ = e2fsck_check_only(&runner, hostile).unwrap();
    let argv = &runner.invocations()[0].argv;
    // The device path is a single argv element even when it contains
    // shell metacharacters — there is no `sh -c` form.
    assert_eq!(argv.last().unwrap(), "/dev/sda1; rm -rf /");
    runner.assert_consumed();
}
