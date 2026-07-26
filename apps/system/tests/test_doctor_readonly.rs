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

use catos_system::repair::runner::{RecordedRunner, ToolResult};
use catos_system::repair::fs_flows::{
    btrfs_check_only, check_only_for, e2fsck_check_only, f2fs_check_only, fat_check_only,
    xfs_check_only, ReadonlyOutcome,
};

#[test]
fn e2fsck_check_only_uses_n_flag_not_y() {
    let runner = RecordedRunner::new().queue_raw(0, b"clean".to_vec(), b"".to_vec());
    let _ = e2fsck_check_only(&runner, "/dev/sda1").unwrap();
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
}

#[test]
fn e2fsck_check_only_clean_returns_clean_outcome() {
    let runner = RecordedRunner::new().queue_raw(0, b"clean".to_vec(), b"".to_vec());
    let result = e2fsck_check_only(&runner, "/dev/sda1").unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::Clean);
    assert_eq!(result.exit_code, 0);
}

#[test]
fn e2fsck_check_only_corruption_returns_corruption_outcome() {
    let runner = RecordedRunner::new().queue_raw(4, b"errors left".to_vec(), b"".to_vec());
    let result = e2fsck_check_only(&runner, "/dev/sda1").unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
}

#[test]
fn fat_check_only_uses_n_flag_never_a() {
    let runner = RecordedRunner::new().queue_raw(0, b"clean".to_vec(), b"".to_vec());
    let _ = fat_check_only(&runner, "/dev/sda1").unwrap();
    let argv = &runner.invocations()[0].argv;
    assert!(argv.contains(&"-n".to_string()));
    assert!(!argv.contains(&"-a".to_string()));
    assert!(!argv.contains(&"-r".to_string()));
}

#[test]
fn f2fs_check_only_uses_dry_run_never_a_or_y() {
    let runner = RecordedRunner::new().queue_raw(0, b"clean".to_vec(), b"".to_vec());
    let _ = f2fs_check_only(&runner, "/dev/sda1").unwrap();
    let argv = &runner.invocations()[0].argv;
    assert!(argv.contains(&"--dry-run".to_string()));
    assert!(!argv.contains(&"-a".to_string()));
    assert!(!argv.contains(&"-y".to_string()));
    assert!(!argv.contains(&"-f".to_string()));
}

#[test]
fn xfs_check_only_uses_n_flag_never_l() {
    let runner = RecordedRunner::new().queue_raw(0, b"clean".to_vec(), b"".to_vec());
    let _ = xfs_check_only(&runner, "/dev/sda1").unwrap();
    let argv = &runner.invocations()[0].argv;
    assert_eq!(argv, &["-n".to_string(), "/dev/sda1".to_string()]);
    assert!(!argv.contains(&"-L".to_string()));
}

#[test]
fn xfs_check_only_dirty_log_does_not_escalate_to_l() {
    // The repair flow would escalate exit 2 → `-L`. The Doctor
    // variant MUST NOT: under `-n` exit 2 simply means "would have
    // needed -L", which is corruption detected.
    let runner = RecordedRunner::new().queue_raw(2, b"".to_vec(), b"dirty log".to_vec());
    let result = xfs_check_only(&runner, "/dev/sda1").unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
    assert_eq!(runner.invocations().len(), 1);
    assert!(!runner.any_invocation_with_flag("-L"));
}

#[test]
fn btrfs_check_only_uses_readonly_never_repair() {
    let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
    let _ = btrfs_check_only(&runner, "/dev/sda1").unwrap();
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
}

#[test]
fn btrfs_check_only_corruption_does_not_escalate_to_repair() {
    // The repair flow runs `btrfs check --readonly`, then if it
    // reports corruption, runs `btrfs check --repair`. The Doctor
    // variant MUST NOT run `--repair` — it surfaces the corruption
    // in the report instead.
    let runner = RecordedRunner::new().queue_raw(1, b"errors".to_vec(), b"".to_vec());
    let result = btrfs_check_only(&runner, "/dev/sda1").unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
    assert_eq!(runner.invocations().len(), 1);
    assert!(!runner.any_invocation_with_flag("--repair"));
}

#[test]
fn btrfs_check_only_checksum_diagnostic_is_corruption_not_clean() {
    let runner = RecordedRunner::new().queue_raw(
        0,
        b"checksum verify failed on 30605312 wanted 0x1 found 0x2".to_vec(),
        b"".to_vec(),
    );
    let result = btrfs_check_only(&runner, "/dev/sda1").unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
    assert!(!result.is_clean());
}

#[test]
fn check_only_for_dispatches_known_fstypes() {
    for fstype in [
        "ext2", "ext3", "ext4", "vfat", "fat", "fat32", "f2fs", "xfs", "btrfs",
    ] {
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let result = check_only_for(fstype, &runner, "/dev/sda1").unwrap();
        assert!(result.is_some(), "expected dispatch for {fstype:?}");
    }
}

#[test]
fn check_only_for_returns_none_for_unsupported_fstype() {
    let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
    assert!(check_only_for("ntfs", &runner, "/dev/sda1")
        .unwrap()
        .is_none());
    assert!(check_only_for("zfs", &runner, "/dev/sda1")
        .unwrap()
        .is_none());
}

#[test]
fn readonly_flows_report_tool_missing_without_invoking_anything() {
    let runner = RecordedRunner::new().queue(ToolResult::binary_missing());
    let result = btrfs_check_only(&runner, "/dev/sda1").unwrap();
    assert_eq!(result.outcome, ReadonlyOutcome::ToolMissing);
    // Single invocation attempt; no retries, no escalation.
    assert_eq!(runner.invocations().len(), 1);
}

#[test]
fn readonly_flows_record_label_for_audit_trail() {
    let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
    let result = btrfs_check_only(&runner, "/dev/sda1").unwrap();
    assert!(result.label.is_some(), "label must be recorded for audit");
    assert!(result.label.as_deref().unwrap().starts_with("btrfs"));
}

#[test]
fn readonly_flows_argv_is_independent_elements_no_shell() {
    let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
    let _ = e2fsck_check_only(&runner, "/dev/sda1; rm -rf /").unwrap();
    let argv = &runner.invocations()[0].argv;
    // The device path is a single argv element even when it contains
    // shell metacharacters — there is no `sh -c` form.
    assert_eq!(argv.last().unwrap(), "/dev/sda1; rm -rf /");
}
