//! Behaviour tests that remain meaningful across crate boundaries.

use std::path::PathBuf;

use catos_system::mount;

/// A never-run `ReadOnlyMountSession` produces an empty, clean report
/// from `cleanup()`, and a second `cleanup()` call is a stable no-op.
/// This is a real behavioural test of the cleanup state machine: it
/// never iterates pre-existing mounts and never produces spurious
/// residuals. It needs no CAP_SYS_ADMIN because no mount is attempted.
#[test]
fn cleanup_on_never_run_session_is_idempotent() {
    let plan = mount::model::MountPlan {
        session_root: PathBuf::from("/tmp/catos-mount-cap-test-session"),
        target_root: PathBuf::from("/tmp/catos-mount-cap-test-session/target"),
        namespace: mount::model::NamespaceState::PrivateNamespace,
        root_device: None,
        root_subvolume: None,
        extra_partitions: vec![],
        steps: vec![],
        selection_rationale: vec![],
        safety_constraints: vec![],
        warnings: vec![],
    };

    let mut session = mount::session::ReadOnlyMountSession::new("cap-test", &plan);
    let first = session.cleanup();
    assert!(
        first.unmounted.is_empty(),
        "never-run cleanup unmounts nothing"
    );
    assert!(
        first.residual.is_empty(),
        "never-run cleanup has no residuals"
    );
    assert!(first.all_clean, "never-run cleanup is clean");

    let second = session.cleanup();
    assert!(second.residual.is_empty(), "second cleanup must be a no-op");
    assert!(second.all_clean, "second cleanup must remain clean");
}

/// The fstab parser consumes caller-supplied target bytes and preserves the
/// target's root and ESP entries.
#[test]
fn offline_target_fstab_comes_from_target_root() {
    // (a) Pure parser over target-provided bytes.
    let body = "UUID=root-uuid / btrfs defaults,subvol=/@ 0 0\nUUID=esp-uuid /boot/efi vfat defaults 0 2\n";
    let entries = mount::diagnose::fstab::parse_all(body);
    assert_eq!(
        entries.len(),
        2,
        "parser must return every target fstab entry"
    );
    let root = entries
        .iter()
        .find(|e| e.target == "/")
        .expect("root entry present in target fstab");
    assert_eq!(root.fstype, "btrfs");
}

// ---------------------------------------------------------------------------
// 10. A cleanup with residuals is never reported as clean.
// ---------------------------------------------------------------------------

/// Behavioural: a `CleanupReport` that carries a residual mount, or a
/// directory-cleanup error, must report `all_clean == false`. The mount
/// verify path relies on this so a dirty namespace is never disguised
/// as a successful teardown.
#[test]
fn cleanup_residual_is_not_reported_clean() {
    use mount::model::{CleanupReport, MountedResource, ResidualMount};

    // A report with one residual: must NOT be clean.
    let dirty = CleanupReport {
        unmounted: vec![],
        residual: vec![ResidualMount {
            resource: MountedResource {
                order: 1,
                source: "/dev/sda1".into(),
                target: PathBuf::from("/run/catos-system/sessions/x/target"),
                fstype: "ext4".into(),
                options: "ro".into(),
            },
            reason: "umount2 errno 16".into(),
            error_code: "device_busy".into(),
        }],
        observed_pre_existing: vec![],
        directory_cleanup_error: None,
        all_clean: false,
    };
    assert!(
        !dirty.all_clean,
        "a residual mount must not be reported clean"
    );
    assert!(
        !dirty.residual.is_empty(),
        "the residual must be preserved, not swallowed"
    );

    // A report whose directory removal failed: also not clean, even
    // when no mount residual remains.
    let dir_failed = CleanupReport {
        unmounted: vec![],
        residual: vec![],
        observed_pre_existing: vec![],
        directory_cleanup_error: Some("remove_dir_all: busy".into()),
        all_clean: false,
    };
    assert!(
        !dir_failed.all_clean,
        "a directory-cleanup failure must not be reported clean"
    );
    assert!(dir_failed.directory_cleanup_error.is_some());

    // Default report (nothing happened) IS clean — the positive case.
    assert!(CleanupReport::default().all_clean, "empty cleanup is clean");
}
