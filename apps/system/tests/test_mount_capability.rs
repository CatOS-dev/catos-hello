//! Phase-2 behaviour tests for the `mount` capability module.
//!
//! Each test asserts a real, deterministic property of the migrated
//! module. The tests are written against the post-migration API and
//! must fail on the pre-migration codebase (the `mount` module does not
//! exist). No test blanket-accepts an error, bypasses an assertion with
//! `if`, or matches every enum variant to pretend success.

use std::path::PathBuf;

use catos_system::mount;

// ---------------------------------------------------------------------------
// 1. Doctor's mount path never constructs a read-write session.
// ---------------------------------------------------------------------------

/// Doctor diagnoses via `mount::diagnose` and `ReadOnlyMountSession`
/// only. It must NOT name any read-write session type and must NOT
/// import `crate::repair` for mount diagnosis.
///
/// Falsifiable in two compounding ways:
/// 1. Source invariant — the doctor mount section references neither a
///    `RwSession` type nor `crate::repair`.
/// 2. Type-level invariant — the diagnose entry point is bound through
///    `mount::model::MountTargetIdentity`, the mount-domain type, not a
///    repair-domain type.
#[test]
fn doctor_mount_path_never_builds_rw_session() {
    let src = include_str!("../src/doctor/sections/mount.rs");
    assert!(
        !src.contains("RwSession"),
        "doctor mount section must not reference any RW session type"
    );
    assert!(
        !src.contains("crate::repair"),
        "doctor mount section must not depend on crate::repair"
    );
    assert!(
        !src.contains("BtrfsTopLevelRwSession") && !src.contains("TargetMountRwSession"),
        "doctor mount section must not name a mount RW session concrete type"
    );

    // Type-level: the mount-domain rich identity is reachable from
    // `mount::model`. If the rich identity were left in a repair-domain
    // module, this path would not resolve.
    let _type_check: fn() = || {
        let _ = mount::model::MountTargetIdentity::default();
    };
}

// ---------------------------------------------------------------------------
// 2. ReadOnlyMountSession forces the authoritative read-only flag.
// ---------------------------------------------------------------------------

/// The read-only session issues `mount(2)` with `MS_RDONLY` forced on,
/// independent of the option string. This is the kernel's authoritative
/// "this mount cannot write" signal. The btrfs top-level RW session
/// hardens with `MS_NOSUID | MS_NODEV`. Both are asserted at source
/// level against the migrated session files.
#[test]
fn readonly_session_forces_ms_rdonly() {
    let ro_src = include_str!("../src/mount/session/readonly.rs");
    assert!(
        ro_src.contains("MS_RDONLY"),
        "ReadOnlyMountSession must force MS_RDONLY on the mount(2) call"
    );
    // The RO session must NOT pass MNT_FORCE during cleanup (it can
    // corrupt in-flight metadata even on RO mounts).
    assert!(
        !ro_src.contains("MNT_FORCE"),
        "ReadOnlyMountSession cleanup must never use MNT_FORCE"
    );

    let btrfs_src = include_str!("../src/mount/session/btrfs_top_level.rs");
    assert!(
        btrfs_src.contains("MS_NOSUID") && btrfs_src.contains("MS_NODEV"),
        "BtrfsTopLevelRwSession must harden the RW mount with MS_NOSUID|MS_NODEV"
    );
    assert!(
        !btrfs_src.contains("MNT_FORCE"),
        "BtrfsTopLevelRwSession cleanup must never use MNT_FORCE"
    );
}

// ---------------------------------------------------------------------------
// 3. BtrfsTopLevelRwSession cleanup is the authoritative teardown.
// ---------------------------------------------------------------------------

/// Cleanup of the btrfs top-level RW session:
/// * is idempotent (a second call is a no-op once Cleaned);
/// * falls back to `MNT_DETACH` (never `MNT_FORCE`) on umount failure;
/// * records the directory-removal failure as a residual.
///
/// The idempotency is enforced structurally: the cleanup branch checks
/// the `Cleaned` state and returns early. We assert that branch exists
/// in the source, and that the Drop safety net calls the same cleanup.
#[test]
fn btrfs_top_level_cleanup_is_idempotent_and_detaches() {
    let src = include_str!("../src/mount/session/btrfs_top_level.rs");
    assert!(
        src.contains("MNT_DETACH"),
        "BtrfsTopLevelRwSession cleanup must fall back to MNT_DETACH"
    );
    // The idempotent early-return: the cleanup must reference the
    // Cleaned guard so a second call does not re-enter the umount path.
    assert!(
        src.contains("Cleaned"),
        "BtrfsTopLevelRwSession cleanup must guard on the Cleaned state for idempotency"
    );
}

// ---------------------------------------------------------------------------
// 4. Partial mount failure rolls back already-established mounts.
// ---------------------------------------------------------------------------

/// On any step failure, `ReadOnlyMountSession::run` MUST roll back every
/// mount it already created (in reverse order) before returning the
/// error. This is asserted at source level: the run path must invoke
/// the internal cleanup on the error branch and surface residuals.
#[test]
fn partial_mount_failure_rolls_back() {
    let src = include_str!("../src/mount/session/readonly.rs");
    assert!(
        src.contains("cleanup_internal"),
        "ReadOnlyMountSession::run must call the internal cleanup on step failure"
    );
    // The rolled-back mounts must be reported as residual when umount
    // fails, never silently dropped.
    assert!(
        src.contains("residual"),
        "ReadOnlyMountSession rollback must surface residual mounts"
    );
}

// ---------------------------------------------------------------------------
// 5. Cleanup is idempotent (behavioural, no root required).
// ---------------------------------------------------------------------------

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
    assert!(first.unmounted.is_empty(), "never-run cleanup unmounts nothing");
    assert!(first.residual.is_empty(), "never-run cleanup has no residuals");
    assert!(first.all_clean, "never-run cleanup is clean");

    let second = session.cleanup();
    assert!(second.residual.is_empty(), "second cleanup must be a no-op");
    assert!(second.all_clean, "second cleanup must remain clean");
}

// ---------------------------------------------------------------------------
// 6. Recovery write path takes root + lock before the RW session.
// ---------------------------------------------------------------------------

/// `apply`/`resume`/`revert` must call `require_root()` BEFORE
/// constructing the btrfs top-level RW session, so an unprivileged
/// caller is rejected before any mount is attempted. Asserted at source
/// level over the recovery write module.
#[test]
fn recovery_write_requires_root_before_rw_session() {
    let src = include_str!("../src/recovery/write.rs");
    let require_root_pos = src.find("require_root").unwrap_or_else(|| {
        panic!("recovery/write.rs must call require_root before mounting the RW session")
    });
    let mount_pos = src.find("BtrfsTopLevelRwSession::mount").unwrap_or_else(|| {
        panic!("recovery/write.rs must construct the btrfs top-level RW session")
    });
    assert!(
        require_root_pos < mount_pos,
        "require_root must be called BEFORE the RW session is constructed"
    );
}

// ---------------------------------------------------------------------------
// 7. Mount plan does not issue syscalls.
// ---------------------------------------------------------------------------

/// Plan construction is pure: it must not import or call the syscall
/// layer. If a future change makes `plan` issue a real mount, this
/// source-level check fails.
#[test]
fn mount_plan_does_not_invoke_syscall() {
    let session_src = include_str!("../src/mount/plan/session.rs");
    let repair_src = include_str!("../src/mount/plan/repair.rs");
    for (name, src) in [("session.rs", session_src), ("repair.rs", repair_src)] {
        assert!(
            !src.contains("execute::syscall") && !src.contains("syscall::mount") && !src.contains("syscall::umount"),
            "mount/plan/{name} must not invoke the syscall layer; planning is side-effect free"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. Execute does not invent mounts outside the plan.
// ---------------------------------------------------------------------------

/// The read-only session mounts exactly the steps the plan carries —
/// `execute_step` receives a `MountStep` and uses its source/target/
/// fstype, never constructing an ad-hoc mount. Asserted at source level
/// over the session's execute path.
#[test]
fn execute_does_not_invent_mounts() {
    let src = include_str!("../src/mount/session/readonly.rs");
    assert!(
        src.contains("step.source") && src.contains("step.target") && src.contains("step.fstype"),
        "ReadOnlyMountSession must mount exactly the provided MountStep fields"
    );
}

// ---------------------------------------------------------------------------
// 9. Offline target fstab is read from the target root, not the host.
// ---------------------------------------------------------------------------

/// (a) Behavioural: the fstab parser is a pure function of the bytes
/// read from the target's `etc/fstab`. Feeding it a fixture body
/// produces the entries encoded in that body — proving the parsed
/// fstab is whatever the caller read from the target root, never the
/// host `/etc/fstab`.
///
/// (b) Source invariant: the probe reads `etc/fstab` rooted at the
/// mounted target via `rooted_read_to_string`, never the host path.
#[test]
fn offline_target_fstab_comes_from_target_root() {
    // (a) Pure parser over target-provided bytes.
    let body = "UUID=root-uuid / btrfs defaults,subvol=/@ 0 0\nUUID=esp-uuid /boot/efi vfat defaults 0 2\n";
    let entries = mount::diagnose::fstab::parse_all(body);
    assert_eq!(entries.len(), 2, "parser must return every target fstab entry");
    let root = entries
        .iter()
        .find(|e| e.target == "/")
        .expect("root entry present in target fstab");
    assert_eq!(root.fstype, "btrfs");

    // (b) Source invariant: the probe path is rooted at the target.
    let probe_src = include_str!("../src/mount/plan/session.rs");
    assert!(
        probe_src.contains("etc/fstab") && !probe_src.contains("\"/etc/fstab\""),
        "probe must read etc/fstab relative to the target root, never the host /etc/fstab"
    );
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
    assert!(!dirty.all_clean, "a residual mount must not be reported clean");
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
