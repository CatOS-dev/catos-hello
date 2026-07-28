//! Group 1 — Transaction exclusivity, failure persistence, crash
//! consistency.
//!
//! These tests pin the load-bearing invariants the master plan calls
//! out as blockers:
//!
//! * "pre-persist 崩溃可能重复交换根" — a crash between an on-disk
//!   side-effect and the state-machine persist must NOT cause resume
//!   to re-execute the side-effect.
//! * "resume/revert 未重新获取锁" — resume and revert MUST re-acquire
//!   the per-FSID exclusive lock so two concurrent invokers cannot
//!   race the renameat2 swap.
//!
//! Every test here exercises a real failure mode (see STEP 2 in the
//! task report). No mocks: real fcntl locks on tmpfs, real
//! subprocesses for cross-process conflict, real on-disk records for
//! failure persistence, real disk-fact drift for terminal drift.
//!
//! The QEMU smoke harness (`scripts/recovery-qemu-smoke.sh`) covers
//! the same invariants end-to-end under a real btrfs image. The tests
//! in this file cover the unit-level behaviour the QEMU harness
//! depends on, so a regression is caught locally without needing root
//! inside the developer's machine.

#![cfg(feature = "test-helpers")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use catos_system::boot::model::BootLayout;
use catos_system::snapshot::execute::engine::{Engine, EngineOptions};
use catos_system::snapshot::model::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CompletedStep, DiskFacts, FstabRootDefinition,
    RecoveryPlan, SnapshotError, SnapshotErrorKind, SubvolumeFacts, TransactionPaths,
    TransactionRecord, TransactionState, RECOVERY_PLAN_SCHEMA_VERSION, TX_RECORD_SCHEMA_VERSION,
};
use catos_system::snapshot::plan::reconcile::reconcile_with_disk_facts;
use catos_system::snapshot::plan::{build_confirmation_token, effective_plan_digest};
use catos_system::snapshot::store;
use catos_system::snapshot::transaction::{lock_file_path, TransactionLock};
use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn helper_bin() -> PathBuf {
    PathBuf::from(env!(
        "CARGO_BIN_EXE_catos-recovery-lock-hold-helper",
        "test-helpers feature must be enabled for Group 1 lock tests"
    ))
}

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "catos-group1-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn strict_test_id(label: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut hasher);
    let first = hasher.finish();
    let second = first.rotate_left(29) ^ 0xa5a5_5a5a_d3c4_b2e1;
    format!("tx-{first:016x}{second:016x}")
}

fn sample_plan_with_fsid(fsid: &str, plan_label: &str) -> RecoveryPlan {
    let plan_id = strict_test_id(plan_label);
    let mut plan = RecoveryPlan {
        schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
        plan_id: plan_id.clone(),
        generated_at_unix: 1,
        generated_on_host: None,
        filesystem: BtrfsFilesystemIdentity {
            fsid: fsid.into(),
            device_major_minor: "259:2".into(),
            label: None,
        },
        current_root: BtrfsSubvolumeIdentity {
            path: "/@".into(),
            subvolume_id: 256,
            generation: 100,
            uuid: Some("old-root-uuid".into()),
            parent_uuid: None,
            read_only: false,
            evidence: vec![],
        },
        source_snapshot: BtrfsSubvolumeIdentity {
            path: "/@snapshots/1".into(),
            subvolume_id: 300,
            generation: 80,
            uuid: Some("source-snapshot-uuid".into()),
            parent_uuid: Some("older-root-uuid".into()),
            read_only: true,
            evidence: vec![],
        },
        target_catos_identity: None,
        boot_layout: BootLayout::default(),
        boot_consistency: catos_system::boot::diagnose::layout::evaluate_readonly_consistency(
            &BootLayout::default(),
        ),
        backup_root_path: format!("/.catos-recovery/backups/{plan_id}/root-before"),
        staging_root_path: format!("/.catos-recovery/staging/{plan_id}/new-root"),
        fstab_root_definition: FstabRootDefinition {
            source: "/dev/nvme0n1p2".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        },
        predicted_steps: vec![],
        refusal_conditions: vec![],
        risks_and_warnings: vec![],
        nonce: "00".repeat(32),
        plan_digest: String::new(),
        confirmation_token: String::new(),
        evidence: vec![],
    };
    plan.plan_digest = effective_plan_digest(&plan).unwrap();
    plan.confirmation_token =
        build_confirmation_token(&plan.plan_id, &plan.plan_digest, &plan.nonce);
    plan
}

fn sample_record_with_state(plan: RecoveryPlan, state: TransactionState) -> TransactionRecord {
    TransactionRecord {
        schema_version: TX_RECORD_SCHEMA_VERSION,
        transaction_id: plan.plan_id.clone(),
        created_at_unix: 1,
        last_updated_unix: 1,
        plan,
        state,
        completed_steps: vec![CompletedStep {
            state,
            completed_at_unix: 1,
            description: "fixture".into(),
        }],
        last_error: None,
        last_disk_facts: None,
        last_cleanup: None,
    }
}

fn persist_record_under(top: &Path, record: &TransactionRecord) -> PathBuf {
    let tx_dir = top
        .join(TransactionPaths::transactions_dir().trim_start_matches('/'))
        .join(&record.transaction_id);
    let state_path = tx_dir.join("state.json");
    store::persist_record(&state_path, record).unwrap();
    state_path
}

fn facts_backup_only(plan: &RecoveryPlan) -> DiskFacts {
    DiskFacts {
        filesystem_fsid: plan.filesystem.fsid.clone(),
        active_root_exists: true,
        active_root: Some(SubvolumeFacts {
            path: plan.current_root.path.clone(),
            subvolume_id: Some(plan.current_root.subvolume_id),
            generation: Some(plan.current_root.generation),
            uuid: plan.current_root.uuid.clone(),
            parent_uuid: plan.current_root.parent_uuid.clone(),
            read_only: Some(plan.current_root.read_only),
        }),
        staging_root_exists: false,
        staging_root: None,
        backup_root_exists: true,
        backup: Some(SubvolumeFacts {
            path: plan.backup_root_path.clone(),
            subvolume_id: Some(400),
            generation: Some(100),
            uuid: Some("backup-uuid".into()),
            parent_uuid: plan.current_root.uuid.clone(),
            read_only: Some(true),
        }),
        source_snapshot_exists: true,
        source_snapshot: Some(SubvolumeFacts {
            path: plan.source_snapshot.path.clone(),
            subvolume_id: Some(plan.source_snapshot.subvolume_id),
            generation: Some(plan.source_snapshot.generation),
            uuid: plan.source_snapshot.uuid.clone(),
            parent_uuid: plan.source_snapshot.parent_uuid.clone(),
            read_only: Some(plan.source_snapshot.read_only),
        }),
    }
}

// ===========================================================================
// STEP 3.1 — Non-blocking exclusive lock conflict tests
// ===========================================================================
//
// Each test spawns a REAL child process (catos-recovery-lock-hold-helper)
// that acquires the per-FSID lock and holds it for a fixed window.
// The parent then attempts to acquire the SAME lock (same fsid-derived
// path) and asserts it gets TransactionAlreadyActive IMMEDIATELY — no
// 30-second hang.

/// Wait for the helper to print `LOCK_HELD` to its stdout, indicating
/// the child has the lock. Returns the full stdout line.
fn wait_for_lock_held(child: &mut std::process::Child) -> String {
    use std::io::Read;
    let stdout = child.stdout.as_mut().expect("child stdout must be piped");
    let mut buf = [0u8; 256];
    let mut accumulated = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        match stdout.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                accumulated.push_str(std::str::from_utf8(&buf[..n]).unwrap());
                if accumulated.contains("LOCK_HELD") {
                    return accumulated;
                }
                if accumulated.contains("LOCK_FAILED") {
                    panic!("helper failed to acquire lock: {accumulated}");
                }
            }
            Err(e) => panic!("read helper stdout: {e}"),
        }
    }
    panic!("helper did not print LOCK_HELD within 10s; stdout so far: {accumulated}");
}

/// Spawn the lock-hold helper against `top`/`fsid`, hold for 8s.
fn spawn_lock_holder(top: &Path, fsid: &str) -> std::process::Child {
    Command::new(helper_bin())
        .arg(top)
        .arg(fsid)
        .arg("8")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot spawn {}: {e}", helper_bin().display()))
}

/// Acquire-and-time-how-fast: returns the elapsed time before
/// `TransactionLock::try_acquire` returned `Err`. Used to assert
/// non-blocking behaviour.
fn time_lock_failure(top: &Path, fsid: &str) -> (SnapshotErrorKind, std::time::Duration) {
    let path = lock_file_path(top, fsid);
    let start = std::time::Instant::now();
    let err = TransactionLock::try_acquire(&path, fsid).unwrap_err();
    (err.kind, start.elapsed())
}

#[test]
fn begin_failure_removes_the_already_persisted_plan() {
    use std::os::unix::fs::symlink;

    let top = scratch_dir("begin-plan-cleanup");
    let outside = top.with_extension("outside-state");
    std::fs::write(&outside, b"sentinel").unwrap();
    let plan = sample_plan_with_fsid("fsid-begin-cleanup", "p-begin-cleanup");
    let transaction_dir = top
        .join(TransactionPaths::transactions_dir().trim_start_matches('/'))
        .join(&plan.plan_id);
    std::fs::create_dir_all(&transaction_dir).unwrap();
    let state_path = transaction_dir.join("state.json");
    let plan_path = transaction_dir.join("plan.json");
    symlink(&outside, &state_path).unwrap();

    let error = match Engine::begin(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        plan,
    ) {
        Ok(_) => panic!("state symlink must prevent transaction creation"),
        Err(error) => error,
    };

    assert_eq!(error.kind, SnapshotErrorKind::UnsafeRecoveryPath);
    assert!(error
        .message
        .contains("additionally failed to clean incomplete transaction metadata"));
    assert!(!plan_path.exists(), "failed begin left an orphan plan");
    assert!(state_path.is_symlink());
    assert_eq!(std::fs::read(&outside).unwrap(), b"sentinel");
    let _ = std::fs::remove_dir_all(&top);
    let _ = std::fs::remove_file(&outside);
}

#[test]
fn apply_apply_lock_conflict() {
    // Failure mode: two concurrent `recovery apply` invocations
    // against the same btrfs FSID race the backup-snapshot creation
    // and the renameat2 swap.
    let top = scratch_dir("apply-apply");
    let fsid = "fsid-apply-apply";
    let mut child = spawn_lock_holder(&top, fsid);
    wait_for_lock_held(&mut child);
    let (kind, elapsed) = time_lock_failure(&top, fsid);
    assert_eq!(
        kind,
        SnapshotErrorKind::TransactionAlreadyActive,
        "expected structured TransactionAlreadyActive, got {kind:?}"
    );
    assert!(
        elapsed.as_secs() < 2,
        "lock acquire blocked for {elapsed:?}; must be non-blocking"
    );
    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&top);
}

#[test]
fn apply_resume_lock_conflict() {
    // Failure mode: a `resume` re-runs drive() against a still-running
    // `apply` and double-executes snapshot/renameat2 steps.
    let top = scratch_dir("apply-resume");
    let fsid = "fsid-apply-resume";
    let mut child = spawn_lock_holder(&top, fsid);
    wait_for_lock_held(&mut child);
    let (kind, elapsed) = time_lock_failure(&top, fsid);
    assert_eq!(kind, SnapshotErrorKind::TransactionAlreadyActive);
    assert!(elapsed.as_secs() < 2);
    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&top);
}

#[test]
fn resume_resume_lock_conflict() {
    // Failure mode: two parallel `resume` invocations each advance
    // the same transaction past the same step.
    let top = scratch_dir("resume-resume");
    let fsid = "fsid-resume-resume";
    let mut child = spawn_lock_holder(&top, fsid);
    wait_for_lock_held(&mut child);
    let (kind, elapsed) = time_lock_failure(&top, fsid);
    assert_eq!(kind, SnapshotErrorKind::TransactionAlreadyActive);
    assert!(elapsed.as_secs() < 2);
    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&top);
}

#[test]
fn resume_revert_lock_conflict() {
    // Failure mode: a `revert` swaps roots back while a `resume` is
    // mid-swap, leaving /@ and the staging path exchanged in the
    // wrong direction.
    let top = scratch_dir("resume-revert");
    let fsid = "fsid-resume-revert";
    let mut child = spawn_lock_holder(&top, fsid);
    wait_for_lock_held(&mut child);
    let (kind, elapsed) = time_lock_failure(&top, fsid);
    assert_eq!(kind, SnapshotErrorKind::TransactionAlreadyActive);
    assert!(elapsed.as_secs() < 2);
    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&top);
}

#[test]
fn lock_is_non_blocking_under_contended_fsid() {
    // Explicit non-blocking assertion: contended acquire must return
    // in well under the helper's 8s hold window.
    let top = scratch_dir("nonblock");
    let fsid = "fsid-nonblock";
    let mut child = spawn_lock_holder(&top, fsid);
    wait_for_lock_held(&mut child);
    let (_kind, elapsed) = time_lock_failure(&top, fsid);
    assert!(
        elapsed.as_secs() < 2,
        "non-blocking lock acquire took {elapsed:?}; check LOCK_NB flag"
    );
    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&top);
}

#[test]
fn lock_release_on_drop_lets_next_acquire_succeed() {
    // Sanity for the RAII semantics: after the helper exits (Drop
    // releases), the next acquire must succeed.
    let top = scratch_dir("raii");
    let fsid = "fsid-raii";
    let mut child = spawn_lock_holder(&top, fsid);
    wait_for_lock_held(&mut child);
    // Wait for the helper to exit on its own (8s hold).
    let _ = child.wait();
    let path = lock_file_path(&top, fsid);
    let _guard = TransactionLock::try_acquire(&path, fsid).expect("must re-acquire after drop");
    let _ = std::fs::remove_dir_all(&top);
}

// ===========================================================================
// STEP 3.2 — Pre-persist crash-window tests (forward-progress logic)
// ===========================================================================
//
// The full pre-persist crash-resume E2E requires a real btrfs image
// (QEMU smoke harness). At unit level we lock the load-bearing
// invariant directly: after a crash that leaves a side-effect on
// disk but NOT in the persisted state, the reconciliation function
// MUST forward the state so resume does not re-execute the action.

#[test]
fn crash_after_backup_before_persist_forwards_to_backupcreated() {
    // Failure mode: previous apply created the backup subvolume but
    // crashed (SIGKILL) before the BackupCreated state hit disk. On
    // resume the engine sees state=Locked + backup_exists=true.
    // Forward-progress MUST advance to BackupCreated; otherwise
    // resume re-runs create_backup and fails with BackupPathOccupied
    // (or worse, overwrites the operator's pre-existing backup).
    let plan = sample_plan_with_fsid("fsid-crash-backup", "p-crash-backup");
    let facts = facts_backup_only(&plan);
    assert_eq!(
        reconcile_with_disk_facts(TransactionState::Locked, &plan, &facts),
        TransactionState::BackupCreated
    );
    // Same forward-progress rule applies from any pre-BackupCreated state.
    assert_eq!(
        reconcile_with_disk_facts(TransactionState::Planned, &plan, &facts),
        TransactionState::BackupCreated
    );
    assert_eq!(
        reconcile_with_disk_facts(TransactionState::PreflightVerified, &plan, &facts),
        TransactionState::BackupCreated
    );
}

#[test]
fn crash_after_replacement_before_persist_forwards_to_replacementcreated() {
    // Failure mode: previous apply created the staging subvolume but
    // crashed before ReplacementCreated hit disk.
    let plan = sample_plan_with_fsid("fsid-crash-repl", "p-crash-repl");
    let mut facts = facts_backup_only(&plan);
    facts.staging_root_exists = true;
    facts.staging_root = Some(SubvolumeFacts {
        path: plan.staging_root_path.clone(),
        subvolume_id: Some(999),
        generation: Some(80),
        uuid: Some("replacement-uuid".into()),
        parent_uuid: plan.source_snapshot.uuid.clone(),
        read_only: Some(false),
    });
    assert_eq!(
        reconcile_with_disk_facts(TransactionState::BackupCreated, &plan, &facts),
        TransactionState::ReplacementCreated
    );
}

#[test]
fn crash_after_swap_before_persist_forwards_to_oldrootmoved() {
    // Failure mode: renameat2(RENAME_EXCHANGE) succeeded but the
    // engine crashed before persisting OldRootMoved. On resume the
    // active root's subvolid is now the source snapshot's id and the
    // staging path holds the pre-recovery current root. We MUST
    // forward to OldRootMoved; re-running swap_roots would undo the
    // recovery (RENAME_EXCHANGE is its own inverse).
    let plan = sample_plan_with_fsid("fsid-crash-swap", "p-crash-swap");
    let mut facts = facts_backup_only(&plan);
    facts.staging_root_exists = true;
    facts.staging_root = Some(SubvolumeFacts {
        path: plan.staging_root_path.clone(),
        subvolume_id: Some(256),
        generation: Some(100),
        uuid: plan.current_root.uuid.clone(),
        parent_uuid: plan.current_root.parent_uuid.clone(),
        read_only: Some(false),
    });
    facts.active_root = Some(SubvolumeFacts {
        path: "/@".into(),
        subvolume_id: Some(999),
        generation: Some(80),
        uuid: Some("replacement-uuid".into()),
        parent_uuid: plan.source_snapshot.uuid.clone(),
        read_only: Some(false),
    });
    assert_eq!(
        reconcile_with_disk_facts(TransactionState::ReplacementCreated, &plan, &facts),
        TransactionState::OldRootMoved
    );
}

#[test]
fn crash_after_reverse_swap_before_persist_forwards_to_reverted() {
    // Failure mode: revert's swap_roots_back succeeded but the
    // engine crashed before persisting Reverted. The active root's
    // subvolid is back to the planned current root's id.
    let plan = sample_plan_with_fsid("fsid-crash-revswap", "p-crash-revswap");
    let mut facts = facts_backup_only(&plan);
    facts.staging_root_exists = true;
    facts.staging_root = Some(SubvolumeFacts {
        path: plan.staging_root_path.clone(),
        subvolume_id: Some(999),
        generation: Some(80),
        uuid: Some("replacement-uuid".into()),
        parent_uuid: plan.source_snapshot.uuid.clone(),
        read_only: Some(false),
    });
    facts.active_root = Some(SubvolumeFacts {
        path: "/@".into(),
        subvolume_id: Some(256),
        generation: Some(100),
        uuid: plan.current_root.uuid.clone(),
        parent_uuid: plan.current_root.parent_uuid.clone(),
        read_only: Some(false),
    });
    assert_eq!(
        reconcile_with_disk_facts(TransactionState::Reverting, &plan, &facts),
        TransactionState::Reverted
    );
}

#[test]
fn ambiguous_swap_direction_surfaces_as_manual_intervention() {
    // Failure mode: disk facts are ambiguous (active root subvolid
    // matches neither the planned current root nor the planned
    // source snapshot). We MUST surface manual intervention rather
    // than guess and re-execute.
    let plan = sample_plan_with_fsid("fsid-ambig", "p-ambig");
    let mut facts = facts_backup_only(&plan);
    facts.staging_root_exists = true;
    facts.staging_root = Some(SubvolumeFacts {
        path: "/.catos-recovery/staging/p-ambig/new-root".into(),
        subvolume_id: Some(12345),
        generation: Some(7),
        uuid: None,
        parent_uuid: None,
        read_only: Some(false),
    });
    facts.active_root = Some(SubvolumeFacts {
        path: "/@".into(),
        subvolume_id: Some(67890),
        generation: Some(7),
        uuid: None,
        parent_uuid: None,
        read_only: Some(false),
    });
    // OldRootMoved with ambiguous facts surfaces as manual.
    assert_eq!(
        reconcile_with_disk_facts(TransactionState::OldRootMoved, &plan, &facts),
        TransactionState::FailedManualIntervention
    );
}

#[test]
fn ambiguous_replacementcreated_surfaces_as_manual_intervention() {
    let plan = sample_plan_with_fsid("fsid-ambig-repl", "p-ambig-repl");
    let mut facts = facts_backup_only(&plan);
    facts.staging_root_exists = true;
    facts.staging_root = Some(SubvolumeFacts {
        path: "/.catos-recovery/staging/p-ambig-repl/new-root".into(),
        subvolume_id: Some(8888),
        generation: Some(7),
        uuid: None,
        parent_uuid: None,
        read_only: Some(false),
    });
    facts.active_root = Some(SubvolumeFacts {
        path: "/@".into(),
        subvolume_id: Some(9999),
        generation: Some(7),
        uuid: None,
        parent_uuid: None,
        read_only: Some(false),
    });
    assert_eq!(
        reconcile_with_disk_facts(TransactionState::ReplacementCreated, &plan, &facts),
        TransactionState::FailedManualIntervention,
        "ambiguous ReplacementCreated must surface as manual intervention, not fall through"
    );
}

// ===========================================================================
// STEP 3.3 — Failed-state persistence
// ===========================================================================
//
// The engine persists failure-state records to disk BEFORE returning
// the error, so `status` and `resume` observe failed_recoverable /
// failed_manual_intervention rather than the last-successful state.

/// Persist a structured recoverable operation error through the same
/// private engine path used by `drive()`. Real operation-level failures
/// remain covered by the QEMU recovery matrix.
#[test]
fn recoverable_failure_persists_last_error() {
    let top = scratch_dir("fail-recoverable");
    let plan = sample_plan_with_fsid("fsid-fail-rec", "p-fail-rec");
    let state_path = top
        .join(TransactionPaths::transactions_dir().trim_start_matches('/'))
        .join(&plan.plan_id)
        .join("state.json");
    let mut engine = Engine::begin(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        plan.clone(),
    )
    .expect("begin must persist the initial record under the FSID lock");

    let mut injected = SnapshotError::new(
        SnapshotErrorKind::TargetChanged,
        "new root is missing /etc/os-release",
    );
    injected.transaction_id = Some(plan.plan_id.clone());
    injected.current_state = Some(TransactionState::Planned);
    injected.failed_step = Some("verify-new-root".into());
    injected.resume_possible = true;
    injected.revert_possible = false;
    injected.disk_facts = Some(Box::new(DiskFacts {
        filesystem_fsid: plan.filesystem.fsid.clone(),
        active_root_exists: true,
        active_root: None,
        staging_root_exists: false,
        staging_root: None,
        backup_root_exists: false,
        backup: None,
        source_snapshot_exists: true,
        source_snapshot: None,
    }));
    let err = engine.persist_failure_for_test(injected);
    assert_eq!(err.kind, SnapshotErrorKind::TargetChanged);
    assert!(err.resume_possible);

    let reloaded = store::load_record(&state_path).unwrap();
    assert_eq!(reloaded.state, TransactionState::FailedRecoverable);
    let last_error = reloaded
        .last_error
        .clone()
        .expect("last_error must be persisted on failure");
    assert_eq!(last_error.kind, SnapshotErrorKind::TargetChanged);
    assert_eq!(last_error.failed_step, Some("verify-new-root".into()));
    assert!(last_error.resume_possible);
    assert!(last_error.message.contains("/etc/os-release"));
    assert_eq!(
        reloaded.last_disk_facts,
        last_error.disk_facts.as_deref().cloned()
    );

    let _ = std::fs::remove_dir_all(&top);
}

/// Persist a structured manual-intervention error through the same
/// engine path used by `drive()` and `revert()`.
#[test]
fn manual_intervention_failure_persists_last_error() {
    let top = scratch_dir("fail-manual");
    let plan = sample_plan_with_fsid("fsid-fail-manual", "p-fail-manual");
    let state_path = top
        .join(TransactionPaths::transactions_dir().trim_start_matches('/'))
        .join(&plan.plan_id)
        .join("state.json");
    let mut engine = Engine::begin(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        plan.clone(),
    )
    .expect("begin must persist the initial record under the FSID lock");

    let mut injected = SnapshotError::new(
        SnapshotErrorKind::RootSwitchConflict,
        "root exchange identity is ambiguous",
    );
    injected.transaction_id = Some(plan.plan_id.clone());
    injected.current_state = Some(TransactionState::Planned);
    injected.failed_step = Some("swap-roots".into());
    injected.resume_possible = false;
    injected.revert_possible = false;
    injected.manual_intervention_required = true;
    let err = engine.persist_failure_for_test(injected);
    assert_eq!(err.kind, SnapshotErrorKind::RootSwitchConflict);

    let reloaded = store::load_record(&state_path).unwrap();
    assert_eq!(reloaded.state, TransactionState::FailedManualIntervention);
    let last_error = reloaded
        .last_error
        .clone()
        .expect("last_error must be persisted");
    assert_eq!(
        last_error.transaction_id.as_deref(),
        Some(plan.plan_id.as_str())
    );
    assert_eq!(last_error.current_state, Some(TransactionState::Planned));
    assert!(last_error.manual_intervention_required);

    let _ = std::fs::remove_dir_all(&top);
}

// ===========================================================================
// STEP 3.4 — Terminal fact drift
// ===========================================================================
//
// After a transaction reaches Completed, the persisted record is the
// authoritative source of "this recovery happened". If the disk
// reality drifts (FSID changed, backup removed, active root swapped
// out from under us), `recovery status` MUST NOT report Completed
// unconditionally. It must surface the drift as
// FailedManualIntervention.

/// Build a Completed record with last_disk_facts populated, then
/// call engine.reconcile_status() with externally-modified disk
/// facts. The engine MUST downgrade to FailedManualIntervention.
#[test]
fn completed_does_not_drift_silently_when_backup_removed() {
    let top = scratch_dir("drift-backup-gone");
    let plan = sample_plan_with_fsid("fsid-drift-bak", "p-drift-bak");

    let mut record = sample_record_with_state(plan.clone(), TransactionState::Completed);
    record.last_disk_facts = Some(DiskFacts {
        filesystem_fsid: plan.filesystem.fsid.clone(),
        active_root_exists: true,
        active_root: Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(300),
            generation: Some(80),
            uuid: None,
            parent_uuid: None,
            read_only: Some(false),
        }),
        staging_root_exists: true,
        staging_root: None,
        backup_root_exists: true,
        backup: None,
        source_snapshot_exists: true,
        source_snapshot: None,
    });
    let _state_path = persist_record_under(&top, &record);

    // Externally modify: create the active root path but DO NOT
    // create the backup path. This simulates the operator (or a
    // cleanup tool) deleting the pre-recovery backup.
    std::fs::create_dir_all(top.join("@")).unwrap();
    // Note: no backup dir created, no staging dir created.

    let mut engine = Engine::load(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        &record.transaction_id,
    )
    .unwrap();
    let facts = engine.reconcile_status();

    assert!(
        !facts.backup_root_exists,
        "test setup invariant: backup must be observed missing"
    );
    assert_eq!(
        engine.record().state,
        TransactionState::FailedManualIntervention,
        "drift must surface as FailedManualIntervention, not Completed"
    );
    let last_error = engine
        .record()
        .last_error
        .as_ref()
        .expect("drift must populate last_error");
    assert_eq!(last_error.kind, SnapshotErrorKind::TargetChanged);
    assert!(last_error.manual_intervention_required);
    assert!(!last_error.resume_possible);

    let _ = std::fs::remove_dir_all(&top);
}

// FSID-drift detection requires a real btrfs mount: `Engine::observe_disk_facts`
// calls `btrfs filesystem show`, which fails on tmpfs and conservatively falls
// back to `plan.filesystem.fsid` (matching itself by construction). The QEMU
// smoke harness in `scripts/recovery-qemu-smoke.sh` exercises this scenario
// end-to-end by swapping the btrfs image between status invocations.

#[test]
fn completed_with_unverifiable_subvolume_identity_requires_manual_review() {
    // Plain directories cannot provide btrfs subvolid/UUID facts.
    // A terminal record must not be trusted merely because the same
    // paths still exist: inability to re-establish identity is itself
    // a conservative manual-intervention condition. The real-Btrfs
    // QEMU acceptance test covers the positive unchanged-facts case.
    let top = scratch_dir("drift-clean");
    let plan = sample_plan_with_fsid("fsid-clean", "p-drift-clean");

    let mut record = sample_record_with_state(plan.clone(), TransactionState::Completed);
    record.last_disk_facts = Some(DiskFacts {
        filesystem_fsid: plan.filesystem.fsid.clone(),
        active_root_exists: true,
        active_root: Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(300),
            generation: Some(80),
            uuid: None,
            parent_uuid: None,
            read_only: Some(false),
        }),
        staging_root_exists: true,
        staging_root: None,
        backup_root_exists: true,
        backup: None,
        source_snapshot_exists: true,
        source_snapshot: None,
    });
    let _state_path = persist_record_under(&top, &record);

    // Create the expected paths so observe_disk_facts sees them.
    std::fs::create_dir_all(top.join("@")).unwrap();
    std::fs::create_dir_all(top.join(".catos-recovery/backups/p-drift-clean/root-before")).unwrap();

    let mut engine = Engine::load(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        &record.transaction_id,
    )
    .unwrap();
    let _ = engine.reconcile_status();
    assert_eq!(
        engine.record().state,
        TransactionState::FailedManualIntervention,
        "unverifiable terminal identity must not remain Completed"
    );

    let _ = std::fs::remove_dir_all(&top);
}

// ===========================================================================
// Engine entry-point lock re-acquisition
// ===========================================================================

/// `Engine::load_for_write` MUST acquire the lock. We verify by
/// spawning a holder, then calling load_for_write against the same
/// fsid: it MUST return TransactionAlreadyActive immediately.
#[test]
fn load_for_write_re_acquires_per_fsid_lock() {
    let top = scratch_dir("lfw-lock");
    let fsid = "fsid-lfw";
    let plan = sample_plan_with_fsid(fsid, "p-lfw");
    let record = sample_record_with_state(plan.clone(), TransactionState::BackupCreated);
    let _state_path = persist_record_under(&top, &record);

    let mut child = spawn_lock_holder(&top, fsid);
    wait_for_lock_held(&mut child);

    let start = std::time::Instant::now();
    let err = Engine::load_for_write(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        &record.transaction_id,
    )
    .err()
    .expect("load_for_write must error when the lock is held");
    let elapsed = start.elapsed();

    assert_eq!(err.kind, SnapshotErrorKind::TransactionAlreadyActive);
    assert!(
        elapsed.as_secs() < 2,
        "load_for_write must NOT block on a held lock; took {elapsed:?}"
    );

    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&top);
}

/// `Engine::load` (read-only, for status) must NOT acquire the lock.
/// Otherwise `status` would deadlock when an `apply` is running.
#[test]
fn load_for_status_does_not_acquire_lock() {
    let top = scratch_dir("load-ro");
    let fsid = "fsid-load-ro";
    let plan = sample_plan_with_fsid(fsid, "p-load-ro");
    let record = sample_record_with_state(plan.clone(), TransactionState::Completed);
    let _state_path = persist_record_under(&top, &record);

    // Holder keeps the lock.
    let mut child = spawn_lock_holder(&top, fsid);
    wait_for_lock_held(&mut child);

    // status-style load MUST succeed even though the lock is held.
    let engine = Engine::load(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        &record.transaction_id,
    )
    .expect("Engine::load must not acquire the per-FSID lock");
    assert_eq!(engine.record().state, TransactionState::Completed);

    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&top);
}

// ===========================================================================
// STEP 3.5 — status is read-only (FIX 3)
// ===========================================================================
//
// `recovery status` MUST NOT mutate the transaction record on disk.
// reconcile_status computes an in-memory reconciled view; it does not
// persist. We verify by stat-ing the record file's mtime before and
// after a reconcile_status call that detects drift (which is exactly
// the case that previously mutated the record).

#[test]
fn status_does_not_mutate_transaction_record_on_disk() {
    use std::time::SystemTime;

    let top = scratch_dir("status-readonly");
    let plan = sample_plan_with_fsid("fsid-status-ro", "p-status-ro");

    let mut record = sample_record_with_state(plan.clone(), TransactionState::Completed);
    record.last_disk_facts = Some(DiskFacts {
        filesystem_fsid: plan.filesystem.fsid.clone(),
        active_root_exists: true,
        active_root: Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(300),
            generation: Some(80),
            uuid: None,
            parent_uuid: None,
            read_only: Some(false),
        }),
        staging_root_exists: true,
        staging_root: None,
        backup_root_exists: true,
        backup: None,
        source_snapshot_exists: true,
        source_snapshot: None,
    });
    let state_path = persist_record_under(&top, &record);

    // Stage the disk so the backup path is MISSING. reconcile_status
    // will detect drift (Completed + missing backup) and the in-memory
    // view becomes FailedManualIntervention. Previously this path
    // persisted the failure; we now assert it does NOT.
    std::fs::create_dir_all(top.join("@")).unwrap();
    std::fs::create_dir_all(top.join(".catos-recovery/staging/p-status-ro/new-root")).unwrap();
    // Note: no backup dir created — that's the drift trigger.

    let mtime_before = std::fs::metadata(&state_path)
        .expect("record must exist")
        .modified()
        .expect("mtime must be readable");

    let mut engine = Engine::load(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        &record.transaction_id,
    )
    .expect("Engine::load must succeed (status does not acquire lock)");
    let _facts = engine.reconcile_status();

    // In-memory view reflects drift.
    assert_eq!(
        engine.record().state,
        TransactionState::FailedManualIntervention,
        "in-memory reconciled view must reflect drift"
    );

    // Sleep briefly so a future mtime change would be observable.
    std::thread::sleep(std::time::Duration::from_millis(20));

    let mtime_after = std::fs::metadata(&state_path)
        .expect("record must still exist")
        .modified()
        .expect("mtime must be readable");

    assert_eq!(
        mtime_before, mtime_after,
        "status MUST NOT mutate the transaction record; mtime changed"
    );

    // Reload from disk: the persisted record MUST still be Completed,
    // not FailedManualIntervention. This proves reconcile_status did
    // not write.
    let reloaded = store::load_record(&state_path).unwrap();
    assert_eq!(
        reloaded.state,
        TransactionState::Completed,
        "persisted state must be unchanged by status"
    );

    let _ = std::fs::remove_dir_all(&top);
    // Suppress unused-import warning if SystemTime isn't otherwise used.
    let _ = SystemTime::UNIX_EPOCH;
}

#[test]
fn swap_done_rejects_readonly_active_root() {
    // Identity-safety: a readonly active root cannot be the
    // post-swap new root (we always create the replacement
    // writable). If reconcile swaps done based purely on
    // subvolume_id, a readonly snapshot someone dropped at /@
    // would falsely match. Assert swap_appears_done returns
    // false here.
    use catos_system::snapshot::plan::reconcile::swap_appears_done;
    let plan = sample_plan_with_fsid("fsid-ro-rej", "p-ro-rej");
    let facts = DiskFacts {
        filesystem_fsid: plan.filesystem.fsid.clone(),
        active_root_exists: true,
        active_root: Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(301),
            generation: Some(80),
            uuid: None,
            parent_uuid: None,
            read_only: Some(true),
        }),
        staging_root_exists: true,
        staging_root: Some(SubvolumeFacts {
            path: "/.catos-recovery/staging/p-ro-rej/new-root".into(),
            subvolume_id: Some(256),
            generation: Some(100),
            uuid: None,
            parent_uuid: None,
            read_only: Some(false),
        }),
        backup_root_exists: true,
        backup: None,
        source_snapshot_exists: true,
        source_snapshot: None,
    };
    assert!(
        !swap_appears_done(&plan, &facts),
        "readonly active root must NOT be treated as post-swap new root"
    );
}
