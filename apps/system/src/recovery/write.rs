//! Write recovery subcommands: `apply`, `resume`, `revert`.
//!
//! These are the only commands that mount the btrfs top-level
//! read-write and perform persistent writes to the target device.

use std::path::{Path, PathBuf};

use crate::cli::RecoveryArgs;
use crate::mount::session::BtrfsTopLevelRwSession;
use crate::snapshot::diagnose::identity::{
    canonical_block_identity, ensure_supported_snapshot_layout, ensure_target_is_not_running_root,
    validate_mounted_filesystem,
};
use crate::snapshot::execute::engine::{Engine, EngineOptions};
use crate::snapshot::model::{
    BtrfsFilesystemIdentity, CleanupSummary, SnapshotError, SnapshotErrorKind, TransactionPaths,
    TransactionRecord, TransactionState,
};
use crate::snapshot::verify::{require_boot_consistency, verify_confirmation_token};
use crate::snapshot::{store, transaction};
use crate::target::execute::lock::{DeviceLock, DeviceLockErrorKind};
use crate::recovery::model::{
    RecoveryCleanupReport, RecoveryCleanupSubject,
};

use super::read::{load_persisted_plan_readonly, probe_existing_transaction_readonly};
use super::{ensure_cli_root_matches_plan, require_root, require_transaction_id};
use crate::snapshot::diagnose::enumerate::probe_target_readonly;

// ---------------------------------------------------------------------------
// lifecycle cleanup
// ---------------------------------------------------------------------------

pub(super) fn run_discard_plan(
    args: &RecoveryArgs,
) -> Result<RecoveryCleanupReport, SnapshotError> {
    let selection = args.require_target_selection()?;
    require_root()?;
    let plan_id = args.plan_id.as_deref().ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::TransactionNotFound,
            "discard-plan requires --plan-id <id>",
        )
    })?;
    let confirm = args.confirm.as_deref().ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "discard-plan requires --confirm <token>",
        )
    })?;
    let plan = load_persisted_plan_readonly(&selection.root_device, plan_id)?;
    verify_confirmation_token(&plan, plan_id, confirm)?;
    ensure_cli_root_matches_plan(selection.root_subvolume.as_deref(), &plan.current_root.path)?;

    let (device, _) = canonical_block_identity(&selection.root_device)?;
    let mut session = BtrfsTopLevelRwSession::mount(&device)?;
    let top = session.top_level_mount().to_path_buf();
    let operation = (|| {
        let mounted = validate_mounted_filesystem(&top, &device)?;
        if mounted.filesystem != plan.filesystem {
            return Err(SnapshotError::new(
                SnapshotErrorKind::StalePlan,
                "target filesystem identity changed after the pending plan was loaded",
            ));
        }
        let lock_path = transaction::lock_file_path(&top, &mounted.filesystem.fsid);
        let _transaction_lock = transaction::TransactionLock::try_acquire(
            &lock_path,
            &mounted.filesystem.fsid,
        )?;
        let _device_lock = DeviceLock::try_acquire_if_block_device(&device)
            .map_err(cleanup_device_lock_error)?;
        let plan_path = top
            .join(TransactionPaths::transactions_dir().trim_start_matches('/'))
            .join(plan_id)
            .join("plan.json");
        let current = store::load_plan(&plan_path)?;
        if current != plan {
            return Err(SnapshotError::new(
                SnapshotErrorKind::TargetChanged,
                "pending recovery plan changed before discard",
            ));
        }
        verify_confirmation_token(&current, plan_id, confirm)?;
        store::remove_pending_plan(&plan_path)?;
        Ok(vec![
            PathBuf::from(TransactionPaths::transactions_dir())
                .join(plan_id)
                .display()
                .to_string(),
        ])
    })();
    let cleanup: CleanupSummary = session.cleanup().into();
    match operation {
        Ok(removed_paths) => Ok(RecoveryCleanupReport {
            subject: RecoveryCleanupSubject::PendingPlan,
            id: plan_id.to_string(),
            removed_paths,
            mount_cleanup: cleanup,
        }),
        Err(mut error) => {
            engine_attach_cleanup_into_error(&mut error, cleanup);
            Err(error)
        }
    }
}

pub(super) fn run_purge(args: &RecoveryArgs) -> Result<RecoveryCleanupReport, SnapshotError> {
    let selection = args.require_target_selection()?;
    require_root()?;
    let transaction_id = require_transaction_id(args.transaction.as_deref(), "purge")?;
    let confirm = args.confirm.as_deref().ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "purge requires --confirm <token> from recovery status",
        )
    })?;
    let probe = probe_existing_transaction_readonly(
        &selection.root_device,
        selection.root_subvolume.as_deref(),
        transaction_id,
        true,
    )?;
    let device = probe.canonical_device;
    let mut session = BtrfsTopLevelRwSession::mount(&device)?;
    let top = session.top_level_mount().to_path_buf();
    let operation = (|| {
        let target = validate_mounted_filesystem(&top, &device)?;
        if target.filesystem != probe.filesystem {
            return Err(SnapshotError::new(
                SnapshotErrorKind::TargetChanged,
                "target filesystem changed between purge preflight and write mount",
            ));
        }
        let mut engine = Engine::load_for_purge(
            EngineOptions {
                top_level_mount: top.clone(),
                device_path: device.clone(),
                validated_filesystem: target.filesystem,
            },
            transaction_id,
            confirm,
        )?;
        engine.purge_owned_artifacts()
    })();
    let cleanup: CleanupSummary = session.cleanup().into();
    match operation {
        Ok(removed_paths) => Ok(RecoveryCleanupReport {
            subject: RecoveryCleanupSubject::Transaction,
            id: transaction_id.to_string(),
            removed_paths,
            mount_cleanup: cleanup,
        }),
        Err(mut error) => {
            engine_attach_cleanup_into_error(&mut error, cleanup);
            Err(error)
        }
    }
}

fn cleanup_device_lock_error(error: crate::target::execute::lock::DeviceLockError) -> SnapshotError {
    let kind = if error.kind == DeviceLockErrorKind::Busy {
        SnapshotErrorKind::TransactionAlreadyActive
    } else {
        SnapshotErrorKind::SyscallFailed
    };
    SnapshotError::new(kind, error.message)
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

pub(super) fn run_apply(
    args: &RecoveryArgs,
) -> Result<(TransactionRecord, TransactionState, CleanupSummary), SnapshotError> {
    let plan_id_arg = args.plan_id.as_deref().ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "apply requires --plan-id",
        )
    })?;
    let confirm = args.confirm.as_deref().ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "apply requires --confirm <token>",
        )
    })?;
    // CLI-contract check FIRST: --esp-device is rejected before any
    // root check, plan load, or mount. A wrapper script that learned
    // the flag from `target plan` must learn it is unsupported
    // here without paying for a privilege check or touching the plan
    // file.
    let selection = args.require_target_selection()?;

    require_root()?;

    let plan = load_persisted_plan_readonly(&selection.root_device, plan_id_arg)?;
    crate::snapshot::verify::validate_plan_shape(&plan)?;
    crate::snapshot::verify::verify_confirmation_token(&plan, plan_id_arg, confirm)?;

    ensure_cli_root_matches_plan(selection.root_subvolume.as_deref(), &plan.current_root.path)?;
    ensure_supported_snapshot_layout(&plan.current_root.path, &plan.source_snapshot.path)?;

    // Re-establish every execution-relevant identity through a
    // read-only mount before the first persistent write. The supplied
    // plan file may be stale even though its own digest is intact.
    let fresh = probe_target_readonly(
        &selection.root_device,
        Some(&plan.current_root.path),
        Some(&plan.source_snapshot.path),
    )?;
    if let Some(error) = crate::snapshot::diagnose::consistency::drift_between(
        &plan,
        &fresh.filesystem,
        &fresh.current_root,
        &fresh.snapshot,
    )
    .into_error()
    {
        return Err(error);
    }
    if fresh.fstab_root_definition != plan.fstab_root_definition {
        return Err(SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            "target fstab root definition changed after the plan was generated",
        ));
    }
    if fresh.boot_layout != plan.boot_layout {
        return Err(SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            "target boot layout changed after the plan was generated",
        ));
    }
    if fresh.boot_consistency != plan.boot_consistency {
        return Err(SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            "boot consistency report changed after the plan was generated",
        ));
    }
    require_boot_consistency(&fresh.boot_consistency)?;
    ensure_target_is_not_running_root(&fresh.filesystem, &fresh.current_root)?;
    let device = fresh.canonical_device;

    let mut mount_session = BtrfsTopLevelRwSession::mount(&device)?;
    let top_level_mount = mount_session.top_level_mount().to_path_buf();
    let rw_target = validate_mounted_filesystem(&top_level_mount, &device)?;
    let validated_filesystem = rw_target.filesystem.clone();

    let drive_outcome = (|| {
        let mut engine = Engine::begin(
            EngineOptions {
                top_level_mount: top_level_mount.clone(),
                device_path: device.clone(),
                validated_filesystem: rw_target.filesystem.clone(),
            },
            plan,
        )?;
        let final_state = engine.drive()?;
        Ok::<(Engine, TransactionState), SnapshotError>((engine, final_state))
    })();

    // Tear down the rw mount FIRST. The returned `CleanupSummary` is
    // the authoritative teardown report — it records whether umount2
    // succeeded, whether MNT_DETACH fallback was needed, and whether
    // the session directory was removed. We persist it to the
    // transaction record AFTER the teardown via a brief remount, so
    // later `status` reads the truth instead of a pre-teardown guess.
    let (engine, final_state) = match drive_outcome {
        Ok(pair) => pair,
        Err(mut error) => {
            let cleanup_summary = mount_session.cleanup().into();
            engine_attach_cleanup_into_error(&mut error, cleanup_summary);
            return Err(error);
        }
    };
    let transaction_id = engine.record().transaction_id.clone();
    let mut returned_record = engine.record().clone();
    // Engine owns the transaction lock file inside the mounted filesystem.
    // Drop it before umount, otherwise the happy path deterministically
    // reaches EBUSY and falls back to lazy detach.
    drop(engine);
    let real_cleanup: CleanupSummary = mount_session.cleanup().into();
    drop(mount_session);
    returned_record.last_cleanup = Some(real_cleanup.clone());

    persist_real_cleanup_after_teardown(
        &device,
        &transaction_id,
        &validated_filesystem,
        real_cleanup.clone(),
    )?;

    Ok((returned_record, final_state, real_cleanup))
}

// ---------------------------------------------------------------------------
// resume
// ---------------------------------------------------------------------------

pub(super) fn run_resume(
    args: &RecoveryArgs,
) -> Result<(TransactionRecord, TransactionState, CleanupSummary), SnapshotError> {
    // CLI-contract check FIRST: --esp-device must be rejected before
    // require_root() so a wrapper learns the rejection without paying
    // for a privilege check.
    let selection = args.require_target_selection()?;
    require_root()?;
    let transaction_id = require_transaction_id(args.transaction.as_deref(), "resume")?;
    let probe = probe_existing_transaction_readonly(
        &selection.root_device,
        selection.root_subvolume.as_deref(),
        transaction_id,
        true,
    )?;
    let device = probe.canonical_device;
    let mut mount_session = BtrfsTopLevelRwSession::mount(&device)?;
    let top_level_mount = mount_session.top_level_mount().to_path_buf();
    let target = validate_mounted_filesystem(&top_level_mount, &device)?;
    if target.filesystem != probe.filesystem {
        let cleanup = mount_session.cleanup().into();
        let mut error = SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            "target filesystem identity changed between read-only preflight and write mount",
        );
        engine_attach_cleanup_into_error(&mut error, cleanup);
        return Err(error);
    }
    let validated_filesystem = target.filesystem.clone();
    let drive_outcome = (|| {
        let mut engine = Engine::load_for_write(
            EngineOptions {
                top_level_mount: top_level_mount.clone(),
                device_path: device.clone(),
                validated_filesystem: validated_filesystem.clone(),
            },
            transaction_id,
        )?;
        let final_state = engine.drive()?;
        Ok::<(Engine, TransactionState), SnapshotError>((engine, final_state))
    })();

    // See run_apply: tear down first, persist the real summary via a
    // brief remount so later `status` reads the truth.
    let (engine, final_state) = match drive_outcome {
        Ok(pair) => pair,
        Err(mut error) => {
            let cleanup_summary = mount_session.cleanup().into();
            engine_attach_cleanup_into_error(&mut error, cleanup_summary);
            return Err(error);
        }
    };
    let transaction_id = engine.record().transaction_id.clone();
    let mut returned_record = engine.record().clone();
    drop(engine);
    let real_cleanup: CleanupSummary = mount_session.cleanup().into();
    drop(mount_session);
    returned_record.last_cleanup = Some(real_cleanup.clone());

    persist_real_cleanup_after_teardown(
        &device,
        &transaction_id,
        &validated_filesystem,
        real_cleanup.clone(),
    )?;

    Ok((returned_record, final_state, real_cleanup))
}

// ---------------------------------------------------------------------------
// revert
// ---------------------------------------------------------------------------

pub(super) fn run_revert(
    args: &RecoveryArgs,
) -> Result<(TransactionRecord, TransactionState, CleanupSummary), SnapshotError> {
    // CLI-contract check FIRST: --esp-device must be rejected before
    // require_root() so a wrapper learns the rejection without paying
    // for a privilege check.
    let selection = args.require_target_selection()?;
    require_root()?;
    let transaction_id = require_transaction_id(args.transaction.as_deref(), "revert")?;
    let confirm = args.confirm.as_deref().ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "revert requires --confirm <token>",
        )
    })?;
    let probe = probe_existing_transaction_readonly(
        &selection.root_device,
        selection.root_subvolume.as_deref(),
        transaction_id,
        true,
    )?;
    let device = probe.canonical_device;
    let mut mount_session = BtrfsTopLevelRwSession::mount(&device)?;
    let top_level_mount = mount_session.top_level_mount().to_path_buf();
    let target = validate_mounted_filesystem(&top_level_mount, &device)?;
    if target.filesystem != probe.filesystem {
        let cleanup = mount_session.cleanup().into();
        let mut error = SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            "target filesystem identity changed between read-only preflight and write mount",
        );
        engine_attach_cleanup_into_error(&mut error, cleanup);
        return Err(error);
    }
    let validated_filesystem = target.filesystem.clone();
    let revert_outcome = (|| {
        let mut engine = Engine::load_for_revert(
            EngineOptions {
                top_level_mount: top_level_mount.clone(),
                device_path: device.clone(),
                validated_filesystem: validated_filesystem.clone(),
            },
            transaction_id,
            confirm,
        )?;
        let final_state = engine.revert()?;
        Ok::<(Engine, TransactionState), SnapshotError>((engine, final_state))
    })();

    // See run_apply: tear down first, persist the real summary via a
    // brief remount so later `status` reads the truth.
    let (engine, final_state) = match revert_outcome {
        Ok(pair) => pair,
        Err(mut error) => {
            let cleanup_summary = mount_session.cleanup().into();
            engine_attach_cleanup_into_error(&mut error, cleanup_summary);
            return Err(error);
        }
    };
    let transaction_id = engine.record().transaction_id.clone();
    let mut returned_record = engine.record().clone();
    drop(engine);
    let real_cleanup: CleanupSummary = mount_session.cleanup().into();
    drop(mount_session);
    returned_record.last_cleanup = Some(real_cleanup.clone());

    persist_real_cleanup_after_teardown(
        &device,
        &transaction_id,
        &validated_filesystem,
        real_cleanup.clone(),
    )?;

    Ok((returned_record, final_state, real_cleanup))
}

fn engine_attach_cleanup_into_error(error: &mut SnapshotError, cleanup: CleanupSummary) {
    if !cleanup.all_clean {
        let suffix = format!(
            " (recovery rw session cleanup was incomplete: residual={:?})",
            cleanup.residual
        );
        let mut combined = error.message.to_string();
        combined.push_str(&suffix);
        error.message = combined.into_boxed_str();
    }
}

/// Persist the real post-teardown `CleanupSummary` into the on-disk
/// transaction record so subsequent `status` reads the truth.
fn persist_real_cleanup_after_teardown(
    device: &Path,
    transaction_id: &str,
    validated_filesystem: &BtrfsFilesystemIdentity,
    real_cleanup: CleanupSummary,
) -> Result<(), SnapshotError> {
    let mut session = BtrfsTopLevelRwSession::mount(device)?;
    let top_level_mount = session.top_level_mount().to_path_buf();
    let persist_outcome = (|| {
        let mut engine = Engine::load_for_write(
            EngineOptions {
                top_level_mount: top_level_mount.clone(),
                device_path: device.to_path_buf(),
                validated_filesystem: validated_filesystem.clone(),
            },
            transaction_id,
        )?;
        engine.attach_cleanup(real_cleanup)
    })();
    let session_cleanup = session.cleanup().into();
    finish_cleanup_persistence(persist_outcome, session_cleanup)
}

pub(super) fn finish_cleanup_persistence(
    persist_outcome: Result<(), SnapshotError>,
    session_cleanup: CleanupSummary,
) -> Result<(), SnapshotError> {
    match (persist_outcome, session_cleanup.all_clean) {
        (Ok(()), true) => Ok(()),
        (Ok(()), false) => Err(SnapshotError::new(
            SnapshotErrorKind::CleanupIncomplete,
            format!(
                "cleanup-persistence mount session left residual mounts: {:?}",
                session_cleanup.residual
            ),
        )),
        (Err(error), true) => Err(error),
        (Err(mut error), false) => {
            let suffix = format!(
                "; cleanup-persistence mount session also left residual mounts: {:?}",
                session_cleanup.residual
            );
            let mut message = error.message.to_string();
            message.push_str(&suffix);
            error.message = message.into_boxed_str();
            error.manual_intervention_required = true;
            Err(error)
        }
    }
}
