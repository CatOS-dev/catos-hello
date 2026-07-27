//! Read-only recovery subcommands: `list`, `inspect`, `plan`, `status`.

use std::path::PathBuf;

use crate::shared::cli::RecoveryArgs;
use crate::target::model::Warning;
use crate::shared::model::recovery::{
    RecoveryError, RecoveryErrorKind, RecoveryInspectReport, RecoveryListReport,
    RecoveryPlan, RecoveryStatusReport, TransactionPaths, TransactionSummary,
};
use crate::shared::mount::plan::build_probe_plan;
use crate::shared::mount::secure_dir::SESSION_ROOT_PARENT;
use crate::shared::mount::session::Session;
use crate::shared::snapshot_engine::identity::validate_mounted_filesystem;
use crate::shared::snapshot_engine::external as btrfs;
use crate::shared::snapshot_engine::plan::{
    build_plan as build_recovery_plan, build_revert_confirmation_token, PlanInputs,
};
use crate::shared::snapshot_engine::store;

use super::probe::{cleanup_summary, probe_existing_transaction_readonly, probe_target_readonly};
use super::{recommend, require_transaction_id, revert_confirmation_is_safe};

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

pub(super) fn run_list(args: &RecoveryArgs) -> Result<RecoveryListReport, RecoveryError> {
    let selection = args.require_target_selection()?;
    let (canonical_device, _) =
        crate::shared::snapshot_engine::identity::canonical_block_identity(&selection.root_device)?;

    let session_root =
        PathBuf::from(SESSION_ROOT_PARENT).join(format!("recovery-list-{}", std::process::id()));
    let source = canonical_device.to_str().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("device {} is not valid UTF-8", canonical_device.display()),
        )
    })?;
    let mount_plan = build_probe_plan(session_root, source, "btrfs", Some("subvolid=5"))
        .map_err(|error| RecoveryError::new(RecoveryErrorKind::SyscallFailed, error.to_string()))?;
    let mut session = Session::new(format!("recovery-list-{}", std::process::id()), &mount_plan);
    let mounted = session.run(&mount_plan).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("cannot mount recovery-list target read-only: {error}"),
        )
    })?;

    let result: Result<
        (
            crate::shared::model::recovery::BtrfsFilesystemIdentity,
            Vec<crate::shared::model::recovery::BtrfsSubvolumeIdentity>,
            Vec<(PathBuf, crate::shared::model::recovery::TransactionRecord)>,
            Vec<RecoveryError>,
        ),
        RecoveryError,
    > = (|| {
        let target = validate_mounted_filesystem(&mounted.target_root, &canonical_device)?;
        let readonly_snapshots = btrfs::list_readonly_subvolumes(&mounted.target_root)?;
        let transactions_dir = mounted
            .target_root
            .join(TransactionPaths::transactions_dir().trim_start_matches('/'));
        let (records, errs) = store::list_records(&transactions_dir);
        Ok((target.filesystem, readonly_snapshots, records, errs))
    })();

    let cleanup = cleanup_summary(session.cleanup());
    if !cleanup.all_clean {
        return Err(RecoveryError::new(
            RecoveryErrorKind::CleanupIncomplete,
            format!(
                "recovery list mount cleanup was incomplete: {:?}",
                cleanup.residual
            ),
        ));
    }
    let (filesystem, readonly_snapshots, records, errs) = result?;
    let mut report = RecoveryListReport {
        source_device: Some(canonical_device.display().to_string()),
        source_filesystem_fsid: Some(filesystem.fsid.clone()),
        mount_cleanup: Some(cleanup),
        filesystems: vec![filesystem],
        readonly_snapshots,
        transactions: Vec::new(),
        warnings: Vec::new(),
    };
    for (_, record) in &records {
        report.transactions.push(TransactionSummary {
            transaction_id: record.transaction_id.clone(),
            state: record.state,
            plan_id: record.plan.plan_id.clone(),
            created_at_unix: record.created_at_unix,
            last_updated_unix: record.last_updated_unix,
            source_snapshot_path: record.plan.source_snapshot.path.clone(),
        });
    }
    for error in errs {
        report.warnings.push(Warning::new(
            "RECOVERY_LIST_ERROR",
            format!("could not read transaction: {error}"),
        ));
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

pub(super) fn run_inspect(args: &RecoveryArgs) -> Result<RecoveryInspectReport, RecoveryError> {
    let selection = args.require_target_selection()?;
    let device = selection.root_device;
    let root_subvolume = selection.root_subvolume;
    let snapshot = args.snapshot_subvolume.clone().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "insufficient space: --snapshot-subvolume is required for inspect",
        )
    })?;

    let probe = probe_target_readonly(&device, root_subvolume.as_deref(), Some(&snapshot))?;
    Ok(RecoveryInspectReport {
        filesystem: probe.filesystem,
        current_root: probe.current_root,
        source_snapshot: probe.snapshot,
        boot_layout: probe.boot_layout,
        boot_consistency: probe.boot_consistency,
        target_catos_identity: probe.catos_identity,
        warnings: vec![],
    })
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

pub(super) fn run_plan(args: &RecoveryArgs) -> Result<RecoveryPlan, RecoveryError> {
    let selection = args.require_target_selection()?;
    let device = selection.root_device;
    let root_subvolume = selection.root_subvolume;
    let snapshot = args.snapshot_subvolume.clone().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "insufficient space: --snapshot-subvolume is required for plan",
        )
    })?;

    let probe = probe_target_readonly(&device, root_subvolume.as_deref(), Some(&snapshot))?;

    let plan_id = generate_plan_id()?;
    let entropy = generate_entropy()?;
    let fstab_root_definition = probe.fstab_root_definition;

    let inputs = PlanInputs {
        filesystem: probe.filesystem,
        current_root: probe.current_root,
        source_snapshot: probe.snapshot,
        boot_layout: probe.boot_layout.clone(),
        catos_identity: probe.catos_identity,
        fstab_root_definition,
        plan_id,
        generated_on_host: current_hostname(),
        confirmation_token_entropy: entropy,
    };
    let plan = build_recovery_plan(inputs)?;
    // run_plan is read-only. The plan is emitted to stdout; the
    // operator (or a wrapper script) saves it and feeds it back to
    // `apply --plan-file <path>`.
    Ok(plan)
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

pub(super) fn run_status(args: &RecoveryArgs) -> Result<RecoveryStatusReport, RecoveryError> {
    let transaction_id = require_transaction_id(args.transaction.as_deref(), "status")?;
    let selection = args.require_target_selection()?;
    let probe = probe_existing_transaction_readonly(
        &selection.root_device,
        selection.root_subvolume.as_deref(),
        transaction_id,
        false,
    )?;
    let disk_facts = probe.disk_facts;
    let record = probe.record;
    let reconciled_state = record.state;
    let recommendation = recommend(&record);
    let revert_confirmation_token = if !revert_confirmation_is_safe(reconciled_state) {
        None
    } else {
        Some(build_revert_confirmation_token(
            &record.transaction_id,
            &record.plan.plan_digest,
            &disk_facts.filesystem_fsid,
            reconciled_state.code(),
            &record.plan.nonce,
        ))
    };
    Ok(RecoveryStatusReport {
        transaction_id: transaction_id.to_string(),
        reconciled_state,
        record,
        disk_facts,
        recommendation,
        mount_cleanup: Some(probe.cleanup),
        revert_confirmation_token,
        warnings: vec![],
    })
}

// ---------------------------------------------------------------------------
// Entropy / id helpers
// ---------------------------------------------------------------------------

fn generate_plan_id() -> Result<String, RecoveryError> {
    let bytes = kernel_random_bytes::<16>()?;
    Ok(format!("tx-{}", hex(&bytes)))
}

fn generate_entropy() -> Result<Vec<u8>, RecoveryError> {
    Ok(kernel_random_bytes::<32>()?.to_vec())
}

fn kernel_random_bytes<const N: usize>() -> Result<[u8; N], RecoveryError> {
    random_bytes_with(|buffer| getrandom::getrandom(buffer).map_err(|error| error.to_string()))
}

fn random_bytes_with<const N: usize>(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<[u8; N], RecoveryError> {
    let mut bytes = [0u8; N];
    fill(&mut bytes).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::RandomSourceFailed,
            format!("kernel random source failed: {error}"),
        )
    })?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn current_hostname() -> Option<String> {
    std::env::var("HOSTNAME").ok().or_else(|| {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::recovery::RecoveryErrorKind;

    #[test]
    fn random_source_failure_is_not_replaced_with_zero_bytes() {
        let error = random_bytes_with::<32>(|_| Err("injected rng failure".into())).unwrap_err();
        assert_eq!(error.kind, RecoveryErrorKind::RandomSourceFailed);
        assert!(error.message.contains("injected rng failure"));
    }

    #[test]
    fn generated_plan_id_uses_strict_recovery_id_grammar() {
        let bytes = random_bytes_with::<16>(|buffer| {
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = index as u8;
            }
            Ok(())
        })
        .unwrap();
        let id = format!("tx-{}", hex(&bytes));
        crate::shared::snapshot_engine::identity::validate_recovery_id(&id).unwrap();
        assert_eq!(id, "tx-000102030405060708090a0b0c0d0e0f");
    }
}
