//! Btrfs snapshot recovery orchestration.
//!
//! Sits between `entry.rs` and the `snapshot` capability. Owns the
//! side-effects the engine does NOT own: discovering the target
//! filesystem, mounting the btrfs top-level inside a private
//! namespace, surfacing structured errors as JSON envelopes.
//!
//! All seven recovery subcommands route through here:
//! `list`, `inspect`, `plan`, `apply`, `status`, `resume`, `revert`.
//!
//! `list`, `inspect`, `plan` are READ-ONLY. They mount targets only
//! via the shared read-only target-probe infrastructure.
//!
//! `apply`, `resume`, `revert` mount the btrfs top-level READ-WRITE.
//! These application paths coordinate snapshot-specific persistent writes;
//! lower-level effects remain confined to capability execute modules.

pub mod model;
pub mod output;
mod read;
mod write;

use std::path::PathBuf;

use crate::cli::{RecoveryArgs, RecoverySubcommand};
use crate::error::exit_code;
use crate::recovery::model::{
    RecoveryInspectReport, RecoveryListReport, RecoveryRecommendation, RecoveryStatusReport,
};
use crate::snapshot::diagnose::identity::{validate_recovery_id, SubvolumePath};
use crate::snapshot::model::{
    CleanupSummary, RecoveryPlan, SnapshotError, SnapshotErrorKind, TransactionRecord,
    TransactionState,
};

/// Outcome of a recovery command. Each variant carries the model
/// the matching output renderer consumes.
//
// `Error` boxes `SnapshotError` so the variant stays small relative
// to the others. Boxing here keeps clippy's `large_enum_variant`
// quiet (the alternatives — making every variant boxed or accepting
// the warning globally — are worse). The renderer dereferences once.
pub enum RecoveryOutcome {
    List(RecoveryListReport),
    Inspect(RecoveryInspectReport),
    Plan(RecoveryPlan),
    Apply {
        record: TransactionRecord,
        final_state: TransactionState,
        cleanup: CleanupSummary,
    },
    Status(Box<RecoveryStatusReport>),
    Resume {
        record: TransactionRecord,
        final_state: TransactionState,
        cleanup: CleanupSummary,
    },
    Revert {
        record: TransactionRecord,
        final_state: TransactionState,
        cleanup: CleanupSummary,
    },
    Error(Box<SnapshotError>),
}

/// Run a recovery subcommand. Called by `entry.rs` after the CLI has
/// routed `recovery <SUB>` here.
pub fn run_recovery(args: RecoveryArgs) -> RecoveryOutcome {
    match args.subcommand {
        RecoverySubcommand::List => match read::run_list(&args) {
            Ok(report) => RecoveryOutcome::List(report),
            Err(error) => RecoveryOutcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Inspect => match read::run_inspect(&args) {
            Ok(report) => RecoveryOutcome::Inspect(report),
            Err(error) => RecoveryOutcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Plan => match read::run_plan(&args) {
            Ok(plan) => RecoveryOutcome::Plan(plan),
            Err(error) => RecoveryOutcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Apply => match write::run_apply(&args) {
            Ok((record, final_state, cleanup)) => RecoveryOutcome::Apply {
                record,
                final_state,
                cleanup,
            },
            Err(error) => RecoveryOutcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Status => match read::run_status(&args) {
            Ok(report) => RecoveryOutcome::Status(Box::new(report)),
            Err(error) => RecoveryOutcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Resume => match write::run_resume(&args) {
            Ok((record, final_state, cleanup)) => RecoveryOutcome::Resume {
                record,
                final_state,
                cleanup,
            },
            Err(error) => RecoveryOutcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Revert => match write::run_revert(&args) {
            Ok((record, final_state, cleanup)) => RecoveryOutcome::Revert {
                record,
                final_state,
                cleanup,
            },
            Err(error) => RecoveryOutcome::Error(Box::new(error)),
        },
    }
}

// ---------------------------------------------------------------------------
// Exit-code mapping
// ---------------------------------------------------------------------------

/// Convert a [`SnapshotError`] into a top-level exit code. Used by
/// `entry.rs` when the recovery subcommand returned
/// `RecoveryOutcome::Error`.
pub fn recovery_error_exit_code(_error: &SnapshotError) -> i32 {
    exit_code::PROBE_FAILED
}

fn exit_code_for_recovery(
    final_state: TransactionState,
    cleanup: &CleanupSummary,
    record: &TransactionRecord,
    success_state: TransactionState,
) -> i32 {
    if final_state != success_state {
        return exit_code::PROBE_FAILED;
    }
    if !cleanup.all_clean {
        return exit_code::PROBE_FAILED;
    }
    match record.last_cleanup.as_ref().map(|c| c.all_clean) {
        Some(false) => exit_code::PROBE_FAILED,
        _ => exit_code::SUCCESS,
    }
}

/// Convenience used by `entry.rs` to map a recovery result
/// should set a non-success exit code based on its outcome.
pub fn exit_code_for(outcome: &RecoveryOutcome) -> i32 {
    match outcome {
        RecoveryOutcome::Error(error) => {
            if matches!(error.kind, SnapshotErrorKind::CurrentRootRefused) {
                exit_code::PERMISSION_DENIED
            } else {
                exit_code::PROBE_FAILED
            }
        }
        RecoveryOutcome::Status(report) => {
            if matches!(
                report.reconciled_state,
                TransactionState::FailedManualIntervention | TransactionState::FailedRecoverable
            ) {
                exit_code::PROBE_FAILED
            } else {
                exit_code::SUCCESS
            }
        }
        RecoveryOutcome::Apply {
            record,
            final_state,
            cleanup,
        }
        | RecoveryOutcome::Resume {
            record,
            final_state,
            cleanup,
        } => exit_code_for_recovery(*final_state, cleanup, record, TransactionState::Completed),
        RecoveryOutcome::Revert {
            record,
            final_state,
            cleanup,
        } => exit_code_for_recovery(*final_state, cleanup, record, TransactionState::Reverted),
        _ => exit_code::SUCCESS,
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn require_transaction_id<'a>(
    transaction_id: Option<&'a str>,
    command: &str,
) -> Result<&'a str, SnapshotError> {
    let transaction_id = transaction_id.ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::TransactionNotFound,
            format!("{command} requires --transaction <id>"),
        )
    })?;
    validate_recovery_id(transaction_id)?;
    Ok(transaction_id)
}

fn ensure_cli_root_matches_plan(
    explicit_root: Option<&str>,
    sealed_root: &str,
) -> Result<(), SnapshotError> {
    let Some(explicit_root) = explicit_root.filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let normalised = if explicit_root.starts_with('/') {
        explicit_root.to_string()
    } else {
        format!("/{explicit_root}")
    };
    SubvolumePath::parse(&normalised)?;
    if normalised != sealed_root {
        return Err(SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            format!(
                "CLI root subvolume {normalised} does not match sealed transaction root {sealed_root}"
            ),
        ));
    }
    Ok(())
}

fn require_root() -> Result<(), SnapshotError> {
    let uid = unsafe {
        extern "C" {
            fn geteuid() -> u32;
        }
        geteuid()
    };
    if uid != 0 {
        return Err(SnapshotError::new(
            SnapshotErrorKind::CurrentRootRefused,
            "recovery apply/resume/revert must run as root",
        ));
    }
    Ok(())
}

fn recommend(record: &TransactionRecord) -> RecoveryRecommendation {
    use crate::recovery::model::RecoveryRecommendation as R;
    use crate::snapshot::model::TransactionState as S;
    match record.state {
        S::Completed => R::None,
        S::Reverted => R::None,
        S::FailedManualIntervention => R::ManualIntervention,
        S::FailedRecoverable => R::ResumeAfterFailure,
        S::Reverting => R::Resume,
        S::Planned
        | S::PreflightVerified
        | S::Locked
        | S::BackupCreated
        | S::ReplacementCreated
        | S::OldRootMoved
        | S::NewRootInstalled
        | S::Verifying => R::Resume,
    }
}

fn revert_confirmation_is_safe(state: TransactionState) -> bool {
    state != TransactionState::FailedManualIntervention
}

impl RecoveryArgs {
    fn require_target_selection(&self) -> Result<TargetSelectionResolved, SnapshotError> {
        let root_device = self.target.root_device.clone().ok_or_else(|| {
            SnapshotError::new(
                SnapshotErrorKind::TargetChanged,
                "this subcommand requires --root-device",
            )
        })?;
        if let Some(esp_device) = self.target.esp_device.as_deref() {
            return Err(SnapshotError::new(
                SnapshotErrorKind::UnsupportedExplicitEsp,
                format!(
                    "snapshot recovery does not maintain or write to the ESP; \
                     --esp-device {} is not supported. The recovery \
                     root swap is bounded to the btrfs top-level and a \
                     read-only boot-consistency report. Omit --esp-device \
                     and arrange ESP reconciliation out-of-band.",
                    esp_device.display()
                ),
            ));
        }
        Ok(TargetSelectionResolved {
            root_device,
            root_subvolume: self.target.root_subvolume.clone(),
        })
    }
}

struct TargetSelectionResolved {
    root_device: PathBuf,
    root_subvolume: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::model::TransactionState;

    #[test]
    fn reconciled_reverted_state_still_offers_idempotent_revert_confirmation() {
        assert!(revert_confirmation_is_safe(TransactionState::Reverted));
        assert!(revert_confirmation_is_safe(TransactionState::Completed));
        assert!(!revert_confirmation_is_safe(
            TransactionState::FailedManualIntervention
        ));
    }

    #[test]
    fn transaction_cli_id_is_validated_before_path_construction() {
        let valid = "tx-00000000000000000000000000000001";
        assert_eq!(
            require_transaction_id(Some(valid), "status").unwrap(),
            valid
        );
        let error = require_transaction_id(Some("../../outside"), "status").unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::InvalidRecoveryId);
        let missing = require_transaction_id(None, "status").unwrap_err();
        assert_eq!(missing.kind, SnapshotErrorKind::TransactionNotFound);
    }

    #[test]
    fn existing_transaction_requires_cli_root_to_match_sealed_root() {
        ensure_cli_root_matches_plan(Some("@root"), "/@root").unwrap();
        ensure_cli_root_matches_plan(Some("/@root"), "/@root").unwrap();
        ensure_cli_root_matches_plan(None, "/@root").unwrap();
        let error = ensure_cli_root_matches_plan(Some("/@"), "/@root").unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::TargetChanged);
    }

    #[test]
    fn nested_snapshot_layout_is_rejected_before_any_write() {
        let error = crate::snapshot::diagnose::identity::ensure_supported_snapshot_layout(
            "/@",
            "/@/.snapshots/1/snapshot",
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            SnapshotErrorKind::UnsupportedNestedSnapshotLayout
        );
    }

    #[test]
    fn non_nested_snapshot_layout_is_supported() {
        crate::snapshot::diagnose::identity::ensure_supported_snapshot_layout(
            "/@",
            "/@snapshots/1",
        )
        .unwrap();
        crate::snapshot::diagnose::identity::ensure_supported_snapshot_layout(
            "/@root",
            "/snapshots/root-1",
        )
        .unwrap();
    }

    #[test]
    fn cleanup_persistence_reports_residual_when_persist_succeeds() {
        let cleanup = CleanupSummary {
            unmounted: vec![],
            residual: vec!["synthetic residual".into()],
            all_clean: false,
        };
        let error = write::finish_cleanup_persistence(Ok(()), cleanup).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::CleanupIncomplete);
        assert!(error.message.contains("synthetic residual"));
    }

    #[test]
    fn cleanup_persistence_preserves_both_primary_and_cleanup_failures() {
        let primary = SnapshotError::new(
            SnapshotErrorKind::RecoveryFailed,
            "synthetic persistence failure",
        );
        let cleanup = CleanupSummary {
            unmounted: vec![],
            residual: vec!["synthetic cleanup residual".into()],
            all_clean: false,
        };
        let error = write::finish_cleanup_persistence(Err(primary), cleanup).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::RecoveryFailed);
        assert!(error.message.contains("synthetic persistence failure"));
        assert!(error.message.contains("synthetic cleanup residual"));
        assert!(error.manual_intervention_required);
    }
}
