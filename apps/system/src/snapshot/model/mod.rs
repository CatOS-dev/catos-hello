//! Snapshot capability data model. Pure data and serde only.

pub mod identity;
pub mod metadata;
pub mod plan;
pub mod record;
pub mod state;

pub use identity::*;
pub use metadata::*;
pub use plan::*;
pub use record::*;
pub use state::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::model::BootLayout;
    use std::path::PathBuf;

    #[test]
    fn transaction_state_default_is_planned() {
        assert_eq!(TransactionState::default(), TransactionState::Planned);
    }

    #[test]
    fn transaction_state_code_is_stable_snake_case() {
        // The code() output is part of the JSON contract. Lock each
        // variant so a rename breaks CI rather than downstream tooling.
        let cases = [
            (TransactionState::Planned, "planned"),
            (TransactionState::PreflightVerified, "preflight_verified"),
            (TransactionState::Locked, "locked"),
            (TransactionState::BackupCreated, "backup_created"),
            (TransactionState::ReplacementCreated, "replacement_created"),
            (TransactionState::OldRootMoved, "old_root_moved"),
            (TransactionState::NewRootInstalled, "new_root_installed"),
            (TransactionState::Verifying, "verifying"),
            (TransactionState::Completed, "completed"),
            (TransactionState::Reverting, "reverting"),
            (TransactionState::Reverted, "reverted"),
            (TransactionState::FailedRecoverable, "failed_recoverable"),
            (
                TransactionState::FailedManualIntervention,
                "failed_manual_intervention",
            ),
        ];
        for (state, expected) in cases {
            assert_eq!(state.code(), expected, "state={:?}", state);
        }
    }

    /// A state that forgot to update `code()` would silently regress
    /// the JSON contract. The serde rename must agree.
    #[test]
    fn transaction_state_code_matches_serde_rename() {
        for state in [
            TransactionState::Planned,
            TransactionState::PreflightVerified,
            TransactionState::Locked,
            TransactionState::BackupCreated,
            TransactionState::ReplacementCreated,
            TransactionState::OldRootMoved,
            TransactionState::NewRootInstalled,
            TransactionState::Verifying,
            TransactionState::Completed,
            TransactionState::Reverting,
            TransactionState::Reverted,
            TransactionState::FailedRecoverable,
            TransactionState::FailedManualIntervention,
        ] {
            let j = serde_json::to_string(&state).unwrap();
            let s = j.trim_matches('"');
            assert_eq!(state.code(), s, "serde/code drift for {state:?}");
        }
    }

    #[test]
    fn terminal_states_are_terminal() {
        assert!(TransactionState::Completed.is_terminal());
        assert!(TransactionState::Reverted.is_terminal());
        assert!(TransactionState::FailedManualIntervention.is_terminal());
        assert!(!TransactionState::Planned.is_terminal());
        assert!(!TransactionState::FailedRecoverable.is_terminal());
    }

    #[test]
    fn first_persistent_write_done_excludes_planned_preflight_locked() {
        // Plans that have not yet written to disk can be abandoned by
        // removing the transaction record. Once we have a backup
        // subvolume, resume must account for it.
        assert!(!TransactionState::Planned.first_persistent_write_done());
        assert!(!TransactionState::PreflightVerified.first_persistent_write_done());
        assert!(!TransactionState::Locked.first_persistent_write_done());
        assert!(TransactionState::BackupCreated.first_persistent_write_done());
        assert!(TransactionState::ReplacementCreated.first_persistent_write_done());
    }

    #[test]
    fn error_kind_code_is_stable_snake_case() {
        let cases = [
            (SnapshotErrorKind::StalePlan, "stale_plan"),
            (SnapshotErrorKind::TargetChanged, "target_changed"),
            (
                SnapshotErrorKind::CurrentRootRefused,
                "current_root_refused",
            ),
            (
                SnapshotErrorKind::SnapshotNotReadonly,
                "snapshot_not_readonly",
            ),
            (
                SnapshotErrorKind::UnsupportedTransactionSchema,
                "unsupported_transaction_schema",
            ),
            (
                SnapshotErrorKind::ConfirmationTokenMismatch,
                "confirmation_token_mismatch",
            ),
            (SnapshotErrorKind::BtrfsToolFailed, "btrfs_tool_failed"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.code(), expected);
        }
    }

    #[test]
    fn recovery_paths_top_level_is_stable() {
        // The on-disk layout is part of the contract; the recovery
        // record MUST NOT live inside @/var/... because that subvolume
        // may be replaced mid-transaction.
        assert_eq!(TransactionPaths::ROOT_DIR, "/.catos-recovery");
        assert_eq!(
            TransactionPaths::transactions_dir(),
            "/.catos-recovery/transactions"
        );
        assert_eq!(TransactionPaths::backups_dir(), "/.catos-recovery/backups");
        assert_eq!(TransactionPaths::staging_dir(), "/.catos-recovery/staging");
    }

    #[test]
    fn transaction_paths_are_namespaced_under_transaction_id() {
        let p = TransactionPaths {
            transaction_id: "tx-001".into(),
        };
        assert_eq!(
            p.state_file_path(),
            PathBuf::from("/.catos-recovery/transactions/tx-001/state.json")
        );
        assert_eq!(
            p.backup_subvolume_path(),
            PathBuf::from("/.catos-recovery/backups/tx-001/root-before")
        );
        assert_eq!(
            p.staging_subvolume_path(),
            PathBuf::from("/.catos-recovery/staging/tx-001/new-root")
        );
    }

    #[test]
    fn plan_round_trips_through_json() {
        let plan = RecoveryPlan {
            schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
            plan_id: "p-001".into(),
            generated_at_unix: 1,
            generated_on_host: Some("h".into()),
            filesystem: BtrfsFilesystemIdentity {
                fsid: "fsid".into(),
                device_major_minor: "259:2".into(),
                label: None,
            },
            current_root: BtrfsSubvolumeIdentity {
                path: "/@".into(),
                subvolume_id: 256,
                generation: 100,
                uuid: None,
                parent_uuid: None,
                read_only: false,
                evidence: vec![],
            },
            source_snapshot: BtrfsSubvolumeIdentity {
                path: "/@snapshots/1".into(),
                subvolume_id: 300,
                generation: 80,
                uuid: None,
                parent_uuid: None,
                read_only: true,
                evidence: vec![],
            },
            target_catos_identity: Some(CatosIdentity {
                name: Some("CatOS".into()),
                id: Some("catos".into()),
                version: Some("1".into()),
                pretty_name: None,
            }),
            boot_layout: BootLayout::default(),
            boot_consistency: crate::boot::diagnose::layout::evaluate_readonly_consistency(
                &BootLayout::default(),
            ),
            backup_root_path: "/.catos-recovery/backups/tx/root-before".into(),
            staging_root_path: "/.catos-recovery/staging/tx/new-root".into(),
            fstab_root_definition: FstabRootDefinition {
                source: "/dev/nvme0n1p2".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            },
            predicted_steps: vec!["preflight".into()],
            refusal_conditions: vec!["fsid drift".into()],
            risks_and_warnings: vec![],
            nonce: "00".repeat(32),
            plan_digest: "00".repeat(32),
            confirmation_token: "tok".into(),
            evidence: vec![],
        };
        let j = serde_json::to_string(&plan).unwrap();
        let back: RecoveryPlan = serde_json::from_str(&j).unwrap();
        assert_eq!(plan, back);
    }
}
