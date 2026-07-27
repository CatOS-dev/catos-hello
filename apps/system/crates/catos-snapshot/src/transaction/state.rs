//! Pure state machine for recovery transactions.
//!
//! This module has NO I/O. It is a function of (current_state, intent)
//! -> Result<next_state, Error>. The engine is the only caller that
//! persists the transition; tests drive this directly to prove which
//! transitions are allowed and which are forbidden.
//!
//! ## Why explicit
//!
//! The spec requires that arbitrary jumps be impossible. In particular:
//!
//! * You cannot reach `Completed` without passing through `Verifying`.
//! * You cannot re-enter `Planned` from any state that has done a
//!   persistent write.
//! * You cannot leave a terminal state via any automatic transition.
//! * `Reverting` is reachable from any non-terminal state, but only via
//!   the dedicated `Intent::Revert` (never as a side-effect of
//!   `Advance`).
//!
//! The engine consults this module before each transition and refuses
//! to persist a state the table does not permit.

use crate::model::{SnapshotError, SnapshotErrorKind, TransactionRecord, TransactionState};

/// What the engine wants to do. One-to-one with the public subcommand
/// verbs plus the internal "advance to the next logical state".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Advance one step along the happy path.
    Advance,
    /// Begin reverting the transaction.
    Revert,
    /// Mark the transaction completed (terminal success).
    Complete,
    /// Mark the transaction reverted (terminal success of revert).
    Reverted,
    /// Record a recoverable failure (the operator may resume).
    FailRecoverable,
    /// Record a failure that requires manual intervention.
    FailManual,
}

impl TransactionState {
    /// The happy-path successor of this state, if any. Returns `None`
    /// for terminal states and for `Reverting`.
    pub fn happy_path_successor(self) -> Option<TransactionState> {
        match self {
            TransactionState::Planned => Some(TransactionState::PreflightVerified),
            TransactionState::PreflightVerified => Some(TransactionState::Locked),
            TransactionState::Locked => Some(TransactionState::BackupCreated),
            TransactionState::BackupCreated => Some(TransactionState::ReplacementCreated),
            TransactionState::ReplacementCreated => Some(TransactionState::OldRootMoved),
            TransactionState::OldRootMoved => Some(TransactionState::NewRootInstalled),
            TransactionState::NewRootInstalled => Some(TransactionState::Verifying),
            TransactionState::Verifying => Some(TransactionState::Completed),
            // Terminal / non-advancing states.
            TransactionState::Completed
            | TransactionState::Reverting
            | TransactionState::Reverted
            | TransactionState::FailedRecoverable
            | TransactionState::FailedManualIntervention => None,
        }
    }

    /// Decide whether `intent` is permitted from `self`. Returns the
    /// resulting state on success.
    pub fn transition(self, intent: Intent) -> Result<TransactionState, SnapshotError> {
        // `Completed` is the ONLY terminal state that accepts an
        // intent: an explicit operator `revert` of a completed
        // recovery swaps the roots back. All other terminal states
        // (Reverted, FailedManualIntervention) reject every intent.
        // Reverted is idempotent and FailedManualIntervention
        // requires operator review before any further automatic
        // action.
        if self.is_terminal() && !(self == TransactionState::Completed && intent == Intent::Revert)
        {
            return Err(illegal(self, intent));
        }

        match intent {
            Intent::Advance => match self.happy_path_successor() {
                Some(next) => Ok(next),
                None => Err(illegal(self, intent)),
            },
            Intent::Complete => {
                // Only `Verifying` reaches `Completed`. This prevents a
                // crash landing in `NewRootInstalled` from being
                // silently upgraded to `Completed` by a buggy resume.
                if self == TransactionState::Verifying {
                    Ok(TransactionState::Completed)
                } else {
                    Err(illegal(self, intent))
                }
            }
            Intent::Revert => {
                // Revert is permitted from every non-terminal state
                // AND from `Completed` (operator-driven explicit
                // revert of a successful recovery). The engine
                // decides what "reverting" actually does based on
                // disk facts (e.g. an OldRootMoved state requires
                // swapping the roots back; a Planned state requires
                // only deleting the transaction record; a Completed
                // state swaps the roots back via renameat2).
                Ok(TransactionState::Reverting)
            }
            Intent::Reverted => {
                // Only Reverting may reach Reverted.
                if self == TransactionState::Reverting {
                    Ok(TransactionState::Reverted)
                } else {
                    Err(illegal(self, intent))
                }
            }
            Intent::FailRecoverable | Intent::FailManual => {
                // A failure can be recorded from any non-terminal
                // state. The engine decides which kind based on disk
                // facts (e.g. OldRootMoved + later failure usually
                // means manual intervention; preflight failure usually
                // means recoverable).
                Ok(if matches!(intent, Intent::FailRecoverable) {
                    TransactionState::FailedRecoverable
                } else {
                    TransactionState::FailedManualIntervention
                })
            }
        }
    }

    /// What the engine should do to advance from this state. Pure
    /// description; the engine maps each variant to a concrete action.
    pub fn advance_action(self) -> Option<AdvanceAction> {
        match self {
            TransactionState::Planned => Some(AdvanceAction::Preflight),
            TransactionState::PreflightVerified => Some(AdvanceAction::AcquireLock),
            TransactionState::Locked => Some(AdvanceAction::CreateBackup),
            TransactionState::BackupCreated => Some(AdvanceAction::CreateReplacement),
            TransactionState::ReplacementCreated => Some(AdvanceAction::SwapRoots),
            TransactionState::OldRootMoved => Some(AdvanceAction::VerifyNewRoot),
            TransactionState::NewRootInstalled => Some(AdvanceAction::VerifyFinal),
            TransactionState::Verifying => Some(AdvanceAction::MarkCompleted),
            // Terminal / non-advancing states have no action.
            TransactionState::Completed
            | TransactionState::Reverting
            | TransactionState::Reverted
            | TransactionState::FailedRecoverable
            | TransactionState::FailedManualIntervention => None,
        }
    }
}

/// Concrete engine action associated with an `Advance` intent. Used by
/// the engine to look up the function that performs the actual work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceAction {
    Preflight,
    AcquireLock,
    CreateBackup,
    CreateReplacement,
    SwapRoots,
    VerifyNewRoot,
    VerifyFinal,
    MarkCompleted,
}

fn illegal(from: TransactionState, intent: Intent) -> SnapshotError {
    SnapshotError::new(
        SnapshotErrorKind::IllegalStateTransition,
        format!("illegal transition from {:?} via intent {:?}", from, intent),
    )
    .with_state(from)
}

/// Return the last state from which an automatic resume is meaningful.
///
/// Failure persistence records the state that failed in
/// `last_error.current_state` before replacing the top-level state with
/// `FailedRecoverable`. The completed-step history is a conservative
/// fallback for older records that lack that field.
pub fn resume_checkpoint(record: &TransactionRecord) -> Option<TransactionState> {
    if record.state != TransactionState::FailedRecoverable {
        return Some(record.state);
    }

    record
        .last_error
        .as_ref()
        .and_then(|error| error.current_state)
        .filter(|state| *state != TransactionState::FailedRecoverable && state.resume_permitted())
        .or_else(|| {
            record
                .completed_steps
                .iter()
                .rev()
                .map(|step| step.state)
                .find(|state| {
                    *state != TransactionState::FailedRecoverable && state.resume_permitted()
                })
        })
}

impl SnapshotError {
    /// Builder-style helper for state-machine errors.
    pub fn with_state(mut self, state: TransactionState) -> Self {
        self.current_state = Some(state);
        self
    }

    /// Builder-style helper to record which engine step failed.
    /// Used by action implementations that build errors via
    /// [`Engine::failure`] so the persisted `last_error` carries
    /// the step an operator sees in `status`.
    pub fn with_failed_step(mut self, step: impl Into<String>) -> Self {
        self.failed_step = Some(step.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, DiskFacts, RecoveryPlan, SubvolumeFacts,
        TransactionState as S, RECOVERY_PLAN_SCHEMA_VERSION,
    };
    use crate::plan::reconcile::*;

    fn sample_plan() -> RecoveryPlan {
        RecoveryPlan {
            schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
            plan_id: "p-test".into(),
            generated_at_unix: 1,
            generated_on_host: None,
            filesystem: BtrfsFilesystemIdentity {
                fsid: "x".into(),
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
            boot_layout: Default::default(),
            boot_consistency: catos_boot::diagnose::layout::evaluate_readonly_consistency(
                &catos_boot::model::BootLayout::default(),
            ),
            backup_root_path: "/.catos-recovery/backups/p-test/root-before".into(),
            staging_root_path: "/.catos-recovery/staging/p-test/new-root".into(),
            fstab_root_definition: crate::model::FstabRootDefinition {
                source: "/dev/nvme0n1p2".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            },
            predicted_steps: vec![],
            refusal_conditions: vec![],
            risks_and_warnings: vec![],
            nonce: "00".repeat(32),
            plan_digest: "00".repeat(32),
            confirmation_token: "tok".into(),
            evidence: vec![],
        }
    }

    fn facts_with(backup: bool, staging: bool) -> DiskFacts {
        DiskFacts {
            filesystem_fsid: "x".into(),
            active_root_exists: true,
            active_root: Some(SubvolumeFacts {
                path: "/@".into(),
                subvolume_id: Some(256),
                generation: Some(100),
                uuid: Some("old-root-uuid".into()),
                parent_uuid: None,
                read_only: Some(false),
            }),
            staging_root_exists: staging,
            staging_root: if staging {
                Some(SubvolumeFacts {
                    path: "/.catos-recovery/staging/p-test/new-root".into(),
                    subvolume_id: Some(999),
                    generation: Some(80),
                    uuid: Some("replacement-uuid".into()),
                    parent_uuid: Some("source-snapshot-uuid".into()),
                    read_only: Some(false),
                })
            } else {
                None
            },
            backup_root_exists: backup,
            backup: if backup {
                Some(SubvolumeFacts {
                    path: "/.catos-recovery/backups/p-test/root-before".into(),
                    subvolume_id: Some(400),
                    generation: Some(100),
                    uuid: Some("backup-uuid".into()),
                    parent_uuid: Some("old-root-uuid".into()),
                    read_only: Some(true),
                })
            } else {
                None
            },
            source_snapshot_exists: true,
            source_snapshot: Some(SubvolumeFacts {
                path: "/@snapshots/1".into(),
                subvolume_id: Some(300),
                generation: Some(80),
                uuid: Some("source-snapshot-uuid".into()),
                parent_uuid: Some("older-root-uuid".into()),
                read_only: Some(true),
            }),
        }
    }

    #[test]
    fn reconciliation_refuses_nonterminal_record_on_different_fsid() {
        let plan = sample_plan();
        let mut facts = facts_with(true, true);
        facts.filesystem_fsid = "different-fsid".into();
        assert_eq!(
            reconcile_with_disk_facts(S::Locked, &plan, &facts),
            S::FailedManualIntervention
        );
    }

    #[test]
    fn happy_path_advances_in_strict_order() {
        // Each state must advance to exactly one successor.
        assert_eq!(
            S::Planned.transition(Intent::Advance).unwrap(),
            S::PreflightVerified
        );
        assert_eq!(
            S::PreflightVerified.transition(Intent::Advance).unwrap(),
            S::Locked
        );
        assert_eq!(
            S::Locked.transition(Intent::Advance).unwrap(),
            S::BackupCreated
        );
        assert_eq!(
            S::BackupCreated.transition(Intent::Advance).unwrap(),
            S::ReplacementCreated
        );
        assert_eq!(
            S::ReplacementCreated.transition(Intent::Advance).unwrap(),
            S::OldRootMoved
        );
        assert_eq!(
            S::OldRootMoved.transition(Intent::Advance).unwrap(),
            S::NewRootInstalled
        );
        assert_eq!(
            S::NewRootInstalled.transition(Intent::Advance).unwrap(),
            S::Verifying
        );
        assert_eq!(
            S::Verifying.transition(Intent::Advance).unwrap(),
            S::Completed
        );
    }

    #[test]
    fn terminal_states_refuse_advance() {
        // Guards against a buggy resume that "advances" a Completed
        // transaction into a second Completed.
        for s in [S::Completed, S::Reverted, S::FailedManualIntervention] {
            let err = s.transition(Intent::Advance).unwrap_err();
            assert_eq!(err.kind, SnapshotErrorKind::IllegalStateTransition);
            assert_eq!(err.current_state, Some(s));
        }
    }

    #[test]
    fn completed_can_only_be_reached_from_verifying() {
        // This is the single most important invariant: nothing skips
        // the final verification step.
        let err = S::NewRootInstalled
            .transition(Intent::Complete)
            .unwrap_err();
        assert_eq!(err.kind, SnapshotErrorKind::IllegalStateTransition);
        assert!(S::Verifying.transition(Intent::Complete).is_ok());
    }

    #[test]
    fn revert_is_reachable_from_any_non_terminal_state() {
        for s in [
            S::Planned,
            S::PreflightVerified,
            S::Locked,
            S::BackupCreated,
            S::ReplacementCreated,
            S::OldRootMoved,
            S::NewRootInstalled,
            S::Verifying,
            S::FailedRecoverable,
        ] {
            assert_eq!(
                s.transition(Intent::Revert).unwrap(),
                S::Reverting,
                "{:?}",
                s
            );
        }
    }

    #[test]
    fn revert_is_not_reachable_from_terminal_states_except_completed() {
        // Reverted and FailedManualIntervention remain terminal: no
        // automatic revert is permitted from them. Completed is the
        // exception — see `revert_of_completed_succeeds` below.
        for s in [S::Reverted, S::FailedManualIntervention] {
            assert!(s.transition(Intent::Revert).is_err(), "{:?}", s);
        }
    }

    /// `Completed + Intent::Revert -> Reverting` is the only
    /// terminal-state transition the engine is permitted to make.
    /// This is the explicit operator revert of a successful recovery:
    /// the engine will swap the roots back via renameat2 and then
    /// persist `Reverted`. Pinned because the previous
    /// implementation hid this as a hardcoded engine shortcut,
    /// which let the state machine drift out of sync with the
    /// engine's behaviour.
    #[test]
    fn revert_of_completed_succeeds() {
        assert_eq!(
            S::Completed.transition(Intent::Revert).unwrap(),
            S::Reverting
        );
    }

    #[test]
    fn reverted_only_from_reverting() {
        assert!(S::Reverting.transition(Intent::Reverted).is_ok());
        assert!(S::Planned.transition(Intent::Reverted).is_err());
        assert!(S::BackupCreated.transition(Intent::Reverted).is_err());
    }

    #[test]
    fn failure_can_be_recorded_from_non_terminal_states() {
        assert!(S::Planned.transition(Intent::FailRecoverable).is_ok());
        assert_eq!(
            S::Planned.transition(Intent::FailRecoverable).unwrap(),
            S::FailedRecoverable
        );
        assert_eq!(
            S::OldRootMoved.transition(Intent::FailManual).unwrap(),
            S::FailedManualIntervention
        );
    }

    #[test]
    fn reconciliation_downgrades_backupcreated_when_backup_missing() {
        // Disk says no backup subvolume but record claims BackupCreated.
        // The honest reconciliation is: the backup step did not persist;
        // rewind to Locked so resume re-creates it.
        let plan = sample_plan();
        let facts = facts_with(false, false);
        assert_eq!(
            reconcile_with_disk_facts(S::BackupCreated, &plan, &facts),
            S::Locked
        );
    }

    #[test]
    fn reconciliation_downgrades_replacementcreated_when_staging_missing() {
        let plan = sample_plan();
        let facts = facts_with(true, false);
        assert_eq!(
            reconcile_with_disk_facts(S::ReplacementCreated, &plan, &facts),
            S::BackupCreated
        );
    }

    #[test]
    fn reconciliation_flags_inconsistent_post_swap_state() {
        // Record says OldRootMoved but the staging path is gone. We
        // cannot know whether the swap partially reverted or whether
        // the operator manually cleaned up. Surface as manual.
        let plan = sample_plan();
        let facts = facts_with(true, false);
        assert_eq!(
            reconcile_with_disk_facts(S::OldRootMoved, &plan, &facts),
            S::FailedManualIntervention
        );
    }

    #[test]
    fn reconciliation_keeps_terminal_persisted_state() {
        let plan = sample_plan();
        let facts = facts_with(true, true);
        assert_eq!(
            reconcile_with_disk_facts(S::Completed, &plan, &facts),
            S::Completed
        );
        assert_eq!(
            reconcile_with_disk_facts(S::Reverted, &plan, &facts),
            S::Reverted
        );
    }

    // Forward-progress reconciliation (Group 1: pre-persist crash recovery).

    #[test]
    fn reconciliation_advances_locked_to_backupcreated_when_backup_exists() {
        let plan = sample_plan();
        let facts = facts_with(true, false);
        assert_eq!(
            reconcile_with_disk_facts(S::Locked, &plan, &facts),
            S::BackupCreated
        );
        assert_eq!(
            reconcile_with_disk_facts(S::Planned, &plan, &facts),
            S::BackupCreated
        );
        assert_eq!(
            reconcile_with_disk_facts(S::PreflightVerified, &plan, &facts),
            S::BackupCreated
        );
    }

    #[test]
    fn reconciliation_advances_backupcreated_to_replacementcreated_when_staging_exists() {
        let plan = sample_plan();
        let facts = facts_with(true, true);
        assert_eq!(
            reconcile_with_disk_facts(S::BackupCreated, &plan, &facts),
            S::ReplacementCreated
        );
    }

    #[test]
    fn reconciliation_advances_replacementcreated_to_oldrootmoved_when_swap_done() {
        let plan = sample_plan();
        let mut facts = facts_with(true, true);
        facts.active_root = Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(300),
            generation: Some(80),
            uuid: Some("replacement-uuid".into()),
            parent_uuid: Some("source-snapshot-uuid".into()),
            read_only: Some(false),
        });
        facts.staging_root = Some(SubvolumeFacts {
            path: "/.catos-recovery/staging/p-test/new-root".into(),
            subvolume_id: Some(256),
            generation: Some(100),
            uuid: Some("old-root-uuid".into()),
            parent_uuid: None,
            read_only: Some(false),
        });
        assert_eq!(
            reconcile_with_disk_facts(S::ReplacementCreated, &plan, &facts),
            S::OldRootMoved
        );
    }

    #[test]
    fn swap_detection_rejects_wrong_old_root_uuid_even_when_subvolid_matches() {
        let plan = sample_plan();
        let mut facts = facts_with(true, true);
        facts.active_root = Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(999),
            generation: Some(80),
            uuid: Some("replacement-uuid".into()),
            parent_uuid: Some("source-snapshot-uuid".into()),
            read_only: Some(false),
        });
        facts.staging_root = Some(SubvolumeFacts {
            path: "/.catos-recovery/staging/p-test/new-root".into(),
            subvolume_id: Some(256),
            generation: Some(100),
            uuid: Some("foreign-subvolume-uuid".into()),
            parent_uuid: None,
            read_only: Some(false),
        });
        assert!(!swap_appears_done(&plan, &facts));
    }

    #[test]
    fn swap_detection_rejects_replacement_from_wrong_parent_uuid() {
        let plan = sample_plan();
        let mut facts = facts_with(true, true);
        facts.active_root = Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(999),
            generation: Some(80),
            uuid: Some("replacement-uuid".into()),
            parent_uuid: Some("unrelated-source-uuid".into()),
            read_only: Some(false),
        });
        facts.staging_root = Some(SubvolumeFacts {
            path: "/.catos-recovery/staging/p-test/new-root".into(),
            subvolume_id: Some(256),
            generation: Some(100),
            uuid: Some("old-root-uuid".into()),
            parent_uuid: None,
            read_only: Some(false),
        });
        assert!(!swap_appears_done(&plan, &facts));
    }

    #[test]
    fn reverse_swap_detection_rejects_wrong_active_root_uuid() {
        let plan = sample_plan();
        let mut facts = facts_with(true, true);
        facts.active_root = Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(256),
            generation: Some(100),
            uuid: Some("foreign-subvolume-uuid".into()),
            parent_uuid: None,
            read_only: Some(false),
        });
        facts.staging_root = Some(SubvolumeFacts {
            path: "/.catos-recovery/staging/p-test/new-root".into(),
            subvolume_id: Some(999),
            generation: Some(80),
            uuid: Some("replacement-uuid".into()),
            parent_uuid: Some("source-snapshot-uuid".into()),
            read_only: Some(false),
        });
        assert!(!reverse_swap_appears_done(&plan, &facts));
    }

    #[test]
    fn reconciliation_advances_reverting_to_reverted_when_reverse_swap_done() {
        let plan = sample_plan();
        let mut facts = facts_with(true, true);
        facts.active_root = Some(SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(256),
            generation: Some(100),
            uuid: Some("old-root-uuid".into()),
            parent_uuid: None,
            read_only: Some(false),
        });
        facts.staging_root = Some(SubvolumeFacts {
            path: "/.catos-recovery/staging/p-test/new-root".into(),
            subvolume_id: Some(999),
            generation: Some(80),
            uuid: Some("replacement-uuid".into()),
            parent_uuid: Some("source-snapshot-uuid".into()),
            read_only: Some(false),
        });
        assert_eq!(
            reconcile_with_disk_facts(S::Reverting, &plan, &facts),
            S::Reverted
        );
    }

    #[test]
    fn reconciliation_keeps_replacementcreated_when_swap_not_done() {
        let plan = sample_plan();
        let facts = facts_with(true, true);
        assert_eq!(
            reconcile_with_disk_facts(S::ReplacementCreated, &plan, &facts),
            S::ReplacementCreated
        );
    }

    #[test]
    fn happy_path_successor_is_none_on_terminal() {
        for s in [
            S::Completed,
            S::Reverting,
            S::Reverted,
            S::FailedRecoverable,
            S::FailedManualIntervention,
        ] {
            assert!(s.happy_path_successor().is_none(), "{:?}", s);
        }
    }

    #[test]
    fn advance_action_returns_expected_step() {
        assert_eq!(S::Planned.advance_action(), Some(AdvanceAction::Preflight));
        assert_eq!(
            S::Locked.advance_action(),
            Some(AdvanceAction::CreateBackup)
        );
        assert_eq!(
            S::ReplacementCreated.advance_action(),
            Some(AdvanceAction::SwapRoots)
        );
        assert_eq!(S::Completed.advance_action(), None);
    }
}
