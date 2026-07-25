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

use crate::model::recovery::{RecoveryError, RecoveryErrorKind, TransactionState};

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
    pub fn transition(self, intent: Intent) -> Result<TransactionState, RecoveryError> {
        // Terminal states never accept any automatic intent.
        if self.is_terminal() {
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
                // Revert is permitted from every non-terminal state.
                // The engine decides what "reverting" actually does
                // based on disk facts (e.g. an OldRootMoved state
                // requires swapping the roots back; a Planned state
                // requires only deleting the transaction record).
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

fn illegal(from: TransactionState, intent: Intent) -> RecoveryError {
    RecoveryError::new(
        RecoveryErrorKind::IllegalStateTransition,
        format!("illegal transition from {:?} via intent {:?}", from, intent),
    )
    .with_state(from)
}

impl RecoveryError {
    /// Builder-style helper for state-machine errors.
    pub fn with_state(mut self, state: TransactionState) -> Self {
        self.current_state = Some(state);
        self
    }
}

/// Reconcile a persisted state with the disk facts the engine just
/// observed. Returns the state the engine SHOULD treat as authoritative.
///
/// Rule: the persisted record is a hint; disk facts win. A record that
/// claims `ReplacementCreated` while no staging subvolume exists is
/// treated as `BackupCreated` (or earlier), not as `ReplacementCreated`.
///
/// Reconciliation is conservative: it can only move the state backwards
/// along the happy path, never forwards. A state that is forwards of
/// the disk facts indicates tampering or external writes and is treated
/// as `FailedManualIntervention`.
pub fn reconcile_with_disk_facts(
    persisted: TransactionState,
    facts: &crate::model::recovery::DiskFacts,
) -> TransactionState {
    use crate::model::recovery::TransactionState as S;

    // If the record claims a terminal state, trust it. Terminal states
    // have observable side-effects (a `Completed` root switch is
    // visible as `/@` being the new root; a `Reverted` root switch is
    // visible as `/@` being the old root). The reconciliation of those
    // is the responsibility of the higher-level status command, not
    // this pure helper.
    if persisted.is_terminal() {
        return persisted;
    }

    let backup_ok = facts.backup_root_exists;
    let staging_ok = facts.staging_root_exists;

    match persisted {
        // Anything before BackupCreated: disk facts should not yet show
        // the backup subvolume. If they do, the transaction record is
        // stale (an earlier apply got further than the record claims).
        // Be conservative: keep the persisted (lower) state. The
        // engine's preflight will discover the truth.
        S::Planned | S::PreflightVerified | S::Locked => persisted,

        // BackupCreated: the backup subvolume MUST exist. If it does
        // not, the record is stale; downgrade to Locked so resume
        // re-creates the backup.
        S::BackupCreated if !backup_ok => S::Locked,
        S::BackupCreated => S::BackupCreated,

        // ReplacementCreated: BOTH backup and staging must exist.
        S::ReplacementCreated if !backup_ok => S::Locked,
        S::ReplacementCreated if !staging_ok => S::BackupCreated,
        S::ReplacementCreated => S::ReplacementCreated,

        // From OldRootMoved onward, the swap has happened: /@ is the
        // new root and the staging path now contains the OLD /@. So
        // staging_root_exists should still be true (it now holds old
        // root), and backup_root_exists should be true. If either is
        // missing we are in an inconsistent state.
        //
        // The conservative reconciliation here is: if the disk shows
        // the staging path does NOT exist but the backup does, then
        // either we never reached ReplacementCreated (stale record) or
        // the swap is partially complete in a way the engine can't
        // reason about safely. Surface as FailedManualIntervention so
        // the operator reviews before any further automatic action.
        S::OldRootMoved | S::NewRootInstalled | S::Verifying => {
            if !backup_ok || !staging_ok {
                S::FailedManualIntervention
            } else {
                persisted
            }
        }

        // Reverting / Reverted / Failed* are reconciled at the higher
        // level (they require comparing the active root generation
        // against the recorded value to detect a partial revert).
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::recovery::{DiskFacts, TransactionState as S};

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
            assert_eq!(err.kind, RecoveryErrorKind::IllegalStateTransition);
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
        assert_eq!(err.kind, RecoveryErrorKind::IllegalStateTransition);
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
    fn revert_is_not_reachable_from_terminal_states() {
        for s in [S::Completed, S::Reverted, S::FailedManualIntervention] {
            assert!(s.transition(Intent::Revert).is_err(), "{:?}", s);
        }
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
        let facts = DiskFacts {
            backup_root_exists: false,
            staging_root_exists: false,
            active_root_exists: true,
            active_root_generation: Some(10),
            filesystem_fsid: "x".into(),
        };
        assert_eq!(
            reconcile_with_disk_facts(S::BackupCreated, &facts),
            S::Locked
        );
    }

    #[test]
    fn reconciliation_downgrades_replacementcreated_when_staging_missing() {
        let facts = DiskFacts {
            backup_root_exists: true,
            staging_root_exists: false,
            active_root_exists: true,
            active_root_generation: Some(10),
            filesystem_fsid: "x".into(),
        };
        assert_eq!(
            reconcile_with_disk_facts(S::ReplacementCreated, &facts),
            S::BackupCreated
        );
    }

    #[test]
    fn reconciliation_flags_inconsistent_post_swap_state() {
        // Record says OldRootMoved but the staging path is gone. We
        // cannot know whether the swap partially reverted or whether
        // the operator manually cleaned up. Surface as manual.
        let facts = DiskFacts {
            backup_root_exists: true,
            staging_root_exists: false,
            active_root_exists: true,
            active_root_generation: Some(10),
            filesystem_fsid: "x".into(),
        };
        assert_eq!(
            reconcile_with_disk_facts(S::OldRootMoved, &facts),
            S::FailedManualIntervention
        );
    }

    #[test]
    fn reconciliation_keeps_terminal_persisted_state() {
        let facts = DiskFacts {
            backup_root_exists: true,
            staging_root_exists: true,
            active_root_exists: true,
            active_root_generation: Some(10),
            filesystem_fsid: "x".into(),
        };
        assert_eq!(
            reconcile_with_disk_facts(S::Completed, &facts),
            S::Completed
        );
        assert_eq!(reconcile_with_disk_facts(S::Reverted, &facts), S::Reverted);
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
