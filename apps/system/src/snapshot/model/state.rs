//! Persisted snapshot transaction states.

use serde::{Deserialize, Serialize};

/// All states a recovery transaction can be in. Transitions are
/// validated by [`crate::snapshot::transaction`] — direct mutation of the
/// persisted state outside the engine is forbidden.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    /// Plan accepted and persisted, no disk write yet.
    #[default]
    Planned,
    /// Re-checked at apply time: identity stable, current root not the
    /// running root, paths free.
    PreflightVerified,
    /// Exclusive per-FSID lock acquired; transaction record is the
    /// authoritative source of truth.
    Locked,
    /// Pre-recovery readonly backup subvolume created at
    /// `/.catos-recovery/backups/<id>/root-before`.
    BackupCreated,
    /// Writable staging subvolume created from the source snapshot at
    /// `/.catos-recovery/staging/<id>/new-root`.
    ReplacementCreated,
    /// Old `/@` and staging subvolume exchanged via renameat2. Disk now:
    /// `/@` = new root, staging path = old root.
    OldRootMoved,
    /// New `/@` re-verified post-swap (CatOS layout, fstab readable).
    NewRootInstalled,
    /// Final verification in progress.
    Verifying,
    /// All steps completed; transaction is terminal-success.
    Completed,
    /// Revert in progress.
    Reverting,
    /// Revert completed; system back to pre-recovery state.
    Reverted,
    /// Failure occurred but resume is safe (engine knows what to do).
    FailedRecoverable,
    /// Failure occurred; manual intervention required.
    FailedManualIntervention,
}

impl TransactionState {
    pub fn code(self) -> &'static str {
        match self {
            TransactionState::Planned => "planned",
            TransactionState::PreflightVerified => "preflight_verified",
            TransactionState::Locked => "locked",
            TransactionState::BackupCreated => "backup_created",
            TransactionState::ReplacementCreated => "replacement_created",
            TransactionState::OldRootMoved => "old_root_moved",
            TransactionState::NewRootInstalled => "new_root_installed",
            TransactionState::Verifying => "verifying",
            TransactionState::Completed => "completed",
            TransactionState::Reverting => "reverting",
            TransactionState::Reverted => "reverted",
            TransactionState::FailedRecoverable => "failed_recoverable",
            TransactionState::FailedManualIntervention => "failed_manual_intervention",
        }
    }

    /// True iff this state represents a terminal end state (no further
    /// automatic transition is permitted).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TransactionState::Completed
                | TransactionState::Reverted
                | TransactionState::FailedManualIntervention
        )
    }

    /// True iff the first persistent write to the target filesystem has
    /// already happened in this state (i.e. backup, replacement, or any
    /// later step has completed at least once).
    pub fn first_persistent_write_done(self) -> bool {
        matches!(
            self,
            TransactionState::BackupCreated
                | TransactionState::ReplacementCreated
                | TransactionState::OldRootMoved
                | TransactionState::NewRootInstalled
                | TransactionState::Verifying
                | TransactionState::Completed
                | TransactionState::Reverting
                | TransactionState::Reverted
                | TransactionState::FailedRecoverable
                | TransactionState::FailedManualIntervention
        )
    }

    /// True iff the old root has been moved out from under `/@` (so
    /// resumption MUST account for the swap).
    pub fn old_root_moved(self) -> bool {
        matches!(
            self,
            TransactionState::OldRootMoved
                | TransactionState::NewRootInstalled
                | TransactionState::Verifying
                | TransactionState::Completed
        )
    }

    /// True iff the new root has been installed and verified at `/@`.
    pub fn new_root_installed(self) -> bool {
        matches!(
            self,
            TransactionState::NewRootInstalled
                | TransactionState::Verifying
                | TransactionState::Completed
        )
    }

    /// True iff automatic resume is permitted from this state.
    pub fn resume_permitted(self) -> bool {
        matches!(
            self,
            TransactionState::Planned
                | TransactionState::PreflightVerified
                | TransactionState::Locked
                | TransactionState::BackupCreated
                | TransactionState::ReplacementCreated
                | TransactionState::OldRootMoved
                | TransactionState::NewRootInstalled
                | TransactionState::Verifying
                | TransactionState::FailedRecoverable
        )
    }
}
