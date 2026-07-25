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

    /// Builder-style helper to record which engine step failed.
    /// Used by action implementations that build errors via
    /// [`Engine::failure`] so the persisted `last_error` carries
    /// the step an operator sees in `status`.
    pub fn with_failed_step(mut self, step: impl Into<String>) -> Self {
        self.failed_step = Some(step.into());
        self
    }
}

/// Reconcile a persisted state with the disk facts the engine just
/// observed. Returns the state the engine SHOULD treat as authoritative.
///
/// ## Trust model
///
/// The persisted record is a hint; disk facts win — but only when the
/// disk facts are unambiguous. A record that claims
/// `ReplacementCreated` while no staging subvolume exists is treated
/// as `BackupCreated` (or earlier), not as `ReplacementCreated`.
///
/// A record that claims `Locked` while the backup subvolume already
/// exists is forwarded to `BackupCreated`, because re-creating the
/// backup would either fail with `BackupPathOccupied` or, worse,
/// overwrite the operator's pre-existing backup.
///
/// ## Direction is decided by UUID, not by path existence
///
/// After the renameat2(RENAME_EXCHANGE) swap, `/@` and the staging
/// path exchange identities. Existence alone cannot tell us whether
/// the swap has happened (both paths exist before AND after the
/// swap). We use UUID: if `active_root.uuid` equals the planned
/// source snapshot's subvolume id (or the staging's pre-swap UUID),
/// the swap has happened; if it equals the planned current root's
/// UUID, it has not.
///
/// ## When ambiguous, refuse
///
/// If the disk facts disagree with each other (e.g. record claims
/// `OldRootMoved` but the staging path is gone, or the active root's
/// UUID matches neither the planned current root nor the planned
/// replacement) we surface `FailedManualIntervention` so the operator
/// reviews before any further automatic action.
pub fn reconcile_with_disk_facts(
    persisted: TransactionState,
    plan: &crate::model::recovery::RecoveryPlan,
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

    // A transaction record copied to another btrfs filesystem must
    // never use that filesystem's path existence as evidence of
    // forward progress. FSID mismatch makes every destructive action
    // ambiguous, so force operator review before resume or revert.
    if facts.filesystem_fsid != plan.filesystem.fsid {
        return S::FailedManualIntervention;
    }

    let backup_ok = facts.backup_root_exists;
    let staging_ok = facts.staging_root_exists;

    // Forward-progress probes: the swap may have happened even though
    // the persisted state is earlier than OldRootMoved. We decide
    // using UUIDs because existence is ambiguous across the swap.
    let swap_done = swap_appears_done(plan, facts);
    let reverse_swap_done = reverse_swap_appears_done(plan, facts);

    match persisted {
        // Anything before BackupCreated: if the backup subvolume is
        // already on disk, the previous apply persisted `Locked` but
        // crashed before persisting `BackupCreated`. Forward to
        // BackupCreated so resume skips snapshot creation.
        S::Planned | S::PreflightVerified | S::Locked if backup_ok => S::BackupCreated,
        S::Planned | S::PreflightVerified | S::Locked => persisted,

        // BackupCreated: the backup subvolume MUST exist. If it does
        // not, the record is stale; downgrade to Locked so resume
        // re-creates the backup.
        S::BackupCreated if !backup_ok => S::Locked,
        S::BackupCreated if staging_ok => S::ReplacementCreated,
        S::BackupCreated => S::BackupCreated,

        // ReplacementCreated: BOTH backup and staging must exist.
        // When they exist but the swap state is ambiguous (the
        // active root's identity does not match either the planned
        // current root or a plausible post-swap replacement), we
        // surface `FailedManualIntervention` rather than guess.
        S::ReplacementCreated if !backup_ok => S::Locked,
        S::ReplacementCreated if !staging_ok => S::BackupCreated,
        S::ReplacementCreated if swap_done => S::OldRootMoved,
        S::ReplacementCreated if replacement_identity_is_ambiguous(plan, facts) => {
            S::FailedManualIntervention
        }
        S::ReplacementCreated => S::ReplacementCreated,

        // From OldRootMoved onward, the swap has happened. If the
        // active root UUID matches the pre-recovery current root
        // again, the swap has been reversed out from under us.
        S::OldRootMoved | S::NewRootInstalled | S::Verifying
            if reverse_swap_appears_done(plan, facts) =>
        {
            S::Reverting
        }
        S::OldRootMoved | S::NewRootInstalled | S::Verifying => {
            if !backup_ok || !staging_ok {
                S::FailedManualIntervention
            } else if post_swap_identity_is_ambiguous(plan, facts) {
                // Both paths exist but the subvolume ids do not match
                // any plausible post-swap arrangement. Refuse to
                // guess; surface as manual.
                S::FailedManualIntervention
            } else {
                persisted
            }
        }

        // Reverting: if the swap has been reversed (active root is
        // the pre-recovery root again), forward to Reverted.
        S::Reverting if reverse_swap_done => S::Reverted,
        S::Reverting => S::Reverting,

        // Failed* states are reconciled at the higher level.
        other => other,
    }
}

/// Decide whether the renameat2(RENAME_EXCHANGE) swap appears to have
/// happened, based on the plan and the freshly observed disk facts.
///
/// Returns `true` only when BOTH identity axes agree:
/// * the staging path's subvolume_id matches the planned
///   `current_root.subvolume_id` (the swap exchanges the two
///   subvolumes in place, so the staging path now holds the
///   pre-recovery current root verbatim), AND
/// * the active root's subvolume_id differs from the planned
///   `current_root.subvolume_id` (it has been replaced).
///
/// When UUIDs are observable, additional axes are checked:
/// * the staging path's UUID, if present, must equal the planned
///   current root's UUID (we compare UUID-to-UUID, never
///   UUID-to-path);
/// * the active root's parent_uuid must equal the selected source
///   snapshot UUID (the replacement is a writable snapshot of that
///   exact source);
/// * the active root's `read_only`, if present, must be `false`
///   (we always create the replacement writable).
///
/// The check returns `false` when ANY observable axis disagrees. It
/// does NOT return `true` on absence of evidence: if UUIDs / readonly
/// are missing we still require the subvolume_id axes to agree
/// unambiguously.
pub fn swap_appears_done(
    plan: &crate::model::recovery::RecoveryPlan,
    facts: &crate::model::recovery::DiskFacts,
) -> bool {
    let Some(active) = &facts.active_root else {
        return false;
    };
    let Some(staging) = &facts.staging_root else {
        return false;
    };

    // Axis 1 (required): staging path now holds the pre-recovery
    // current root. Compare subvolume_id directly.
    let staging_holds_old = staging
        .subvolume_id
        .map(|id| id == plan.current_root.subvolume_id)
        .unwrap_or(false);
    if !staging_holds_old {
        return false;
    }

    // Axis 2 (required): active root is NOT the pre-recovery current
    // root. Compare subvolume_id directly.
    let active_is_new = active
        .subvolume_id
        .map(|id| id != plan.current_root.subvolume_id)
        .unwrap_or(false);
    if !active_is_new {
        return false;
    }

    // Axis 3: when the plan pinned a current-root UUID, the staging
    // path must expose the same UUID. A missing observed UUID is not
    // enough evidence to repeat or skip a destructive exchange.
    if let Some(expected_old_uuid) = plan.current_root.uuid.as_deref() {
        if staging.uuid.as_deref() != Some(expected_old_uuid) {
            return false;
        }
        if active.uuid.as_deref() == Some(expected_old_uuid) {
            return false;
        }
    }

    // Axis 4: the replacement must be a snapshot of the selected
    // source. btrfs records that relation in Parent UUID. If the plan
    // pinned a source UUID, absence or mismatch is ambiguous and must
    // not be treated as a completed swap.
    if let Some(expected_source_uuid) = plan.source_snapshot.uuid.as_deref() {
        if active.parent_uuid.as_deref() != Some(expected_source_uuid) {
            return false;
        }
    }

    // Axis 5 (when observable): the post-swap active root is a
    // writable subvolume (we created it writable; a readonly active
    // root would mean the swap did not happen or someone replaced
    // the active root with a readonly snapshot afterwards).
    if let Some(ro) = active.read_only {
        if ro {
            return false;
        }
    }

    true
}

/// Decide whether the swap has been reversed (either by a successful
/// revert, or by external tampering that swapped the roots back).
///
/// Requires the staging path to still exist: after a successful
/// reverse swap, the staging path holds the just-removed new root.
/// If the staging path is gone AND the active root matches the
/// pre-recovery root, we cannot distinguish "swap was reversed" from
/// "swap never happened and someone deleted staging" — leave that
/// disambiguation to the caller.
///
/// Identity axes:
/// * the active root's subvolume_id matches the planned
///   `current_root.subvolume_id`;
/// * when observable, the staging path's subvolume_id differs from
///   the planned `current_root.subvolume_id` (it now holds the
///   just-removed new root);
/// * when observable, the active root's `read_only` is `false`
///   (the planned current root was writable).
pub fn reverse_swap_appears_done(
    plan: &crate::model::recovery::RecoveryPlan,
    facts: &crate::model::recovery::DiskFacts,
) -> bool {
    if !facts.staging_root_exists {
        return false;
    }
    let Some(active) = &facts.active_root else {
        return false;
    };
    let active_is_old = active
        .subvolume_id
        .map(|id| id == plan.current_root.subvolume_id)
        .unwrap_or(false);
    if !active_is_old {
        return false;
    }
    if let Some(expected_old_uuid) = plan.current_root.uuid.as_deref() {
        if active.uuid.as_deref() != Some(expected_old_uuid) {
            return false;
        }
    }
    if let Some(expected_source_uuid) = plan.source_snapshot.uuid.as_deref() {
        let Some(staging) = facts.staging_root.as_ref() else {
            return false;
        };
        if staging.parent_uuid.as_deref() != Some(expected_source_uuid) {
            return false;
        }
    }
    // When observable, the active root must be writable (the planned
    // current root was writable; a readonly active root would mean
    // someone replaced it with a snapshot).
    if let Some(ro) = active.read_only {
        if ro {
            return false;
        }
    }
    true
}

/// Decide whether the post-swap disk facts are consistent with ANY
/// plausible post-swap arrangement. Returns `true` when the active
/// root and staging subvolume ids together do not match either of:
///   * the normal post-swap layout (active = pre-swap staging id;
///     staging = pre-swap active id), OR
///   * the reverse-swap layout (active = planned current_root id;
///     staging = anything).
///
/// When ambiguous, the caller MUST refuse to advance and surface
/// `FailedManualIntervention`: re-running renameat2 with an unknown
/// starting arrangement could corrupt the layout further.
fn post_swap_identity_is_ambiguous(
    plan: &crate::model::recovery::RecoveryPlan,
    facts: &crate::model::recovery::DiskFacts,
) -> bool {
    let Some(active) = &facts.active_root else {
        return false;
    };
    let Some(active_id) = active.subvolume_id else {
        return false;
    };
    let staging_id = facts.staging_root.as_ref().and_then(|s| s.subvolume_id);

    // The reverse-swap layout: active is the planned current root.
    // This is the only state from which re-running renameat2 would
    // be safe (it would just swap back to the new root). Caller has
    // already checked reverse_swap_appears_done; reaching ambiguity
    // here means we are NOT in the reverse-swap layout.
    if active_id == plan.current_root.subvolume_id {
        return false;
    }

    // The normal post-swap layout: active is the new-root subvolume
    // id (some unknown id assigned by btrfs at snapshot time), and
    // staging holds the planned current root's id. We do NOT know
    // the new-root id ahead of time (btrfs assigns it), so the only
    // signal we have is staging == plan.current_root.subvolume_id.
    if let Some(staging_id) = staging_id {
        if staging_id == plan.current_root.subvolume_id {
            // active is "something else", staging is the old root.
            // That is the textbook post-swap layout.
            return false;
        }
        // Both axes are non-current-root AND differ from each other:
        // we cannot reconstruct what happened. Refuse.
        if staging_id != active_id {
            return true;
        }
    }

    // active is non-current-root; staging has no observable id.
    // Plausibly post-swap with an old btrfs-progs that omits
    // subvolume id. Do not flag as ambiguous on absence of evidence
    // alone — the existence check already covers missing paths.
    false
}

/// Decide whether the disk facts observed while the persisted state
/// is `ReplacementCreated` are ambiguous about whether the swap has
/// happened. Used to refuse to advance when the engine cannot tell
/// whether it should re-execute `swap_roots` or skip it.
///
/// Returns `true` when the active root's subvolume_id is neither the
/// planned current root (pre-swap) nor the staging subvolume_id
/// (post-swap), AND the staging subvolume_id does not match the
/// planned current root (which would be the textbook post-swap
/// layout). When the swap state is ambiguous, the engine MUST
/// surface `FailedManualIntervention` rather than guess.
fn replacement_identity_is_ambiguous(
    plan: &crate::model::recovery::RecoveryPlan,
    facts: &crate::model::recovery::DiskFacts,
) -> bool {
    let Some(active) = &facts.active_root else {
        return false;
    };
    let Some(active_id) = active.subvolume_id else {
        return false;
    };
    // Pre-swap layout: active root is the planned current root.
    if active_id == plan.current_root.subvolume_id {
        return false;
    }
    // Post-swap layout would have staging holding the planned current
    // root's subvolume_id. If staging holds something else entirely,
    // we cannot tell what happened.
    if let Some(staging_id) = facts.staging_root.as_ref().and_then(|s| s.subvolume_id) {
        if staging_id != plan.current_root.subvolume_id {
            return true;
        }
    }
    // active is "not the planned current root" and we cannot confirm
    // post-swap layout from staging. Refuse.
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::recovery::{
        BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, DiskFacts, RecoveryPlan, SubvolumeFacts,
        TransactionState as S, RECOVERY_PLAN_SCHEMA_VERSION,
    };

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
            boot_consistency: crate::recovery::boot::evaluate_readonly_consistency(
                &crate::model::recovery::BootLayout::default(),
            ),
            backup_root_path: "/.catos-recovery/backups/p-test/root-before".into(),
            staging_root_path: "/.catos-recovery/staging/p-test/new-root".into(),
            fstab_root_definition: crate::model::recovery::FstabRootDefinition {
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
                generation: Some(10),
                uuid: None,
                parent_uuid: None,
                read_only: Some(false),
            }),
            staging_root_exists: staging,
            staging_root: if staging {
                Some(SubvolumeFacts {
                    path: "/.catos-recovery/staging/p-test/new-root".into(),
                    subvolume_id: Some(999),
                    generation: Some(10),
                    uuid: None,
                    parent_uuid: None,
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
                    uuid: None,
                    parent_uuid: None,
                    read_only: Some(true),
                })
            } else {
                None
            },
            source_snapshot_exists: true,
            source_snapshot: None,
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
