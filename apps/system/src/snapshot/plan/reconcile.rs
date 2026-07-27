//! Pure reconciliation of persisted transaction state with observed disk facts.

use crate::snapshot::model::{BtrfsSubvolumeIdentity, SubvolumeFacts, TransactionState};

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
    plan: &crate::snapshot::model::RecoveryPlan,
    facts: &crate::snapshot::model::DiskFacts,
) -> TransactionState {
    use crate::snapshot::model::TransactionState as S;

    // Terminal records are checked for later drift by Engine::reconcile_status.
    if persisted.is_terminal() {
        return persisted;
    }

    if facts.filesystem_fsid != plan.filesystem.fsid {
        return S::FailedManualIntervention;
    }

    if !fact_shape_is_consistent(facts.active_root_exists, facts.active_root.as_ref())
        || !fact_shape_is_consistent(facts.backup_root_exists, facts.backup.as_ref())
        || !fact_shape_is_consistent(facts.staging_root_exists, facts.staging_root.as_ref())
        || !fact_shape_is_consistent(facts.source_snapshot_exists, facts.source_snapshot.as_ref())
    {
        return S::FailedManualIntervention;
    }

    // The source snapshot is immutable transaction input. A different
    // subvolume at the same path must never become the replacement root.
    if !exact_identity_matches(&plan.source_snapshot, facts.source_snapshot.as_ref()) {
        return S::FailedManualIntervention;
    }

    let current_root_ok = exact_identity_matches(&plan.current_root, facts.active_root.as_ref());
    let backup_ok = backup_matches_plan(plan, facts.backup.as_ref());
    let staging_replacement_ok = staging_matches_source(plan, facts.staging_root.as_ref());
    let swap_done = swap_appears_done(plan, facts);
    let reverse_swap_done = reverse_swap_appears_done(plan, facts);

    match persisted {
        S::Planned | S::PreflightVerified | S::Locked if !current_root_ok => {
            S::FailedManualIntervention
        }
        S::Planned | S::PreflightVerified | S::Locked
            if facts.staging_root_exists && (!facts.backup_root_exists || !backup_ok) =>
        {
            S::FailedManualIntervention
        }
        S::Planned | S::PreflightVerified | S::Locked if facts.staging_root_exists => {
            if staging_replacement_ok {
                S::ReplacementCreated
            } else {
                S::FailedManualIntervention
            }
        }
        S::Planned | S::PreflightVerified | S::Locked if facts.backup_root_exists => {
            if backup_ok {
                S::BackupCreated
            } else {
                S::FailedManualIntervention
            }
        }
        S::Planned | S::PreflightVerified | S::Locked => persisted,

        S::BackupCreated if !current_root_ok => S::FailedManualIntervention,
        S::BackupCreated if !facts.backup_root_exists => S::Locked,
        S::BackupCreated if !backup_ok => S::FailedManualIntervention,
        S::BackupCreated if facts.staging_root_exists && !staging_replacement_ok => {
            S::FailedManualIntervention
        }
        S::BackupCreated if facts.staging_root_exists => S::ReplacementCreated,
        S::BackupCreated => S::BackupCreated,

        S::ReplacementCreated if !facts.backup_root_exists || !backup_ok => {
            S::FailedManualIntervention
        }
        S::ReplacementCreated if !facts.staging_root_exists => S::BackupCreated,
        S::ReplacementCreated if swap_done => S::OldRootMoved,
        S::ReplacementCreated if !current_root_ok || !staging_replacement_ok => {
            S::FailedManualIntervention
        }
        S::ReplacementCreated => S::ReplacementCreated,

        S::OldRootMoved | S::NewRootInstalled | S::Verifying if reverse_swap_done => S::Reverting,
        S::OldRootMoved | S::NewRootInstalled | S::Verifying => {
            if !facts.backup_root_exists || !backup_ok || !facts.staging_root_exists || !swap_done {
                S::FailedManualIntervention
            } else {
                persisted
            }
        }

        S::Reverting if reverse_swap_done => S::Reverted,
        S::Reverting if swap_done => S::Reverting,
        S::Reverting => S::FailedManualIntervention,

        // FailedRecoverable is converted to its safe checkpoint by the
        // engine before this function is called. FailedManualIntervention
        // was handled by the terminal-state branch above.
        other => other,
    }
}

fn fact_shape_is_consistent(exists: bool, facts: Option<&SubvolumeFacts>) -> bool {
    exists == facts.is_some()
}

fn exact_identity_matches(
    expected: &BtrfsSubvolumeIdentity,
    observed: Option<&SubvolumeFacts>,
) -> bool {
    let Some(observed) = observed else {
        return false;
    };
    observed.path == expected.path
        && observed.subvolume_id == Some(expected.subvolume_id)
        && observed.generation == Some(expected.generation)
        && observed.uuid == expected.uuid
        && observed.parent_uuid == expected.parent_uuid
        && observed.read_only == Some(expected.read_only)
}

/// A backup is safe crash progress only when it is a readonly snapshot
/// of the exact root sealed in the plan. Path existence alone is never
/// sufficient because an unrelated subvolume can occupy the canonical
/// transaction path after a crash.
fn backup_matches_plan(
    plan: &crate::snapshot::model::RecoveryPlan,
    backup: Option<&SubvolumeFacts>,
) -> bool {
    let (Some(backup), Some(root_uuid)) = (backup, plan.current_root.uuid.as_deref()) else {
        return false;
    };
    backup.path == plan.backup_root_path
        && backup
            .subvolume_id
            .is_some_and(|id| id != plan.current_root.subvolume_id)
        && backup.uuid.as_deref().is_some_and(|uuid| uuid != root_uuid)
        && backup.parent_uuid.as_deref() == Some(root_uuid)
        && backup.read_only == Some(true)
}

/// A staging root is safe crash progress only when it is a writable
/// snapshot of the exact source snapshot sealed in the plan.
fn staging_matches_source(
    plan: &crate::snapshot::model::RecoveryPlan,
    staging: Option<&SubvolumeFacts>,
) -> bool {
    let (Some(staging), Some(source_uuid)) = (staging, plan.source_snapshot.uuid.as_deref()) else {
        return false;
    };
    staging.path == plan.staging_root_path
        && staging.subvolume_id.is_some_and(|id| {
            id != plan.source_snapshot.subvolume_id && id != plan.current_root.subvolume_id
        })
        && staging
            .uuid
            .as_deref()
            .is_some_and(|uuid| uuid != source_uuid)
        && staging.parent_uuid.as_deref() == Some(source_uuid)
        && staging.read_only == Some(false)
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
    plan: &crate::snapshot::model::RecoveryPlan,
    facts: &crate::snapshot::model::DiskFacts,
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
    plan: &crate::snapshot::model::RecoveryPlan,
    facts: &crate::snapshot::model::DiskFacts,
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
