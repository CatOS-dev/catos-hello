//! Stage-4 snapshot capability boundary tests.
//!
//! These tests pin the new public ownership: snapshot transaction state,
//! planning primitives, durable record storage, and execution live under
//! `snapshot`, while Recovery remains an application orchestrator.

use catos_system::snapshot::model::{
    BootLayout, BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, FstabRootDefinition,
    SnapshotErrorKind, TransactionState,
};
use catos_system::snapshot::plan::{build_plan, PlanInputs};
use catos_system::snapshot::transaction::{AdvanceAction, Intent};
use catos_system::snapshot::verify::validate_plan_shape;

const PLAN_ID: &str = "tx-00000000000000000000000000000009";

fn plan_inputs(source_read_only: bool) -> PlanInputs {
    PlanInputs {
        filesystem: BtrfsFilesystemIdentity {
            fsid: "fsid-stage4".into(),
            device_major_minor: "259:9".into(),
            label: Some("catos-root".into()),
        },
        current_root: BtrfsSubvolumeIdentity {
            path: "/@".into(),
            subvolume_id: 256,
            generation: 100,
            uuid: Some("current-root".into()),
            parent_uuid: None,
            read_only: false,
            evidence: vec![],
        },
        source_snapshot: BtrfsSubvolumeIdentity {
            path: "/@snapshots/9".into(),
            subvolume_id: 309,
            generation: 90,
            uuid: Some("source-snapshot".into()),
            parent_uuid: Some("older-root".into()),
            read_only: source_read_only,
            evidence: vec![],
        },
        boot_layout: BootLayout::default(),
        catos_identity: None,
        fstab_root_definition: FstabRootDefinition {
            source: "UUID=fsid-stage4".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        },
        plan_id: PLAN_ID.into(),
        generated_at_unix: 42,
        generated_on_host: Some("stage4-test".into()),
        confirmation_token_entropy: vec![9; 32],
    }
}

#[test]
fn transaction_state_machine_is_pure_and_explicit() {
    let state = TransactionState::Planned;
    assert_eq!(state.advance_action(), Some(AdvanceAction::Preflight));
    assert_eq!(
        state.transition(Intent::Advance).unwrap(),
        TransactionState::PreflightVerified
    );
}

#[test]
fn terminal_state_refuses_automatic_advance() {
    let error = TransactionState::Completed
        .transition(Intent::Advance)
        .expect_err("completed transaction must not advance automatically");
    assert_eq!(error.kind, SnapshotErrorKind::IllegalStateTransition);
}

#[test]
fn explicit_revert_is_the_only_exit_from_completed() {
    assert_eq!(
        TransactionState::Completed
            .transition(Intent::Revert)
            .unwrap(),
        TransactionState::Reverting
    );
}

#[test]
fn planning_is_deterministic_and_uses_caller_supplied_time() {
    let inputs = plan_inputs(true);
    let first = build_plan(inputs.clone()).expect("valid snapshot plan");
    let second = build_plan(inputs).expect("same inputs produce the same plan");

    assert_eq!(first, second);
    assert_eq!(first.generated_at_unix, 42);
    validate_plan_shape(&first).expect("planner must emit a sealed valid plan");
}

#[test]
fn writable_source_snapshot_is_refused_during_planning() {
    let error = build_plan(plan_inputs(false))
        .expect_err("a writable source cannot become a recovery snapshot plan");
    assert_eq!(error.kind, SnapshotErrorKind::SnapshotNotReadonly);
}

#[test]
fn tampered_confirmation_token_is_rejected_before_execution() {
    let mut plan = build_plan(plan_inputs(true)).expect("valid snapshot plan");
    plan.confirmation_token = "forged".into();

    let error = validate_plan_shape(&plan).expect_err("forged authorization must be rejected");
    assert_eq!(error.kind, SnapshotErrorKind::ConfirmationTokenMismatch);
}
