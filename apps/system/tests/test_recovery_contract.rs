//! Phase-3 recovery integration tests.
//!
//! These tests exercise cross-module invariants of the recovery
//! engine without requiring a real btrfs image. They cover:
//!
//! * Plan id binding: a confirmation token cannot be replayed
//!   against a different plan.
//! * Stale-plan detection: identity drift between plan and apply is
//!   surfaced as a structured error.
//! * State-record corruption: a truncated or future-version state
//!   file is rejected, not re-interpreted.
//! * Path-escape rejection: subvolume paths that escape the btrfs
//!   top-level are refused.
//! * Current-root refusal: a planned recovery against the running
//!   root is detected and refused.
//! * Reconciliation: a persisted state that disagrees with disk
//!   facts is downgraded to the safest earlier state.
//!
//! The QEMU crash-resume test in scripts/recovery-qemu-smoke.sh
//! exercises the same invariants under real SIGKILL.

use catos_system::model::recovery::TransactionState as S;
use catos_system::model::recovery::{
    BootLayout, BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CatosIdentity, CompletedStep,
    DiskFacts, FstabRootDefinition, RecoveryErrorKind, RecoveryPlan, SubvolumeFacts,
    TransactionPaths, TransactionRecord, TransactionState, RECOVERY_PLAN_SCHEMA_VERSION,
    TX_RECORD_SCHEMA_VERSION,
};
use catos_system::recovery::identity::{
    drift_between, is_protected_recovery_path, safe_join, target_is_running_root,
    validate_plan_shape, verify_confirmation_token, RunningRoot, SubvolumePath,
};
use catos_system::recovery::plan::{build_confirmation_token, effective_plan_digest, PlanInputs};
use catos_system::recovery::state::{reconcile_with_disk_facts, AdvanceAction, Intent};
use catos_system::recovery::{confined, store};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn sample_plan() -> RecoveryPlan {
    let mut plan = RecoveryPlan {
        schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
        plan_id: "tx-00000000000000000000000000000001".into(),
        generated_at_unix: 1,
        generated_on_host: None,
        filesystem: BtrfsFilesystemIdentity {
            fsid: "fsid-A".into(),
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
        target_catos_identity: Some(CatosIdentity::default()),
        boot_layout: BootLayout::default(),
        boot_consistency: catos_system::recovery::boot::evaluate_readonly_consistency(
            &BootLayout::default(),
        ),
        backup_root_path:
            "/.catos-recovery/backups/tx-00000000000000000000000000000001/root-before".into(),
        staging_root_path: "/.catos-recovery/staging/tx-00000000000000000000000000000001/new-root"
            .into(),
        fstab_root_definition: FstabRootDefinition {
            source: "/dev/nvme0n1p2".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        },
        predicted_steps: vec![],
        refusal_conditions: vec![],
        risks_and_warnings: vec![],
        nonce: "00".repeat(32),
        plan_digest: String::new(),
        confirmation_token: String::new(),
        evidence: vec![],
    };
    plan.plan_digest = effective_plan_digest(&plan).unwrap();
    plan.confirmation_token =
        build_confirmation_token(&plan.plan_id, &plan.plan_digest, &plan.nonce);
    plan
}

fn sample_record() -> TransactionRecord {
    TransactionRecord {
        schema_version: TX_RECORD_SCHEMA_VERSION,
        transaction_id: "tx-00000000000000000000000000000001".into(),
        created_at_unix: 1,
        last_updated_unix: 1,
        plan: sample_plan(),
        state: TransactionState::Planned,
        completed_steps: vec![],
        last_error: None,
        last_disk_facts: None,
        last_cleanup: None,
    }
}

// ---------------------------------------------------------------------------
// Plan-id / confirmation-token binding
// ---------------------------------------------------------------------------

#[test]
fn confirmation_token_rejects_replay_against_other_plan() {
    let plan = sample_plan();
    // Same plan_id + same token: accepted.
    assert!(verify_confirmation_token(&plan, &plan.plan_id, &plan.confirmation_token).is_ok());
    // Different plan_id: rejected even with the same token.
    let other_plan_id = "tx-00000000000000000000000000000002";
    assert!(verify_confirmation_token(&plan, other_plan_id, &plan.confirmation_token).is_err());
    // Same plan_id but a token from a different plan: rejected.
    let other_token = build_confirmation_token(other_plan_id, &plan.plan_digest, &plan.nonce);
    assert!(verify_confirmation_token(&plan, &plan.plan_id, &other_token).is_err());
}

// ---------------------------------------------------------------------------
// Stale-plan detection via identity drift
// ---------------------------------------------------------------------------

#[test]
fn stale_plan_error_carries_structured_drift_detail() {
    let plan = sample_plan();
    let mut observed_fs = plan.filesystem.clone();
    observed_fs.fsid = "fsid-B".into();
    let drift = drift_between(
        &plan,
        &observed_fs,
        &plan.current_root,
        &plan.source_snapshot,
    );
    let error = drift.into_error().expect("drift should produce an error");
    assert_eq!(error.kind, RecoveryErrorKind::StalePlan);
    assert!(error.message.contains("fsid changed"));
    assert!(!error.resume_possible);
}

#[test]
fn stale_plan_detected_when_snapshot_readonly_was_cleared() {
    let plan = sample_plan();
    let mut snapshot = plan.source_snapshot.clone();
    snapshot.read_only = false;
    let drift = drift_between(&plan, &plan.filesystem, &plan.current_root, &snapshot);
    assert!(drift.source_snapshot_readonly_changed.is_some());
}

// ---------------------------------------------------------------------------
// Path-escape rejection
// ---------------------------------------------------------------------------

#[test]
fn subvolume_path_rejects_dotdot_attack() {
    assert!(SubvolumePath::parse("/@/../host").is_err());
    assert!(SubvolumePath::parse("/../@").is_err());
    assert!(SubvolumePath::parse("@").is_err());
}

#[test]
fn protected_recovery_path_cannot_be_used_as_target() {
    assert!(is_protected_recovery_path("/.catos-recovery"));
    assert!(is_protected_recovery_path(
        "/.catos-recovery/transactions/x/state.json"
    ));
    assert!(!is_protected_recovery_path("/@"));
    assert!(!is_protected_recovery_path("/@/.snapshots/1/snapshot"));
}

#[test]
fn safe_join_cannot_escape_its_prefix() {
    let prefix = Path::new("/tmp/catos-prefix");
    assert_eq!(
        safe_join(prefix, "a/b").unwrap(),
        PathBuf::from("/tmp/catos-prefix/a/b")
    );
    assert!(safe_join(prefix, "../escape").is_err());
    assert!(safe_join(prefix, "a/../../escape").is_err());
}

// ---------------------------------------------------------------------------
// State-record corruption / schema-version rejection
// ---------------------------------------------------------------------------

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "catos-recovery-it-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn record_path(root: &Path) -> PathBuf {
    root.join(".catos-recovery/transactions")
        .join("tx-00000000000000000000000000000001")
        .join("state.json")
}

#[test]
fn load_record_rejects_truncated_json() {
    let dir = scratch("truncated");
    std::fs::create_dir_all(&dir).unwrap();
    let path = record_path(&dir);
    confined::atomic_write(&path, b"{\"schema_version\":3,\"transaction_", 0o600).unwrap();
    let err = store::load_record(&path).unwrap_err();
    assert_eq!(err.kind, RecoveryErrorKind::StateRecordCorrupt);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_record_rejects_future_schema_version() {
    let dir = scratch("future-schema");
    std::fs::create_dir_all(&dir).unwrap();
    let path = record_path(&dir);
    let mut record = sample_record();
    record.schema_version = 99;
    let body = serde_json::to_vec(&record).unwrap();
    confined::atomic_write(&path, &body, 0o600).unwrap();
    let err = store::load_record(&path).unwrap_err();
    assert_eq!(err.kind, RecoveryErrorKind::UnsupportedTransactionSchema);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A v1 transaction record MUST surface as unsupported before typed
/// deserialisation, even though it contains a removed state variant.
#[test]
fn load_record_rejects_v1_schema_as_unsupported_not_corrupt() {
    let dir = scratch("v1-schema");
    std::fs::create_dir_all(&dir).unwrap();
    let path = record_path(&dir);
    confined::atomic_write(
        &path,
        b"{\"schema_version\":1,\"transaction_id\":\"x\",\"created_at_unix\":1,\
          \"last_updated_unix\":1,\"plan\":null,\"state\":\"boot_finalization_pending\",\
          \"completed_steps\":[]}",
        0o600,
    )
    .unwrap();
    let err = store::load_record(&path).unwrap_err();
    assert_eq!(err.kind, RecoveryErrorKind::UnsupportedTransactionSchema);
    assert!(err.message.contains("found 1"), "message: {}", err.message);
    assert!(
        err.message.contains("supported 3"),
        "message: {}",
        err.message
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A v2 transaction record MUST also surface as unsupported now that
/// DiskFacts has a structured v3 shape.
#[test]
fn load_record_rejects_v2_schema_as_unsupported_not_corrupt() {
    let dir = scratch("v2-schema");
    std::fs::create_dir_all(&dir).unwrap();
    let path = record_path(&dir);
    confined::atomic_write(
        &path,
        b"{\"schema_version\":2,\"transaction_id\":\"x\",\"created_at_unix\":1,\
          \"last_updated_unix\":1,\"plan\":null,\"state\":\"backup_created\",\
          \"completed_steps\":[],\"last_disk_facts\":{\"backup_root_exists\":true,\
          \"staging_root_exists\":false,\"active_root_exists\":true,\
          \"active_root_generation\":10,\"filesystem_fsid\":\"fsid-A\"}}",
        0o600,
    )
    .unwrap();
    let err = store::load_record(&path).unwrap_err();
    assert_eq!(err.kind, RecoveryErrorKind::UnsupportedTransactionSchema);
    assert!(err.message.contains("found 2"), "message: {}", err.message);
    assert!(
        err.message.contains("supported 3"),
        "message: {}",
        err.message
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_record_rejects_missing_file() {
    let dir = scratch("missing");
    std::fs::create_dir_all(&dir).unwrap();
    let err = store::load_record(&record_path(&dir)).unwrap_err();
    assert_eq!(err.kind, RecoveryErrorKind::TransactionNotFound);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_and_reload_round_trips_record() {
    let dir = scratch("round-trip");
    std::fs::create_dir_all(&dir).unwrap();
    let path = record_path(&dir);
    let record = sample_record();
    store::persist_record(&path, &record).unwrap();
    let loaded = store::load_record(&path).unwrap();
    assert_eq!(loaded, record);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_record_leaves_no_temp_file() {
    let dir = scratch("no-temp");
    std::fs::create_dir_all(&dir).unwrap();
    let path = record_path(&dir);
    store::persist_record(&path, &sample_record()).unwrap();
    let entries: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("state.json")]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Plan shape validation
// ---------------------------------------------------------------------------

#[test]
fn validate_plan_shape_rejects_non_readonly_snapshot() {
    let mut plan = sample_plan();
    plan.source_snapshot.read_only = false;
    let err = validate_plan_shape(&plan).unwrap_err();
    assert_eq!(err.kind, RecoveryErrorKind::SnapshotNotReadonly);
}

#[test]
fn validate_plan_shape_rejects_identical_paths() {
    let mut plan = sample_plan();
    plan.source_snapshot.path = plan.current_root.path.clone();
    let err = validate_plan_shape(&plan).unwrap_err();
    assert_eq!(err.kind, RecoveryErrorKind::TargetChanged);
}

#[test]
fn validate_plan_shape_rejects_unsupported_schema_version() {
    let mut plan = sample_plan();
    plan.schema_version = 99;
    let err = validate_plan_shape(&plan).unwrap_err();
    assert_eq!(err.kind, RecoveryErrorKind::UnsupportedPlanSchema);
}

// ---------------------------------------------------------------------------
// Current-root refusal
// ---------------------------------------------------------------------------

#[test]
fn recovery_target_equal_to_running_root_is_refused() {
    let plan = sample_plan();
    let running = RunningRoot {
        mount_point: PathBuf::from("/"),
        fstype: "btrfs".into(),
        source: "/dev/nvme0n1p2".into(),
        major_minor: Some("259:2".into()),
        subvol: None,
        subvolid: Some(256),
    };
    assert!(target_is_running_root(&plan, "259:2", 256, Some(&running)));
    // A different subvolid must NOT be flagged as the running root.
    assert!(!target_is_running_root(&plan, "259:2", 999, Some(&running)));
    // A different device must NOT be flagged.
    assert!(!target_is_running_root(
        &plan,
        "259:99",
        256,
        Some(&running)
    ));
}

#[test]
fn running_root_falls_back_to_subvol_path_when_subvolid_missing() {
    let plan = sample_plan();
    let running = RunningRoot {
        mount_point: PathBuf::from("/"),
        fstype: "btrfs".into(),
        source: "/dev/nvme0n1p2".into(),
        major_minor: Some("259:2".into()),
        subvol: Some("/@".into()),
        subvolid: None,
    };
    assert!(target_is_running_root(&plan, "259:2", 999, Some(&running)));
}

// ---------------------------------------------------------------------------
// State machine: hard rules
// ---------------------------------------------------------------------------

#[test]
fn state_machine_completed_only_from_verifying() {
    // The most load-bearing invariant: nothing skips the final
    // verification step.
    assert!(S::Verifying.transition(Intent::Complete).is_ok());
    assert!(S::NewRootInstalled.transition(Intent::Complete).is_err());
    assert!(S::Planned.transition(Intent::Complete).is_err());
}

#[test]
fn state_machine_terminal_states_are_terminal() {
    // Reverted and FailedManualIntervention reject every intent.
    // Completed is the exception: it accepts Intent::Revert (explicit
    // operator revert of a successful recovery). All three reject
    // Advance and Complete regardless.
    for s in [S::Completed, S::Reverted, S::FailedManualIntervention] {
        assert!(s.transition(Intent::Advance).is_err());
        assert!(s.transition(Intent::Complete).is_err());
    }
    // Reverted and FailedManualIntervention still reject Revert.
    for s in [S::Reverted, S::FailedManualIntervention] {
        assert!(s.transition(Intent::Revert).is_err());
    }
    // Completed + Revert is the only legal terminal transition.
    assert_eq!(
        S::Completed.transition(Intent::Revert).unwrap(),
        S::Reverting
    );
}

#[test]
fn state_machine_revert_always_reaches_reverting_from_non_terminal() {
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
fn state_machine_advance_action_matches_state() {
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

// ---------------------------------------------------------------------------
// Reconciliation: disk facts override persisted state
// ---------------------------------------------------------------------------

fn facts_with(backup: bool, staging: bool) -> DiskFacts {
    DiskFacts {
        filesystem_fsid: "fsid-A".into(),
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
                path: "/.catos-recovery/staging/p-001/new-root".into(),
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
                path: "/.catos-recovery/backups/p-001/root-before".into(),
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
fn reconcile_downgrades_backupcreated_when_backup_missing() {
    let facts = facts_with(false, false);
    assert_eq!(
        reconcile_with_disk_facts(S::BackupCreated, &sample_plan(), &facts),
        S::Locked
    );
}

#[test]
fn reconcile_downgrades_replacementcreated_when_staging_missing() {
    let facts = facts_with(true, false);
    assert_eq!(
        reconcile_with_disk_facts(S::ReplacementCreated, &sample_plan(), &facts),
        S::BackupCreated
    );
}

#[test]
fn reconcile_marks_manual_intervention_when_post_swap_artifacts_missing() {
    let facts = facts_with(true, false);
    assert_eq!(
        reconcile_with_disk_facts(S::OldRootMoved, &sample_plan(), &facts),
        S::FailedManualIntervention
    );
}

#[test]
fn reconcile_keeps_terminal_state_unchanged() {
    let facts = facts_with(true, true);
    assert_eq!(
        reconcile_with_disk_facts(S::Completed, &sample_plan(), &facts),
        S::Completed
    );
    assert_eq!(
        reconcile_with_disk_facts(S::Reverted, &sample_plan(), &facts),
        S::Reverted
    );
}

// ---------------------------------------------------------------------------
// Recovery layout stability
// ---------------------------------------------------------------------------

#[test]
fn recovery_paths_layout_is_namespaced_under_top_level() {
    let p = TransactionPaths {
        transaction_id: "tx-9".into(),
    };
    assert!(p
        .state_file_path()
        .starts_with("/.catos-recovery/transactions"));
    assert!(p
        .backup_subvolume_path()
        .starts_with("/.catos-recovery/backups"));
    assert!(p
        .staging_subvolume_path()
        .starts_with("/.catos-recovery/staging"));
}

// ---------------------------------------------------------------------------
// Plan builder integration
// ---------------------------------------------------------------------------

#[test]
fn plan_builder_emits_no_boot_finalization_step() {
    use catos_system::recovery::build_recovery_plan;
    let inputs = PlanInputs {
        filesystem: BtrfsFilesystemIdentity {
            fsid: "fsid-A".into(),
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
        boot_layout: BootLayout {
            boot_inside_root: false,
            boot_separate_filesystem: true,
            boot_separate_subvolume: false,
            esp_mount_point: None,
            esp_device: None,
            uki_paths: vec![],
            kernel_versions: vec![],
            has_initramfs: false,
        },
        catos_identity: None,
        fstab_root_definition: FstabRootDefinition {
            source: "/dev/nvme0n1p2".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        },
        plan_id: "tx-00000000000000000000000000000003".into(),
        generated_on_host: None,
        confirmation_token_entropy: vec![1u8; 32],
    };
    let plan = build_recovery_plan(inputs).unwrap();
    // Recovery MUST NOT plan to call any bootloader tool. The predicted
    // step list is part of the JSON contract; pinning it here locks out
    // re-introducing any bootloader-step regardless of the boot layout
    // (separate /boot, ESP, etc.).
    assert!(!plan
        .predicted_steps
        .iter()
        .any(|s| s.contains("finalize") || s.contains("bootloader")));
    assert!(plan.predicted_steps.contains(&"verify_final".to_string()));
}

// ---------------------------------------------------------------------------
// State machine: completed_steps log
// ---------------------------------------------------------------------------

#[test]
fn completed_steps_log_appends_in_order() {
    let mut record = sample_record();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for state in [
        S::Planned,
        S::PreflightVerified,
        S::Locked,
        S::BackupCreated,
        S::ReplacementCreated,
    ] {
        record.completed_steps.push(CompletedStep {
            state,
            completed_at_unix: now,
            description: format!("{:?}", state),
        });
    }
    assert_eq!(record.completed_steps.len(), 5);
    assert_eq!(record.completed_steps[0].state, S::Planned);
    assert_eq!(record.completed_steps[4].state, S::ReplacementCreated);
}
