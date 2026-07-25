use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use catos_system::model::recovery::{
    BootLayout, BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CompletedStep, DiskFacts,
    FstabRootDefinition, RecoveryError, RecoveryErrorKind, RecoveryPlan, SubvolumeFacts,
    TransactionRecord, TransactionState, RECOVERY_PLAN_SCHEMA_VERSION, TX_RECORD_SCHEMA_VERSION,
};
use catos_system::phase3::{exit_code_for, Phase3Outcome};
use catos_system::recovery::engine::{Engine, EngineOptions};
use catos_system::recovery::lock::{lock_file_path, TransactionLock};
use catos_system::recovery::state::{reconcile_with_disk_facts, resume_checkpoint};

const ID: &str = "tx-00000000000000000000000000000001";
const FSID: &str = "11111111-2222-3333-4444-555555555555";

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "catos-recovery-regression-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn plan() -> RecoveryPlan {
    let boot_layout = BootLayout {
        boot_inside_root: true,
        boot_separate_filesystem: false,
        boot_separate_subvolume: false,
        esp_mount_point: None,
        esp_device: None,
        uki_paths: vec![],
        kernel_versions: vec![],
        has_initramfs: false,
    };
    RecoveryPlan {
        schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
        plan_id: ID.into(),
        generated_at_unix: 1,
        generated_on_host: None,
        filesystem: BtrfsFilesystemIdentity {
            fsid: FSID.into(),
            device_major_minor: "7:1".into(),
            label: None,
        },
        current_root: BtrfsSubvolumeIdentity {
            path: "/@".into(),
            subvolume_id: 256,
            generation: 10,
            uuid: Some("old-root-uuid".into()),
            parent_uuid: None,
            read_only: false,
            evidence: vec![],
        },
        source_snapshot: BtrfsSubvolumeIdentity {
            path: "/@snapshots/2".into(),
            subvolume_id: 300,
            generation: 8,
            uuid: Some("source-snapshot-uuid".into()),
            parent_uuid: Some("older-root-uuid".into()),
            read_only: true,
            evidence: vec![],
        },
        target_catos_identity: None,
        boot_consistency: catos_system::recovery::boot::evaluate_readonly_consistency(&boot_layout),
        boot_layout,
        backup_root_path: format!("/.catos-recovery/backups/{ID}/root-before"),
        staging_root_path: format!("/.catos-recovery/staging/{ID}/new-root"),
        fstab_root_definition: FstabRootDefinition {
            source: "/dev/vda1".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        },
        predicted_steps: vec![],
        refusal_conditions: vec![],
        risks_and_warnings: vec![],
        nonce: "00".repeat(32),
        plan_digest: "00".repeat(32),
        confirmation_token: "unused".into(),
        evidence: vec![],
    }
}

fn old_root() -> SubvolumeFacts {
    SubvolumeFacts {
        path: "/@".into(),
        subvolume_id: Some(256),
        generation: Some(10),
        uuid: Some("old-root-uuid".into()),
        parent_uuid: None,
        read_only: Some(false),
    }
}

fn source_snapshot() -> SubvolumeFacts {
    SubvolumeFacts {
        path: "/@snapshots/2".into(),
        subvolume_id: Some(300),
        generation: Some(8),
        uuid: Some("source-snapshot-uuid".into()),
        parent_uuid: Some("older-root-uuid".into()),
        read_only: Some(true),
    }
}

fn valid_backup(plan: &RecoveryPlan) -> SubvolumeFacts {
    SubvolumeFacts {
        path: plan.backup_root_path.clone(),
        subvolume_id: Some(400),
        generation: Some(11),
        uuid: Some("backup-uuid".into()),
        parent_uuid: Some("old-root-uuid".into()),
        read_only: Some(true),
    }
}

fn record(state: TransactionState) -> TransactionRecord {
    TransactionRecord {
        schema_version: TX_RECORD_SCHEMA_VERSION,
        transaction_id: ID.into(),
        created_at_unix: 1,
        last_updated_unix: 1,
        plan: plan(),
        state,
        completed_steps: vec![CompletedStep {
            state: TransactionState::BackupCreated,
            completed_at_unix: 1,
            description: "backup completed".into(),
        }],
        last_error: Some(
            RecoveryError::new(
                RecoveryErrorKind::BtrfsToolFailed,
                "replacement snapshot failed",
            )
            .with_state(TransactionState::BackupCreated),
        ),
        last_disk_facts: None,
        last_cleanup: None,
    }
}

#[test]
fn failed_recoverable_resumes_from_the_last_safe_checkpoint() {
    let record = record(TransactionState::FailedRecoverable);
    assert_eq!(
        resume_checkpoint(&record),
        Some(TransactionState::BackupCreated)
    );
}

#[test]
fn resume_cannot_exit_success_with_a_failure_state() {
    let record = record(TransactionState::FailedRecoverable);
    let outcome = Phase3Outcome::Resume {
        record,
        final_state: TransactionState::FailedRecoverable,
        cleanup: catos_system::model::recovery::CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        },
    };
    assert_ne!(exit_code_for(&outcome), catos_system::exit_code::SUCCESS);
}

#[test]
fn foreign_backup_is_not_accepted_as_crash_progress() {
    let plan = plan();
    let mut foreign = valid_backup(&plan);
    foreign.parent_uuid = Some("foreign-parent".into());
    foreign.read_only = Some(false);
    let facts = DiskFacts {
        filesystem_fsid: FSID.into(),
        active_root_exists: true,
        active_root: Some(old_root()),
        staging_root_exists: false,
        staging_root: None,
        backup_root_exists: true,
        backup: Some(foreign),
        source_snapshot_exists: true,
        source_snapshot: Some(source_snapshot()),
    };

    assert_eq!(
        reconcile_with_disk_facts(TransactionState::Locked, &plan, &facts),
        TransactionState::FailedManualIntervention
    );
}

#[test]
fn foreign_staging_is_not_accepted_as_replacement() {
    let plan = plan();
    let facts = DiskFacts {
        filesystem_fsid: FSID.into(),
        active_root_exists: true,
        active_root: Some(old_root()),
        staging_root_exists: true,
        staging_root: Some(SubvolumeFacts {
            path: plan.staging_root_path.clone(),
            subvolume_id: Some(999),
            generation: Some(1),
            uuid: Some("foreign-staging".into()),
            parent_uuid: Some("foreign-parent".into()),
            read_only: Some(false),
        }),
        backup_root_exists: true,
        backup: Some(valid_backup(&plan)),
        source_snapshot_exists: true,
        source_snapshot: Some(source_snapshot()),
    };

    assert_eq!(
        reconcile_with_disk_facts(TransactionState::BackupCreated, &plan, &facts),
        TransactionState::FailedManualIntervention
    );
}

#[test]
fn replaced_source_snapshot_blocks_resume() {
    let plan = plan();
    let mut changed_source = source_snapshot();
    changed_source.subvolume_id = Some(777);
    changed_source.uuid = Some("replacement-source".into());
    let facts = DiskFacts {
        filesystem_fsid: FSID.into(),
        active_root_exists: true,
        active_root: Some(old_root()),
        staging_root_exists: false,
        staging_root: None,
        backup_root_exists: true,
        backup: Some(valid_backup(&plan)),
        source_snapshot_exists: true,
        source_snapshot: Some(changed_source),
    };

    assert_eq!(
        reconcile_with_disk_facts(TransactionState::BackupCreated, &plan, &facts),
        TransactionState::FailedManualIntervention
    );
}

#[test]
fn write_lock_is_checked_before_transaction_record_is_read() {
    let root = scratch("lock-before-read");
    let _guard = TransactionLock::try_acquire(&lock_file_path(&root, FSID), FSID).unwrap();
    let error = match Engine::load_for_write(
        EngineOptions {
            top_level_mount: root,
            device_path: PathBuf::from("/dev/fake"),
            validated_filesystem: BtrfsFilesystemIdentity {
                fsid: FSID.into(),
                device_major_minor: "7:1".into(),
                label: None,
            },
        },
        ID,
    ) {
        Ok(_) => panic!("writer loaded transaction state while the FSID lock was held"),
        Err(error) => error,
    };
    assert_eq!(error.kind, RecoveryErrorKind::TransactionAlreadyActive);
}
