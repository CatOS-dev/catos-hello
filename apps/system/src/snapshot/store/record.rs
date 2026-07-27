//! Durable transaction-record store.
//!
//! Every persistent write the engine makes to its state goes through
//! this module. The protocol is strict:
//!
//! 1. Serialise the record as pretty JSON.
//! 2. Write to a temp file in the same directory (so rename is atomic
//!    on the same filesystem).
//! 3. `fsync` the temp file.
//! 4. `rename` temp -> final.
//! 5. `fsync` the parent directory.
//!
//! Steps 3 and 5 are the load-bearing ones. Without file fsync, the
//! kernel may keep the bytes in the page cache and lose them on power
//! loss. Without parent fsync, the rename may be lost even though the
//! file data is durable.
//!
//! On btrfs, step 5 is technically a no-op (btrfs journals directory
//! operations atomically with the data), but we issue it anyway so
//! the same code path is correct on ext4 / xfs if someone ever moves
//! the recovery dir.
//!
//! Schema versioning: every record carries `schema_version`. The
//! loader rejects unknown future versions and surfaces
//! [`SnapshotErrorKind::UnsupportedTransactionSchema`] so the operator
//! knows to upgrade their tooling.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::snapshot::diagnose::identity::validate_recovery_id;
use crate::snapshot::model::fs_to_snapshot;
use crate::snapshot::model::{
    SnapshotError, SnapshotErrorKind, TransactionRecord, RECOVERY_PLAN_SCHEMA_VERSION,
    TX_RECORD_SCHEMA_VERSION,
};
use crate::snapshot::verify::validate_plan_shape;
use crate::target::execute::confined;

/// Minimal view used to peek at a record's `schema_version` field
/// BEFORE attempting a typed deserialization. This keeps v1 records
/// (whose embedded state enum has lost a variant) from being
/// misreported as `StateRecordCorrupt`: they surface as
/// `UnsupportedTransactionSchema` instead.
#[derive(Deserialize)]
struct SchemaVersionProbe {
    schema_version: u32,
}

/// Load a transaction record from `path`. Performs schema validation
/// and surfaces a structured error for missing, corrupt, or
/// future-version files.
pub fn load_record(path: &Path) -> Result<TransactionRecord, SnapshotError> {
    let body = confined::read_file(path)?;
    // Peek at schema_version BEFORE typed deserialization. A v1 record
    // whose embedded `TransactionState` enum lost a variant would
    // otherwise fail serde parsing and surface as `StateRecordCorrupt`,
    // masking the real cause. Reject it explicitly here.
    let probe: SchemaVersionProbe = match serde_json::from_slice(&body) {
        Ok(probe) => probe,
        Err(error) => {
            return Err(SnapshotError::new(
                SnapshotErrorKind::StateRecordCorrupt,
                format!("cannot parse {}: {error}", path.display()),
            ));
        }
    };
    if probe.schema_version != TX_RECORD_SCHEMA_VERSION {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsupportedTransactionSchema,
            format!(
                "transaction record {} has unsupported schema_version: found {}, supported {}; \
                 recreate the transaction with the current tooling",
                path.display(),
                probe.schema_version,
                TX_RECORD_SCHEMA_VERSION
            ),
        ));
    }
    let record: TransactionRecord = match serde_json::from_slice(&body) {
        Ok(record) => record,
        Err(error) => {
            return Err(SnapshotError::new(
                SnapshotErrorKind::StateRecordCorrupt,
                format!("cannot parse {}: {error}", path.display()),
            ));
        }
    };
    validate_recovery_id(&record.transaction_id)?;
    validate_plan_shape(&record.plan)?;
    if record.transaction_id != record.plan.plan_id {
        return Err(SnapshotError::new(
            SnapshotErrorKind::StateRecordCorrupt,
            "transaction id does not match embedded plan id",
        ));
    }
    Ok(record)
}

/// Atomically persist a transaction record. See module docs for the
/// protocol. The parent directory is created with `0o700` if missing.
pub fn persist_record(path: &Path, record: &TransactionRecord) -> Result<(), SnapshotError> {
    if record.schema_version != TX_RECORD_SCHEMA_VERSION {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsupportedTransactionSchema,
            format!(
                "cannot persist transaction schema {}; supported {}",
                record.schema_version, TX_RECORD_SCHEMA_VERSION
            ),
        ));
    }
    validate_recovery_id(&record.transaction_id)?;
    validate_plan_shape(&record.plan)?;
    if record.transaction_id != record.plan.plan_id {
        return Err(SnapshotError::new(
            SnapshotErrorKind::StateRecordCorrupt,
            "transaction id does not match embedded plan id",
        ));
    }
    let expected_suffix = PathBuf::from(".catos-recovery")
        .join("transactions")
        .join(&record.transaction_id)
        .join("state.json");
    if !path.ends_with(&expected_suffix) {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsafeRecoveryPath,
            format!(
                "state path {} does not match canonical transaction path {}",
                path.display(),
                expected_suffix.display()
            ),
        ));
    }
    path.parent().ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::UnsafeRecoveryPath,
            format!("record path {} has no parent directory", path.display()),
        )
    })?;

    let json = serde_json::to_vec_pretty(record).map_err(|e| {
        SnapshotError::new(
            SnapshotErrorKind::StateRecordCorrupt,
            format!("cannot serialise record: {e}"),
        )
    })?;

    Ok(confined::atomic_write(path, &json, 0o600)?)
}

/// Load every transaction record under `transactions_dir`. Skips
/// unreadable entries with a warning rather than failing the whole
/// scan; an unreadable record may be a partial write from a concurrent
/// apply and is best left alone.
pub fn list_records(
    transactions_dir: &Path,
) -> (Vec<(PathBuf, TransactionRecord)>, Vec<SnapshotError>) {
    let mut ok = Vec::new();
    let mut errs = Vec::new();
    let entries = match confined::list_directory_names(transactions_dir) {
        Ok(entries) => entries,
        Err(error) => {
            errs.push(fs_to_snapshot(error));
            return (ok, errs);
        }
    };
    for name in entries {
        let Some(id) = name.to_str() else {
            errs.push(SnapshotError::new(
                SnapshotErrorKind::InvalidRecoveryId,
                "transaction directory name is not valid UTF-8",
            ));
            continue;
        };
        if let Err(error) = validate_recovery_id(id) {
            errs.push(error);
            continue;
        }
        let entry_path = transactions_dir.join(&name);
        let state_file = entry_path.join("state.json");
        match load_record(&state_file) {
            Ok(record) => ok.push((entry_path, record)),
            Err(error) => {
                if error.kind != SnapshotErrorKind::TransactionNotFound {
                    errs.push(error);
                }
            }
        }
    }
    (ok, errs)
}

/// Remove a transaction record. Used by revert when the revert leaves
/// no persistent writes behind. Does NOT remove backup or staging
/// subvolumes — those are owned by btrfs-progs and managed by the
/// engine.
pub fn remove_record(path: &Path) -> Result<(), SnapshotError> {
    Ok(confined::remove_file(path)?)
}

/// Persist a [`RecoveryPlan`] as a standalone file (used by `recovery
/// plan` before any transaction exists).
pub fn persist_plan(
    path: &Path,
    plan: &crate::snapshot::model::RecoveryPlan,
) -> Result<(), SnapshotError> {
    validate_plan_shape(plan)?;
    let expected_suffix = PathBuf::from(".catos-recovery")
        .join("transactions")
        .join(&plan.plan_id)
        .join("plan.json");
    if !path.ends_with(&expected_suffix) {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsafeRecoveryPath,
            "plan path does not match canonical transaction layout",
        ));
    }

    let json = serde_json::to_vec_pretty(plan).map_err(|e| {
        SnapshotError::new(
            SnapshotErrorKind::StateRecordCorrupt,
            format!("cannot serialise plan: {e}"),
        )
    })?;

    Ok(confined::atomic_write(path, &json, 0o600)?)
}

pub fn load_plan(path: &Path) -> Result<crate::snapshot::model::RecoveryPlan, SnapshotError> {
    let body = if confined::is_confined_recovery_path(path) {
        confined::read_file(path)?
    } else {
        confined::read_external_file(path)?
    };
    // Operators produce a plan file by running `recovery plan --json`
    // and redirecting stdout to a file. That output is the standard
    // envelope `{ invocation, kind, payload, ... }`; the actual plan
    // lives under `payload`. Accept both the bare `RecoveryPlan` and
    // the wrapped envelope so a freshly-redirected file just works.
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            return Err(SnapshotError::new(
                SnapshotErrorKind::StateRecordCorrupt,
                format!("cannot parse plan {}: {error}", path.display()),
            ));
        }
    };
    let plan_value = match value.get("payload") {
        Some(payload) => payload,
        None => &value,
    };
    // Peek at schema_version BEFORE typed deserialization. Older plans
    // omit execution-critical fields introduced by later schemas, and
    // serde defaults/unknown-field handling must not silently upgrade
    // them into an apparently valid current plan.
    let probe: SchemaVersionProbe = match serde_json::from_value(plan_value.clone()) {
        Ok(probe) => probe,
        Err(error) => {
            return Err(SnapshotError::new(
                SnapshotErrorKind::StateRecordCorrupt,
                format!(
                    "cannot read plan {} schema_version: {error}",
                    path.display()
                ),
            ));
        }
    };
    if probe.schema_version != RECOVERY_PLAN_SCHEMA_VERSION {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsupportedPlanSchema,
            format!(
                "plan {} has unsupported schema_version: found {}, supported {}; \
                 regenerate the plan with the current tooling",
                path.display(),
                probe.schema_version,
                RECOVERY_PLAN_SCHEMA_VERSION
            ),
        ));
    }
    let plan: crate::snapshot::model::RecoveryPlan =
        match serde_json::from_value(plan_value.clone()) {
            Ok(plan) => plan,
            Err(error) => {
                return Err(SnapshotError::new(
                    SnapshotErrorKind::StateRecordCorrupt,
                    format!("cannot parse plan {}: {error}", path.display()),
                ));
            }
        };
    validate_plan_shape(&plan)?;
    Ok(plan)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::error::FsError;
    use crate::snapshot::model::{
        BootLayout, BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CompletedStep, DiskFacts,
        FstabRootDefinition, RecoveryPlan, TransactionPaths, TransactionState,
    };
    use crate::snapshot::plan::{build_confirmation_token, effective_plan_digest};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ID1: &str = "tx-00000000000000000000000000000001";
    const ID2: &str = "tx-00000000000000000000000000000002";
    const ID3: &str = "tx-00000000000000000000000000000003";
    const ID4: &str = "tx-00000000000000000000000000000004";

    fn scratch_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "catos-store-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn sample_plan_for(id: &str) -> RecoveryPlan {
        let mut plan = RecoveryPlan {
            schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
            plan_id: id.into(),
            generated_at_unix: 100,
            generated_on_host: None,
            filesystem: BtrfsFilesystemIdentity {
                fsid: "fsid".into(),
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
                parent_uuid: Some("old-root-uuid".into()),
                read_only: true,
                evidence: vec![],
            },
            target_catos_identity: None,
            boot_layout: BootLayout::default(),
            boot_consistency: crate::snapshot::diagnose::boot::evaluate_readonly_consistency(
                &BootLayout::default(),
            ),
            backup_root_path: format!("/.catos-recovery/backups/{id}/root-before"),
            staging_root_path: format!("/.catos-recovery/staging/{id}/new-root"),
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

    fn record_for(id: &str) -> TransactionRecord {
        TransactionRecord {
            schema_version: TX_RECORD_SCHEMA_VERSION,
            transaction_id: id.into(),
            created_at_unix: 100,
            last_updated_unix: 100,
            plan: sample_plan_for(id),
            state: TransactionState::Planned,
            completed_steps: vec![CompletedStep {
                state: TransactionState::Planned,
                completed_at_unix: 100,
                description: "test".into(),
            }],
            last_error: None,
            last_disk_facts: Some(DiskFacts {
                filesystem_fsid: "fsid".into(),
                active_root_exists: true,
                active_root: None,
                staging_root_exists: false,
                staging_root: None,
                backup_root_exists: false,
                backup: None,
                source_snapshot_exists: false,
                source_snapshot: None,
            }),
            last_cleanup: None,
        }
    }

    fn state_path(root: &Path, id: &str) -> PathBuf {
        root.join(".catos-recovery/transactions")
            .join(id)
            .join("state.json")
    }

    fn plan_path(root: &Path, id: &str) -> PathBuf {
        root.join(".catos-recovery/transactions")
            .join(id)
            .join("plan.json")
    }

    #[test]
    fn persist_and_load_round_trips() {
        let root = scratch_root("roundtrip");
        fs::create_dir_all(&root).unwrap();
        let path = state_path(&root, ID1);
        let record = record_for(ID1);
        persist_record(&path, &record).unwrap();
        assert_eq!(load_record(&path).unwrap(), record);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_record_returns_not_found_for_missing_file() {
        let root = scratch_root("missing");
        fs::create_dir_all(&root).unwrap();
        let error = load_record(&state_path(&root, ID1)).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::TransactionNotFound);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_record_rejects_unsupported_schema_version() {
        let root = scratch_root("schema");
        fs::create_dir_all(&root).unwrap();
        let path = state_path(&root, ID1);
        let mut record = record_for(ID1);
        record.schema_version = 99;
        confined::atomic_write(&path, &serde_json::to_vec(&record).unwrap(), 0o600).unwrap();
        let error = load_record(&path).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::UnsupportedTransactionSchema);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_record_rejects_truncated_json() {
        let root = scratch_root("truncated");
        fs::create_dir_all(&root).unwrap();
        let path = state_path(&root, ID1);
        confined::atomic_write(&path, b"{\"schema_version\":3", 0o600).unwrap();
        let error = load_record(&path).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::StateRecordCorrupt);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn persist_record_is_atomic_and_creates_parents() {
        let root = scratch_root("atomic");
        fs::create_dir_all(&root).unwrap();
        let path = state_path(&root, ID1);
        persist_record(&path, &record_for(ID1)).unwrap();
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("state.json")]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn remove_record_is_idempotent() {
        let root = scratch_root("remove");
        fs::create_dir_all(&root).unwrap();
        let path = state_path(&root, ID1);
        persist_record(&path, &record_for(ID1)).unwrap();
        remove_record(&path).unwrap();
        remove_record(&path).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn list_records_returns_empty_for_missing_directory() {
        let root = scratch_root("list-missing");
        fs::create_dir_all(&root).unwrap();
        let dir = root.join(".catos-recovery/transactions");
        let (records, errors) = list_records(&dir);
        assert!(records.is_empty());
        assert!(errors.is_empty(), "{errors:?}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn list_records_handles_multiple_and_corrupt_transactions() {
        let root = scratch_root("list");
        fs::create_dir_all(&root).unwrap();
        for id in [ID1, ID2, ID3] {
            persist_record(&state_path(&root, id), &record_for(id)).unwrap();
        }
        confined::atomic_write(&state_path(&root, ID4), b"not json", 0o600).unwrap();
        let dir = root.join(".catos-recovery/transactions");
        let (records, errors) = list_records(&dir);
        assert_eq!(records.len(), 3);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind, SnapshotErrorKind::StateRecordCorrupt);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn transaction_paths_layout_is_stable() {
        let paths = TransactionPaths {
            transaction_id: ID1.into(),
        };
        assert_eq!(
            paths.state_file_path(),
            PathBuf::from(format!("/.catos-recovery/transactions/{ID1}/state.json"))
        );
    }

    #[test]
    fn confined_path_rejects_parent_escape() {
        let root = scratch_root("escape");
        let hostile = root.join(".catos-recovery/transactions/../outside/state.json");
        let error = confined::ConfinedPath::parse(&hostile).unwrap_err();
        assert!(
            matches!(error, FsError::OutsideRoot(_)),
            "parent-escape must surface as FsError::OutsideRoot, got {error:?}"
        );
    }

    #[test]
    fn persist_and_load_bare_recovery_plan() {
        let root = scratch_root("plan-bare");
        fs::create_dir_all(&root).unwrap();
        let plan = sample_plan_for(ID1);
        let path = plan_path(&root, ID1);
        persist_plan(&path, &plan).unwrap();
        assert_eq!(load_plan(&path).unwrap(), plan);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plan_accepts_external_wrapped_envelope() {
        let dir = scratch_root("plan-envelope");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.json");
        let plan = sample_plan_for(ID1);
        let envelope = serde_json::json!({
            "invocation": "catos-system",
            "kind": "recovery_plan",
            "payload": serde_json::to_value(&plan).unwrap(),
            "programVersion": "0.1.0",
            "schemaVersion": 2,
            "targetRoot": "/",
        });
        fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        assert_eq!(load_plan(&path).unwrap(), plan);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_plan_rejects_tampered_effective_field_with_old_token() {
        let dir = scratch_root("plan-tamper");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.json");
        let mut plan = sample_plan_for(ID1);
        plan.filesystem.fsid = "tampered-fsid".into();
        fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        let error = load_plan(&path).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::PlanDigestMismatch);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_plan_rejects_neither_bare_nor_envelope() {
        let dir = scratch_root("plan-junk");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.json");
        fs::write(&path, b"{\"unrelated\":\"json\"}").unwrap();
        assert_eq!(
            load_plan(&path).unwrap_err().kind,
            SnapshotErrorKind::StateRecordCorrupt
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn persist_record_rejects_recovery_root_symlink() {
        use std::os::unix::fs::symlink;
        let top = scratch_root("root-symlink");
        let outside = scratch_root("root-symlink-outside");
        fs::create_dir_all(&top).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, top.join(".catos-recovery")).unwrap();
        let error = persist_record(&state_path(&top, ID1), &record_for(ID1)).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::UnsafeRecoveryPath);
        assert!(!outside.join("transactions").exists());
        let _ = fs::remove_dir_all(top);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn persist_record_rejects_transaction_directory_symlink() {
        use std::os::unix::fs::symlink;
        let top = scratch_root("transaction-symlink");
        let outside = scratch_root("transaction-symlink-outside");
        fs::create_dir_all(top.join(".catos-recovery/transactions")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, top.join(".catos-recovery/transactions").join(ID1)).unwrap();
        let error = persist_record(&state_path(&top, ID1), &record_for(ID1)).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::UnsafeRecoveryPath);
        assert!(!outside.join("state.json").exists());
        let _ = fs::remove_dir_all(top);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn persist_record_rejects_state_file_symlink() {
        use std::os::unix::fs::symlink;
        let top = scratch_root("state-symlink");
        let outside = scratch_root("state-symlink-outside");
        let path = state_path(&top, ID1);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, b"unchanged").unwrap();
        symlink(&sentinel, &path).unwrap();
        let error = persist_record(&path, &record_for(ID1)).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::UnsafeRecoveryPath);
        assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
        let _ = fs::remove_dir_all(top);
        let _ = fs::remove_dir_all(outside);
    }
}
