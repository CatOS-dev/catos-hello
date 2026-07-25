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
//! [`RecoveryErrorKind::UnsupportedTransactionSchema`] so the operator
//! knows to upgrade their tooling.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::recovery::{
    RecoveryError, RecoveryErrorKind, TransactionRecord, RECOVERY_PLAN_SCHEMA_VERSION,
    TX_RECORD_SCHEMA_VERSION,
};

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
pub fn load_record(path: &Path) -> Result<TransactionRecord, RecoveryError> {
    let body = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::TransactionNotFound,
                format!("transaction record {} does not exist", path.display()),
            ));
        }
        Err(error) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!("cannot read {}: {error}", path.display()),
            ));
        }
    };
    // Peek at schema_version BEFORE typed deserialization. A v1 record
    // whose embedded `TransactionState` enum lost a variant would
    // otherwise fail serde parsing and surface as `StateRecordCorrupt`,
    // masking the real cause. Reject it explicitly here.
    let probe: SchemaVersionProbe = match serde_json::from_slice(&body) {
        Ok(probe) => probe,
        Err(error) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!("cannot parse {}: {error}", path.display()),
            ));
        }
    };
    if probe.schema_version != TX_RECORD_SCHEMA_VERSION {
        return Err(RecoveryError::new(
            RecoveryErrorKind::UnsupportedTransactionSchema,
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
            return Err(RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!("cannot parse {}: {error}", path.display()),
            ));
        }
    };
    Ok(record)
}

/// Atomically persist a transaction record. See module docs for the
/// protocol. The parent directory is created with `0o700` if missing.
pub fn persist_record(path: &Path, record: &TransactionRecord) -> Result<(), RecoveryError> {
    let parent = path.parent().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("record path {} has no parent directory", path.display()),
        )
    })?;

    // Create the parent dir hierarchy with strict mode. Idempotent.
    ensure_dir_with_mode(parent, 0o700)?;

    let json = serde_json::to_vec_pretty(record).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot serialise record: {e}"),
        )
    })?;

    // Write to a temp file in the same directory so rename is atomic.
    let temp_path = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|e| {
            RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!("cannot open temp file {}: {e}", temp_path.display()),
            )
        })?;
    // Tighten permissions: temp file is owned by the creating EUID
    // already, but be explicit.
    fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot chmod temp file {}: {e}", temp_path.display()),
        )
    })?;

    file.write_all(&json).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot write temp file {}: {e}", temp_path.display()),
        )
    })?;
    file.flush().map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot flush temp file {}: {e}", temp_path.display()),
        )
    })?;

    fsync_file(&file, &temp_path)?;

    // Drop the file handle BEFORE the rename so we do not race with
    // the kernel's deferred fsync. On btrfs / ext4 this is harmless;
    // on xfs this avoids a known interaction where a renaming file
    // handle could bypass the fsync.
    drop(file);

    fs::rename(&temp_path, path).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!(
                "cannot rename {} to {}: {e}",
                temp_path.display(),
                path.display()
            ),
        )
    })?;

    fsync_parent(parent)?;

    Ok(())
}

/// Load every transaction record under `transactions_dir`. Skips
/// unreadable entries with a warning rather than failing the whole
/// scan; an unreadable record may be a partial write from a concurrent
/// apply and is best left alone.
pub fn list_records(
    transactions_dir: &Path,
) -> (Vec<(PathBuf, TransactionRecord)>, Vec<RecoveryError>) {
    let mut ok = Vec::new();
    let mut errs = Vec::new();
    let entries = match fs::read_dir(transactions_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (ok, errs),
        Err(error) => {
            errs.push(RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!(
                    "cannot read transactions directory {}: {error}",
                    transactions_dir.display()
                ),
            ));
            return (ok, errs);
        }
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let state_file = entry_path.join("state.json");
        if !state_file.is_file() {
            continue;
        }
        match load_record(&state_file) {
            Ok(record) => ok.push((entry_path, record)),
            Err(error) => {
                if error.kind != RecoveryErrorKind::TransactionNotFound {
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
pub fn remove_record(path: &Path) -> Result<(), RecoveryError> {
    match fs::remove_file(path) {
        Ok(()) => {
            // Best-effort parent fsync; ignore failures because the
            // record is already gone and the operator can sync
            // manually if they care.
            if let Some(parent) = path.parent() {
                let _ = fsync_parent(parent);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot remove {}: {error}", path.display()),
        )),
    }
}

/// Persist a [`RecoveryPlan`] as a standalone file (used by `recovery
/// plan` before any transaction exists).
pub fn persist_plan(
    path: &Path,
    plan: &crate::model::recovery::RecoveryPlan,
) -> Result<(), RecoveryError> {
    let parent = path.parent().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("plan path {} has no parent", path.display()),
        )
    })?;
    ensure_dir_with_mode(parent, 0o700)?;

    let json = serde_json::to_vec_pretty(plan).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot serialise plan: {e}"),
        )
    })?;

    let temp_path = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|e| {
            RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!("cannot open plan temp {}: {e}", temp_path.display()),
            )
        })?;
    fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot chmod plan temp {}: {e}", temp_path.display()),
        )
    })?;
    file.write_all(&json).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot write plan temp {}: {e}", temp_path.display()),
        )
    })?;
    fsync_file(&file, &temp_path)?;
    drop(file);
    fs::rename(&temp_path, path).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!(
                "cannot rename {} to {}: {e}",
                temp_path.display(),
                path.display()
            ),
        )
    })?;
    fsync_parent(parent)?;
    Ok(())
}

pub fn load_plan(path: &Path) -> Result<crate::model::recovery::RecoveryPlan, RecoveryError> {
    let body = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::TransactionNotFound,
                format!("plan file {} does not exist", path.display()),
            ));
        }
        Err(error) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!("cannot read plan {}: {error}", path.display()),
            ));
        }
    };
    // Operators produce a plan file by running `recovery plan --json`
    // and redirecting stdout to a file. That output is the standard
    // envelope `{ invocation, kind, payload, ... }`; the actual plan
    // lives under `payload`. Accept both the bare `RecoveryPlan` and
    // the wrapped envelope so a freshly-redirected file just works.
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!("cannot parse plan {}: {error}", path.display()),
            ));
        }
    };
    let plan_value = match value.get("payload") {
        Some(payload) => payload,
        None => &value,
    };
    // Peek at schema_version BEFORE typed deserialization. A v1 plan
    // whose `BootLayout` lost `bootloadu_detected` would otherwise be
    // silently accepted (serde ignores unknown fields) and surface no
    // diagnostic. Reject it explicitly here.
    let probe: SchemaVersionProbe = match serde_json::from_value(plan_value.clone()) {
        Ok(probe) => probe,
        Err(error) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::StateRecordCorrupt,
                format!(
                    "cannot read plan {} schema_version: {error}",
                    path.display()
                ),
            ));
        }
    };
    if probe.schema_version != RECOVERY_PLAN_SCHEMA_VERSION {
        return Err(RecoveryError::new(
            RecoveryErrorKind::UnsupportedPlanSchema,
            format!(
                "plan {} has unsupported schema_version: found {}, supported {}; \
                 regenerate the plan with the current tooling",
                path.display(),
                probe.schema_version,
                RECOVERY_PLAN_SCHEMA_VERSION
            ),
        ));
    }
    let plan: crate::model::recovery::RecoveryPlan =
        match serde_json::from_value(plan_value.clone()) {
            Ok(plan) => plan,
            Err(error) => {
                return Err(RecoveryError::new(
                    RecoveryErrorKind::StateRecordCorrupt,
                    format!("cannot parse plan {}: {error}", path.display()),
                ));
            }
        };
    Ok(plan)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn ensure_dir_with_mode(path: &Path, mode: u32) -> Result<(), RecoveryError> {
    use std::os::unix::fs::PermissionsExt;

    if path.as_os_str().is_empty() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            "directory path is empty",
        ));
    }

    // Walk the path and create missing components. Each component is
    // tightened to `mode` only when we just created it. Pre-existing
    // components are left alone: they may legitimately be owned by
    // root with a different mode (e.g. /.catos-recovery itself).
    let mut current = PathBuf::new();
    let created_something = {
        let mut created = false;
        for component in path.components() {
            use std::path::Component;
            match component {
                Component::RootDir => {
                    current = PathBuf::from("/");
                }
                Component::Normal(part) => {
                    current.push(part);
                    if !current.exists() {
                        fs::create_dir(&current).map_err(|e| {
                            RecoveryError::new(
                                RecoveryErrorKind::StateRecordCorrupt,
                                format!("cannot create {}: {e}", current.display()),
                            )
                        })?;
                        fs::set_permissions(&current, std::fs::Permissions::from_mode(mode))
                            .map_err(|e| {
                                RecoveryError::new(
                                    RecoveryErrorKind::StateRecordCorrupt,
                                    format!("cannot chmod {}: {e}", current.display()),
                                )
                            })?;
                        created = true;
                    }
                }
                Component::CurDir => {}
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(RecoveryError::new(
                        RecoveryErrorKind::StateRecordCorrupt,
                        format!(
                            "refusing to create a path with escaping component: {}",
                            path.display()
                        ),
                    ));
                }
            }
        }
        created
    };
    if created_something {
        // Best-effort: fsync the deepest created directory so a crash
        // immediately after persist does not lose the parent. Failures
        // are tolerated; the next persist will recreate if needed.
        let _ = fsync_dir(path);
    }
    Ok(())
}

fn fsync_file(file: &File, label: &Path) -> Result<(), RecoveryError> {
    // SAFETY: fsync(2) takes a file descriptor and has no memory
    // safety implications. The raw fd is valid because `file` owns it.
    let rc = libc_fsync(file.as_raw_fd());
    if rc != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        return Err(RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("fsync({}) failed; errno={errno}", label.display()),
        ));
    }
    Ok(())
}

fn fsync_dir(path: &Path) -> Result<(), RecoveryError> {
    let file = File::open(path).map_err(|e| {
        RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!("cannot open {} for fsync: {e}", path.display()),
        )
    })?;
    fsync_file(&file, path)
}

fn fsync_parent(parent: &Path) -> Result<(), RecoveryError> {
    fsync_dir(parent)
}

extern "C" {
    fn fsync(fd: std::os::raw::c_int) -> std::os::raw::c_int;
}

/// Wrapper so call sites are explicit about the FFI.
fn libc_fsync(fd: std::os::raw::c_int) -> std::os::raw::c_int {
    // SAFETY: see comment in fsync_file.
    unsafe { fsync(fd) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::recovery::{
        BootLayout, BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CompletedStep, DiskFacts,
        FstabRootDefinition, RecoveryPlan, TransactionPaths, TransactionState,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_plan() -> RecoveryPlan {
        RecoveryPlan {
            schema_version: crate::model::recovery::RECOVERY_PLAN_SCHEMA_VERSION,
            plan_id: "p-1".into(),
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
                read_only: false,
                evidence: vec![],
            },
            source_snapshot: BtrfsSubvolumeIdentity {
                path: "/@/.snapshots/1/snapshot".into(),
                subvolume_id: 300,
                generation: 80,
                read_only: true,
                evidence: vec![],
            },
            target_catos_identity: None,
            boot_layout: BootLayout::default(),
            backup_root_path: "/.catos-recovery/backups/p-1/root-before".into(),
            staging_root_path: "/.catos-recovery/staging/p-1/new-root".into(),
            fstab_root_definition: FstabRootDefinition {
                source: "/dev/nvme0n1p2".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            },
            predicted_steps: vec![],
            refusal_conditions: vec![],
            risks_and_warnings: vec![],
            confirmation_token: "tok".into(),
            evidence: vec![],
        }
    }

    fn sample_record(path: &str) -> (PathBuf, TransactionRecord) {
        let root = std::env::temp_dir().join(format!(
            "catos-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        let record_path = root.join(path);
        let plan = sample_plan();
        let record = TransactionRecord {
            schema_version: TX_RECORD_SCHEMA_VERSION,
            transaction_id: "p-1".into(),
            created_at_unix: 100,
            last_updated_unix: 100,
            plan,
            state: TransactionState::Planned,
            completed_steps: vec![CompletedStep {
                state: TransactionState::Planned,
                completed_at_unix: 100,
                description: "test".into(),
            }],
            last_error: None,
            last_disk_facts: Some(DiskFacts {
                backup_root_exists: false,
                staging_root_exists: false,
                active_root_exists: true,
                active_root_generation: Some(10),
                filesystem_fsid: "fsid".into(),
            }),
            last_cleanup: None,
        };
        (record_path, record)
    }

    #[test]
    fn persist_and_load_round_trips() {
        let (path, record) = sample_record("tx/tx-1/state.json");
        persist_record(&path, &record).unwrap();
        let loaded = load_record(&path).unwrap();
        assert_eq!(loaded, record);
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn load_record_returns_not_found_for_missing_file() {
        let path = std::env::temp_dir().join(format!("catos-missing-{}", std::process::id()));
        let err = load_record(&path).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::TransactionNotFound);
    }

    #[test]
    fn load_record_rejects_unsupported_schema_version() {
        let (path, mut record) = sample_record("tx-2/state.json");
        record.schema_version = 99;
        persist_record(&path, &record).unwrap();
        let err = load_record(&path).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::UnsupportedTransactionSchema);
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn load_record_rejects_truncated_json() {
        let (path, _record) = sample_record("tx-3/state.json");
        // Create parent dir then write truncated bytes directly.
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::write(&path, b"{\"schema_version\":2,\"transaction_id\":\"x\"").unwrap();
        let err = load_record(&path).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::StateRecordCorrupt);
        let _ = fs::remove_dir_all(parent.parent().unwrap());
    }

    #[test]
    fn persist_record_is_atomic_under_temp_rename() {
        let (path, record) = sample_record("tx-4/state.json");
        persist_record(&path, &record).unwrap();
        // The temp file must NOT remain after persist.
        let temp = path.with_extension("json.tmp");
        assert!(!temp.exists(), "temp file {} leaked", temp.display());
        // The real file MUST exist.
        assert!(path.exists());
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn persist_record_creates_missing_parent_directories() {
        let (path, record) = sample_record("deep/nested/tx/state.json");
        persist_record(&path, &record).unwrap();
        assert!(path.exists());
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap().parent().unwrap());
    }

    #[test]
    fn remove_record_is_idempotent() {
        let (path, record) = sample_record("tx-5/state.json");
        persist_record(&path, &record).unwrap();
        remove_record(&path).unwrap();
        // Second call must succeed (NotFound is silently treated as success).
        remove_record(&path).unwrap();
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn list_records_returns_empty_for_missing_dir() {
        let missing = std::env::temp_dir().join(format!(
            "catos-list-missing-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let (records, errors) = list_records(&missing);
        assert!(records.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn list_records_picks_up_multiple_transactions() {
        let root = std::env::temp_dir().join(format!(
            "catos-list-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        for id in ["tx-a", "tx-b", "tx-c"] {
            let (mut path, mut record) = sample_record(&format!("{id}/state.json"));
            // Re-root under `root`.
            path = root.join(id).join("state.json");
            record.transaction_id = id.into();
            persist_record(&path, &record).unwrap();
        }
        let (records, errors) = list_records(&root);
        assert_eq!(records.len(), 3);
        assert!(errors.is_empty(), "{:?}", errors);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_records_skips_corrupt_files_with_error() {
        let root = std::env::temp_dir().join(format!(
            "catos-list-corrupt-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        let (good_path, good_record) = sample_record("good/state.json");
        let good_path = root.join("good/state.json");
        persist_record(&good_path, &good_record).unwrap();
        let bad_path = root.join("bad/state.json");
        fs::create_dir_all(bad_path.parent().unwrap()).unwrap();
        fs::write(&bad_path, b"definitely not json").unwrap();
        let (records, errors) = list_records(&root);
        assert_eq!(records.len(), 1);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind, RecoveryErrorKind::StateRecordCorrupt);
        let _ = fs::remove_dir_all(&root);
    }

    /// `TransactionPaths::state_file_path()` is the canonical path
    /// used by the engine. It MUST live under
    /// `/.catos-recovery/transactions/...` regardless of input.
    #[test]
    fn transaction_paths_layout_is_stable() {
        let paths = TransactionPaths {
            transaction_id: "abc".into(),
        };
        let path = paths.state_file_path();
        assert!(path.starts_with("/.catos-recovery/transactions"));
        assert!(path.ends_with("abc/state.json"));
    }

    /// Reject paths that try to escape via `..` during directory
    /// creation. Guards against a hostile record id.
    #[test]
    fn ensure_dir_rejects_escaping_paths() {
        let tmp = std::env::temp_dir().join(format!("catos-escape-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let hostile = tmp.join("../../etc/catos-hostile");
        let err = ensure_dir_with_mode(&hostile, 0o700).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::StateRecordCorrupt);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_plan_accepts_bare_recovery_plan() {
        let dir = std::env::temp_dir().join(format!(
            "catos-plan-bare-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("plan.json");
        let plan = sample_plan();
        persist_plan(&path, &plan).unwrap();
        let loaded = load_plan(&path).unwrap();
        assert_eq!(loaded, plan);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_plan_accepts_wrapped_envelope_from_recovery_plan_json() {
        let dir = std::env::temp_dir().join(format!(
            "catos-plan-envelope-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.json");
        let plan = sample_plan();
        let payload = serde_json::to_value(&plan).unwrap();
        let envelope = serde_json::json!({
            "invocation": "catos-system",
            "kind": "recovery_plan",
            "payload": payload,
            "programVersion": "0.1.0",
            "schemaVersion": 2,
            "targetRoot": "/",
        });
        fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        let loaded = load_plan(&path).unwrap();
        assert_eq!(loaded, plan);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_plan_rejects_neither_bare_nor_envelope() {
        let dir = std::env::temp_dir().join(format!(
            "catos-plan-junk-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.json");
        fs::write(&path, b"{\"unrelated\": \"json\"}").unwrap();
        let err = load_plan(&path).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::StateRecordCorrupt);
        let _ = fs::remove_dir_all(&dir);
    }
}
