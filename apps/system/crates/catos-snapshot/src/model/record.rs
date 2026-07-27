//! Durable snapshot transaction records and structured errors.

use super::metadata::{CleanupSummary, DiskFacts};
use super::plan::RecoveryPlan;
use super::state::TransactionState;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Recovery transaction record schema version. Bumped only on
/// backward-incompatible changes to [`TransactionRecord`].
///
/// ## v3 (current)
///
/// v3 expands [`DiskFacts`] from a flat set of booleans + a single
/// `active_root_generation` to a structured per-subvolume view that
/// records path / subvolid / generation / UUID / parent UUID /
/// readonly for the active root, the staging root, the backup, and
/// the source snapshot. The richer facts are required by the
/// recovery reconciliation logic to decide — unambiguously — whether
/// a renameat2 swap has happened (the previous shape had to infer
/// swap direction from path existence + generation alone, which is
/// unsafe: a swap is its own inverse).
///
/// ## v2
///
/// v2 dropped the `BootFinalizationPending` variant from
/// [`TransactionState`] (recovery no longer finalizes boot) and the
/// `finalization` field from the embedded [`RecoveryPlan`].
///
/// ## v1
///
/// v1 is the original phase-3-pre-release shape. Both v1 and v2
/// records are rejected as `UnsupportedTransactionSchema` rather than
/// re-interpreted: their [`DiskFacts`] shape is too thin to drive
/// the v3 reconciliation logic safely.
pub const TX_RECORD_SCHEMA_VERSION: u32 = 3;

/// One completed step recorded in the transaction record. The engine
/// appends to this list as it persists each transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletedStep {
    /// State that was reached when this step completed.
    pub state: TransactionState,
    /// Wall-clock seconds since UNIX epoch.
    pub completed_at_unix: u64,
    /// Short human-readable description of what was done.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Durable transaction record
// ---------------------------------------------------------------------------

/// The on-disk transaction record. Persisted atomically by
/// `recovery::store` after every successful transition. The structure
/// is versioned; an unknown future version MUST be rejected, not
/// re-interpreted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionRecord {
    /// [`TX_RECORD_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Opaque transaction id (UUID-like).
    pub transaction_id: String,
    /// Wall-clock seconds since UNIX epoch when the record was first
    /// created (i.e. when `apply` started).
    pub created_at_unix: u64,
    /// Wall-clock seconds since UNIX epoch of the most recent persist.
    pub last_updated_unix: u64,

    /// The plan this transaction is executing. Bound by id, identity
    /// fields, and confirmation token.
    pub plan: RecoveryPlan,

    /// Current state of the transaction. Note: status command MUST
    /// reconcile this with disk facts before reporting.
    pub state: TransactionState,

    /// Every successfully persisted step, in order. The last entry's
    /// state equals `state` (after reconciliation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_steps: Vec<CompletedStep>,

    /// Most recent error, if any. Cleared on successful resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<SnapshotError>,

    /// Disk facts observed by the engine at the last successful
    /// transition. Used by `status` to reconcile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_disk_facts: Option<DiskFacts>,

    /// Optional mount cleanup summary (residual mounts, if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cleanup: Option<CleanupSummary>,
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Structured recovery error. Distinct variants for genuinely distinct
/// failures; the JSON contract exposes the variant name as a stable
/// `code`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotError {
    pub kind: SnapshotErrorKind,
    /// User-readable message; no ANSI escapes.
    pub message: Box<str>,
    /// Transaction id, when the error happened inside a transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Current state at the time of failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_state: Option<TransactionState>,
    /// Step that failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<String>,
    /// Raw errno (positive) when the error originated from a syscall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    /// External tool exit code, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_exit_code: Option<i32>,
    /// Steps already completed before this failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_steps: Box<Vec<String>>,
    /// Disk facts at the time of failure, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_facts: Option<Box<DiskFacts>>,
    /// Whether the engine believes automatic resume is safe.
    pub resume_possible: bool,
    /// Whether `revert` is a safe action from this failure.
    pub revert_possible: bool,
    /// Whether human intervention is required.
    pub manual_intervention_required: bool,
    /// When the engine detected an operation failure AND then failed
    /// to persist the failure-state record to disk, this field
    /// carries the persistence-failure message. The operator MUST see
    /// both the original operation error and the persistence failure
    /// so they can recover the on-disk record manually. `None` when
    /// the failure-state record was persisted successfully (or when
    /// no operation failure occurred).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_persistence_error: Option<Box<str>>,
}

impl SnapshotError {
    /// Helper to build a minimal error.
    pub fn new(kind: SnapshotErrorKind, message: impl Into<String>) -> Self {
        SnapshotError {
            kind,
            message: message.into().into_boxed_str(),
            transaction_id: None,
            current_state: None,
            failed_step: None,
            errno: None,
            external_exit_code: None,
            completed_steps: Box::default(),
            disk_facts: None,
            resume_possible: false,
            revert_possible: false,
            manual_intervention_required: false,
            record_persistence_error: None,
        }
    }
}

/// Convert confined target-filesystem errors into the snapshot capability's
/// structured error taxonomy.
pub fn fs_to_snapshot(error: catos_target::FsError) -> SnapshotError {
    use catos_target::FsError;
    match error {
        FsError::NotFound => {
            SnapshotError::new(SnapshotErrorKind::TransactionNotFound, error.to_string())
        }
        FsError::PermissionDenied | FsError::NotUtf8 => {
            SnapshotError::new(SnapshotErrorKind::StateRecordCorrupt, error.to_string())
        }
        FsError::OutsideRoot(message) => {
            SnapshotError::new(SnapshotErrorKind::UnsafeRecoveryPath, message)
        }
        FsError::Io(message) => SnapshotError::new(SnapshotErrorKind::StateRecordCorrupt, message),
    }
}

impl From<catos_target::FsError> for SnapshotError {
    fn from(error: catos_target::FsError) -> Self {
        fs_to_snapshot(error)
    }
}

impl From<catos_mount::session::cleanup::MountSessionError> for SnapshotError {
    fn from(error: catos_mount::session::cleanup::MountSessionError) -> Self {
        SnapshotError::new(
            SnapshotErrorKind::SyscallFailed,
            format!(
                "btrfs top-level rw session: {} (kind={:?})",
                error.message, error.kind
            ),
        )
    }
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.code(), self.message)
    }
}

/// Recovery failure taxonomy. Each variant maps to a stable snake_case
/// code in JSON.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotErrorKind {
    /// The plan was generated against a different on-disk reality
    /// (FSID, subvolid, generation, or device major:minor changed).
    StalePlan,
    /// The target device/subvolume has changed in a way that the plan
    /// did not anticipate (different fstype, missing subvolume, ...).
    TargetChanged,
    /// The target root subvolume cannot be selected uniquely from the
    /// explicit argument, fstab, default subvolume, or candidates.
    AmbiguousTarget,
    /// This recovery phase does not yet support a multi-device btrfs
    /// filesystem because a single major:minor cannot identify it.
    UnsupportedMultiDeviceBtrfs,
    /// The running-root identity could not be established reliably,
    /// so a destructive operation is conservatively refused.
    RunningRootProtectionIndeterminate,
    /// The recovery would operate on the currently running root.
    CurrentRootRefused,
    /// The source snapshot is not readonly (or its readonly attribute
    /// changed between plan and apply).
    SnapshotNotReadonly,
    /// The source snapshot does not belong to the same btrfs FSID as
    /// the target root.
    SnapshotBelongsToAnotherFsid,
    /// The configured backup path is already occupied.
    BackupPathOccupied,
    /// The configured staging path is already occupied.
    StagingPathOccupied,
    /// Another transaction is already active for this FSID.
    TransactionAlreadyActive,
    /// Estimated free space on the filesystem is below the safety
    /// threshold for the planned operation.
    InsufficientSpace,
    /// The root swap cannot be performed because of a name/path
    /// conflict.
    RootSwitchConflict,
    /// Mount cleanup left residual mounts.
    CleanupIncomplete,
    /// The transaction state file is corrupt, truncated, or
    /// unparsable.
    StateRecordCorrupt,
    /// The transaction state file uses an unknown future schema
    /// version.
    UnsupportedTransactionSchema,
    /// The plan file uses an unknown future schema version.
    UnsupportedPlanSchema,
    /// The confirmation token does not match the plan id.
    ConfirmationTokenMismatch,
    /// A plan or transaction identifier does not match the strict
    /// `tx-<32 lowercase hexadecimal digits>` grammar.
    InvalidRecoveryId,
    /// The effective plan no longer hashes to its persisted digest.
    PlanDigestMismatch,
    /// The kernel random source failed; plan generation must fail
    /// rather than using predictable or all-zero bytes.
    RandomSourceFailed,
    /// A recovery storage path escaped its confined directory or
    /// traversed a symlink/magic link.
    UnsafeRecoveryPath,
    /// The selected snapshot is nested below the active root, so a
    /// root exchange would move its declared path.
    UnsupportedNestedSnapshotLayout,
    /// Boot resources outside the recovered root are inconsistent
    /// with the selected snapshot.
    BootConsistencyInconsistent,
    /// Boot-resource consistency could not be established safely.
    BootConsistencyUnknown,
    /// The external boot-resource topology is not supported by this
    /// recovery phase.
    UnsupportedExternalBootLayout,
    /// The operator supplied `--esp-device` on a phase-3 recovery
    /// subcommand. Phase 3 deliberately does not maintain or write to
    /// the ESP: the root-snapshot swap is bounded to the btrfs
    /// top-level and a read-only boot-consistency report. Explicit
    /// ESP selection is therefore rejected BEFORE any mount or
    /// persistent write rather than silently ignored, so a script
    /// that expects ESP handling cannot proceed under a false
    /// contract. A future phase that performs real ESP reconciliation
    /// will replace this kind, not reinterpret it.
    UnsupportedExplicitEsp,
    /// The recovery runtime session directory under
    /// `/run/catos-system/sessions/` could not be established as
    /// attacker-controlled-safe: a component was a symlink, a regular
    /// file, owned by the wrong user, world- or group-writable, or
    /// otherwise not the exclusive directory this process created.
    SessionDirectoryNotSecure,
    /// An exclusive recovery session directory could not be created
    /// because the chosen name already existed (collision with a
    /// concurrent transaction, stale leftover, or attacker-prepared
    /// honeypot). Phase 3 never reuses an existing directory.
    SessionDirectoryConflict,
    /// The recovery session directory could not be removed after the
    /// transaction completed and all mounts were torn down. The
    /// transaction itself may be in a clean state but the runtime
    /// directory leaked; operators need a stable code to detect and
    /// clean it up.
    SessionDirectoryCleanupFailed,
    /// A requested transaction id was not found on disk.
    TransactionNotFound,
    /// A step transitions from a state that does not allow it.
    IllegalStateTransition,
    /// The btrfs helper tool is missing or returned an unrecoverable
    /// error.
    BtrfsToolFailed,
    /// A kernel syscall failed (mount, renameat2, fsync, ...).
    SyscallFailed,
    /// Generic recovery failure not covered by the above.
    RecoveryFailed,
}

impl SnapshotErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            SnapshotErrorKind::StalePlan => "stale_plan",
            SnapshotErrorKind::TargetChanged => "target_changed",
            SnapshotErrorKind::AmbiguousTarget => "ambiguous_target",
            SnapshotErrorKind::UnsupportedMultiDeviceBtrfs => "unsupported_multi_device_btrfs",
            SnapshotErrorKind::RunningRootProtectionIndeterminate => {
                "running_root_protection_indeterminate"
            }
            SnapshotErrorKind::CurrentRootRefused => "current_root_refused",
            SnapshotErrorKind::SnapshotNotReadonly => "snapshot_not_readonly",
            SnapshotErrorKind::SnapshotBelongsToAnotherFsid => "snapshot_belongs_to_another_fsid",
            SnapshotErrorKind::BackupPathOccupied => "backup_path_occupied",
            SnapshotErrorKind::StagingPathOccupied => "staging_path_occupied",
            SnapshotErrorKind::TransactionAlreadyActive => "transaction_already_active",
            SnapshotErrorKind::InsufficientSpace => "insufficient_space",
            SnapshotErrorKind::RootSwitchConflict => "root_switch_conflict",
            SnapshotErrorKind::CleanupIncomplete => "cleanup_incomplete",
            SnapshotErrorKind::StateRecordCorrupt => "state_record_corrupt",
            SnapshotErrorKind::UnsupportedTransactionSchema => "unsupported_transaction_schema",
            SnapshotErrorKind::UnsupportedPlanSchema => "unsupported_plan_schema",
            SnapshotErrorKind::ConfirmationTokenMismatch => "confirmation_token_mismatch",
            SnapshotErrorKind::InvalidRecoveryId => "invalid_recovery_id",
            SnapshotErrorKind::PlanDigestMismatch => "plan_digest_mismatch",
            SnapshotErrorKind::RandomSourceFailed => "random_source_failed",
            SnapshotErrorKind::UnsafeRecoveryPath => "unsafe_recovery_path",
            SnapshotErrorKind::UnsupportedNestedSnapshotLayout => {
                "unsupported_nested_snapshot_layout"
            }
            SnapshotErrorKind::BootConsistencyInconsistent => "boot_consistency_inconsistent",
            SnapshotErrorKind::BootConsistencyUnknown => "boot_consistency_unknown",
            SnapshotErrorKind::UnsupportedExternalBootLayout => "unsupported_external_boot_layout",
            SnapshotErrorKind::UnsupportedExplicitEsp => "unsupported_explicit_esp",
            SnapshotErrorKind::SessionDirectoryNotSecure => "session_directory_not_secure",
            SnapshotErrorKind::SessionDirectoryConflict => "session_directory_conflict",
            SnapshotErrorKind::SessionDirectoryCleanupFailed => "session_directory_cleanup_failed",
            SnapshotErrorKind::TransactionNotFound => "transaction_not_found",
            SnapshotErrorKind::IllegalStateTransition => "illegal_state_transition",
            SnapshotErrorKind::BtrfsToolFailed => "btrfs_tool_failed",
            SnapshotErrorKind::SyscallFailed => "syscall_failed",
            SnapshotErrorKind::RecoveryFailed => "recovery_failed",
        }
    }
}

/// Path helpers for transaction artifacts. Centralised so the engine,
/// store, and status all agree on the on-disk layout.
pub struct TransactionPaths {
    pub transaction_id: String,
}

impl TransactionPaths {
    /// Top-level recovery directory. Lives on the btrfs toplevel.
    pub const ROOT_DIR: &'static str = "/.catos-recovery";

    pub fn transactions_dir() -> &'static str {
        // Returned as &str for cheap references; the layout is fixed.
        const DIR: &str = "/.catos-recovery/transactions";
        DIR
    }

    pub fn backups_dir() -> &'static str {
        const DIR: &str = "/.catos-recovery/backups";
        DIR
    }

    pub fn staging_dir() -> &'static str {
        const DIR: &str = "/.catos-recovery/staging";
        DIR
    }

    pub fn state_file_path(&self) -> PathBuf {
        PathBuf::from(Self::transactions_dir())
            .join(&self.transaction_id)
            .join("state.json")
    }

    pub fn plan_file_path(&self) -> PathBuf {
        PathBuf::from(Self::transactions_dir())
            .join(&self.transaction_id)
            .join("plan.json")
    }

    pub fn backup_subvolume_path(&self) -> PathBuf {
        PathBuf::from(Self::backups_dir())
            .join(&self.transaction_id)
            .join("root-before")
    }

    pub fn staging_subvolume_path(&self) -> PathBuf {
        PathBuf::from(Self::staging_dir())
            .join(&self.transaction_id)
            .join("new-root")
    }
}
