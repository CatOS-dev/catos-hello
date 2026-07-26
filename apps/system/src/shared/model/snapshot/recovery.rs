//! Phase-3 recovery data model. Pure data + serde; no I/O.
//!
//! This module is the contract for the btrfs root-snapshot recovery
//! transaction. The types here are produced and consumed by
//! `src/recovery/*` and rendered by `src/output/recovery.rs`.
//!
//! ## Hard rules
//!
//! * The transaction record lives on the btrfs top-level (subvolid=5)
//!   under `/.catos-recovery/transactions/<id>/state.json`, NEVER inside
//!   a subvolume that may be replaced.
//! * The pre-recovery backup lives at
//!   `/.catos-recovery/backups/<id>/root-before` on the same top-level.
//! * The staging area lives at
//!   `/.catos-recovery/staging/<id>/new-root`.
//! * Identity is anchored on the btrfs FSID + major:minor + subvolume ID
//!   + subvolume generation. A `/dev/nvme...` name is NEVER the only
//!     identifier.
//! * Every state file has a schema version; unknown future versions are
//!   rejected, not re-interpreted.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::shared::model::evidence::Evidence;
use crate::shared::model::inspection::Warning;

// ---------------------------------------------------------------------------
// Schema versions
// ---------------------------------------------------------------------------

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

/// Recovery plan schema version. Bumped only on backward-incompatible
/// changes to [`RecoveryPlan`].
///
/// v3 adds a kernel-generated nonce and SHA-256 digest of the
/// canonical effective plan. Older plans are rejected rather than
/// treated as if their limited confirmation token covered every
/// execution field. v2 dropped the erroneous boot finalization
/// coupling. A v1/v2 plan is rejected as
/// `UnsupportedPlanSchema` rather than silently loading with
/// removed fields ignored.
pub const RECOVERY_PLAN_SCHEMA_VERSION: u32 = 4;

// ---------------------------------------------------------------------------
// Identity of a btrfs subvolume / filesystem at a point in time
// ---------------------------------------------------------------------------

/// Stable identity of a btrfs filesystem, independent of `/dev/...` names.
///
/// `fsid` is the kernel-reported btrfs filesystem UUID; `device_major_minor`
/// is the `major:minor` of the block device the filesystem lives on at the
/// time of observation. Both must be unchanged between plan and apply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BtrfsFilesystemIdentity {
    /// btrfs filesystem UUID (mkfs.btrfs `-U`, also in
    /// `/sys/fs/<uuid>/`).
    pub fsid: String,
    /// `major:minor` of the block device that carries this filesystem.
    pub device_major_minor: String,
    /// Filesystem label, if any (informational; not used as identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Stable identity of a single btrfs subvolume.
///
/// `subvolume_id` is the kernel subvolid; `generation` is the btrfs
/// `ogen`/`gen` value at observation time. A generation change between
/// plan and apply means the subvolume has been written to and the plan
/// is stale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BtrfsSubvolumeIdentity {
    /// Absolute path relative to the btrfs top-level, leading slash,
    /// e.g. `/@`, `/@/.snapshots/123/snapshot`.
    pub path: String,
    /// Kernel subvolid (256, 257, ...). 5 means the top-level.
    pub subvolume_id: u64,
    /// btrfs generation (transid) at observation time.
    pub generation: u64,
    /// Stable btrfs subvolume UUID. Required for deciding whether a
    /// root exchange has already happened after a pre-persist crash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// UUID of the subvolume this subvolume was snapshotted from, when
    /// btrfs reports one. For a replacement root this must identify the
    /// selected source snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_uuid: Option<String>,
    /// Whether the subvolume was readonly at observation time.
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

// ---------------------------------------------------------------------------
// Boot / ESP layout description
// ---------------------------------------------------------------------------

/// Layout of the boot resources of the system being recovered.
///
/// This is purely descriptive. Recovery performs no boot writes: it does
/// not touch the ESP, regenerate UKIs, or invoke any bootloader tool.
/// A future phase may consult these fields as part of a read-only
/// boot-consistency check that refuses the first persistent write if
/// external boot resources disagree with the new root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BootLayout {
    /// `/boot` is a directory inside the root subvolume (not a separate
    /// filesystem, not a separate subvolume).
    pub boot_inside_root: bool,
    /// `/boot` is mounted from a separate filesystem (ext4 / btrfs / ...).
    pub boot_separate_filesystem: bool,
    /// `/boot` is itself a separate btrfs subvolume.
    pub boot_separate_subvolume: bool,
    /// ESP location, if known (e.g. `/boot/efi`, `/efi`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_mount_point: Option<String>,
    /// Block device path of the ESP, if separately identified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_device: Option<String>,
    /// UKI files (`*.efi`) detected in the source snapshot's `/boot/EFI/...`.
    /// Empty when none were observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uki_paths: Vec<String>,
    /// Kernel versions visible in the source snapshot's
    /// `/usr/lib/modules/`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kernel_versions: Vec<String>,
    /// Whether the snapshot appears to ship an initramfs.
    pub has_initramfs: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BootConsistencyStatus {
    /// Every boot resource relevant to this recovery is contained in
    /// the root subvolume and moves with the atomic exchange.
    Consistent,
    /// A concrete mismatch was observed. Reserved for checks that can
    /// compare two authoritative resource sets.
    Inconsistent,
    /// The topology could not be established safely.
    #[default]
    Unknown,
    /// The topology is understood but phase 3 deliberately does not
    /// support it because boot resources live outside the root swap.
    Unsupported,
}

/// Read-only result describing whether a root-only exchange preserves
/// boot consistency. This report never authorizes or performs writes to
/// `/boot`, the ESP, UKIs, initramfs images, or bootloader state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BootConsistencyReport {
    pub status: BootConsistencyStatus,
    /// True only when the report was derived from a read-only target
    /// mount and parsed target metadata.
    pub checked_read_only: bool,
    /// Whether the root exchange covers all observed boot resources.
    pub root_switch_covers_all_boot_resources: bool,
    /// `/boot` is outside the root subvolume.
    pub external_boot: bool,
    /// An ESP is mounted outside the root subvolume.
    pub external_esp: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Recovery plan
// ---------------------------------------------------------------------------

/// An immutable recovery plan. Produced by `recovery plan`; consumed
/// (with re-verification) by `recovery apply`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPlan {
    /// [`RECOVERY_PLAN_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Opaque plan id (UUID-like). Bound into the confirmation token.
    pub plan_id: String,
    /// Wall-clock seconds since UNIX epoch when the plan was produced.
    pub generated_at_unix: u64,
    /// Hostname / kernel version at plan time (for human context only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_on_host: Option<String>,

    /// Identity of the target btrfs filesystem.
    pub filesystem: BtrfsFilesystemIdentity,
    /// Identity of the current root subvolume (the one to be replaced).
    pub current_root: BtrfsSubvolumeIdentity,
    /// Identity of the source readonly snapshot (the recovery target).
    pub source_snapshot: BtrfsSubvolumeIdentity,

    /// CatOS identity of the snapshot (os-release name/id/version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_catos_identity: Option<CatosIdentity>,

    /// Boot layout of the source snapshot.
    pub boot_layout: BootLayout,
    /// Read-only boot consistency decision sealed into the plan.
    pub boot_consistency: BootConsistencyReport,

    /// Where the pre-recovery backup of the current root will live.
    /// Always under the btrfs top-level.
    pub backup_root_path: String,
    /// Where the new writable root will be staged before the swap.
    /// Always under the btrfs top-level.
    pub staging_root_path: String,

    /// The fstab root definition observed inside the source snapshot.
    /// This is what the recovered root will use after the swap.
    pub fstab_root_definition: FstabRootDefinition,

    /// Predicted ordered execution steps. The engine must complete them
    /// in this order; resume continues from the last persisted step.
    pub predicted_steps: Vec<String>,
    /// Conditions under which the plan refuses to apply (re-checked at
    /// apply time).
    pub refusal_conditions: Vec<String>,
    /// Risks and warnings the operator should be aware of before
    /// confirming.
    pub risks_and_warnings: Vec<String>,

    /// 256-bit kernel-generated nonce encoded as lowercase hex.
    /// Generation fails closed if the kernel random source fails.
    pub nonce: String,
    /// SHA-256 digest of the canonical effective plan. This excludes
    /// presentation-only fields and the confirmation token itself,
    /// but covers every field that can change execution or refusal.
    pub plan_digest: String,

    /// Operator-facing confirmation token. The plan is invalid without
    /// a matching token at apply time; the token is bound to `plan_id`
    /// and to the plan identity fields so it cannot be replayed against
    /// a different plan.
    pub confirmation_token: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// Subset of `/etc/os-release` we anchor into the plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CatosIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pretty_name: Option<String>,
}

/// The root fstab line that the recovered root will mount.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FstabRootDefinition {
    pub source: String,
    pub fstype: String,
    /// Mount options (subvol=...,compress=...). Stored verbatim from the
    /// source snapshot's fstab.
    pub options: Vec<String>,
}

// ---------------------------------------------------------------------------
// Transaction state machine
// ---------------------------------------------------------------------------

/// All states a recovery transaction can be in. Transitions are
/// validated by [`crate::shared::snapshot_engine::state`] — direct mutation of the
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
    pub last_error: Option<RecoveryError>,

    /// Disk facts observed by the engine at the last successful
    /// transition. Used by `status` to reconcile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_disk_facts: Option<DiskFacts>,

    /// Optional mount cleanup summary (residual mounts, if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cleanup: Option<CleanupSummary>,
}

/// Disk facts the engine records after each persistent transition.
/// `status` re-observes these and uses them to override a stale
/// `state` field when reality disagrees.
///
/// Every subvolume slot is `Option<SubvolumeFacts>`: `None` means
/// the engine could not observe that subvolume at all (e.g. it does
/// not exist, or `btrfs subvolume show` failed); `Some` carries the
/// identity fields the reconciliation logic uses to decide whether a
/// persistent action has already happened.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DiskFacts {
    /// FSID observed at this transition. Reconciled against the plan
    /// by [`crate::shared::snapshot_engine::state`] to detect that the recovery is
    /// now talking to a different btrfs filesystem than it started
    /// against.
    pub filesystem_fsid: String,
    /// Does the btrfs top-level `/@` subvolume exist? Kept as a
    /// separate boolean because the engine uses it as a fast
    /// pre-check before paying for a `btrfs subvolume show`.
    pub active_root_exists: bool,
    /// Identity of the active `/@` subvolume, if observable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_root: Option<SubvolumeFacts>,
    /// Does the staging path `/.catos-recovery/staging/<id>/new-root`
    /// exist? After the swap, the staging path holds the OLD `/@`,
    /// so this stays true across the swap.
    pub staging_root_exists: bool,
    /// Identity of whatever currently lives at the staging path.
    /// After the swap this is the pre-recovery root; before the swap
    /// this is the freshly-created writable snapshot of the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staging_root: Option<SubvolumeFacts>,
    /// Does the backup path `/.catos-recovery/backups/<id>/root-before`
    /// exist?
    pub backup_root_exists: bool,
    /// Identity of the backup subvolume, if observable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<SubvolumeFacts>,
    /// Does the source snapshot path still exist? Recovery MUST NOT
    /// modify the source; a missing source is a drift signal.
    #[serde(default)]
    pub source_snapshot_exists: bool,
    /// Identity of the source snapshot, if observable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_snapshot: Option<SubvolumeFacts>,
}

/// Identity of a single subvolume as observed by the engine at a
/// given moment. Mirrors [`BtrfsSubvolumeIdentity`] but every field
/// is optional because `btrfs subvolume show` may legitimately fail
/// to populate some of them (e.g. an old btrfs-progs that omits
/// `Parent UUID:`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SubvolumeFacts {
    /// Absolute path relative to the btrfs top-level (leading `/`).
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subvolume_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// btrfs subvolume UUID (`btrfs subvolume show` `UUID:` line).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// btrfs subvolume Parent UUID. Used to detect that a subvolume
    /// is a snapshot of a specific parent (e.g. the backup is a
    /// snapshot of the original `/@`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

/// Result of mount cleanup during a transition or revert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CleanupSummary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmounted: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residual: Vec<String>,
    pub all_clean: bool,
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Structured recovery error. Distinct variants for genuinely distinct
/// failures; the JSON contract exposes the variant name as a stable
/// `code`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryError {
    pub kind: RecoveryErrorKind,
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

impl RecoveryError {
    /// Helper to build a minimal error.
    pub fn new(kind: RecoveryErrorKind, message: impl Into<String>) -> Self {
        RecoveryError {
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

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.code(), self.message)
    }
}

/// Recovery failure taxonomy. Each variant maps to a stable snake_case
/// code in JSON.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryErrorKind {
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

impl RecoveryErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            RecoveryErrorKind::StalePlan => "stale_plan",
            RecoveryErrorKind::TargetChanged => "target_changed",
            RecoveryErrorKind::AmbiguousTarget => "ambiguous_target",
            RecoveryErrorKind::UnsupportedMultiDeviceBtrfs => "unsupported_multi_device_btrfs",
            RecoveryErrorKind::RunningRootProtectionIndeterminate => {
                "running_root_protection_indeterminate"
            }
            RecoveryErrorKind::CurrentRootRefused => "current_root_refused",
            RecoveryErrorKind::SnapshotNotReadonly => "snapshot_not_readonly",
            RecoveryErrorKind::SnapshotBelongsToAnotherFsid => "snapshot_belongs_to_another_fsid",
            RecoveryErrorKind::BackupPathOccupied => "backup_path_occupied",
            RecoveryErrorKind::StagingPathOccupied => "staging_path_occupied",
            RecoveryErrorKind::TransactionAlreadyActive => "transaction_already_active",
            RecoveryErrorKind::InsufficientSpace => "insufficient_space",
            RecoveryErrorKind::RootSwitchConflict => "root_switch_conflict",
            RecoveryErrorKind::CleanupIncomplete => "cleanup_incomplete",
            RecoveryErrorKind::StateRecordCorrupt => "state_record_corrupt",
            RecoveryErrorKind::UnsupportedTransactionSchema => "unsupported_transaction_schema",
            RecoveryErrorKind::UnsupportedPlanSchema => "unsupported_plan_schema",
            RecoveryErrorKind::ConfirmationTokenMismatch => "confirmation_token_mismatch",
            RecoveryErrorKind::InvalidRecoveryId => "invalid_recovery_id",
            RecoveryErrorKind::PlanDigestMismatch => "plan_digest_mismatch",
            RecoveryErrorKind::RandomSourceFailed => "random_source_failed",
            RecoveryErrorKind::UnsafeRecoveryPath => "unsafe_recovery_path",
            RecoveryErrorKind::UnsupportedNestedSnapshotLayout => {
                "unsupported_nested_snapshot_layout"
            }
            RecoveryErrorKind::BootConsistencyInconsistent => "boot_consistency_inconsistent",
            RecoveryErrorKind::BootConsistencyUnknown => "boot_consistency_unknown",
            RecoveryErrorKind::UnsupportedExternalBootLayout => "unsupported_external_boot_layout",
            RecoveryErrorKind::UnsupportedExplicitEsp => "unsupported_explicit_esp",
            RecoveryErrorKind::SessionDirectoryNotSecure => "session_directory_not_secure",
            RecoveryErrorKind::SessionDirectoryConflict => "session_directory_conflict",
            RecoveryErrorKind::SessionDirectoryCleanupFailed => "session_directory_cleanup_failed",
            RecoveryErrorKind::TransactionNotFound => "transaction_not_found",
            RecoveryErrorKind::IllegalStateTransition => "illegal_state_transition",
            RecoveryErrorKind::BtrfsToolFailed => "btrfs_tool_failed",
            RecoveryErrorKind::SyscallFailed => "syscall_failed",
            RecoveryErrorKind::RecoveryFailed => "recovery_failed",
        }
    }
}

// ---------------------------------------------------------------------------
// Status envelope returned by all recovery subcommands
// ---------------------------------------------------------------------------

/// Output envelope for `recovery list` — the readonly listing of
/// snapshots and transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RecoveryListReport {
    /// Canonical block-device path that was mounted for this listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_device: Option<String>,
    /// FSID observed from the mounted target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_filesystem_fsid: Option<String>,
    /// Explicit cleanup result for the short-lived read-only mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_cleanup: Option<CleanupSummary>,
    /// Filesystem identities observed (one per probed btrfs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystems: Vec<BtrfsFilesystemIdentity>,
    /// Subvolumes that look like readonly snapshots eligible as a
    /// recovery source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readonly_snapshots: Vec<BtrfsSubvolumeIdentity>,
    /// Transactions known to exist on this machine (across all
    /// filesystems), with their current state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transactions: Vec<TransactionSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionSummary {
    pub transaction_id: String,
    pub state: TransactionState,
    pub plan_id: String,
    pub created_at_unix: u64,
    pub last_updated_unix: u64,
    pub source_snapshot_path: String,
}

/// Output envelope for `recovery inspect`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryInspectReport {
    pub filesystem: BtrfsFilesystemIdentity,
    pub current_root: BtrfsSubvolumeIdentity,
    pub source_snapshot: BtrfsSubvolumeIdentity,
    pub boot_layout: BootLayout,
    pub boot_consistency: BootConsistencyReport,
    pub target_catos_identity: Option<CatosIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

/// Output envelope for `recovery status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryStatusReport {
    pub transaction_id: String,
    /// State after reconciling the persisted record with current disk
    /// facts. Consumers MUST use this, not `record.state`.
    pub reconciled_state: TransactionState,
    pub record: TransactionRecord,
    pub disk_facts: DiskFacts,
    /// Operator-facing recommendation. Stable enum so the recovery UI
    /// can route without parsing free text.
    pub recommendation: RecoveryRecommendation,
    /// Cleanup result for the short-lived read-only status mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_cleanup: Option<CleanupSummary>,
    /// State-bound confirmation required by `recovery revert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_confirmation_token: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

/// What the engine recommends the operator do next.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRecommendation {
    /// Transaction is complete; no action needed.
    #[default]
    None,
    /// Transaction is in progress; safe to call `resume`.
    Resume,
    /// Transaction failed but `resume` is safe.
    ResumeAfterFailure,
    /// Transaction failed and `revert` is the safer path.
    Revert,
    /// Manual intervention required; neither `resume` nor `revert` is
    /// safe without operator review.
    ManualIntervention,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_state_default_is_planned() {
        assert_eq!(TransactionState::default(), TransactionState::Planned);
    }

    #[test]
    fn transaction_state_code_is_stable_snake_case() {
        // The code() output is part of the JSON contract. Lock each
        // variant so a rename breaks CI rather than downstream tooling.
        let cases = [
            (TransactionState::Planned, "planned"),
            (TransactionState::PreflightVerified, "preflight_verified"),
            (TransactionState::Locked, "locked"),
            (TransactionState::BackupCreated, "backup_created"),
            (TransactionState::ReplacementCreated, "replacement_created"),
            (TransactionState::OldRootMoved, "old_root_moved"),
            (TransactionState::NewRootInstalled, "new_root_installed"),
            (TransactionState::Verifying, "verifying"),
            (TransactionState::Completed, "completed"),
            (TransactionState::Reverting, "reverting"),
            (TransactionState::Reverted, "reverted"),
            (TransactionState::FailedRecoverable, "failed_recoverable"),
            (
                TransactionState::FailedManualIntervention,
                "failed_manual_intervention",
            ),
        ];
        for (state, expected) in cases {
            assert_eq!(state.code(), expected, "state={:?}", state);
        }
    }

    /// A state that forgot to update `code()` would silently regress
    /// the JSON contract. The serde rename must agree.
    #[test]
    fn transaction_state_code_matches_serde_rename() {
        for state in [
            TransactionState::Planned,
            TransactionState::PreflightVerified,
            TransactionState::Locked,
            TransactionState::BackupCreated,
            TransactionState::ReplacementCreated,
            TransactionState::OldRootMoved,
            TransactionState::NewRootInstalled,
            TransactionState::Verifying,
            TransactionState::Completed,
            TransactionState::Reverting,
            TransactionState::Reverted,
            TransactionState::FailedRecoverable,
            TransactionState::FailedManualIntervention,
        ] {
            let j = serde_json::to_string(&state).unwrap();
            let s = j.trim_matches('"');
            assert_eq!(state.code(), s, "serde/code drift for {state:?}");
        }
    }

    #[test]
    fn terminal_states_are_terminal() {
        assert!(TransactionState::Completed.is_terminal());
        assert!(TransactionState::Reverted.is_terminal());
        assert!(TransactionState::FailedManualIntervention.is_terminal());
        assert!(!TransactionState::Planned.is_terminal());
        assert!(!TransactionState::FailedRecoverable.is_terminal());
    }

    #[test]
    fn first_persistent_write_done_excludes_planned_preflight_locked() {
        // Plans that have not yet written to disk can be abandoned by
        // removing the transaction record. Once we have a backup
        // subvolume, resume must account for it.
        assert!(!TransactionState::Planned.first_persistent_write_done());
        assert!(!TransactionState::PreflightVerified.first_persistent_write_done());
        assert!(!TransactionState::Locked.first_persistent_write_done());
        assert!(TransactionState::BackupCreated.first_persistent_write_done());
        assert!(TransactionState::ReplacementCreated.first_persistent_write_done());
    }

    #[test]
    fn error_kind_code_is_stable_snake_case() {
        let cases = [
            (RecoveryErrorKind::StalePlan, "stale_plan"),
            (RecoveryErrorKind::TargetChanged, "target_changed"),
            (
                RecoveryErrorKind::CurrentRootRefused,
                "current_root_refused",
            ),
            (
                RecoveryErrorKind::SnapshotNotReadonly,
                "snapshot_not_readonly",
            ),
            (
                RecoveryErrorKind::UnsupportedTransactionSchema,
                "unsupported_transaction_schema",
            ),
            (
                RecoveryErrorKind::ConfirmationTokenMismatch,
                "confirmation_token_mismatch",
            ),
            (RecoveryErrorKind::BtrfsToolFailed, "btrfs_tool_failed"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.code(), expected);
        }
    }

    #[test]
    fn recovery_paths_top_level_is_stable() {
        // The on-disk layout is part of the contract; the recovery
        // record MUST NOT live inside @/var/... because that subvolume
        // may be replaced mid-transaction.
        assert_eq!(TransactionPaths::ROOT_DIR, "/.catos-recovery");
        assert_eq!(
            TransactionPaths::transactions_dir(),
            "/.catos-recovery/transactions"
        );
        assert_eq!(TransactionPaths::backups_dir(), "/.catos-recovery/backups");
        assert_eq!(TransactionPaths::staging_dir(), "/.catos-recovery/staging");
    }

    #[test]
    fn transaction_paths_are_namespaced_under_transaction_id() {
        let p = TransactionPaths {
            transaction_id: "tx-001".into(),
        };
        assert_eq!(
            p.state_file_path(),
            PathBuf::from("/.catos-recovery/transactions/tx-001/state.json")
        );
        assert_eq!(
            p.backup_subvolume_path(),
            PathBuf::from("/.catos-recovery/backups/tx-001/root-before")
        );
        assert_eq!(
            p.staging_subvolume_path(),
            PathBuf::from("/.catos-recovery/staging/tx-001/new-root")
        );
    }

    #[test]
    fn plan_round_trips_through_json() {
        let plan = RecoveryPlan {
            schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
            plan_id: "p-001".into(),
            generated_at_unix: 1,
            generated_on_host: Some("h".into()),
            filesystem: BtrfsFilesystemIdentity {
                fsid: "fsid".into(),
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
            target_catos_identity: Some(CatosIdentity {
                name: Some("CatOS".into()),
                id: Some("catos".into()),
                version: Some("1".into()),
                pretty_name: None,
            }),
            boot_layout: BootLayout::default(),
            boot_consistency: crate::shared::snapshot_engine::boot::evaluate_readonly_consistency(
                &BootLayout::default(),
            ),
            backup_root_path: "/.catos-recovery/backups/tx/root-before".into(),
            staging_root_path: "/.catos-recovery/staging/tx/new-root".into(),
            fstab_root_definition: FstabRootDefinition {
                source: "/dev/nvme0n1p2".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            },
            predicted_steps: vec!["preflight".into()],
            refusal_conditions: vec!["fsid drift".into()],
            risks_and_warnings: vec![],
            nonce: "00".repeat(32),
            plan_digest: "00".repeat(32),
            confirmation_token: "tok".into(),
            evidence: vec![],
        };
        let j = serde_json::to_string(&plan).unwrap();
        let back: RecoveryPlan = serde_json::from_str(&j).unwrap();
        assert_eq!(plan, back);
    }
}
