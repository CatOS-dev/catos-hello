//! Snapshot and transaction metadata that does not perform I/O.

use serde::{Deserialize, Serialize};

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
    /// by [`crate::transaction`] to detect that the recovery is
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeProgress {
    pub started_at_unix: u64,
    pub authorized_state: crate::model::TransactionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staging_identity: Option<SubvolumeFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_identity: Option<SubvolumeFacts>,
    #[serde(default)]
    pub staging_removed: bool,
    #[serde(default)]
    pub backup_removed: bool,
}

pub use catos_mount::model::CleanupSummary;
