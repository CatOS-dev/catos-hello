//! Snapshot and transaction metadata that does not perform I/O.

use serde::{Deserialize, Serialize};

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
    /// by [`crate::snapshot::transaction`] to detect that the recovery is
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
