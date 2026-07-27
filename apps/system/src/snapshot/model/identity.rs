//! Stable Btrfs filesystem and subvolume identities.

use crate::shared::model::evidence::Evidence;
use serde::{Deserialize, Serialize};

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
