//! Storage data model. Pure data + serde; no I/O.
//!
//! This is the type layer every probe and parser feeds into. By
//! convention:
//!   * `*_detected / not_detected / unknown` use the three-state Detection
//!     from `runtime.rs` when they describe an environment fact.
//!   * `Presence` (present / absent / unknown) describes whether a file or
//!     directory exists.
//!   * `Confidence` is its own four-state enum (high / medium / low /
//!     unknown) so we never collapse "we don't know" into "low confidence".
//!
//! Every device, candidate, and warning carries an evidence trail
//! (`Vec<Evidence>`). Nothing here is constructed from a guess: every field
//! must be traceable to a probe source.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::evidence::Evidence;
use crate::model::inspection::Warning;
use crate::model::runtime::Detection;

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

/// Coarse device class. Used for human display and for selecting which
/// sub-probes apply. Fine-grained attributes (partition vs whole-disk,
/// read-only vs rw) live in [`BlockDevice`] as separate fields.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    /// Whole-disk node (sda, nvme0n1, loop0). Has no parent partition.
    Disk,
    /// Partition of a disk (sda1, nvme0n1p2).
    Partition,
    /// device-mapper node (dm-0, dm-1) - LUKS, LVM, multipath.
    DeviceMapper,
    /// mdraid member or array (md0, md127).
    MdRaid,
    /// loop-backed file (loop0..loopN).
    Loop,
    /// Anything not falling in the above (zram, DRBD, nbd).
    #[default]
    Other,
}

/// Refines [`DeviceClass::DeviceMapper`] / `MdRaid` / `Loop` with what the
/// backing layer actually is. `Unknown` is a legitimate answer when
/// blkid and sysfs disagree or when we deliberately did not probe.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    /// Plain SSD/HDD/NVMe without partition table information available.
    #[default]
    Unknown,
    /// GPT partition table detected.
    Gpt,
    /// MBR (legacy) partition table detected.
    Mbr,
    /// No partition table (whole device is one filesystem / LUKS / LVM PV).
    Bare,
    /// Loop-backed file; no on-disk partition table.
    Loop,
}

/// Partition "type" hint. GPT partitions expose a PARTUUID (which IS the
/// type GUID) and a separate PARTLABEL; MBR partitions expose a numeric
/// type byte. We model both as the same enum so consumers can switch
/// uniformly.
///
/// `Other` carries the raw GUID or byte for cases we don't categorise
/// (e.g. a vendor-specific partition type).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PartitionRole {
    /// EFI System Partition (GPT type C12A7328-F81F-11D2-BA4B-00A0C93EC93B).
    Esp,
    /// BIOS boot partition (GPT type 21686148-6449-6E6F-744E-656564454649).
    BiosBoot,
    /// Linux filesystem / home / raid / lvm — non-boot data partitions.
    LinuxFilesystem,
    /// Microsoft Reserved / Basic Data.
    Microsoft,
    /// MBR type byte we did not classify.
    MbrOther(u8),
    /// GPT partition-type GUID we did not classify.
    GptOther(String),
    /// Whole-disk device (no partition table on this node).
    WholeDisk,
    /// Could not be determined. Different from `LinuxFilesystem`:
    /// explicitly a probe gap, not a positive classification.
    Unknown,
}

/// One block device as observed by the discovery pass. Every optional
/// field is `Option<T>` so we can express "not probed" vs "absent" vs
/// "unreadable"; for the latter, an [`Evidence`] entry in `evidence`
/// carries the failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockDevice {
    /// Kernel device name, e.g. `nvme0n1p2`. Stable within a boot.
    pub name: String,
    /// Preferred `/dev` path, e.g. `/dev/nvme0n1p2`. May be `None` when
    /// the device has no stable `/dev` entry (rare; only certain dm
    /// nodes in degraded environments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_path: Option<PathBuf>,
    /// `major:minor`, parsed from `/sys/class/block/<name>/dev`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub major_minor: Option<String>,
    /// Kernel name of the parent device (the disk for a partition, the
    /// VG/PV backing for an LV). Empty for whole disks.
    #[serde(default)]
    pub parent: String,
    /// Coarse device class.
    pub class: DeviceClass,
    /// Refined disk/partition-table kind.
    pub disk_kind: DiskKind,
    /// Detected partition role for partitions; `WholeDisk` / `Unknown`
    /// for disks.
    pub partition_role: PartitionRole,
    /// Partition number, when this is a partition. `None` for whole disks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_number: Option<u32>,
    /// Device size in 512-byte sectors (matches /sys/class/block/<>/size).
    /// `None` when the sysfs attribute is unreadable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_sectors: Option<u64>,
    /// Whether the device reports itself read-only via `/sys/.../ro`.
    pub read_only: bool,
    /// Whether the device reports itself removable via `/sys/.../removable`.
    pub removable: bool,
    /// Filesystem type if detected (ext4, btrfs, vfat, swap, ...).
    /// `None` means we did not positively identify a filesystem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<String>,
    /// Filesystem UUID (blkid-style). Distinct from PARTUUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// GPT partition UUID (only for partitions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_uuid: Option<String>,
    /// Filesystem LABEL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// GPT partition LABEL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_label: Option<String>,
    /// Current mount point (canonical path) when the device is mounted
    /// in `/proc/self/mountinfo` at the moment of discovery. `None` is
    /// "not mounted as far as we can see".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<PathBuf>,
    /// Every mount observed for this device. `mount_point` remains the
    /// primary/first mount for compatibility; this vector preserves
    /// multiple Btrfs subvolumes and repeated mounts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountObservation>,
    /// Whether the device was mounted BEFORE this program started. If
    /// true, the device must NEVER be unmounted by our mount session.
    /// We track this as an explicit field (not derived from `mount_point`)
    /// because a mount session might mount on top of a pre-existing
    /// mount of the same device — only the session-owned layer is ours.
    #[serde(default)]
    pub mounted_before_session: bool,
    /// Sub-probe evidence: why we classified this device the way we did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountObservation {
    pub mount_point: PathBuf,
    pub root: PathBuf,
    pub fstype: String,
    pub read_only: bool,
}

impl BlockDevice {
    /// Human-friendly size in bytes; `None` if size was not probed.
    pub fn size_bytes(&self) -> Option<u64> {
        self.size_sectors.map(|s| s * 512)
    }
}

// ---------------------------------------------------------------------------
// Btrfs subvolume classification
// ---------------------------------------------------------------------------

/// What kind of subvolume this is. Distinct from the filesystem type
/// itself: a single btrfs filesystem can host hundreds of subvolumes,
/// only some of which are usable as a system root.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BtrfsSubvolumeKind {
    /// Top-level subvolume (subvolid=5 by kernel convention).
    TopLevel,
    /// Plausible Linux root subvolume (named @, @root, root and containing
    /// an OS layout). Determined by post-mount inspection, NOT by name
    /// alone.
    #[default]
    RootCandidate,
    /// Read-write subvolume that looks like a snapshot container
    /// (`.snapshots`, `timeshift-btrfs`, etc.) but is not itself a usable
    /// root.
    SnapshotContainer,
    /// Positively identified read-only snapshot.
    ReadOnlySnapshot,
    /// Subvolume whose contents do not look like a system root (data
    /// directory, home, etc.).
    Data,
    /// Could not be classified without mounting; we did not inspect.
    Unknown,
}

/// A discovered btrfs subvolume. `path` is the subvolume path relative
/// to the toplevel (`/`); `id` is the kernel subvolid when known.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BtrfsSubvolume {
    /// Subvolume path relative to the toplevel, with leading slash, e.g.
    /// `/@`, `/@home`, `/.snapshots/2024-...`.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// Subvolume name as btrfs exposes it (last path component).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub kind: BtrfsSubvolumeKind,
    /// True iff the kernel reports this as the default subvolume (used
    /// when no `subvol=`/`subvolid=` is given at mount time).
    pub is_default: bool,
    /// True iff the subvolume was reported read-only by btrfs.
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

// ---------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------

/// Confidence in a candidate identification. Explicit four-state to
/// forbid collapsing "low" into "unknown" or vice versa.
///
/// Confidence levels are produced by deterministic rules documented in
/// `probe/candidate.rs`. They are NOT a numeric score and never will be.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RootCandidateConfidence {
    /// Multiple strong OS-layout signals present AND os-release positively
    /// identifies a Linux/CatOS root.
    High,
    /// OS-layout signals present but os-release was missing or unreadable,
    /// OR os-release was readable but did not match CatOS.
    Medium,
    /// Only one weak signal (e.g. `/etc` alone) — could equally be a
    /// data partition or stale recovery artifact.
    Low,
    /// Identification incomplete (e.g. we never mounted this candidate
    /// to inspect its contents). Distinct from Low: we are not asserting
    /// the candidate is weak, we are asserting we cannot rank it.
    #[default]
    Unknown,
}

/// Why this candidate was demoted or rejected. Carried in
/// [`RootCandidate::demotion_reasons`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DemotionReason {
    /// os-release readable but does not identify CatOS.
    NotCatOs,
    /// No /etc/os-release and no /usr/lib/os-release found.
    NoOsRelease,
    /// Required OS-layout directory missing (e.g. no /usr).
    MissingOsLayout,
    /// Candidate looks like a snapshot, not a current root.
    SnapshotSubvolume,
    /// Candidate is a read-only snapshot.
    ReadOnlySnapshot,
    /// Filesystem type is one we deliberately treat as low-confidence
    /// for root identification (e.g. swap, vfat, exfat).
    ImplausibleFilesystem,
    /// fstab explicitly refers to a different device for `/`.
    FstabPointsElsewhere,
}

/// A possible Linux/CatOS root filesystem. Evidence-driven; never
/// produced from a label or a name guess.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootCandidate {
    /// Best `/dev` path (or other source) we used to mount or would mount.
    pub source: String,
    /// Filesystem type, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<String>,
    /// Btrfs subvolume path (e.g. `/@`) when the candidate is a
    /// subvolume rather than the toplevel. `None` for non-btrfs filesystems
    /// or for the btrfs toplevel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subvolume: Option<String>,
    /// Confidence classification with the rules above.
    pub confidence: RootCandidateConfidence,
    /// Whether os-release positively identifies CatOS.
    pub is_catos: Detection,
    /// Whether the candidate is positively mounted right now.
    pub mounted_at: Option<PathBuf>,
    /// OS-layout signals observed (or not) — /etc/os-release, /etc/fstab,
    /// /usr, /var/lib/pacman/local, /boot.
    pub signals: OsLayoutSignals,
    /// Reasons this candidate was demoted below `High`. Empty for `High`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub demotion_reasons: Vec<DemotionReason>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// Presence of OS-layout signals under a mounted candidate. Used for
/// confidence scoring and reported in JSON so consumers can replay the
/// decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OsLayoutSignals {
    pub has_os_release: Presence2,
    pub has_fstab: Presence2,
    pub has_usr: Presence2,
    pub has_pacman_db: Presence2,
    pub has_boot: Presence2,
}

/// Local copy of three-state presence for storage models. Identical to
/// `inspection::Presence` in semantics; kept separate so a future
/// divergence in field names does not silently break the JSON contract
/// of the existing `inspect` command.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Presence2 {
    #[default]
    Unknown,
    Present,
    Absent,
}

impl From<crate::model::inspection::Presence> for Presence2 {
    fn from(p: crate::model::inspection::Presence) -> Self {
        match p {
            crate::model::inspection::Presence::Present => Presence2::Present,
            crate::model::inspection::Presence::Absent => Presence2::Absent,
            crate::model::inspection::Presence::Unknown => Presence2::Unknown,
        }
    }
}

/// A possible EFI System Partition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EspCandidate {
    /// Best `/dev` path for the candidate.
    pub source: String,
    /// Confidence in this being an ESP. Reuses the same enum as root
    /// candidates because the model is identical: evidence-driven,
    /// four-state, never a numeric score.
    pub confidence: RootCandidateConfidence,
    /// Combined ESP evidence: GPT type, FAT fs, size, mount point, fstab.
    pub signals: EspSignals,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// ESP-detection signals. Each field contributes to confidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EspSignals {
    /// GPT partition type matches the ESP GUID.
    pub gpt_esp_type: bool,
    /// Filesystem is FAT (vfat / fat32 / exfat).
    pub fat_filesystem: bool,
    /// Partition size is in the plausible ESP range (we keep this loose:
    /// 32 MiB .. 1 GiB; bigger or smaller does not disqualify on its own).
    pub plausible_size: bool,
    /// Partition is currently mounted at a typical ESP location
    /// (/boot/efi, /efi, /boot).
    pub mounted_at_esp_location: bool,
    /// fstab references this device for one of /boot/efi, /efi, /boot.
    pub fstab_referenced: bool,
    /// Toplevel directory listing includes `EFI/` (the canonical layout).
    pub has_efi_directory: bool,
}

// ---------------------------------------------------------------------------
// Top-level report
// ---------------------------------------------------------------------------

/// Snapshot of storage state at a single point in time. The phase-2
/// `storage scan` subcommand emits this directly; the `storage candidates`
/// subcommand emits the inner candidate lists with the device array
/// hidden.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StorageReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<BlockDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_candidates: Vec<RootCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub esp_candidates: Vec<EspCandidate>,
    /// Btrfs subvolumes observed while probing an unmounted filesystem.
    /// Empty when no btrfs filesystem was probed or the helper was absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub btrfs_subvolumes: Vec<BtrfsSubvolume>,
    /// Non-fatal notices from the discovery layer (e.g. "blkid not found,
    /// continuing with sysfs only").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
    /// Explicit ambiguity flags derived from `root_candidates` /
    /// `esp_candidates`. Empty when identification is unambiguous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambiguities: Vec<Ambiguity>,
}

/// An ambiguity is reported (NOT silently resolved) when multiple
/// candidates meet the same confidence level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ambiguity {
    /// What kind of candidate is ambiguous.
    pub kind: AmbiguityKind,
    /// Sources participating in the ambiguity.
    pub candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityKind {
    /// Multiple root candidates at the same confidence level.
    Root,
    /// Multiple ESP candidates at the same confidence level.
    Esp,
}

// ---------------------------------------------------------------------------
// Unit tests for the pure helpers and serde shape
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_confidence_default_is_unknown() {
        // Default must be Unknown, not High — never a false positive.
        assert_eq!(
            RootCandidateConfidence::default(),
            RootCandidateConfidence::Unknown
        );
    }

    #[test]
    fn partition_role_gpt_other_round_trips_through_json() {
        // The shape of an "unclassified" GPT partition type is part of the
        // contract; we must not lose the raw GUID via enum collapse.
        let r = PartitionRole::GptOther("11111111-1111-1111-1111-111111111111".to_string());
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("gpt_other"));
        let back: PartitionRole = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn esp_signals_default_is_all_false_not_unknown() {
        // For ESP we deliberately use bool (vs Presence2) because every
        // signal is positively derived from observation, never inferred.
        let s = EspSignals::default();
        assert!(!s.gpt_esp_type);
        assert!(!s.fat_filesystem);
    }

    #[test]
    fn block_device_size_bytes_uses_512_byte_sectors() {
        // Guards against an off-by-one where someone confuses sectors and
        // blocks; the kernel /sys/class/block/<>/size is always in
        // 512-byte sectors.
        let d = BlockDevice {
            name: "sda1".into(),
            dev_path: Some(PathBuf::from("/dev/sda1")),
            major_minor: Some("8:1".into()),
            parent: "sda".into(),
            class: DeviceClass::Partition,
            disk_kind: DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: Some(1),
            size_sectors: Some(2048),
            read_only: false,
            removable: false,
            filesystem: Some("ext4".into()),
            uuid: None,
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: vec![],
            mounted_before_session: false,
            evidence: vec![],
        };
        assert_eq!(d.size_bytes(), Some(2048 * 512));
    }

    #[test]
    fn presence2_mirrors_inspection_presence() {
        // The two enums must stay semantically aligned so cross-module
        // conversion is lossless.
        use crate::model::inspection::Presence as P1;
        assert_eq!(Presence2::from(P1::Present), Presence2::Present);
        assert_eq!(Presence2::from(P1::Absent), Presence2::Absent);
        assert_eq!(Presence2::from(P1::Unknown), Presence2::Unknown);
    }
}
