//! Target-domain data model. Pure data + serde. No I/O.
//!
//! Contents migrated in phase 1 from the legacy flat
//! `shared::model::{storage::storage, system::{capability,inspection,runtime}}`
//! modules so the `target` capability owns its own vocabulary.
//!
//! This module deliberately contains NO Doctor / Repair / Recovery report
//! types; those remain in `shared::model`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::evidence::Evidence;

// ===========================================================================
// Target identity
// ===========================================================================

/// Stable identity of a selected target. The minimal, mount-free shape
/// used by the target plan and Doctor. Mount-repair's richer
/// `TargetIdentity` (which carries ESP + boot layout) stays in
/// `shared::model::mount_repair` for now; phase 4 will unify them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetIdentity {
    /// Resolved target root path (offline mount point or `/` for the
    /// running root).
    pub root: PathBuf,
    /// Resolved block-device path for the root filesystem, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_device: Option<PathBuf>,
    /// Filesystem type of the root filesystem (`btrfs`, `ext4`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_fstype: Option<String>,
    /// Root subvolume path for btrfs roots (e.g. `/@`). `None` for
    /// non-btrfs roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_subvol: Option<String>,
    /// UUID of the root filesystem, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_uuid: Option<String>,
}

// ===========================================================================
// Storage device + candidate model
// ===========================================================================
//
// Target owns the canonical block-device and candidate types consumed by
// every higher capability crate.

/// Coarse device class.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Disk,
    Partition,
    DeviceMapper,
    MdRaid,
    Loop,
    #[default]
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    #[default]
    Unknown,
    Gpt,
    Mbr,
    Bare,
    Loop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PartitionRole {
    Esp,
    BiosBoot,
    LinuxFilesystem,
    Microsoft,
    MbrOther(u8),
    GptOther(String),
    WholeDisk,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockDevice {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub major_minor: Option<String>,
    #[serde(default)]
    pub parent: String,
    pub class: DeviceClass,
    pub disk_kind: DiskKind,
    pub partition_role: PartitionRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_number: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_sectors: Option<u64>,
    pub read_only: bool,
    pub removable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountObservation>,
    #[serde(default)]
    pub mounted_before_session: bool,
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
    pub fn size_bytes(&self) -> Option<u64> {
        self.size_sectors.map(|s| s * 512)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BtrfsSubvolumeKind {
    TopLevel,
    #[default]
    RootCandidate,
    SnapshotContainer,
    ReadOnlySnapshot,
    Data,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BtrfsSubvolume {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub kind: BtrfsSubvolumeKind,
    pub is_default: bool,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RootCandidateConfidence {
    High,
    Medium,
    Low,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DemotionReason {
    NotCatOs,
    NoOsRelease,
    MissingOsLayout,
    SnapshotSubvolume,
    ReadOnlySnapshot,
    ImplausibleFilesystem,
    FstabPointsElsewhere,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootCandidate {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subvolume: Option<String>,
    pub confidence: RootCandidateConfidence,
    pub is_catos: Detection,
    pub mounted_at: Option<PathBuf>,
    pub signals: OsLayoutSignals,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub demotion_reasons: Vec<DemotionReason>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OsLayoutSignals {
    pub has_os_release: Presence2,
    pub has_fstab: Presence2,
    pub has_usr: Presence2,
    pub has_pacman_db: Presence2,
    pub has_boot: Presence2,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Presence2 {
    #[default]
    Unknown,
    Present,
    Absent,
}

impl From<Presence> for Presence2 {
    fn from(p: Presence) -> Self {
        match p {
            Presence::Present => Presence2::Present,
            Presence::Absent => Presence2::Absent,
            Presence::Unknown => Presence2::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EspCandidate {
    pub source: String,
    pub confidence: RootCandidateConfidence,
    pub signals: EspSignals,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EspSignals {
    pub gpt_esp_type: bool,
    pub fat_filesystem: bool,
    pub plausible_size: bool,
    pub mounted_at_esp_location: bool,
    pub fstab_referenced: bool,
    pub has_efi_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StorageReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<BlockDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_candidates: Vec<RootCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub esp_candidates: Vec<EspCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub btrfs_subvolumes: Vec<BtrfsSubvolume>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambiguities: Vec<Ambiguity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ambiguity {
    pub kind: AmbiguityKind,
    pub candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityKind {
    Root,
    Esp,
}

// ===========================================================================
// Capability model (migrated from shared/model/system/capability.rs)
// ===========================================================================

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Available,
    Unavailable,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    ReadTargetRoot,
    ReadProc,
    ReadSysfs,
    ReadBlockSysfs,
    AccessDev,
    ShellAvailable,
    MountOperationsPossible,
    WriteEfivarsPossible,
    SystemdAvailable,
    PacmanPresentInTarget,
    MkinitcpioPresentInTarget,
    BtrfsToolAvailable,
    CryptsetupAvailable,
    LsblkAvailable,
    MountToolAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub name: CapabilityKind,
    pub status: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl Capability {
    pub fn available(name: CapabilityKind, evidence: Vec<Evidence>) -> Self {
        Self {
            name,
            status: CapabilityStatus::Available,
            evidence,
        }
    }
    pub fn unavailable(name: CapabilityKind, evidence: Vec<Evidence>) -> Self {
        Self {
            name,
            status: CapabilityStatus::Unavailable,
            evidence,
        }
    }
    pub fn unknown(name: CapabilityKind, evidence: Vec<Evidence>) -> Self {
        Self {
            name,
            status: CapabilityStatus::Unknown,
            evidence,
        }
    }
}

// ===========================================================================
// Inspection model (migrated from shared/model/system/inspection.rs)
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct OsRelease {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_like: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pretty_name: Option<String>,
    #[serde(default)]
    pub raw_fields: Vec<(String, String)>,
}

impl OsRelease {
    pub fn parse(input: &str) -> OsRelease {
        let mut out = OsRelease::default();
        for raw_line in input.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim().to_string();
            if key.is_empty() {
                continue;
            }
            let value = normalise_os_release_value(value.trim());
            match key.as_str() {
                "NAME" => out.name = Some(value.clone()),
                "ID" => out.id = Some(value.clone()),
                "ID_LIKE" => out.id_like = Some(value.clone()),
                "VERSION" => out.version = Some(value.clone()),
                "PRETTY_NAME" => out.pretty_name = Some(value.clone()),
                _ => {}
            }
            out.raw_fields.push((key, value));
        }
        out
    }

    pub fn looks_like_catos(&self) -> bool {
        let matches = |s: &Option<String>| {
            s.as_ref()
                .is_some_and(|v| v.to_ascii_lowercase().contains("catos"))
        };
        matches(&self.id) || matches(&self.id_like) || matches(&self.name)
    }
}

fn normalise_os_release_value(raw: &str) -> String {
    let s = raw.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    #[default]
    Unknown,
    Present,
    Absent,
}

impl Presence {
    pub fn as_str(self) -> &'static str {
        match self {
            Presence::Present => "present",
            Presence::Absent => "absent",
            Presence::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Presence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPath {
    pub name: String,
    pub path: PathBuf,
    pub status: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TargetInspection {
    pub root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_release: Option<OsRelease>,
    pub has_fstab: Presence,
    pub has_crypttab: Presence,
    pub has_pacman_db: Presence,
    pub has_usr: Presence,
    pub has_boot: Presence,
    pub has_efi: Presence,
    pub has_boot_efi: Presence,
    pub is_catos_target: Detection,
    #[serde(default)]
    pub tool_paths: Vec<ToolPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

impl Warning {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "programVersion")]
    pub program_version: String,
    pub invocation: String,
    #[serde(rename = "targetRoot")]
    pub target_root: PathBuf,
    pub runtime: RuntimeFacts,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    pub target: TargetInspection,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

// ===========================================================================
// Runtime model (migrated from shared/model/system/runtime.rs)
// ===========================================================================

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    Detected,
    NotDetected,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Detection {
    pub status: DetectionStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl Detection {
    pub fn detected(evidence: Vec<Evidence>) -> Self {
        Self {
            status: DetectionStatus::Detected,
            evidence,
        }
    }

    pub fn not_detected(evidence: Vec<Evidence>) -> Self {
        Self {
            status: DetectionStatus::NotDetected,
            evidence,
        }
    }

    pub fn unknown(evidence: Vec<Evidence>) -> Self {
        Self {
            status: DetectionStatus::Unknown,
            evidence,
        }
    }

    pub fn is_detected(&self) -> bool {
        matches!(self.status, DetectionStatus::Detected)
    }

    pub fn merge(self, other: Detection) -> Detection {
        use DetectionStatus::*;
        let mut evidence = self.evidence;
        evidence.extend(other.evidence);
        let status = match (self.status, other.status) {
            (Detected, Detected) => Detected,
            (NotDetected, NotDetected) => NotDetected,
            (a, Unknown) => a,
            (Unknown, b) => b,
            _ => Unknown,
        };
        Detection { status, evidence }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RuntimeFacts {
    pub is_initramfs: Detection,
    pub is_chroot: Detection,
    pub is_live_environment: Detection,
    pub is_snapshot_boot: Detection,
    pub has_systemd: Detection,
    pub root_is_read_only: Detection,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryRuntimeMode {
    RunningSystem,
    Chroot,
    LiveEnvironment,
    Initramfs,
    Unknown,
}

impl RuntimeFacts {
    pub fn primary_mode(&self) -> PrimaryRuntimeMode {
        use DetectionStatus::*;
        if matches!(self.is_initramfs.status, Detected) {
            return PrimaryRuntimeMode::Initramfs;
        }
        if matches!(self.is_live_environment.status, Detected) {
            return PrimaryRuntimeMode::LiveEnvironment;
        }
        if matches!(self.is_chroot.status, Detected) {
            return PrimaryRuntimeMode::Chroot;
        }
        if [
            self.is_initramfs.status,
            self.is_live_environment.status,
            self.is_chroot.status,
        ]
        .iter()
        .all(|status| matches!(status, NotDetected))
        {
            PrimaryRuntimeMode::RunningSystem
        } else {
            PrimaryRuntimeMode::Unknown
        }
    }
}

// ===========================================================================
// Unit tests migrated verbatim from the three legacy source files.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_confidence_default_is_unknown() {
        assert_eq!(
            RootCandidateConfidence::default(),
            RootCandidateConfidence::Unknown
        );
    }

    #[test]
    fn partition_role_gpt_other_round_trips_through_json() {
        let r = PartitionRole::GptOther("11111111-1111-1111-1111-111111111111".to_string());
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("gpt_other"));
        let back: PartitionRole = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn block_device_size_bytes_uses_512_byte_sectors() {
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
    fn presence2_mirrors_presence() {
        assert_eq!(Presence2::from(Presence::Present), Presence2::Present);
        assert_eq!(Presence2::from(Presence::Absent), Presence2::Absent);
        assert_eq!(Presence2::from(Presence::Unknown), Presence2::Unknown);
    }

    #[test]
    fn parses_basic_os_release() {
        let src = "# comment\nNAME=\"CatOS\"\nID=catos\nID_LIKE=arch\nVERSION=1\n";
        let p = OsRelease::parse(src);
        assert_eq!(p.name.as_deref(), Some("CatOS"));
        assert_eq!(p.id.as_deref(), Some("catos"));
        assert_eq!(p.id_like.as_deref(), Some("arch"));
        assert!(p.looks_like_catos());
    }

    #[test]
    fn os_release_handles_single_quotes_and_bare() {
        let p = OsRelease::parse("NAME='Arch'\nPRETTY_NAME=Arch Linux");
        assert_eq!(p.name.as_deref(), Some("Arch"));
        assert_eq!(p.pretty_name.as_deref(), Some("Arch Linux"));
        assert!(!p.looks_like_catos());
    }

    #[test]
    fn os_release_skips_malformed_lines() {
        let p = OsRelease::parse("garbage line\n=\nID=arch\n");
        assert_eq!(p.id.as_deref(), Some("arch"));
        assert_eq!(p.raw_fields.len(), 1);
    }

    #[test]
    fn merge_conflict_produces_unknown() {
        let a = Detection::detected(vec![]);
        let b = Detection::not_detected(vec![]);
        assert_eq!(a.merge(b).status, DetectionStatus::Unknown);
    }

    #[test]
    fn merge_same_status_preserves_it() {
        let a = Detection::detected(vec![]);
        let b = Detection::detected(vec![]);
        assert_eq!(a.merge(b).status, DetectionStatus::Detected);
    }

    #[test]
    fn merge_with_unknown_preserves_other() {
        let a = Detection::detected(vec![]);
        let b = Detection::unknown(vec![]);
        assert_eq!(a.merge(b).status, DetectionStatus::Detected);
    }

    #[test]
    fn unknown_status_does_not_serialize_as_false() {
        let d = Detection::unknown(vec![]);
        let json = serde_json::to_string(&d.status).unwrap();
        assert_eq!(json, "\"unknown\"");
    }

    #[test]
    fn primary_mode_is_running_only_when_special_environments_are_ruled_out() {
        let not_detected = || Detection::not_detected(vec![]);
        let facts = RuntimeFacts {
            is_initramfs: not_detected(),
            is_chroot: not_detected(),
            is_live_environment: not_detected(),
            is_snapshot_boot: Detection::unknown(vec![]),
            has_systemd: Detection::unknown(vec![]),
            root_is_read_only: Detection::unknown(vec![]),
        };
        assert_eq!(facts.primary_mode(), PrimaryRuntimeMode::RunningSystem);
    }
}
