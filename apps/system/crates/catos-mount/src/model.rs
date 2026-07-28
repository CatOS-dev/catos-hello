//! Mount-domain data model: mount plan + session + structured error
//! taxonomy, fstab/mountinfo-independent mount repair data, and the
//! mount target identity.
//!
//! Pure data + serde, no I/O. Sourced from the phase-1 `shared::model`
//! storage/repair modules; consolidated here as the single mount-domain
//! model home.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use catos_target::model::Warning;
use catos_target::Evidence;

// ===========================================================================
// Errors
// ===========================================================================

/// Structured mount-layer error. Each variant maps to a stable string
/// code in JSON (see [`MountError::code`]). Distinct from the probe-level
/// `FsError`: this only describes mount operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountError {
    pub kind: MountErrorKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_or_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_steps: Vec<String>,
    pub cleanup_complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residual_mounts: Vec<String>,
}

impl MountError {
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl std::fmt::Display for MountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message)?;
        if let Some(d) = &self.device_or_path {
            write!(f, " (device={d})")?;
        }
        Ok(())
    }
}

/// All mount-layer failure modes. Variants are part of the JSON contract;
/// do not rename. Adding a variant is backward-compatible.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MountErrorKind {
    CapabilityMissing,
    PermissionDenied,
    NamespaceUnavailable,
    DeviceNotFound,
    DeviceBusy,
    AlreadyMounted,
    UnsupportedFilesystem,
    WrongFilesystemType,
    InvalidMountOption,
    BadSuperblock,
    UnsafeReadOnlyMode,
    AmbiguousDeviceReference,
    AmbiguousRootCandidate,
    UnsafeTargetPath,
    MountFailed,
    UnmountFailed,
    CleanupIncomplete,
    ExternalToolMissing,
    ExternalToolFailed,
    ExternalOutputInvalid,
}

impl MountErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            MountErrorKind::CapabilityMissing => "capability_missing",
            MountErrorKind::PermissionDenied => "permission_denied",
            MountErrorKind::NamespaceUnavailable => "namespace_unavailable",
            MountErrorKind::DeviceNotFound => "device_not_found",
            MountErrorKind::DeviceBusy => "device_busy",
            MountErrorKind::AlreadyMounted => "already_mounted",
            MountErrorKind::UnsupportedFilesystem => "unsupported_filesystem",
            MountErrorKind::WrongFilesystemType => "wrong_filesystem_type",
            MountErrorKind::InvalidMountOption => "invalid_mount_option",
            MountErrorKind::BadSuperblock => "bad_superblock",
            MountErrorKind::UnsafeReadOnlyMode => "unsafe_read_only_mode",
            MountErrorKind::AmbiguousDeviceReference => "ambiguous_device_reference",
            MountErrorKind::AmbiguousRootCandidate => "ambiguous_root_candidate",
            MountErrorKind::UnsafeTargetPath => "unsafe_target_path",
            MountErrorKind::MountFailed => "mount_failed",
            MountErrorKind::UnmountFailed => "unmount_failed",
            MountErrorKind::CleanupIncomplete => "cleanup_incomplete",
            MountErrorKind::ExternalToolMissing => "external_tool_missing",
            MountErrorKind::ExternalToolFailed => "external_tool_failed",
            MountErrorKind::ExternalOutputInvalid => "external_output_invalid",
        }
    }
}

// ===========================================================================
// Mount namespace
// ===========================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceState {
    PrivateNamespace,
    #[default]
    HostNamespaceRefused,
    SetupFailed,
}

// ===========================================================================
// Mount plan
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountStep {
    pub order: u32,
    pub source: String,
    pub fstype: String,
    pub target: PathBuf,
    pub options: Vec<String>,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl MountStep {
    pub fn options_string(&self) -> String {
        self.options.join(",")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountPlan {
    pub session_root: PathBuf,
    pub target_root: PathBuf,
    pub namespace: NamespaceState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_subvolume: Option<String>,
    #[serde(default)]
    pub extra_partitions: Vec<String>,
    pub steps: Vec<MountStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selection_rationale: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safety_constraints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

// ===========================================================================
// Mount session
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountedResource {
    pub order: u32,
    pub source: String,
    pub target: PathBuf,
    pub fstype: String,
    pub options: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MountSessionState {
    #[default]
    Ready,
    Active,
    RollingBack,
    Cleaned,
    CleanupIncomplete,
    Finished,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountSession {
    pub id: String,
    pub state: MountSessionState,
    pub namespace: NamespaceState,
    pub session_root: PathBuf,
    pub target_root: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountedResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupReport {
    #[serde(default)]
    pub unmounted: Vec<MountedResource>,
    #[serde(default)]
    pub residual: Vec<ResidualMount>,
    #[serde(default)]
    pub observed_pre_existing: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_cleanup_error: Option<String>,
    pub all_clean: bool,
}

impl Default for CleanupReport {
    fn default() -> Self {
        Self {
            unmounted: Vec::new(),
            residual: Vec::new(),
            observed_pre_existing: Vec::new(),
            directory_cleanup_error: None,
            all_clean: true,
        }
    }
}

/// Compact cleanup summary shared with application transaction records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CleanupSummary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmounted: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residual: Vec<String>,
    pub all_clean: bool,
}

impl From<CleanupReport> for CleanupSummary {
    fn from(report: CleanupReport) -> Self {
        let mut residual = report
            .residual
            .into_iter()
            .map(|residual| {
                format!(
                    "{}: {}",
                    residual.resource.target.display(),
                    residual.reason
                )
            })
            .collect::<Vec<_>>();
        if let Some(error) = report.directory_cleanup_error {
            residual.push(error);
        }
        let all_clean = report.all_clean && residual.is_empty();
        Self {
            unmounted: report
                .unmounted
                .into_iter()
                .map(|resource| resource.target.display().to_string())
                .collect(),
            residual,
            all_clean,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidualMount {
    pub resource: MountedResource,
    pub reason: String,
    pub error_code: String,
}

// ===========================================================================
// CatOS standard btrfs layout (single source of truth)
// ===========================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatosSubvolSpec {
    pub mount_point: &'static str,
    pub subvol: &'static str,
}

pub const CATOS_STANDARD_SUBVOLS: &[CatosSubvolSpec] = &[
    CatosSubvolSpec {
        mount_point: "/",
        subvol: "/@",
    },
    CatosSubvolSpec {
        mount_point: "/home",
        subvol: "/@home",
    },
    CatosSubvolSpec {
        mount_point: "/root",
        subvol: "/@root",
    },
    CatosSubvolSpec {
        mount_point: "/srv",
        subvol: "/@srv",
    },
    CatosSubvolSpec {
        mount_point: "/var/cache",
        subvol: "/@cache",
    },
    CatosSubvolSpec {
        mount_point: "/var/tmp",
        subvol: "/@tmp",
    },
    CatosSubvolSpec {
        mount_point: "/var/log",
        subvol: "/@log",
    },
    CatosSubvolSpec {
        mount_point: "/.snapshots",
        subvol: "/@snapshots",
    },
];

pub fn standard_subvol_for_mount_point(mount_point: &str) -> Option<&'static str> {
    CATOS_STANDARD_SUBVOLS
        .iter()
        .find(|row| row.mount_point == mount_point)
        .map(|row| row.subvol)
}

pub fn standard_mount_point_for_subvol(subvol: &str) -> Option<&'static str> {
    CATOS_STANDARD_SUBVOLS
        .iter()
        .find(|row| row.subvol == subvol)
        .map(|row| row.mount_point)
}

pub fn default_mount_options(fstype: &str) -> Option<&'static str> {
    match fstype {
        "btrfs" => Some("defaults,noatime,compress=zstd,commit=120"),
        "ext4" => Some("defaults,noatime,commit=60"),
        "xfs" => Some("defaults,lazytime,noatime,attr2,inode64,logbsize=256k,noquota"),
        "f2fs" => Some("defaults,compress_algorithm=lz4,compress_chksum,gc_merge,lazytime"),
        "vfat" | "fat" | "exfat" => Some("defaults,umask=0077"),
        _ => None,
    }
}

// ===========================================================================
// Boot / ESP mount topology
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootMountLayout {
    EspAtBootEfi {
        esp_device: PathBuf,
    },
    EspAtEfi {
        esp_device: PathBuf,
    },
    EspAtBoot {
        esp_device: PathBuf,
    },
    SeparateBootAndEsp {
        boot_device: PathBuf,
        esp_device: PathBuf,
        esp_mount_point: String,
    },
    BootBtrfsSubvolume {
        subvolume: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        esp_device: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        esp_mount_point: Option<String>,
    },
    BootInsideRoot,
}

impl BootMountLayout {
    pub fn esp_device(&self) -> Option<&Path> {
        match self {
            BootMountLayout::EspAtBootEfi { esp_device }
            | BootMountLayout::EspAtEfi { esp_device }
            | BootMountLayout::EspAtBoot { esp_device }
            | BootMountLayout::SeparateBootAndEsp { esp_device, .. } => Some(esp_device),
            BootMountLayout::BootBtrfsSubvolume { esp_device, .. } => esp_device.as_deref(),
            BootMountLayout::BootInsideRoot => None,
        }
    }

    pub fn esp_mount_point(&self) -> Option<&str> {
        match self {
            BootMountLayout::EspAtBootEfi { .. } => Some("/boot/efi"),
            BootMountLayout::EspAtEfi { .. } => Some("/efi"),
            BootMountLayout::EspAtBoot { .. } => Some("/boot"),
            BootMountLayout::SeparateBootAndEsp {
                esp_mount_point, ..
            } => Some(esp_mount_point),
            BootMountLayout::BootBtrfsSubvolume {
                esp_mount_point, ..
            } => esp_mount_point.as_deref(),
            BootMountLayout::BootInsideRoot => None,
        }
    }
}

// ===========================================================================
// Final outcome taxonomy
// ===========================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MountRepairOutcome {
    Clean,
    Repaired,
    PartiallyRepaired,
    AmbiguousTarget,
    NotCatos,
    UnsafePath,
    ConflictingFstab,
    DeviceChanged,
    FstabChanged,
    SubvolumeConflict,
    DataConflict,
    VerificationFailed,
    RollbackFailed,
    CleanupIncomplete,
    UnsupportedLayout,
    #[default]
    Unknown,
}

impl MountRepairOutcome {
    pub fn code(self) -> &'static str {
        match self {
            MountRepairOutcome::Clean => "clean",
            MountRepairOutcome::Repaired => "repaired",
            MountRepairOutcome::PartiallyRepaired => "partially_repaired",
            MountRepairOutcome::AmbiguousTarget => "ambiguous_target",
            MountRepairOutcome::NotCatos => "not_catos",
            MountRepairOutcome::UnsafePath => "unsafe_path",
            MountRepairOutcome::ConflictingFstab => "conflicting_fstab",
            MountRepairOutcome::DeviceChanged => "device_changed",
            MountRepairOutcome::FstabChanged => "fstab_changed",
            MountRepairOutcome::SubvolumeConflict => "subvolume_conflict",
            MountRepairOutcome::DataConflict => "data_conflict",
            MountRepairOutcome::VerificationFailed => "verification_failed",
            MountRepairOutcome::RollbackFailed => "rollback_failed",
            MountRepairOutcome::CleanupIncomplete => "cleanup_incomplete",
            MountRepairOutcome::UnsupportedLayout => "unsupported_layout",
            MountRepairOutcome::Unknown => "unknown",
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, MountRepairOutcome::Clean | MountRepairOutcome::Repaired)
    }

    pub fn is_refusal(self) -> bool {
        matches!(
            self,
            MountRepairOutcome::AmbiguousTarget
                | MountRepairOutcome::NotCatos
                | MountRepairOutcome::UnsafePath
                | MountRepairOutcome::ConflictingFstab
                | MountRepairOutcome::SubvolumeConflict
                | MountRepairOutcome::UnsupportedLayout
        )
    }
}

// ===========================================================================
// Diagnosis problem taxonomy (read-only; shared with Doctor)
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MountProblem {
    UnparseableLine {
        line: usize,
        reason: String,
    },
    MissingRootEntry,
    RootSourceUnresolvable,
    RootUuidMismatch {
        expected: String,
        actual: String,
    },
    RootWrongSubvol {
        actual: String,
    },
    StandardWrongSubvol {
        mount_point: String,
        expected: String,
        actual: String,
    },
    MissingStandardEntry {
        mount_point: String,
        subvol: String,
    },
    SnapshotsWrongSubvol {
        actual: String,
    },
    EspUuidMismatch {
        expected: String,
        actual: String,
    },
    EspMountPointMismatch {
        expected: String,
        actual: String,
    },
    DuplicateMountPoint {
        mount_point: String,
    },
    SwapEntryMistyped,
    MissingSubvolume {
        subvol: String,
    },
    MissingMountPoint {
        mount_point: String,
    },
    UnsafeMountPoint {
        mount_point: String,
        reason: String,
    },
    AmbiguousEsp {
        candidates: Vec<String>,
    },
    StaleSource {
        source: String,
    },
}

impl MountProblem {
    pub fn code(&self) -> &'static str {
        match self {
            MountProblem::UnparseableLine { .. } => "unparseable_line",
            MountProblem::MissingRootEntry => "missing_root_entry",
            MountProblem::RootSourceUnresolvable => "root_source_unresolvable",
            MountProblem::RootUuidMismatch { .. } => "root_uuid_mismatch",
            MountProblem::RootWrongSubvol { .. } => "root_wrong_subvol",
            MountProblem::StandardWrongSubvol { .. } => "standard_wrong_subvol",
            MountProblem::MissingStandardEntry { .. } => "missing_standard_entry",
            MountProblem::SnapshotsWrongSubvol { .. } => "snapshots_wrong_subvol",
            MountProblem::EspUuidMismatch { .. } => "esp_uuid_mismatch",
            MountProblem::EspMountPointMismatch { .. } => "esp_mount_point_mismatch",
            MountProblem::DuplicateMountPoint { .. } => "duplicate_mount_point",
            MountProblem::SwapEntryMistyped => "swap_entry_mistyped",
            MountProblem::MissingSubvolume { .. } => "missing_subvolume",
            MountProblem::MissingMountPoint { .. } => "missing_mount_point",
            MountProblem::UnsafeMountPoint { .. } => "unsafe_mount_point",
            MountProblem::AmbiguousEsp { .. } => "ambiguous_esp",
            MountProblem::StaleSource { .. } => "stale_source",
        }
    }
}

// ===========================================================================
// Edit operations (immutable plan building blocks)
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannedFstabEdit {
    ReplaceSource {
        line: usize,
        new_source: String,
        reason: String,
    },
    ReplaceEntry {
        line: usize,
        new_line: String,
        reason: String,
    },
    AppendEntry {
        new_line: String,
        reason: String,
    },
    DropDuplicate {
        line: usize,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedSubvolume {
    pub subvol: String,
    pub mount_point: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedDirectory {
    pub mount_point: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppliedAction {
    FstabEdited {
        edit: PlannedFstabEdit,
    },
    FstabEditSkipped {
        edit: PlannedFstabEdit,
        reason: String,
    },
    SubvolumeCreated {
        subvol: String,
    },
    SubvolumeSkipped {
        subvol: String,
        reason: String,
    },
    SubvolumeRolledBack {
        subvol: String,
    },
    DirectoryCreated {
        mount_point: String,
    },
    DirectorySkipped {
        mount_point: String,
        reason: String,
    },
    DirectoryRolledBack {
        mount_point: String,
    },
    RollbackResidual {
        resource: String,
        reason: String,
    },
}

// ===========================================================================
// Mount target identity (bound to disk facts at plan time)
// ===========================================================================

/// Snapshot of the mount target root identity at plan time, including
/// the boot/ESP topology signals that mount repair consumes. This is the
/// mount-domain rich identity; the minimal canonical identity lives in
/// `catos_target::model::TargetIdentity`. Any drift detected at apply
/// time MUST abort the plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MountTargetIdentity {
    pub root_device: PathBuf,
    pub root_fstype: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_subvol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_device: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_layout: Option<BootMountLayout>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FstabDigest {
    pub sha256: String,
    pub byte_len: u64,
}

// ===========================================================================
// Immutable RepairPlan
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MountRepairPlan {
    #[serde(default)]
    pub target: MountTargetIdentity,
    #[serde(default)]
    pub fstab_digest: FstabDigest,
    #[serde(default)]
    pub problems: Vec<MountProblem>,
    #[serde(default)]
    pub fstab_edits: Vec<PlannedFstabEdit>,
    #[serde(default)]
    pub subvolumes: Vec<PlannedSubvolume>,
    #[serde(default)]
    pub directories: Vec<PlannedDirectory>,
    #[serde(default)]
    pub unresolved_conflicts: Vec<String>,
    #[serde(default)]
    pub risks: Vec<String>,
}

// ===========================================================================
// Final report
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FstabTransaction {
    pub original_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_path: Option<PathBuf>,
    pub atomic_replace_succeeded: bool,
    pub parent_fsynced: bool,
    #[serde(default)]
    pub rollback_attempted: bool,
    #[serde(default)]
    pub rollback_succeeded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MountVerification {
    pub mounted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_root_fstype: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounted_targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountRepairCleanup {
    #[serde(default)]
    pub unmounted: Vec<String>,
    #[serde(default)]
    pub residual: Vec<String>,
    pub all_clean: bool,
}

impl Default for MountRepairCleanup {
    fn default() -> Self {
        Self {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MountRepairReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<MountTargetIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<MountRepairPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fstab_transaction: Option<FstabTransaction>,
    #[serde(default)]
    pub actions: Vec<AppliedAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<MountVerification>,
    #[serde(default)]
    pub cleanup: MountRepairCleanup,
    pub final_outcome: MountRepairOutcome,
    pub requires_human_action: bool,
    pub fully_complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

impl MountRepairReport {
    pub fn refused(outcome: MountRepairOutcome, reason: &str) -> Self {
        debug_assert!(
            outcome.is_refusal()
                || matches!(
                    outcome,
                    MountRepairOutcome::Unknown | MountRepairOutcome::DeviceChanged
                ),
            "refused() called with non-refusal outcome {outcome:?}"
        );
        Self {
            final_outcome: outcome,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new(
                "REFUSED",
                "repair::mount",
                reason.to_string(),
            )],
            ..Default::default()
        }
    }

    pub fn clean(target: MountTargetIdentity) -> Self {
        Self {
            target: Some(target),
            final_outcome: MountRepairOutcome::Clean,
            requires_human_action: false,
            fully_complete: true,
            evidence: vec![Evidence::new(
                "CLEAN",
                "repair::mount",
                "fstab and standard layout already correct".to_string(),
            )],
            ..Default::default()
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_step_options_string_joins_with_commas() {
        let s = MountStep {
            order: 1,
            source: "/dev/sda1".into(),
            fstype: "ext4".into(),
            target: PathBuf::from("/run/catos-system/sessions/abc/target"),
            options: vec!["ro".into(), "noload".into(), "nosuid".into()],
            rationale: "root fs".into(),
            depends_on: vec![],
            failure_modes: vec![],
            evidence: vec![],
        };
        assert_eq!(s.options_string(), "ro,noload,nosuid");
    }

    #[test]
    fn mount_error_kind_code_matches_serde_variant() {
        for kind in [
            MountErrorKind::CapabilityMissing,
            MountErrorKind::NamespaceUnavailable,
            MountErrorKind::UnsafeReadOnlyMode,
            MountErrorKind::AmbiguousRootCandidate,
            MountErrorKind::CleanupIncomplete,
        ] {
            let j = serde_json::to_string(&kind).unwrap();
            let s = j.trim_matches('"');
            assert_eq!(kind.code(), s, "serde/code drift for {kind:?}");
        }
    }

    #[test]
    fn cleanup_summary_never_reports_clean_with_residual_entries() {
        let report = CleanupReport {
            residual: vec![ResidualMount {
                resource: MountedResource {
                    order: 0,
                    source: "/dev/root".into(),
                    target: PathBuf::from("/run/catos-system/sessions/test"),
                    fstype: "btrfs".into(),
                    options: String::new(),
                },
                reason: "detached lazily".into(),
                error_code: "busy".into(),
            }],
            all_clean: true,
            ..CleanupReport::default()
        };

        let summary = CleanupSummary::from(report);
        assert!(!summary.all_clean);
        assert_eq!(summary.residual.len(), 1);
    }

    #[test]
    fn namespace_state_default_is_host_namespace_refused() {
        assert_eq!(
            NamespaceState::default(),
            NamespaceState::HostNamespaceRefused
        );
    }

    #[test]
    fn mount_session_state_default_is_ready() {
        assert_eq!(MountSessionState::default(), MountSessionState::Ready);
    }

    #[test]
    fn only_complete_mount_outcomes_are_successful() {
        assert!(MountRepairOutcome::Clean.is_success());
        assert!(MountRepairOutcome::Repaired.is_success());
        assert!(!MountRepairOutcome::PartiallyRepaired.is_success());
        assert!(!MountRepairOutcome::VerificationFailed.is_success());
        assert!(!MountRepairOutcome::CleanupIncomplete.is_success());
    }

    #[test]
    fn outcome_code_matches_serde_form() {
        for outcome in [
            MountRepairOutcome::Clean,
            MountRepairOutcome::Repaired,
            MountRepairOutcome::PartiallyRepaired,
            MountRepairOutcome::AmbiguousTarget,
            MountRepairOutcome::NotCatos,
            MountRepairOutcome::UnsafePath,
            MountRepairOutcome::ConflictingFstab,
            MountRepairOutcome::DeviceChanged,
            MountRepairOutcome::FstabChanged,
            MountRepairOutcome::SubvolumeConflict,
            MountRepairOutcome::DataConflict,
            MountRepairOutcome::VerificationFailed,
            MountRepairOutcome::RollbackFailed,
            MountRepairOutcome::CleanupIncomplete,
            MountRepairOutcome::UnsupportedLayout,
            MountRepairOutcome::Unknown,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let trimmed = json.trim_matches('"');
            assert_eq!(outcome.code(), trimmed, "serde/code drift for {outcome:?}");
        }
    }

    #[test]
    fn standard_subvol_table_covers_required_mount_points() {
        let required = [
            "/",
            "/home",
            "/root",
            "/srv",
            "/var/cache",
            "/var/tmp",
            "/var/log",
            "/.snapshots",
        ];
        for mp in required {
            let sub = standard_subvol_for_mount_point(mp);
            assert!(sub.is_some(), "missing standard subvol for {mp}");
        }
        assert_eq!(standard_subvol_for_mount_point("/home"), Some("/@home"));
        assert_eq!(
            standard_subvol_for_mount_point("/.snapshots"),
            Some("/@snapshots")
        );
        assert_eq!(standard_mount_point_for_subvol("/@log"), Some("/var/log"));
    }

    #[test]
    fn default_options_cover_required_fstypes() {
        assert!(default_mount_options("btrfs").is_some());
        assert!(default_mount_options("ext4").is_some());
        assert!(default_mount_options("xfs").is_some());
        assert!(default_mount_options("f2fs").is_some());
        assert!(default_mount_options("vfat").is_some());
        assert!(default_mount_options("nilfs2").is_none());
    }

    #[test]
    fn refused_report_marks_requires_human_action() {
        let r = MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "multiple root candidates",
        );
        assert!(r.requires_human_action);
        assert!(!r.fully_complete);
        assert!(r.cleanup.all_clean);
    }

    #[test]
    fn clean_report_marks_fully_complete() {
        let target = MountTargetIdentity {
            root_device: PathBuf::from("/dev/sda2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("abc".into()),
            esp_device: None,
            esp_uuid: None,
            boot_layout: None,
        };
        let r = MountRepairReport::clean(target.clone());
        assert_eq!(r.final_outcome, MountRepairOutcome::Clean);
        assert!(r.fully_complete);
        assert!(!r.requires_human_action);
        assert_eq!(r.target.as_ref().unwrap(), &target);
    }
}
