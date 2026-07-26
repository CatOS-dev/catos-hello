//! Data model layer. Pure data + serde, no I/O.

pub mod capability;
pub mod evidence;
pub mod fstab;
pub mod inspection;
pub mod mount;
pub mod mount_repair;
pub mod recovery;
pub mod repair;
pub mod runtime;
pub mod storage;

pub use capability::{Capability, CapabilityKind, CapabilityStatus};
pub use evidence::Evidence;
pub use fstab::{FstabEntry, FstabEntryKind, FstabParseError, FstabSource};
pub use inspection::{InspectionReport, OsRelease, Presence, TargetInspection, ToolPath, Warning};
pub use mount::{
    CleanupReport, MountError, MountErrorKind, MountPlan, MountSession, MountSessionState,
    MountStep, MountedResource, NamespaceState,
};
pub use mount_repair::{
    default_mount_options, AppliedAction, CatosSubvolSpec, FstabDigest, FstabTransaction,
    MountProblem, MountRepairCleanup, MountRepairOutcome, MountRepairPlan, MountRepairReport,
    MountVerification, PlannedDirectory, PlannedFstabEdit, PlannedSubvolume, TargetIdentity,
    CATOS_STANDARD_SUBVOLS,
};
pub use runtime::{Detection, DetectionStatus, PrimaryRuntimeMode, RuntimeFacts};
pub use storage::{
    BlockDevice, BtrfsSubvolume, BtrfsSubvolumeKind, DeviceClass, DiskKind, EspCandidate,
    PartitionRole, RootCandidate, RootCandidateConfidence, StorageReport,
};
