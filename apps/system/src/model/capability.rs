//! Capability model. Capability status is computed from facts, not from the
//! runtime mode name.

use serde::{Deserialize, Serialize};

use crate::model::evidence::Evidence;

/// Three-state capability. `Unknown` means we could not gather enough
/// evidence to decide; it must not collapse to `Unavailable` in JSON.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Available,
    Unavailable,
    #[default]
    Unknown,
}

/// The set of capabilities phase 1 probes. Exhaustive enum so future additions
/// are visible at the call site (and trigger `match` lints).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// Can read files under the target root.
    ReadTargetRoot,
    /// `/proc` of the running system is mounted and readable.
    ReadProc,
    /// `/sys` of the running system is mounted and readable.
    ReadSysfs,
    /// `/sys/class/block` (block-device sysfs tree) is readable.
    ReadBlockSysfs,
    /// `/dev` is accessible (read enough to enumerate).
    AccessDev,
    /// Spawning external commands is permitted (kernel execve available,
    /// PATH populated). Phase 1 does NOT actually spawn anything.
    RunExternalCommands,
    /// Environment looks capable of performing mount/unmount operations
    /// (has mount(8) tool AND permission is plausible). Phase 1 does NOT
    /// perform any mount.
    MountOperationsPossible,
    /// Writing EFI variables looks possible (efivarfs mounted RW and
    /// `/sys/firmware/efi/efivars` exists). Phase 1 does NOT write.
    WriteEfivarsPossible,
    /// systemd is running as PID 1 in the *current* environment.
    SystemdAvailable,
    /// `pacman` binary present inside the *target* root.
    PacmanPresentInTarget,
    /// `mkinitcpio` binary present inside the *target* root.
    MkinitcpioPresentInTarget,
    /// `bootloadu` binary present inside the *target* root.
    BootloaduPresentInTarget,
    /// `btrfs` tool resolvable on host PATH.
    BtrfsToolAvailable,
    /// `cryptsetup` tool resolvable on host PATH.
    CryptsetupAvailable,
    /// `lsblk` tool resolvable on host PATH.
    LsblkAvailable,
    /// `mount` tool resolvable on host PATH.
    MountToolAvailable,
}

/// A single capability with its evidence trail.
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
