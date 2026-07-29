//! Chroot capability data model. Pure data only; no I/O or process execution.

use std::path::PathBuf;

use serde::Deserialize;

/// `lsblk` row used by the Chroot capability.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockDevice {
    pub name: String,
    #[serde(rename = "fstype")]
    pub fs_type: Option<String>,
    pub uuid: Option<String>,
    pub partuuid: Option<String>,
    pub label: Option<String>,
    pub partlabel: Option<String>,
}

impl BlockDevice {
    pub fn is_crypto_luks(&self) -> bool {
        self.fs_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("crypto_LUKS"))
    }

    pub fn is_btrfs(&self) -> bool {
        self.fs_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("btrfs"))
    }

    pub fn id(&self) -> String {
        self.uuid.clone().unwrap_or_else(|| self.name.clone())
    }

    pub fn matches_spec(&self, spec: &str) -> bool {
        if let Some(uuid) = spec.strip_prefix("UUID=") {
            return self.uuid.as_deref() == Some(uuid);
        }
        if let Some(uuid) = spec.strip_prefix("/dev/disk/by-uuid/") {
            return self.uuid.as_deref() == Some(uuid);
        }
        if let Some(partuuid) = spec.strip_prefix("PARTUUID=") {
            return self.partuuid.as_deref() == Some(partuuid);
        }
        if let Some(partuuid) = spec.strip_prefix("/dev/disk/by-partuuid/") {
            return self.partuuid.as_deref() == Some(partuuid);
        }
        if let Some(label) = spec.strip_prefix("LABEL=") {
            return self.label.as_deref() == Some(label);
        }
        if let Some(partlabel) = spec.strip_prefix("PARTLABEL=") {
            return self.partlabel.as_deref() == Some(partlabel);
        }
        spec == self.name
    }
}

impl std::fmt::Display for BlockDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}  fs={}  uuid={}",
            self.name,
            self.fs_type.as_deref().unwrap_or("-"),
            self.uuid.as_deref().unwrap_or("-")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subvolume {
    pub id: u64,
    pub name: String,
}

impl std::fmt::Display for Subvolume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.id, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsTabEntry {
    pub fs_spec: String,
    pub mountpoint: String,
    pub vfs_type: String,
    pub mount_options: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChrootMountKind {
    Root,
    Fstab,
    Extra,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChrootMount {
    pub device: BlockDevice,
    /// Absolute path inside the target root. The root mount is `/`.
    pub mount_point: String,
    pub options: Vec<String>,
    pub kind: ChrootMountKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChrootPlan {
    pub root: ChrootMount,
    pub mounts: Vec<ChrootMount>,
    pub use_systemd_chroot: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChrootRuntimeMount {
    Proc,
    Sys,
    Dev,
    Run,
}

impl ChrootRuntimeMount {
    pub const ALL: [Self; 4] = [Self::Proc, Self::Sys, Self::Dev, Self::Run];

    pub fn mount_point(self) -> &'static str {
        match self {
            Self::Proc => "/proc",
            Self::Sys => "/sys",
            Self::Dev => "/dev",
            Self::Run => "/run",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChrootExecutionOutcome {
    Entered,
    MountFailed,
    VerificationFailed,
    ShellFailed,
    CleanupIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChrootExecutionReport {
    pub outcome: ChrootExecutionOutcome,
    pub cleanup_complete: bool,
    pub failure: Option<String>,
    pub warnings: Vec<String>,
    pub mounted_paths: Vec<PathBuf>,
    pub residual_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChrootVerification {
    pub ready: bool,
    pub checks: Vec<String>,
    pub reasons: Vec<String>,
    pub shell: Option<String>,
}
