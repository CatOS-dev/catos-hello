//! Block-device discovery and mount helpers for `catos-chroot`.
//!
//! All external commands (`lsblk`, `mount`, `umount`) are resolved
//! through [`crate::process::trusted_tool_path`] so they can only come
//! from the fixed trusted system directories. `lsblk` is run with a
//! bounded reader because its JSON output on a busy host can be large;
//! `mount`/`umount` are run with inherited stdio so the operator sees
//! kernel error messages verbatim.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::Duration;

use serde::Deserialize;

use crate::process::{run_trusted_tool, trusted_tool_path};

const LSBLK_TIMEOUT: Duration = Duration::from_secs(30);
const LSBLK_MAX_OUTPUT: usize = 4 * 1024 * 1024;

/// `lsblk -Jo` row for a partition or crypt device. Only the fields
/// the chroot flow consults are decoded; everything else is dropped.
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
            .map(|s| s.eq_ignore_ascii_case("crypto_LUKS"))
            .unwrap_or(false)
    }

    pub fn is_btrfs(&self) -> bool {
        self.fs_type
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("btrfs"))
            .unwrap_or(false)
    }

    /// Stable identity for "already mounted" deduplication. UUID is
    /// preferred; the kernel name is the fallback for synthetic or
    /// odd devices.
    pub fn id(&self) -> String {
        self.uuid.clone().unwrap_or_else(|| self.name.clone())
    }

    /// True if this device matches a single `fstab` fs_spec token.
    /// Supports the five standard forms (`UUID=`, `PARTUUID=`,
    /// `LABEL=`, `PARTLABEL=`, kernel name) plus the `/dev/disk/by-*`
    /// symlinks that resolve to them.
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
        let fs = self.fs_type.as_deref().unwrap_or("-");
        let uuid = self.uuid.as_deref().unwrap_or("-");
        write!(f, "{}  fs={}  uuid={}", self.name, fs, uuid)
    }
}

#[derive(Debug, Deserialize)]
struct LsblkReport {
    #[serde(rename = "blockdevices")]
    devices: Vec<BlockDevice>,
}

/// Enumerate partitions and crypt devices that carry a filesystem and
/// a UUID. Swap, unknown, and empty-UUID rows are dropped at the
/// `lsblk` query level so the caller never sees them.
pub fn list_block_devices() -> Result<Vec<BlockDevice>, String> {
    let output = run_trusted_tool(
        "lsblk",
        &[
            "-f",
            "-o",
            "NAME,FSTYPE,UUID,PARTUUID,LABEL,PARTLABEL",
            "-p",
            "-a",
            "-J",
            "-Q",
            "type=='part' || type=='crypt' && fstype!='swap' && fstype && uuid",
        ],
        LSBLK_TIMEOUT,
        LSBLK_MAX_OUTPUT,
    )?;
    if !output.success() {
        return Err(format!(
            "lsblk failed with status {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let report: LsblkReport = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("lsblk output was not valid JSON: {e}"))?;
    Ok(report.devices)
}

/// Mount `device.name` at `mount_point` with optional extra `-o`
/// options (used to pass `subvolid=` for btrfs). Returns the raw
/// `ExitStatus` so the caller can decide whether to abort or skip.
pub fn mount_device(
    device: &BlockDevice,
    mount_point: &Path,
    extra_options: Option<&str>,
) -> Result<ExitStatus, String> {
    let mount = trusted_tool_path("mount")
        .ok_or_else(|| "mount not found in trusted system directories".to_string())?;
    let mut command = Command::new(&mount);
    command.arg(&device.name).arg(mount_point);
    if let Some(options) = extra_options {
        command.arg("-o").arg(options);
    }
    command.status().map_err(|e| format!("failed to spawn mount: {e}"))
}

/// Unmount `mount_point`. When `recursive` is true the call uses
/// `umount -R` so a chroot tree is torn down even if some bind-mounts
/// were added out-of-band.
pub fn umount_path(mount_point: &Path, recursive: bool) -> Result<(), String> {
    let umount = trusted_tool_path("umount")
        .ok_or_else(|| "umount not found in trusted system directories".to_string())?;
    let mut command = Command::new(&umount);
    if recursive {
        command.arg("-R");
    }
    command.arg(mount_point);
    let status = command
        .status()
        .map_err(|e| format!("failed to spawn umount: {e}"))?;
    if !status.success() {
        return Err(format!("umount exited with status {status}"));
    }
    Ok(())
}

/// Resolve a trusted tool to its absolute path. Thin wrapper so
/// callers outside this module do not need to reach into
/// `crate::process` directly.
pub fn tool_path(name: &str) -> Option<PathBuf> {
    trusted_tool_path(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str, fs: Option<&str>, uuid: Option<&str>) -> BlockDevice {
        BlockDevice {
            name: name.to_string(),
            fs_type: fs.map(str::to_string),
            uuid: uuid.map(str::to_string),
            partuuid: None,
            label: None,
            partlabel: None,
        }
    }

    #[test]
    fn luks_detection_is_case_insensitive() {
        assert!(device("/dev/sda1", Some("crypto_LUKS"), Some("u")).is_crypto_luks());
        assert!(device("/dev/sda1", Some("crypto_luks"), Some("u")).is_crypto_luks());
        assert!(!device("/dev/sda1", Some("ext4"), Some("u")).is_crypto_luks());
        assert!(!device("/dev/sda1", None, Some("u")).is_crypto_luks());
    }

    #[test]
    fn btrfs_detection_is_case_insensitive() {
        assert!(device("/dev/sda1", Some("btrfs"), Some("u")).is_btrfs());
        assert!(device("/dev/sda1", Some("BTRFS"), Some("u")).is_btrfs());
        assert!(!device("/dev/sda1", Some("ext4"), Some("u")).is_btrfs());
        assert!(!device("/dev/sda1", None, Some("u")).is_btrfs());
    }

    #[test]
    fn matches_spec_handles_all_canonical_forms() {
        let dev = BlockDevice {
            name: "/dev/sda1".into(),
            fs_type: Some("ext4".into()),
            uuid: Some("111".into()),
            partuuid: Some("222".into()),
            label: Some("root".into()),
            partlabel: Some("rootpart".into()),
        };
        assert!(dev.matches_spec("UUID=111"));
        assert!(dev.matches_spec("/dev/disk/by-uuid/111"));
        assert!(dev.matches_spec("PARTUUID=222"));
        assert!(dev.matches_spec("/dev/disk/by-partuuid/222"));
        assert!(dev.matches_spec("LABEL=root"));
        assert!(dev.matches_spec("PARTLABEL=rootpart"));
        assert!(dev.matches_spec("/dev/sda1"));
        assert!(!dev.matches_spec("/dev/sda2"));
        assert!(!dev.matches_spec("UUID=999"));
    }

    #[test]
    fn id_prefers_uuid() {
        assert_eq!(device("/dev/sda1", Some("ext4"), Some("u")).id(), "u");
        assert_eq!(device("/dev/sda1", Some("ext4"), None).id(), "/dev/sda1");
    }

    #[test]
    fn list_block_devices_parses_minimal_json() {
        let json = r#"{"blockdevices":[{"name":"/dev/sda1","fstype":"ext4","uuid":"u","partuuid":null,"label":null,"partlabel":null}]}"#;
        let report: LsblkReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.devices.len(), 1);
        assert_eq!(report.devices[0].name, "/dev/sda1");
    }
}
