//! Read-only block-device diagnosis for Chroot.

use std::time::Duration;

use serde::Deserialize;

use crate::chroot::model::BlockDevice;
use crate::shared::process::run_trusted_tool;

const LSBLK_TIMEOUT: Duration = Duration::from_secs(30);
const LSBLK_MAX_OUTPUT: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct LsblkReport {
    #[serde(rename = "blockdevices")]
    devices: Vec<BlockDevice>,
}

pub fn parse_lsblk_json(bytes: &[u8]) -> Result<Vec<BlockDevice>, String> {
    let report: LsblkReport = serde_json::from_slice(bytes)
        .map_err(|error| format!("lsblk output was not valid JSON: {error}"))?;
    Ok(report.devices)
}

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
    parse_lsblk_json(&output.stdout)
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
    }

    #[test]
    fn btrfs_detection_is_case_insensitive() {
        assert!(device("/dev/sda1", Some("btrfs"), Some("u")).is_btrfs());
        assert!(device("/dev/sda1", Some("BTRFS"), Some("u")).is_btrfs());
        assert!(!device("/dev/sda1", Some("ext4"), Some("u")).is_btrfs());
    }

    #[test]
    fn identity_prefers_uuid_and_falls_back_to_device_path() {
        assert_eq!(device("/dev/sda1", Some("ext4"), Some("u")).id(), "u");
        assert_eq!(device("/dev/sda1", Some("ext4"), None).id(), "/dev/sda1");
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
    }

    #[test]
    fn parse_fixture() {
        let json = br#"{"blockdevices":[{"name":"/dev/sda1","fstype":"ext4","uuid":"u","partuuid":null,"label":null,"partlabel":null}]}"#;
        let devices = parse_lsblk_json(json).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "/dev/sda1");
    }
}
