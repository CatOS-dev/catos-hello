//! LUKS open/close for `catos-chroot`.
//!
//! `cryptsetup luksOpen` needs the operator's passphrase on a TTY, so
//! it is run with inherited stdio. The mapper name is fixed to
//! `luks-<uuid>` — the same convention `genfstab` and the initramfs
//! use — so a fstab produced inside the chroot will reference the
//! right device.

use std::process::Command;

use crate::chroot::block_device::{tool_path, BlockDevice};

/// Open `device` as `luks-<uuid>`. The caller is expected to surface
/// the error verbatim; cryptsetup's stderr already explains the
/// failure mode (wrong passphrase, HW op, etc.).
pub fn open(device: &BlockDevice) -> Result<(), String> {
    let cryptsetup = tool_path("cryptsetup")
        .ok_or_else(|| "cryptsetup not found in trusted system directories".to_string())?;
    let mapper = mapper_name(device)?;
    let status = Command::new(&cryptsetup)
        .arg("luksOpen")
        .arg(&device.name)
        .arg(&mapper)
        .status()
        .map_err(|e| format!("failed to spawn cryptsetup: {e}"))?;
    if !status.success() {
        return Err(format!("cryptsetup luksOpen exited with status {status}"));
    }
    Ok(())
}

/// Close the mapper device previously opened for `device`. Failures
/// are reported but non-fatal during cleanup: a stuck mapper is
/// better surfaced as a warning than as an abort that leaves the rest
/// of the chroot tree mounted.
pub fn close(device: &BlockDevice) -> Result<(), String> {
    let cryptsetup = tool_path("cryptsetup")
        .ok_or_else(|| "cryptsetup not found in trusted system directories".to_string())?;
    let mapper = mapper_name(device)?;
    let status = Command::new(&cryptsetup)
        .arg("luksClose")
        .arg(&mapper)
        .status()
        .map_err(|e| format!("failed to spawn cryptsetup: {e}"))?;
    if !status.success() {
        return Err(format!("cryptsetup luksClose exited with status {status}"));
    }
    Ok(())
}

/// The mapper name expected to appear under /dev/mapper/ once the
/// device is opened.
pub fn mapper_name(device: &BlockDevice) -> Result<String, String> {
    let uuid = device
        .uuid
        .as_ref()
        .ok_or_else(|| format!("LUKS device {} has no UUID; refusing to open", device.name))?;
    Ok(format!("luks-{uuid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luks_device() -> BlockDevice {
        BlockDevice {
            name: "/dev/sda2".into(),
            fs_type: Some("crypto_LUKS".into()),
            uuid: Some("abc-123".into()),
            partuuid: None,
            label: None,
            partlabel: None,
        }
    }

    #[test]
    fn mapper_name_follows_luks_uuid_convention() {
        assert_eq!(mapper_name(&luks_device()).unwrap(), "luks-abc-123");
    }

    #[test]
    fn mapper_name_requires_uuid() {
        let mut dev = luks_device();
        dev.uuid = None;
        assert!(mapper_name(&dev).is_err());
    }
}
