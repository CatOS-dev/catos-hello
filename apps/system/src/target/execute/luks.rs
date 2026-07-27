//! LUKS open/close (migrated from `chroot::luks`).
//!
//! `cryptsetup luksOpen` needs the operator's passphrase on a TTY, so it
//! runs with inherited stdio. The mapper name is fixed to
//! `luks-<uuid>` — the same convention `genfstab` and the initramfs use
//! — so an fstab produced inside the chroot references the right device.
//!
//! The functions take primitive device-identity arguments (`name`,
//! `Option<uuid>`) rather than a `BlockDevice` so this module stays free
//! of any dependency on `crate::chroot` or on `target::model`. Both the
//! minimal chroot `BlockDevice` and the rich `target::model::BlockDevice`
//! can call into these.

use std::process::Command;

use crate::shared::process::trusted_tool_path;

/// Open `device_name` as `luks-<uuid>`. The caller is expected to surface
/// the error verbatim; cryptsetup's stderr already explains the failure
/// mode (wrong passphrase, HW op, etc.).
pub fn open(device_name: &str, uuid: Option<&str>) -> Result<(), String> {
    let cryptsetup = trusted_tool_path("cryptsetup")
        .ok_or_else(|| "cryptsetup not found in trusted system directories".to_string())?;
    let mapper = mapper_name(uuid.ok_or_else(|| {
        format!("LUKS device {device_name} has no UUID; refusing to open")
    })?)?;
    let status = Command::new(&cryptsetup)
        .arg("luksOpen")
        .arg(device_name)
        .arg(&mapper)
        .status()
        .map_err(|e| format!("failed to spawn cryptsetup: {e}"))?;
    if !status.success() {
        return Err(format!("cryptsetup luksOpen exited with status {status}"));
    }
    Ok(())
}

/// Close the mapper device previously opened for `device_name`/`uuid`.
/// Failures are reported but non-fatal during cleanup.
pub fn close(uuid: &str) -> Result<(), String> {
    let cryptsetup = trusted_tool_path("cryptsetup")
        .ok_or_else(|| "cryptsetup not found in trusted system directories".to_string())?;
    let mapper = mapper_name(uuid)?;
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

/// The mapper name expected to appear under /dev/mapper/ once the device
/// is opened.
pub fn mapper_name(uuid: &str) -> Result<String, String> {
    Ok(format!("luks-{uuid}"))
}
