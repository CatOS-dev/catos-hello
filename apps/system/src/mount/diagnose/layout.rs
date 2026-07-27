//! Boot mount layout detection and small device-classification helpers.
//!
//! Pure: a function of fstab entries + already-discovered devices. The
//! richer target-identity / mount-point observation types live in
//! [`crate::mount::diagnose::target`].

use std::path::Path;

use crate::mount::diagnose::fstab::FstabEntry;
use crate::mount::diagnose::target::same_block_device;
use crate::mount::model::BootMountLayout;
use crate::target::diagnose::candidate::device_matches_fstab_source;
use crate::target::model::BlockDevice;

pub fn detect_boot_mount_layout(
    fstab: &[FstabEntry],
    devices: &[BlockDevice],
    root_device: &Path,
    selected_esp: Option<&Path>,
) -> Result<BootMountLayout, String> {
    let entries_at = |target: &str| -> Vec<&FstabEntry> {
        fstab
            .iter()
            .filter(|entry| entry.target == target)
            .collect()
    };
    for target in ["/boot", "/boot/efi", "/efi"] {
        if entries_at(target).len() > 1 {
            return Err(format!("multiple fstab entries target {target}"));
        }
    }

    let boot_entry = entries_at("/boot").into_iter().next();
    let boot_efi_entry = entries_at("/boot/efi").into_iter().next();
    let efi_entry = entries_at("/efi").into_iter().next();

    let fat_entry = |entry: &FstabEntry| is_fat_fstype(&entry.fstype);
    let nested_esp_entries: Vec<(&str, &FstabEntry)> =
        [("/boot/efi", boot_efi_entry), ("/efi", efi_entry)]
            .into_iter()
            .filter_map(|(target, entry)| {
                entry
                    .filter(|entry| fat_entry(entry))
                    .map(|entry| (target, entry))
            })
            .collect();
    if nested_esp_entries.len() > 1 {
        return Err("both /boot/efi and /efi are configured as ESP mounts".into());
    }

    let resolve = |entry: &FstabEntry| -> Result<&BlockDevice, String> {
        let matches: Vec<&BlockDevice> = devices
            .iter()
            .filter(|device| device_matches_fstab_source(device, &entry.source))
            .collect();
        match matches.as_slice() {
            [device] => Ok(*device),
            [] => Err(format!(
                "fstab source for {} does not resolve to a discovered device",
                entry.target
            )),
            _ => Err(format!(
                "fstab source for {} resolves to multiple devices",
                entry.target
            )),
        }
    };

    let selected_esp_device = match selected_esp {
        Some(path) => Some(
            devices
                .iter()
                .find(|device| {
                    device
                        .dev_path
                        .as_deref()
                        .is_some_and(|candidate| same_block_device(candidate, path))
                })
                .ok_or_else(|| "selected ESP is not a discovered block device".to_string())?,
        ),
        None => None,
    };
    if let Some(device) = selected_esp_device {
        if !is_fat_device(device) {
            return Err("selected ESP is not a FAT filesystem".into());
        }
    }

    let nested_esp = match nested_esp_entries.as_slice() {
        [] => None,
        [(mount_point, entry)] => {
            let resolved = match resolve(entry) {
                Ok(device) => device,
                Err(_) => selected_esp_device.ok_or_else(|| {
                    format!("{mount_point} source is stale and no unique ESP was selected")
                })?,
            };
            if !is_fat_device(resolved) {
                return Err(format!(
                    "{mount_point} does not resolve to a FAT filesystem"
                ));
            }
            if let Some(selected) = selected_esp_device {
                if !same_device_records(resolved, selected) {
                    return Err(format!(
                        "{mount_point} resolves to a different device than the selected ESP"
                    ));
                }
            }
            Some((*mount_point, resolved))
        }
        _ => unreachable!(),
    };

    if let Some(entry) = boot_entry {
        let boot_device = if is_fat_fstype(&entry.fstype) {
            match resolve(entry) {
                Ok(device) => device,
                Err(_) => selected_esp_device.ok_or_else(|| {
                    "direct /boot ESP source is stale and no unique ESP was selected".to_string()
                })?,
            }
        } else {
            resolve(entry)?
        };
        if is_fat_fstype(&entry.fstype) {
            if nested_esp.is_some() {
                return Err(
                    "direct /boot ESP conflicts with an additional nested ESP entry".into(),
                );
            }
            if !is_fat_device(boot_device) {
                return Err("direct /boot ESP does not resolve to a FAT filesystem".into());
            }
            if let Some(selected) = selected_esp_device {
                if !same_device_records(boot_device, selected) {
                    return Err("direct /boot entry does not match the selected ESP".into());
                }
            }
            let esp_device = boot_device
                .dev_path
                .clone()
                .ok_or_else(|| "direct /boot ESP has no stable device path".to_string())?;
            return Ok(BootMountLayout::EspAtBoot { esp_device });
        }

        if entry.fstype == "btrfs"
            && boot_device
                .dev_path
                .as_deref()
                .is_some_and(|path| same_block_device(path, root_device))
        {
            let subvolume = entry
                .options
                .iter()
                .find_map(|option| option.strip_prefix("subvol=").map(str::to_string))
                .ok_or_else(|| "separate Btrfs /boot entry has no subvol= selector".to_string())?;
            if subvolume == "/@" {
                return Err("/boot cannot reuse the root subvolume /@".into());
            }
            return Ok(BootMountLayout::BootBtrfsSubvolume {
                subvolume,
                esp_device: nested_esp
                    .and_then(|(_, device)| device.dev_path.clone())
                    .or_else(|| selected_esp_device.and_then(|device| device.dev_path.clone())),
                esp_mount_point: nested_esp.map(|(mount_point, _)| mount_point.to_string()),
            });
        }

        let Some((esp_mount_point, esp_device)) = nested_esp else {
            return Err(
                "a separate ordinary /boot filesystem requires a separate ESP entry".into(),
            );
        };
        let boot_path = boot_device
            .dev_path
            .clone()
            .ok_or_else(|| "separate /boot filesystem has no stable device path".to_string())?;
        let esp_path = esp_device
            .dev_path
            .clone()
            .ok_or_else(|| "ESP has no stable device path".to_string())?;
        return Ok(BootMountLayout::SeparateBootAndEsp {
            boot_device: boot_path,
            esp_device: esp_path,
            esp_mount_point: esp_mount_point.to_string(),
        });
    }

    match nested_esp {
        Some(("/boot/efi", device)) => Ok(BootMountLayout::EspAtBootEfi {
            esp_device: device
                .dev_path
                .clone()
                .ok_or_else(|| "ESP has no stable device path".to_string())?,
        }),
        Some(("/efi", device)) => Ok(BootMountLayout::EspAtEfi {
            esp_device: device
                .dev_path
                .clone()
                .ok_or_else(|| "ESP has no stable device path".to_string())?,
        }),
        Some((mount_point, _)) => Err(format!("unsupported ESP mount point {mount_point}")),
        None if selected_esp_device.is_some() => {
            Err("an ESP was selected but target fstab does not establish its mount point".into())
        }
        None => Ok(BootMountLayout::BootInsideRoot),
    }
}

pub fn is_fat_fstype(fstype: &str) -> bool {
    matches!(fstype, "vfat" | "fat" | "fat32" | "fat16" | "fat12")
}

pub fn is_fat_device(device: &BlockDevice) -> bool {
    device.filesystem.as_deref().is_some_and(is_fat_fstype)
}

pub fn same_device_records(left: &BlockDevice, right: &BlockDevice) -> bool {
    match (left.dev_path.as_deref(), right.dev_path.as_deref()) {
        (Some(left), Some(right)) => same_block_device(left, right),
        _ => left.major_minor.is_some() && left.major_minor == right.major_minor,
    }
}
