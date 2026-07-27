//! Pure-mount rollback helpers: undo created directories and nested
//! ESP mountpoints after a mid-repair failure.
//!
//! btrfs subvolume rollback (`delete_empty_btrfs_subvolume`) is
//! deliberately NOT here — it lives in the repair orchestration layer,
//! which is the only layer allowed to depend on the snapshot engine.
//! [`rollback_mount_resources`] returns the list of subvolumes the
//! caller still needs to delete so the orchestration layer can drive
//! the btrfs teardown in the same reverse-order pass.

use std::path::Path;

use crate::diagnose::target::{same_block_device, target_rooted_path};
use crate::execute::secure_dir::{create_session_dir, remove_session_dir, SESSION_ROOT_PARENT};
use crate::execute::syscall::{self, ms_flags};
use crate::model::{AppliedAction, BootMountLayout, MountTargetIdentity};
use catos_target::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
use catos_target::execute::confined;

/// Subvolumes the caller must still delete after the pure-mount
/// rollback has undone every directory and nested-ESP resource.
/// Returned in reverse declaration order so the orchestration layer
/// can feed them straight to `delete_empty_btrfs_subvolume`.
pub struct PendingSubvolumeRollback {
    pub subvol: String,
}

/// Roll back the pure-mount side of created resources: nested ESP
/// mountpoints (via temporary `/boot` mounts) and created directories.
/// Returns `(residuals, pending_subvolume_rollbacks)`. The caller is
/// responsible for deleting the pending subvolumes via the snapshot
/// engine and for merging any failures into the residual list.
pub fn rollback_mount_resources(
    top: &Path,
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
    created_subvolumes: &[String],
    created_directories: &[String],
    nested_esp_directory_created: bool,
    actions: &mut Vec<AppliedAction>,
) -> (Vec<String>, Vec<PendingSubvolumeRollback>) {
    let mut residuals = Vec::new();
    if nested_esp_directory_created {
        match rollback_nested_esp_mountpoint(top, target, devices) {
            Ok(()) => actions.push(AppliedAction::DirectoryRolledBack {
                mount_point: "/boot/efi".into(),
            }),
            Err(reason) => {
                actions.push(AppliedAction::RollbackResidual {
                    resource: "/boot/efi".into(),
                    reason: reason.clone(),
                });
                residuals.push(format!("/boot/efi: {reason}"));
            }
        }
    }
    for mount_point in created_directories.iter().rev() {
        let rooted = target_rooted_path(target, mount_point);
        match confined::remove_empty_rooted_directory(top, &rooted) {
            Ok(()) => actions.push(AppliedAction::DirectoryRolledBack {
                mount_point: mount_point.clone(),
            }),
            Err(error) => {
                let reason = error.to_string();
                actions.push(AppliedAction::RollbackResidual {
                    resource: mount_point.clone(),
                    reason: reason.clone(),
                });
                residuals.push(format!("{mount_point}: {reason}"));
            }
        }
    }
    // Subvolumes are returned to the caller; the snapshot engine owns
    // their deletion. Reverse order matches the directory pass above.
    let pending = created_subvolumes
        .iter()
        .rev()
        .map(|subvol| PendingSubvolumeRollback {
            subvol: subvol.clone(),
        })
        .collect();
    (residuals, pending)
}

pub fn rollback_nested_esp_mountpoint(
    top: &Path,
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
) -> Result<(), String> {
    let Some(layout) = target.boot_layout.as_ref() else {
        return Ok(());
    };
    match layout {
        BootMountLayout::SeparateBootAndEsp {
            boot_device,
            esp_mount_point,
            ..
        } if esp_mount_point == "/boot/efi" => {
            let boot = devices
                .iter()
                .find(|device| {
                    device
                        .dev_path
                        .as_deref()
                        .is_some_and(|path| same_block_device(path, boot_device))
                })
                .ok_or_else(|| "separate /boot device disappeared during rollback".to_string())?;
            // The btrfs top-level lock is owned by the repair
            // orchestration layer; here we only manipulate the plain
            // /boot mountpoint, which is never a btrfs subvolume.
            if mountpoint_matches_device(Path::new("/boot"), boot) {
                return confined::remove_empty_rooted_directory(Path::new("/boot"), "/efi")
                    .map_err(|error| error.to_string());
            }
            let fstype = boot
                .filesystem
                .as_deref()
                .ok_or_else(|| "separate /boot filesystem type is unknown".to_string())?;
            let source = boot_device
                .to_str()
                .ok_or_else(|| "separate /boot device path is not UTF-8".to_string())?;
            let session_dir =
                create_session_dir(Path::new(SESSION_ROOT_PARENT), "mount-repair-boot-rollback")
                    .map_err(|error| error.to_string())?;
            let mount_point = session_dir.join("boot");
            std::fs::create_dir(&mount_point)
                .map_err(|error| format!("cannot create rollback /boot mountpoint: {error}"))?;
            syscall::mount(
                Some(source),
                &mount_point,
                Some(fstype),
                ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
                None,
            )
            .map_err(|error| format!("cannot mount separate /boot for rollback: {error}"))?;
            let remove_result = confined::remove_empty_rooted_directory(&mount_point, "/efi")
                .map_err(|error| error.to_string());
            let unmount_result = syscall::umount2(&mount_point, 0)
                .map_err(|error| format!("cannot unmount rollback /boot: {error}"));
            let session_remove = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &session_dir)
                .map_err(|error| error.to_string());
            remove_result?;
            unmount_result?;
            session_remove
        }
        BootMountLayout::BootBtrfsSubvolume {
            subvolume,
            esp_mount_point: Some(esp_mount_point),
            ..
        } if esp_mount_point == "/boot/efi" => {
            let rooted = format!("{}/efi", subvolume.trim_end_matches('/'));
            confined::remove_empty_rooted_directory(top, &rooted).map_err(|error| error.to_string())
        }
        _ => Ok(()),
    }
}

pub fn mountpoint_matches_device(
    mount_point: &Path,
    device: &catos_target::model::BlockDevice,
) -> bool {
    let Some(expected_major_minor) = device.major_minor.as_deref() else {
        return false;
    };
    std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|body| {
            crate::diagnose::mountinfo::parse_all(&body)
                .into_iter()
                .find(|mount| mount.mount_point == mount_point)
        })
        .is_some_and(|mount| mount.major_minor == expected_major_minor)
}

/// Ensure the nested ESP mountpoint exists inside `/boot` before the
/// repair writes the fstab. Returns `Some(mount_point)` when a new
/// directory was created (so the caller can record it for rollback).
/// Pure mount: temporary `/boot` mount + confined directory creation.
pub fn ensure_nested_esp_mountpoint(
    top: &Path,
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
) -> Result<Option<String>, String> {
    let Some(layout) = target.boot_layout.as_ref() else {
        return Ok(None);
    };
    match layout {
        BootMountLayout::SeparateBootAndEsp {
            boot_device,
            esp_mount_point,
            ..
        } if esp_mount_point == "/boot/efi" => {
            let boot = devices
                .iter()
                .find(|device| {
                    device
                        .dev_path
                        .as_deref()
                        .is_some_and(|path| same_block_device(path, boot_device))
                })
                .ok_or_else(|| "separate /boot device disappeared before repair".to_string())?;
            let fstype = boot
                .filesystem
                .as_deref()
                .ok_or_else(|| "separate /boot filesystem type is unknown".to_string())?;
            let source = boot_device
                .to_str()
                .ok_or_else(|| "separate /boot device path is not UTF-8".to_string())?;
            if mountpoint_matches_device(Path::new("/boot"), boot) {
                let fs = RealFilesystem;
                let existed = match fs.rooted_metadata(Path::new("/boot"), Path::new("efi")) {
                    Ok(metadata) if metadata.is_dir && !metadata.is_symlink => true,
                    Ok(_) => {
                        return Err(
                            "mounted separate /boot contains a non-directory efi entry".into()
                        );
                    }
                    Err(catos_target::FsError::NotFound) => false,
                    Err(error) => {
                        return Err(format!("cannot inspect mounted /boot/efi: {error}"));
                    }
                };
                if !existed {
                    confined::create_rooted_directory(Path::new("/boot"), "/efi")
                        .map_err(|error| error.to_string())?;
                }
                return Ok((!existed).then(|| "/boot/efi".to_string()));
            }
            let session_dir =
                create_session_dir(Path::new(SESSION_ROOT_PARENT), "mount-repair-boot-parent")
                    .map_err(|error| error.to_string())?;
            let mount_point = session_dir.join("boot");
            std::fs::create_dir(&mount_point)
                .map_err(|error| format!("cannot create temporary /boot mountpoint: {error}"))?;
            if let Err(error) = syscall::mount(
                Some(source),
                &mount_point,
                Some(fstype),
                ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
                None,
            ) {
                let _ = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &session_dir);
                return Err(format!("cannot mount separate /boot read-write: {error}"));
            }
            let fs = RealFilesystem;
            let existed = match fs.rooted_metadata(&mount_point, Path::new("efi")) {
                Ok(metadata) if metadata.is_dir && !metadata.is_symlink => true,
                Ok(_) => {
                    let _ = syscall::umount2(&mount_point, 0);
                    return Err("separate /boot contains a non-directory efi entry".into());
                }
                Err(catos_target::FsError::NotFound) => false,
                Err(error) => {
                    let _ = syscall::umount2(&mount_point, 0);
                    return Err(format!("cannot inspect separate /boot/efi: {error}"));
                }
            };
            let create_result = if existed {
                Ok(())
            } else {
                confined::create_rooted_directory(&mount_point, "/efi")
                    .map_err(|error| error.to_string())
            };
            let unmount_result = syscall::umount2(&mount_point, 0)
                .map_err(|error| format!("cannot unmount temporary separate /boot: {error}"));
            let remove_result = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &session_dir)
                .map_err(|error| error.to_string());
            create_result?;
            unmount_result?;
            remove_result?;
            Ok((!existed).then(|| "/boot/efi".to_string()))
        }
        BootMountLayout::BootBtrfsSubvolume {
            subvolume,
            esp_mount_point: Some(esp_mount_point),
            ..
        } if esp_mount_point == "/boot/efi" => {
            let rooted = format!("{}/efi", subvolume.trim_end_matches('/'));
            let physical = top.join(rooted.trim_start_matches('/'));
            let existed = match std::fs::symlink_metadata(&physical) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
                Ok(_) => {
                    return Err("Btrfs boot subvolume contains a non-directory efi entry".into())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(format!("cannot inspect Btrfs boot subvolume: {error}")),
            };
            if !existed {
                confined::create_rooted_directory(top, &rooted)
                    .map_err(|error| error.to_string())?;
            }
            Ok((!existed).then(|| "/boot/efi".to_string()))
        }
        _ => Ok(None),
    }
}
