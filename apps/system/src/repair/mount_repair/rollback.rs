//! Rollback helpers for mount repair: undo created subvolumes,
//! directories, and nested ESP mountpoints after a mid-repair failure.

use std::path::Path;

use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount_repair::{
    AppliedAction, BootMountLayout, FstabTransaction, MountRepairCleanup, MountRepairOutcome,
    MountRepairPlan, MountRepairReport, MountVerification, PlannedDirectory, TargetIdentity,
};
use crate::target::model::BlockDevice;
use crate::shared::mount::syscall::{self, ms_flags};
use crate::target::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
use crate::target::execute::confined;
use crate::shared::snapshot_engine::external as btrfs;
use crate::shared::snapshot_engine::lock::DeviceLock;

use super::MountRepairInputs;
use super::select::{same_block_device, target_rooted_path};

pub(super) fn failure_after_created_resources(
    inputs: &MountRepairInputs,
    plan: MountRepairPlan,
    top: &Path,
    devices: &[BlockDevice],
    mut actions: Vec<AppliedAction>,
    created_subvolumes: &[String],
    created_directories: &[String],
    nested_esp_directory_created: bool,
    requested_outcome: MountRepairOutcome,
    evidence_code: &str,
    message: String,
    fstab_transaction: Option<FstabTransaction>,
    verification: Option<MountVerification>,
) -> MountRepairReport {
    let residuals = rollback_created_resources(
        top,
        &inputs.target,
        devices,
        created_subvolumes,
        created_directories,
        nested_esp_directory_created,
        &mut actions,
    );
    let final_outcome = if residuals.is_empty() {
        requested_outcome
    } else {
        MountRepairOutcome::RollbackFailed
    };
    let mut evidence = vec![Evidence::new(evidence_code, "repair::mount", message)];
    for residual in &residuals {
        evidence.push(Evidence::new(
            "ROLLBACK_RESIDUAL",
            "repair::mount",
            residual.clone(),
        ));
    }
    MountRepairReport {
        target: Some(inputs.target.clone()),
        plan: Some(plan),
        fstab_transaction,
        actions,
        verification,
        cleanup: MountRepairCleanup::default(),
        final_outcome,
        requires_human_action: true,
        fully_complete: false,
        evidence,
        warnings: Vec::new(),
    }
}

pub(super) fn rollback_created_resources(
    top: &Path,
    target: &TargetIdentity,
    devices: &[BlockDevice],
    created_subvolumes: &[String],
    created_directories: &[String],
    nested_esp_directory_created: bool,
    actions: &mut Vec<AppliedAction>,
) -> Vec<String> {
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
    for subvolume in created_subvolumes.iter().rev() {
        match crate::shared::snapshot_engine::confined::delete_empty_btrfs_subvolume(top, subvolume) {
            Ok(()) => actions.push(AppliedAction::SubvolumeRolledBack {
                subvol: subvolume.clone(),
            }),
            Err(error) => {
                let reason = error.to_string();
                actions.push(AppliedAction::RollbackResidual {
                    resource: subvolume.clone(),
                    reason: reason.clone(),
                });
                residuals.push(format!("{subvolume}: {reason}"));
            }
        }
    }
    residuals
}

pub(super) fn rollback_nested_esp_mountpoint(
    top: &Path,
    target: &TargetIdentity,
    devices: &[BlockDevice],
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
            let _lock =
                DeviceLock::try_acquire(boot_device).map_err(|error| error.to_string())?;
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
            let session_dir = crate::shared::mount::secure_dir::create_session_dir(
                Path::new(crate::shared::mount::secure_dir::SESSION_ROOT_PARENT),
                "mount-repair-boot-rollback",
            )
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
            let session_remove = crate::shared::mount::secure_dir::remove_session_dir(
                Path::new(crate::shared::mount::secure_dir::SESSION_ROOT_PARENT),
                &session_dir,
            )
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
            confined::remove_empty_rooted_directory(top, &rooted)
                .map_err(|error| error.to_string())
        }
        _ => Ok(()),
    }
}

pub(super) fn mountpoint_matches_device(mount_point: &Path, device: &BlockDevice) -> bool {
    let Some(expected_major_minor) = device.major_minor.as_deref() else {
        return false;
    };
    std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|body| {
            crate::shared::parse::mountinfo::parse_all(&body)
                .into_iter()
                .find(|mount| mount.mount_point == mount_point)
        })
        .is_some_and(|mount| mount.major_minor == expected_major_minor)
}

pub(super) fn ensure_nested_esp_mountpoint(
    top: &Path,
    target: &TargetIdentity,
    devices: &[BlockDevice],
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
            let _lock =
                DeviceLock::try_acquire(boot_device).map_err(|error| error.to_string())?;
            if mountpoint_matches_device(Path::new("/boot"), boot) {
                let fs = RealFilesystem;
                let existed = match fs.rooted_metadata(Path::new("/boot"), Path::new("efi")) {
                    Ok(metadata) if metadata.is_dir && !metadata.is_symlink => true,
                    Ok(_) => {
                        return Err(
                            "mounted separate /boot contains a non-directory efi entry".into()
                        );
                    }
                    Err(crate::shared::error::FsError::NotFound) => false,
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
            let session_dir = crate::shared::mount::secure_dir::create_session_dir(
                Path::new(crate::shared::mount::secure_dir::SESSION_ROOT_PARENT),
                "mount-repair-boot-parent",
            )
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
                let _ = crate::shared::mount::secure_dir::remove_session_dir(
                    Path::new(crate::shared::mount::secure_dir::SESSION_ROOT_PARENT),
                    &session_dir,
                );
                return Err(format!("cannot mount separate /boot read-write: {error}"));
            }
            let fs = RealFilesystem;
            let existed = match fs.rooted_metadata(&mount_point, Path::new("efi")) {
                Ok(metadata) if metadata.is_dir && !metadata.is_symlink => true,
                Ok(_) => {
                    let _ = syscall::umount2(&mount_point, 0);
                    return Err("separate /boot contains a non-directory efi entry".into());
                }
                Err(crate::shared::error::FsError::NotFound) => false,
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
            let remove_result = crate::shared::mount::secure_dir::remove_session_dir(
                Path::new(crate::shared::mount::secure_dir::SESSION_ROOT_PARENT),
                &session_dir,
            )
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

