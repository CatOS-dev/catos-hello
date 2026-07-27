//! CLI target selection helpers: device discovery, root/ESP selection,
//! running-root detection, and target input observation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::shared::model::fstab::FstabSource;
use crate::shared::model::inspection::Warning;
use crate::shared::model::mount_repair::{BootMountLayout, MountProblem, TargetIdentity};
use crate::shared::model::runtime::DetectionStatus;
use crate::shared::model::storage::{BlockDevice, DeviceClass, DiskKind, EspCandidate, PartitionRole, RootCandidateConfidence};
use crate::shared::mount::probe::{
    inspect_selected_root, probe_unmounted_candidates, SelectedTargetProbe,
};
use crate::shared::parse::fstab::{parse_all_with_diagnostics, FstabEntry};
use crate::shared::probe::candidate::device_matches_fstab_source;
use crate::shared::probe::fs_probe::{FilesystemProbe, RealFilesystem};
use crate::shared::system_root::SystemRoot;
use crate::shared::snapshot_engine::external as btrfs;
use crate::repair::subvol_decision::{CatosConfirmation, SubvolFacts};

use super::{detect_boot_mount_layout, is_fat_device, is_fat_fstype, MountRepairInputs, MountPointObservation};

pub(super) fn select_mount_repair_esp<'a>(
    devices: &'a [BlockDevice],
    fstab: &[FstabEntry],
    candidates: &[EspCandidate],
    explicit: Option<&str>,
) -> Result<Option<&'a BlockDevice>, String> {
    let candidate_for = |device: &BlockDevice| {
        let source = device.dev_path.as_deref();
        candidates
            .iter()
            .find(|candidate| source.is_some_and(|path| candidate.source == path.to_string_lossy()))
    };
    let valid = |device: &BlockDevice| {
        is_fat_device(device)
            && (matches!(device.partition_role, PartitionRole::Esp)
                || candidate_for(device)
                    .is_some_and(|candidate| candidate.signals.has_efi_directory))
    };

    if let Some(requested) = explicit {
        let device = devices
            .iter()
            .find(|device| {
                device
                    .dev_path
                    .as_deref()
                    .is_some_and(|path| same_block_device(path, Path::new(requested)))
            })
            .ok_or_else(|| "explicit ESP is not a discovered block device".to_string())?;
        if !valid(device) {
            return Err(
                "explicit ESP must be FAT and have GPT ESP type or an EFI directory".into(),
            );
        }
        return Ok(Some(device));
    }

    let esp_entries: Vec<&FstabEntry> = fstab
        .iter()
        .filter(|entry| {
            matches!(entry.target.as_str(), "/boot/efi" | "/efi")
                || (entry.target == "/boot" && is_fat_fstype(&entry.fstype))
        })
        .collect();
    if esp_entries.len() > 1 {
        return Err("target fstab contains multiple ESP mount entries".into());
    }
    if let Some(entry) = esp_entries.first() {
        let resolved: Vec<&BlockDevice> = devices
            .iter()
            .filter(|device| device_matches_fstab_source(device, &entry.source))
            .filter(|device| valid(device))
            .collect();
        match resolved.as_slice() {
            [device] => return Ok(Some(*device)),
            [] => {
                let probed: Vec<&BlockDevice> = devices
                    .iter()
                    .filter(|device| valid(device))
                    .filter(|device| {
                        candidate_for(device).is_some_and(|candidate| {
                            candidate.confidence == RootCandidateConfidence::High
                        })
                    })
                    .collect();
                return match probed.as_slice() {
                    [device] => Ok(Some(*device)),
                    [] => Err(format!(
                        "ESP entry {} is stale and no validated ESP candidate exists",
                        entry.target
                    )),
                    _ => {
                        Err("ESP entry is stale and multiple validated ESP candidates exist".into())
                    }
                };
            }
            _ => return Err("ESP fstab source resolves to multiple devices".into()),
        }
    }

    // No ESP entry means the layout may genuinely be BIOS/boot-inside-root.
    // Do not invent a mount point merely because a disk happens to contain
    // an unrelated ESP.
    Ok(None)
}

pub(super) fn select_cli_root<'a>(
    devices: &'a [BlockDevice],
    root_device: Option<&str>,
) -> Option<&'a BlockDevice> {
    match root_device {
        Some(requested) => devices.iter().find(|device| {
            device
                .dev_path
                .as_ref()
                .is_some_and(|path| same_block_device(path, Path::new(requested)))
                && supported_mount_repair_root(device.filesystem.as_deref())
                && (!device.mounted_before_session || is_running_root_device(device))
        }),
        None => auto_select_running_root(devices).or_else(|| auto_select_cli_root(devices)),
    }
}

pub(super) fn is_running_root_device(device: &BlockDevice) -> bool {
    device.mount_point.as_deref() == Some(Path::new("/"))
        || device
            .mounts
            .iter()
            .any(|mount| mount.mount_point == Path::new("/"))
}

pub(super) fn auto_select_running_root(devices: &[BlockDevice]) -> Option<&BlockDevice> {
    let os_release = std::fs::read_to_string("/etc/os-release").ok()?;
    let is_catos = os_release.lines().any(|line| {
        line.trim()
            .strip_prefix("ID=")
            .is_some_and(|value| value.trim_matches(['\"', '\'']) == "catos")
    });
    if !is_catos {
        return None;
    }
    let fstab_text = std::fs::read_to_string("/etc/fstab").ok()?;
    let (fstab, diagnostics) = parse_all_with_diagnostics(&fstab_text);
    if !diagnostics.is_empty() {
        return None;
    }
    let root_entries: Vec<&FstabEntry> = fstab.iter().filter(|entry| entry.target == "/").collect();
    let [root_entry] = root_entries.as_slice() else {
        return None;
    };
    let matches: Vec<&BlockDevice> = devices
        .iter()
        .filter(|device| is_running_root_device(device))
        .filter(|device| supported_mount_repair_root(device.filesystem.as_deref()))
        .filter(|device| device_matches_fstab_source(device, &root_entry.source))
        .collect();
    match matches.as_slice() {
        [device] => Some(*device),
        _ => None,
    }
}

pub(super) fn inspect_running_root() -> Result<SelectedTargetProbe, String> {
    let root = SystemRoot::from_user_input("/").map_err(|error| error.to_string())?;
    let fs = RealFilesystem;
    let fstab_text = fs
        .rooted_read_to_string(root.canonical_path(), Path::new("etc/fstab"))
        .map_err(|error| format!("cannot read running-system fstab: {error}"))?;
    let (fstab, diagnostics) = parse_all_with_diagnostics(&fstab_text);
    let mut warning_strings = Vec::new();
    let inspection = crate::shared::probe::inspect_target(&fs, &root, &mut warning_strings);
    let mut warnings = diagnostics
        .into_iter()
        .map(|diagnostic| {
            Warning::new(
                "FSTAB_PARSE_ERROR",
                format!(
                    "running-system fstab line {} is invalid ({:?}): {}",
                    diagnostic.line, diagnostic.kind, diagnostic.text
                ),
            )
        })
        .collect::<Vec<_>>();
    warnings.extend(
        warning_strings
            .into_iter()
            .map(|message| Warning::new("TARGET_INSPECTION_WARNING", message)),
    );
    Ok(SelectedTargetProbe {
        fstab,
        inspection,
        cleanup: crate::shared::model::mount::CleanupReport {
            all_clean: true,
            ..Default::default()
        },
        warnings,
    })
}

pub(super) fn auto_select_cli_root(devices: &[BlockDevice]) -> Option<&BlockDevice> {
    let probes = probe_unmounted_candidates(devices, &[]);
    let candidates: Vec<&str> = probes
        .roots
        .iter()
        .filter(|root| {
            supported_mount_repair_root(root.filesystem.as_deref())
                && (root.filesystem.as_deref() != Some("btrfs")
                    || root.subvolume.as_deref() == Some("/@"))
                && root.confidence == RootCandidateConfidence::High
                && root.is_catos.status == DetectionStatus::Detected
                && root
                    .evidence
                    .iter()
                    .any(|evidence| evidence.code == "FSTAB_ROOT_MATCH")
        })
        .map(|root| root.source.as_str())
        .collect();
    match candidates.as_slice() {
        [source] => devices.iter().find(|device| {
            device.dev_path.as_deref() == Some(Path::new(source))
                && !device.mounted_before_session
                && !device.removable
                && device.class != DeviceClass::Disk
                && device.partition_role != PartitionRole::WholeDisk
        }),
        _ => None,
    }
}

pub(super) fn supported_mount_repair_root(fstype: Option<&str>) -> bool {
    matches!(
        fstype,
        Some("btrfs" | "ext2" | "ext3" | "ext4" | "xfs" | "f2fs")
    )
}

pub(super) fn same_block_device(discovered: &Path, requested: &Path) -> bool {
    if discovered == requested {
        return true;
    }
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match (std::fs::metadata(discovered), std::fs::metadata(requested)) {
        (Ok(left), Ok(right)) => {
            left.file_type().is_block_device()
                && right.file_type().is_block_device()
                && left.rdev() == right.rdev()
        }
        _ => false,
    }
}

pub(super) fn observe_target_inputs(
    fs: &RealFilesystem,
    top: &Path,
    root: &Path,
    target: TargetIdentity,
) -> Result<MountRepairInputs, String> {
    let fstab_text = fs
        .rooted_read_to_string(root, Path::new("etc/fstab"))
        .map_err(|error| format!("cannot safely read target /etc/fstab: {error}"))?;
    let os_release = fs
        .rooted_read_to_string(root, Path::new("etc/os-release"))
        .map_err(|error| format!("cannot safely read target os-release: {error}"))?;
    let catos_confirmation = if os_release.lines().any(|line| {
        let Some(value) = line.trim().strip_prefix("ID=") else {
            return false;
        };
        value.trim_matches('"') == "catos"
    }) {
        CatosConfirmation::Confirmed
    } else {
        CatosConfirmation::NotConfirmed
    };
    if catos_confirmation != CatosConfirmation::Confirmed {
        return Err("selected target is not identified as CatOS".into());
    }
    let listed = if target.root_fstype == "btrfs" {
        btrfs::list_subvolumes(top).map_err(|error| {
            format!(
                "cannot enumerate target Btrfs subvolumes: {}",
                error.message
            )
        })?
    } else {
        Vec::new()
    };
    let mut subvol_facts = SubvolFacts::default();
    let mut mount_point_observations = HashMap::new();
    if target.root_fstype == "btrfs" {
        for spec in crate::shared::model::mount_repair::CATOS_STANDARD_SUBVOLS {
            let exists_as_subvol = listed.iter().any(|item| item.path == spec.subvol);
            let top_path = top.join(spec.subvol.trim_start_matches('/'));
            let (exists_as_directory, exists_as_other) = match std::fs::symlink_metadata(&top_path)
            {
                Ok(metadata) if metadata.file_type().is_symlink() => (false, true),
                Ok(metadata) if metadata.is_dir() => (true, false),
                Ok(_) => (false, true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, false),
                Err(_) => (false, true),
            };
            subvol_facts
                .observations
                .push(crate::repair::subvol_decision::SubvolObservation {
                    subvol: spec.subvol.to_string(),
                    exists_as_subvol,
                    exists_as_directory,
                    exists_as_other,
                    mount_point_entry_count: None,
                });
            if spec.mount_point == "/" {
                continue;
            }
            let relative = Path::new(spec.mount_point.trim_start_matches('/'));
            let observation = match fs.rooted_metadata(root, relative) {
                Ok(metadata) => MountPointObservation {
                    exists: true,
                    is_symlink: metadata.is_symlink,
                    is_directory: metadata.is_dir,
                    is_other_object: !metadata.is_dir,
                    entry_count: if metadata.is_dir {
                        fs.read_dir_names(&root.join(relative))
                            .ok()
                            .map(|entries| entries.len())
                    } else {
                        None
                    },
                },
                Err(crate::shared::error::FsError::NotFound) => MountPointObservation::missing(),
                Err(error) => {
                    return Err(format!(
                        "cannot safely inspect target mount point {}: {error}",
                        spec.mount_point
                    ));
                }
            };
            mount_point_observations.insert(spec.mount_point.to_string(), observation);
        }
    }
    for mount_point in ["/boot", "/boot/efi", "/efi"] {
        let relative = Path::new(mount_point.trim_start_matches('/'));
        let observation = match fs.rooted_metadata(root, relative) {
            Ok(metadata) => MountPointObservation {
                exists: true,
                is_symlink: metadata.is_symlink,
                is_directory: metadata.is_dir,
                is_other_object: !metadata.is_dir,
                entry_count: if metadata.is_dir {
                    fs.read_dir_names(&root.join(relative))
                        .ok()
                        .map(|entries| entries.len())
                } else {
                    None
                },
            },
            Err(crate::shared::error::FsError::NotFound) => MountPointObservation::missing(),
            Err(error) => {
                return Err(format!(
                    "cannot safely inspect target mount point {mount_point}: {error}"
                ));
            }
        };
        mount_point_observations.insert(mount_point.to_string(), observation);
    }

    Ok(MountRepairInputs {
        fstab_text,
        target,
        catos_confirmation,
        subvol_facts,
        mount_point_observations,
    })
}

pub(super) fn target_rooted_path(target: &TargetIdentity, path: &str) -> String {
    let suffix = path.trim_start_matches('/');
    match target.root_subvol.as_deref() {
        Some(subvolume) => format!("{}/{}", subvolume.trim_end_matches('/'), suffix),
        None => format!("/{suffix}"),
    }
}

