use super::Phase2Outcome;
use super::util::{fresh_session_root, mount_error_to_top_error};
use std::path::Path;

use crate::shared::cli::TargetSelection;
use crate::shared::error::Error;
use crate::shared::model::fstab::{FstabEntry, FstabEntryKind, FstabSource};
use crate::shared::model::inspection::Warning;
use crate::shared::model::mount::MountError;
use crate::shared::mount::plan::{build_plan, PlanInputs};
use crate::shared::mount::probe::inspect_selected_root;
use crate::shared::mount::session::Session;
use crate::shared::parse::fstab::parse_all_with_diagnostics;
use crate::shared::probe::fs_probe::{FilesystemProbe, RealFilesystem};
use crate::shared::probe::discover_devices;
use crate::shared::system_root::SystemRoot;

struct TargetInputs {
    devices: Vec<crate::shared::model::storage::BlockDevice>,
    fstab: Vec<FstabEntry>,
    warnings: Vec<Warning>,
}

pub fn run_target_plan(
    root: &SystemRoot,
    selection: &TargetSelection,
) -> Result<Phase2Outcome, Error> {
    let inputs = prepare_target_inputs(root, selection)?;
    let session_root = fresh_session_root();
    let plan = build_plan(PlanInputs {
        session_root,
        devices: &inputs.devices,
        fstab: &inputs.fstab,
        include_boot: true,
        include_local: false,
    })
    .map_err(mount_error_to_top_error)?;
    Ok(Phase2Outcome::TargetPlan {
        plan,
        warnings: inputs.warnings,
    })
}

/// Run `target mount`: build a plan, then execute it inside a private
/// mount namespace. On success the session snapshot and cleanup report
/// are returned. On failure the session rolls back automatically and the
/// error is propagated (the cleanup report is embedded in the error).
pub fn run_target_mount(
    root: &SystemRoot,
    selection: &TargetSelection,
) -> Result<Phase2Outcome, Error> {
    let inputs = prepare_target_inputs(root, selection)?;
    let session_root = fresh_session_root();
    let plan = build_plan(PlanInputs {
        session_root,
        devices: &inputs.devices,
        fstab: &inputs.fstab,
        include_boot: true,
        include_local: false,
    })
    .map_err(mount_error_to_top_error)?;

    let session_id = plan
        .session_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("anon")
        .to_string();
    let mut session = Session::new(session_id, &plan);
    match session.run(&plan) {
        Ok(snapshot) => {
            let target_root =
                SystemRoot::from_user_input(snapshot.target_root.to_str().ok_or_else(|| {
                    Error::ProbeFailed {
                        detail: "mounted target path is not valid UTF-8".into(),
                    }
                })?)?;
            let mut inspection_warnings = Vec::new();
            let inspection = crate::shared::probe::inspect_target(
                &RealFilesystem,
                &target_root,
                &mut inspection_warnings,
            );
            let cleanup = session.cleanup();
            let final_snapshot = session.snapshot();
            let mut warnings = inputs.warnings;
            warnings.extend(
                inspection_warnings
                    .into_iter()
                    .map(|message| Warning::new("TARGET_INSPECTION_WARNING", message)),
            );
            Ok(Phase2Outcome::TargetMount {
                session: final_snapshot,
                inspection: Box::new(inspection),
                cleanup,
                warnings,
            })
        }
        Err(mount_err) => {
            // Session::run already rolled back and embedded cleanup
            // evidence in the MountError. A second cleanup pass would
            // overwrite residual evidence with an empty report.
            Err(Error::MountFailed(mount_err))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn prepare_target_inputs(
    root: &SystemRoot,
    selection: &TargetSelection,
) -> Result<TargetInputs, Error> {
    let fs = RealFilesystem;
    let (devices, mut warnings) = discover_devices(&fs);
    let Some(root_path) = selection.root_device.as_deref() else {
        let (fstab, mut fstab_warnings) = read_target_fstab(root)?;
        warnings.append(&mut fstab_warnings);
        return Ok(TargetInputs {
            devices,
            fstab,
            warnings,
        });
    };

    let root_device = find_selected_device(&devices, root_path)?;
    let probe = inspect_selected_root(root_device, selection.root_subvolume.as_deref())
        .map_err(Error::MountFailed)?;
    warnings.extend(probe.warnings.clone());
    let mut fstab = probe.fstab;
    replace_root_entry(&mut fstab, root_device, selection.root_subvolume.as_deref())?;

    if probe.inspection.is_catos_target.status != crate::shared::model::runtime::DetectionStatus::Detected {
        warnings.push(Warning::new(
            "SELECTED_ROOT_NOT_CONFIRMED_CATOS",
            format!(
                "selected root {} did not positively identify as CatOS",
                root_path.display()
            ),
        ));
    }
    if !probe.cleanup.all_clean {
        return Err(Error::MountFailed(MountError {
            kind: crate::shared::model::mount::MountErrorKind::CleanupIncomplete,
            message: "selected-root discovery probe did not clean up completely".into(),
            device_or_path: Some(root_path.display().to_string()),
            errno: None,
            completed_steps: vec!["selected root inspected".into()],
            cleanup_complete: false,
            residual_mounts: probe
                .cleanup
                .residual
                .iter()
                .map(|item| item.resource.target.display().to_string())
                .collect(),
        }));
    }

    if let Some(esp_path) = selection.esp_device.as_deref() {
        let esp_device = find_selected_device(&devices, esp_path)?;
        replace_esp_entry(&mut fstab, esp_device)?;
    }

    Ok(TargetInputs {
        devices,
        fstab,
        warnings,
    })
}

fn find_selected_device<'a>(
    devices: &'a [crate::shared::model::storage::BlockDevice],
    path: &Path,
) -> Result<&'a crate::shared::model::storage::BlockDevice, Error> {
    devices
        .iter()
        .find(|device| device.dev_path.as_deref() == Some(path))
        .ok_or_else(|| {
            Error::MountFailed(MountError {
                kind: crate::shared::model::mount::MountErrorKind::DeviceNotFound,
                message: "explicitly selected block device was not discovered".into(),
                device_or_path: Some(path.display().to_string()),
                errno: None,
                completed_steps: vec![],
                cleanup_complete: true,
                residual_mounts: vec![],
            })
        })
}

fn replace_root_entry(
    fstab: &mut Vec<FstabEntry>,
    device: &crate::shared::model::storage::BlockDevice,
    subvolume: Option<&str>,
) -> Result<(), Error> {
    let source = device
        .dev_path
        .as_ref()
        .and_then(|path| path.to_str())
        .ok_or_else(|| Error::ProbeFailed {
            detail: "selected root device path is not valid UTF-8".into(),
        })?;
    let fstype = device.filesystem.clone().ok_or_else(|| {
        Error::MountFailed(MountError {
            kind: crate::shared::model::mount::MountErrorKind::UnsupportedFilesystem,
            message: "selected root filesystem type is unknown".into(),
            device_or_path: Some(source.to_string()),
            errno: None,
            completed_steps: vec![],
            cleanup_complete: true,
            residual_mounts: vec![],
        })
    })?;
    fstab.retain(|entry| entry.kind != FstabEntryKind::Root);
    fstab.push(FstabEntry {
        source: FstabSource::Path(source.to_string()),
        target: "/".into(),
        fstype,
        options: subvolume
            .map(|path| vec![format!("subvol={path}")])
            .unwrap_or_default(),
        dump: 0,
        pass: 0,
        kind: FstabEntryKind::Root,
        noauto: false,
        nofail: false,
        has_systemd_options: false,
    });
    Ok(())
}

fn replace_esp_entry(
    fstab: &mut Vec<FstabEntry>,
    device: &crate::shared::model::storage::BlockDevice,
) -> Result<(), Error> {
    let source = device
        .dev_path
        .as_ref()
        .and_then(|path| path.to_str())
        .ok_or_else(|| Error::ProbeFailed {
            detail: "selected ESP device path is not valid UTF-8".into(),
        })?;
    let fstype = device.filesystem.as_deref().ok_or_else(|| {
        Error::MountFailed(MountError {
            kind: crate::shared::model::mount::MountErrorKind::UnsupportedFilesystem,
            message: "selected ESP filesystem type is unknown".into(),
            device_or_path: Some(source.to_string()),
            errno: None,
            completed_steps: vec![],
            cleanup_complete: true,
            residual_mounts: vec![],
        })
    })?;
    if !matches!(fstype, "vfat" | "fat" | "fat32" | "fat16" | "fat12") {
        return Err(Error::MountFailed(MountError {
            kind: crate::shared::model::mount::MountErrorKind::WrongFilesystemType,
            message: "selected ESP is not a FAT filesystem".into(),
            device_or_path: Some(source.to_string()),
            errno: None,
            completed_steps: vec![],
            cleanup_complete: true,
            residual_mounts: vec![],
        }));
    }

    let existing_index = fstab.iter().position(|entry| {
        entry.kind == FstabEntryKind::Boot
            && (matches!(entry.target.as_str(), "/efi" | "/boot/efi")
                || matches!(
                    entry.fstype.as_str(),
                    "vfat" | "fat" | "fat32" | "fat16" | "fat12"
                ))
    });
    let target = existing_index
        .map(|index| fstab[index].target.clone())
        .unwrap_or_else(|| "/boot/efi".into());
    if let Some(index) = existing_index {
        fstab.remove(index);
    }
    fstab.push(FstabEntry {
        source: FstabSource::Path(source.to_string()),
        target,
        fstype: fstype.to_string(),
        options: vec![],
        dump: 0,
        pass: 2,
        kind: FstabEntryKind::Boot,
        noauto: false,
        nofail: false,
        has_systemd_options: false,
    });
    Ok(())
}

pub(super) fn read_target_fstab(root: &SystemRoot) -> Result<(Vec<FstabEntry>, Vec<Warning>), Error> {
    let fs = RealFilesystem;
    match fs.rooted_read_to_string(root.canonical_path(), Path::new("etc/fstab")) {
        Ok(body) => {
            let (entries, diagnostics) = parse_all_with_diagnostics(&body);
            let warnings = diagnostics
                .into_iter()
                .map(|diagnostic| {
                    Warning::new(
                        "FSTAB_PARSE_ERROR",
                        format!(
                            "target fstab line {} is invalid ({:?}): {}",
                            diagnostic.line, diagnostic.kind, diagnostic.text
                        ),
                    )
                })
                .collect();
            Ok((entries, warnings))
        }
        Err(crate::shared::error::FsError::NotFound) => Ok((Vec::new(), Vec::new())),
        Err(crate::shared::error::FsError::PermissionDenied) => Err(Error::PermissionDenied {
            path: root.join("etc/fstab"),
            detail: "target fstab is not readable through confined root access".into(),
        }),
        Err(error) => Err(Error::ProbeFailed {
            detail: format!("confined target fstab read failed: {error}"),
        }),
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    /// A missing fstab is a legitimate recovery state and produces an
    /// empty list rather than a fabricated host fstab.
    #[test]
    fn read_target_fstab_missing_returns_empty_vec() {
        let path = std::env::temp_dir().join(format!("catos-fstab-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let root = SystemRoot::from_user_input(path.to_str().unwrap()).unwrap();
        let (entries, warnings) = read_target_fstab(&root).unwrap();
        assert!(entries.is_empty());
        assert!(warnings.is_empty());
        let _ = std::fs::remove_dir_all(path);
    }

    /// Phase 2 must retain the same openat2 confinement as phase 1. An
    /// absolute symlink inside the target root is interpreted inside that
    /// root and must never expose the host or an arbitrary outside tree.
    #[test]
    fn read_target_fstab_does_not_follow_absolute_symlink_outside_root() {
        use std::os::unix::fs::symlink;

        let base =
            std::env::temp_dir().join(format!("catos-fstab-confined-{}", std::process::id()));
        let root_path = base.join("root");
        let outside = base.join("outside");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&root_path).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("fstab"), "UUID=ESCAPE / ext4 defaults 0 1\n").unwrap();
        symlink(outside.to_str().unwrap(), root_path.join("etc")).unwrap();

        let root = SystemRoot::from_user_input(root_path.to_str().unwrap()).unwrap();
        let result = read_target_fstab(&root);
        assert!(result.is_err() || result.as_ref().is_ok_and(|(entries, _)| entries.is_empty()));
        if let Ok((entries, _)) = result {
            assert!(entries.is_empty());
        }
        let _ = std::fs::remove_dir_all(base);
    }
}
