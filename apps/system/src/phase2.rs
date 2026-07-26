//! Phase-2 orchestrators: storage scan, target plan, target mount.
//!
//! These functions sit between `entry.rs` (which dispatches by command)
//! and the probe/mount/output layers. They own the side-effects that
//! probes deliberately avoid: spawning blkid, reading the target fstab,
//! entering the mount namespace, and producing the final structured
//! output that `output/` renders.
//!
//! Hard rule: every function here is READ-ONLY with respect to the target.
//! `run_target_mount` mounts inside a private namespace but every mount
//! is read-only with filesystem-specific safety options applied by
//! `mount::plan`. No write to the target device is ever performed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cli::TargetSelection;
use crate::shared::error::{exit_code, Error};
use crate::shared::model::fstab::{FstabEntry, FstabEntryKind, FstabSource};
use crate::shared::model::inspection::{TargetInspection, Warning};
use crate::shared::model::mount::{MountError, MountPlan, MountSession};
use crate::shared::model::storage::StorageReport;
use crate::mount::plan::{build_plan, PlanInputs};
use crate::mount::probe::{inspect_selected_root, probe_unmounted_candidates};
use crate::mount::session::{Session, SESSION_ROOT_PARENT};
use crate::parse::fstab::parse_all_with_diagnostics;
use crate::probe::candidate::candidate_ambiguities;
use crate::probe::fs_probe::{FilesystemProbe, RealFilesystem};
use crate::probe::{discover_devices, identify_candidates};
use crate::system_root::SystemRoot;

static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Outcome of a phase-2 command. Each variant carries the structured
/// model that the matching output renderer consumes.
pub enum Phase2Outcome {
    StorageScan(StorageReport),
    TargetPlan {
        plan: MountPlan,
        warnings: Vec<Warning>,
    },
    TargetMount {
        session: MountSession,
        inspection: Box<TargetInspection>,
        cleanup: crate::shared::model::mount::CleanupReport,
        warnings: Vec<Warning>,
    },
}

struct TargetInputs {
    devices: Vec<crate::shared::model::storage::BlockDevice>,
    fstab: Vec<FstabEntry>,
    warnings: Vec<Warning>,
}

/// Run `storage scan`: enumerate devices, identify candidates, emit a
/// [`StorageReport`]. Existing mounts are inspected directly; when the
/// caller has CAP_SYS_ADMIN, unmounted candidates are briefly mounted
/// read-only in a private namespace and cleaned before this returns.
pub fn run_storage_scan(root: &SystemRoot) -> Result<Phase2Outcome, Error> {
    let fs = RealFilesystem;
    let (devices, mut dev_warnings) = discover_devices(&fs);
    let fstab = match read_target_fstab(root) {
        Ok((entries, mut warnings)) => {
            dev_warnings.append(&mut warnings);
            entries
        }
        Err(error) => {
            dev_warnings.push(Warning::new(
                "TARGET_FSTAB_UNREADABLE",
                format!("could not read target fstab: {error}"),
            ));
            Vec::new()
        }
    };
    let (mut root_candidates, mut esp_candidates, _, cand_warnings) =
        identify_candidates(&devices, &fstab);
    let mut probed = probe_unmounted_candidates(&devices, &fstab);

    let probed_root_sources: HashSet<&str> = probed
        .roots
        .iter()
        .map(|candidate| candidate.source.as_str())
        .collect();
    root_candidates.retain(|candidate| !probed_root_sources.contains(candidate.source.as_str()));
    root_candidates.append(&mut probed.roots);

    let probed_esp_sources: HashSet<&str> = probed
        .esps
        .iter()
        .map(|candidate| candidate.source.as_str())
        .collect();
    esp_candidates.retain(|candidate| !probed_esp_sources.contains(candidate.source.as_str()));
    esp_candidates.append(&mut probed.esps);

    let ambiguities = candidate_ambiguities(&root_candidates, &esp_candidates);
    let mut warnings = merge_warnings(dev_warnings, cand_warnings);
    warnings.append(&mut probed.warnings);

    Ok(Phase2Outcome::StorageScan(StorageReport {
        devices,
        root_candidates,
        esp_candidates,
        btrfs_subvolumes: probed.btrfs_subvolumes,
        warnings,
        ambiguities,
    }))
}

/// Run `target plan`: read the target fstab, discover devices, build a
/// [`MountPlan`] WITHOUT executing any mount. Returns the plan plus any
/// non-fatal warnings (e.g. ambiguous device references that were
/// resolved conservatively).
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
            let inspection = crate::probe::inspect_target(
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

fn read_target_fstab(root: &SystemRoot) -> Result<(Vec<FstabEntry>, Vec<Warning>), Error> {
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

fn fresh_session_root() -> PathBuf {
    let id = generate_session_id();
    Path::new(SESSION_ROOT_PARENT).join(id)
}

/// Generate a process-local unique session id without relying on an early
/// initramfs random pool. Exclusive directory creation remains the final
/// collision and stale-session guard.
fn generate_session_id() -> String {
    let sequence = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("s{}-{sequence}", std::process::id())
}

fn merge_warnings(a: Vec<Warning>, b: Vec<Warning>) -> Vec<Warning> {
    let mut out = a;
    out.extend(b);
    out
}

fn mount_error_to_top_error(err: MountError) -> Error {
    Error::MountFailed(err)
}

/// Convenience used by entry.rs to detect whether a phase-2 command
/// should set a non-success exit code based on its outcome.
pub fn exit_code_for(outcome: &Phase2Outcome) -> i32 {
    match outcome {
        Phase2Outcome::StorageScan(report) if !report.ambiguities.is_empty() => {
            // Ambiguities are surfaced but not fatal: the report still
            // contains useful device data. We exit 0 so downstream
            // tooling can consume the JSON.
            exit_code::SUCCESS
        }
        Phase2Outcome::TargetMount { cleanup, .. } if !cleanup.all_clean => exit_code::PROBE_FAILED,
        _ => exit_code::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// generate_session_id must produce a non-empty, filesystem-safe
    /// string. Locking the format guards against a refactor that
    /// accidentally introduces a `/` and breaks the session_root path.
    #[test]
    fn session_id_is_filesystem_safe() {
        let id = generate_session_id();
        assert!(id.starts_with('s'));
        assert!(!id.contains('/'));
        assert!(!id.is_empty());
    }

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

    /// exit_code_for returns SUCCESS for a clean TargetMount outcome.
    #[test]
    fn exit_code_for_clean_target_mount_is_success() {
        let outcome = Phase2Outcome::TargetMount {
            session: MountSession {
                id: "test".into(),
                state: crate::shared::model::mount::MountSessionState::Active,
                namespace: crate::shared::model::mount::NamespaceState::PrivateNamespace,
                session_root: PathBuf::from("/tmp/x"),
                target_root: PathBuf::from("/tmp/x/target"),
                mounts: vec![],
                warnings: vec![],
            },
            inspection: Box::new(TargetInspection::default()),
            cleanup: crate::shared::model::mount::CleanupReport::default(),
            warnings: vec![],
        };
        assert_eq!(exit_code_for(&outcome), exit_code::SUCCESS);
    }

    /// exit_code_for returns PROBE_FAILED when residuals remain.
    #[test]
    fn exit_code_for_residual_target_mount_is_probe_failed() {
        let outcome = Phase2Outcome::TargetMount {
            session: MountSession {
                id: "test".into(),
                state: crate::shared::model::mount::MountSessionState::CleanupIncomplete,
                namespace: crate::shared::model::mount::NamespaceState::PrivateNamespace,
                session_root: PathBuf::from("/tmp/x"),
                target_root: PathBuf::from("/tmp/x/target"),
                mounts: vec![],
                warnings: vec![],
            },
            inspection: Box::new(TargetInspection::default()),
            cleanup: crate::shared::model::mount::CleanupReport {
                residual: vec![crate::shared::model::mount::ResidualMount {
                    resource: crate::shared::model::mount::MountedResource {
                        order: 1,
                        source: "/dev/sda1".into(),
                        target: PathBuf::from("/tmp/x/target"),
                        fstype: "ext4".into(),
                        options: "ro".into(),
                    },
                    reason: "test".into(),
                    error_code: "test".into(),
                }],
                directory_cleanup_error: None,
                all_clean: false,
                ..Default::default()
            },
            warnings: vec![],
        };
        assert_eq!(exit_code_for(&outcome), exit_code::PROBE_FAILED);
    }
}
