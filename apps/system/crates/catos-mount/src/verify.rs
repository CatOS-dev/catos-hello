//! Post-repair verification: mount the repaired target read-only in a
//! private namespace, read back the fstab, and confirm the written
//! state matches the plan. Pure mount (mount/unmount/fstab) — no
//! btrfs subvolume enumeration.

use std::path::{Path, PathBuf};

use crate::diagnose::fstab::{parse_all_with_diagnostics, FstabEntry};
use crate::diagnose::target::same_block_device;
use crate::execute::namespace;
use crate::execute::secure_dir::{fresh_session_name, SESSION_ROOT_PARENT};
use crate::execute::syscall::{self, mnt_flags, ms_flags};
use crate::model::{MountRepairCleanup, MountTargetIdentity, MountVerification};
use crate::plan::session::probe_unmounted_candidates;
use crate::plan::session::{build_plan as build_mount_plan, PlanInputs};
use crate::session::ReadOnlyMountSession;
use catos_target::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
use catos_target::model::BlockDevice;

pub fn verify_written_target(
    devices: &[BlockDevice],
    target: &MountTargetIdentity,
    expected_fstab: &str,
    existing_storage_root: &Path,
) -> MountVerification {
    if target.root_subvol.is_none() {
        return verify_plain_written_target(devices, target, expected_fstab, existing_storage_root);
    }
    verify_fresh_written_target(devices, target, expected_fstab)
}

pub fn verify_fresh_written_target(
    devices: &[BlockDevice],
    target: &MountTargetIdentity,
    expected_fstab: &str,
) -> MountVerification {
    let (entries, diagnostics) = parse_all_with_diagnostics(expected_fstab);
    if !diagnostics.is_empty() {
        return MountVerification {
            mounted: false,
            observed_root_fstype: None,
            mounted_targets: Vec::new(),
            failure_message: Some("rewritten fstab did not parse cleanly".into()),
        };
    }
    let session_name = match fresh_session_name("mount-repair-verify") {
        Ok(name) => name,
        Err(error) => {
            return MountVerification {
                mounted: false,
                observed_root_fstype: None,
                mounted_targets: Vec::new(),
                failure_message: Some(error.message.to_string()),
            };
        }
    };
    let session_root = Path::new(SESSION_ROOT_PARENT).join(&session_name);
    let plan = match build_mount_plan(PlanInputs {
        session_root,
        devices,
        fstab: &entries,
        include_boot: true,
        include_local: true,
    }) {
        Ok(plan) => plan,
        Err(error) => {
            return MountVerification {
                mounted: false,
                observed_root_fstype: None,
                mounted_targets: Vec::new(),
                failure_message: Some(error.message),
            };
        }
    };
    let mut session = ReadOnlyMountSession::new(session_name, &plan);
    let snapshot = match session.run(&plan) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return MountVerification {
                mounted: false,
                observed_root_fstype: None,
                mounted_targets: Vec::new(),
                failure_message: Some(error.message),
            };
        }
    };
    let root_fstab_matches = RealFilesystem
        .rooted_read_to_string(&snapshot.target_root, Path::new("etc/fstab"))
        .map(|actual| actual == expected_fstab)
        .unwrap_or(false);
    let mounted_targets = snapshot
        .mounts
        .iter()
        .map(|mount| {
            mount
                .target
                .strip_prefix(&snapshot.target_root)
                .ok()
                .filter(|relative| !relative.as_os_str().is_empty())
                .map(|relative| format!("/{}", relative.display()))
                .unwrap_or_else(|| "/".into())
        })
        .collect::<Vec<_>>();
    let observed_root_fstype = snapshot
        .mounts
        .iter()
        .find(|mount| mount.target == snapshot.target_root)
        .map(|mount| mount.fstype.clone());
    let root_type_matches = observed_root_fstype.as_deref() == Some(target.root_fstype.as_str());
    let cleanup = session.cleanup();
    let mounted = root_fstab_matches && root_type_matches && cleanup.all_clean;
    let failure_message = if !root_fstab_matches {
        Some("verification mount did not expose the written fstab".into())
    } else if !root_type_matches {
        Some(format!(
            "verification root fstype mismatch: expected {}, observed {:?}",
            target.root_fstype, observed_root_fstype
        ))
    } else if !cleanup.all_clean {
        Some("verification mount cleanup was incomplete".into())
    } else {
        None
    };
    MountVerification {
        mounted,
        observed_root_fstype,
        mounted_targets,
        failure_message,
    }
}

pub fn verify_plain_written_target(
    devices: &[BlockDevice],
    target: &MountTargetIdentity,
    expected_fstab: &str,
    existing_root: &Path,
) -> MountVerification {
    let (entries, diagnostics) = parse_all_with_diagnostics(expected_fstab);
    if !diagnostics.is_empty() {
        return MountVerification {
            mounted: false,
            observed_root_fstype: None,
            mounted_targets: Vec::new(),
            failure_message: Some("rewritten fstab did not parse cleanly".into()),
        };
    }

    let plan_root = existing_root
        .parent()
        .unwrap_or(existing_root)
        .join("plain-verification-plan");
    let plan = match build_mount_plan(PlanInputs {
        session_root: plan_root,
        devices,
        fstab: &entries,
        include_boot: true,
        include_local: true,
    }) {
        Ok(plan) => plan,
        Err(error) => {
            return MountVerification {
                mounted: false,
                observed_root_fstype: None,
                mounted_targets: Vec::new(),
                failure_message: Some(error.message),
            };
        }
    };

    let observed_root_fstype = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|body| {
            crate::diagnose::mountinfo::parse_all(&body)
                .into_iter()
                .find(|mount| mount.mount_point == existing_root)
                .map(|mount| mount.fstype)
        });
    if observed_root_fstype.as_deref() != Some(target.root_fstype.as_str()) {
        return MountVerification {
            mounted: false,
            observed_root_fstype: observed_root_fstype.clone(),
            mounted_targets: vec!["/".into()],
            failure_message: Some(format!(
                "verification root fstype mismatch: expected {}, observed {:?}",
                target.root_fstype, observed_root_fstype
            )),
        };
    }

    let mut mounted_resources: Vec<(PathBuf, String)> = Vec::new();
    let mut mounted_targets = vec!["/".to_string()];
    let mut steps: Vec<_> = plan.steps.iter().collect();
    steps.sort_by_key(|step| step.order);
    for step in steps {
        if step.target == plan.target_root {
            continue;
        }
        let relative = match step.target.strip_prefix(&plan.target_root) {
            Ok(relative) => relative,
            Err(_) => {
                cleanup_plain_verification_mounts(&mut mounted_resources);
                return MountVerification {
                    mounted: false,
                    observed_root_fstype,
                    mounted_targets,
                    failure_message: Some("verification plan target escaped its root".into()),
                };
            }
        };
        let actual_target = existing_root.join(relative);
        if let Err(error) = validate_existing_mount_target(existing_root, &actual_target) {
            cleanup_plain_verification_mounts(&mut mounted_resources);
            return MountVerification {
                mounted: false,
                observed_root_fstype,
                mounted_targets,
                failure_message: Some(error),
            };
        }
        let logical = if relative.as_os_str().is_empty() {
            "/".to_string()
        } else {
            format!("/{}", relative.display())
        };
        let pre_existing = std::fs::read_to_string("/proc/self/mountinfo")
            .ok()
            .and_then(|body| {
                crate::diagnose::mountinfo::parse_all(&body)
                    .into_iter()
                    .find(|mount| mount.mount_point == actual_target)
            });
        if let Some(observed) = pre_existing {
            let source_matches =
                if observed.source.starts_with("/dev/") && step.source.starts_with("/dev/") {
                    same_block_device(Path::new(&observed.source), Path::new(&step.source))
                } else {
                    observed.source == step.source
                };
            if observed.fstype != step.fstype || !source_matches {
                cleanup_plain_verification_mounts(&mut mounted_resources);
                return MountVerification {
                    mounted: false,
                    observed_root_fstype,
                    mounted_targets,
                    failure_message: Some(format!(
                        "pre-existing verification mount {logical} does not match fstab: source={} fstype={}",
                        observed.source, observed.fstype
                    )),
                };
            }
            mounted_targets.push(logical);
            continue;
        }
        let options = step.options_string();
        if let Err(error) = syscall::mount(
            Some(&step.source),
            &actual_target,
            Some(&step.fstype),
            ms_flags::MS_RDONLY,
            Some(&options),
        ) {
            cleanup_plain_verification_mounts(&mut mounted_resources);
            return MountVerification {
                mounted: false,
                observed_root_fstype,
                mounted_targets,
                failure_message: Some(format!(
                    "verification mount {} failed: {error}",
                    actual_target.display()
                )),
            };
        }
        mounted_targets.push(logical.clone());
        mounted_resources.push((actual_target, logical));
    }

    let fstab_matches = RealFilesystem
        .rooted_read_to_string(existing_root, Path::new("etc/fstab"))
        .map(|actual| actual == expected_fstab)
        .unwrap_or(false);
    let cleanup_error = cleanup_plain_verification_mounts(&mut mounted_resources);
    let mounted = fstab_matches && cleanup_error.is_none();
    let failure_message = if !fstab_matches {
        Some("verification root did not expose the written fstab".into())
    } else {
        cleanup_error
    };
    MountVerification {
        mounted,
        observed_root_fstype,
        mounted_targets,
        failure_message,
    }
}

pub fn validate_existing_mount_target(root: &Path, target: &Path) -> Result<(), String> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| "verification target is outside the mounted root".to_string())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err("verification target contains an unsafe path component".into());
        };
        current.push(part);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "verification mountpoint {} cannot be inspected: {error}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "verification mountpoint {} is not a real directory",
                current.display()
            ));
        }
    }
    Ok(())
}

pub fn cleanup_plain_verification_mounts(mounted: &mut Vec<(PathBuf, String)>) -> Option<String> {
    let mut residual = Vec::new();
    while let Some((target, logical)) = mounted.pop() {
        if let Err(error) = syscall::umount2(&target, 0) {
            let detach = syscall::umount2(&target, mnt_flags::MNT_DETACH);
            residual.push(match detach {
                Ok(()) => format!(
                    "verification mount {logical} required lazy detach after {error}"
                ),
                Err(detach_error) => format!(
                    "verification mount {logical} could not be unmounted: {error}; detach: {detach_error}"
                ),
            });
        }
    }
    (!residual.is_empty()).then(|| residual.join("; "))
}

pub fn cleanup_into_mount_repair(cleanup: crate::model::CleanupSummary) -> MountRepairCleanup {
    MountRepairCleanup {
        unmounted: cleanup.unmounted,
        residual: cleanup.residual,
        all_clean: cleanup.all_clean,
    }
}

// Anchor unused imports that were present in the original (namespace,
// probe) until the wider caller migration settles; the spec forbids
// `mount` from importing application modules but these are sibling
// `mount::*` symbols kept live for the future relocation of the
// orchestration layer.
#[allow(dead_code)]
fn _imports_anchor() {
    let _ = std::marker::PhantomData::<namespace::NamespaceSetup>;
    let _ = std::marker::PhantomData::<FstabEntry>;
    let _ = probe_unmounted_candidates;
}
