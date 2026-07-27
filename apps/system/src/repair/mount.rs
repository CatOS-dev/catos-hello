//! `catos-repair mount` orchestration: the application-layer glue that
//! combines the pure `mount` capability (diagnose/plan/execute/verify)
//! with the snapshot-engine btrfs subvolume calls (create/delete/list)
//! and the shared device lock.
//!
//! This module is the ONLY place that may depend on BOTH `mount::*`
//! and `snapshot_engine::*`. The `mount` capability is forbidden from
//! depending on `snapshot`; `repair` (an application module) is not.
//!
//! What lives here:
//! * [`run_mount_repair_via_cli`] — the privileged CLI entry point.
//! * [`run_mount_repair_diagnosis`] / [`apply_in_memory`] /
//!   [`detect_drift`] — the diagnosis-only / in-memory apply surface
//!   shared with Doctor.
//! * [`open_boot_repair_target_session`] / [`BootRepairTargetSession`]
//!   — discover + mount the exact target boot repair needs.
//! * [`observe_target_inputs`] — read target-local facts (incl. btrfs
//!   subvolume enumeration via the snapshot engine).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::mount::diagnose::target::{
    inspect_running_root, is_running_root_device, same_block_device, select_cli_root,
    select_mount_repair_esp, MountPointObservation,
};
use crate::mount::diagnose::layout::detect_boot_mount_layout;
use crate::mount::execute::repair::execute_mount_repair;
use crate::mount::model::{
    AppliedAction, FstabDigest, FstabTransaction, MountRepairCleanup,
    MountRepairOutcome, MountRepairPlan, MountRepairReport, MountTargetIdentity, MountVerification,
};
use crate::mount::plan::repair::apply_in_memory as apply_in_memory_pure;
use crate::mount::plan::session::{inspect_selected_root, probe_unmounted_candidates};
use crate::mount::session::TargetMountRwSession;
use crate::shared::model::evidence::Evidence;
use crate::snapshot::model::CleanupSummary;
use crate::snapshot::diagnose::enumerate as btrfs;
use crate::target::execute::lock::DeviceLock;
use crate::target::diagnose::block::discover_devices;
use crate::target::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
use crate::target::model::{BlockDevice, DetectionStatus, Warning};

/// Re-export the inputs type so callers (`entry`, Doctor) keep a stable
/// path. The canonical definition lives in `mount::diagnose::target`.
pub use crate::mount::diagnose::target::{MountRepairInputs, diagnose};
pub use crate::mount::plan::repair::build_plan;

/// In-memory apply: rewrite the fstab text per the plan and verify it
/// re-parses. Thin wrapper over the pure `mount::plan::repair` impl.
pub fn apply_in_memory(
    original: &str,
    plan: &MountRepairPlan,
) -> Result<String, MountRepairOutcome> {
    apply_in_memory_pure(original, plan)
}

/// Detect identity/digest drift between a plan and a fresh observation.
pub fn detect_drift(
    plan: &MountRepairPlan,
    new_target: &MountTargetIdentity,
    new_fstab_digest: &FstabDigest,
) -> Option<MountRepairOutcome> {
    if plan.target != *new_target {
        return Some(MountRepairOutcome::DeviceChanged);
    }
    if plan.fstab_digest != *new_fstab_digest {
        return Some(MountRepairOutcome::FstabChanged);
    }
    None
}

/// Diagnosis-only entry point: build a plan + report WITHOUT touching
/// disk. Used by Doctor and by the unauthorised `catos-repair mount`
/// (no `--yes`) path.
pub fn run_mount_repair_diagnosis(
    inputs: MountRepairInputs,
    authorised: bool,
) -> MountRepairReport {
    let plan = build_plan(&inputs);
    let evidence = vec![Evidence::new(
        "DIAGNOSIS",
        "repair::mount",
        format!("diagnosed {} problem(s)", plan.problems.len()),
    )];
    let warnings: Vec<Warning> = plan
        .risks
        .iter()
        .map(|r| Warning::new("MOUNT_REPAIR_RISK", r.clone()))
        .collect();

    if plan.problems.is_empty() {
        return MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan),
            fstab_transaction: None,
            actions: Vec::new(),
            verification: None,
            cleanup: MountRepairCleanup::default(),
            final_outcome: MountRepairOutcome::Clean,
            requires_human_action: false,
            fully_complete: true,
            evidence,
            warnings,
        };
    }

    if !authorised {
        let problem_count = plan.problems.len();
        return MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan),
            fstab_transaction: None,
            actions: Vec::new(),
            verification: None,
            cleanup: MountRepairCleanup::default(),
            final_outcome: MountRepairOutcome::Clean,
            requires_human_action: problem_count > 0,
            fully_complete: false,
            evidence,
            warnings,
        };
    }

    let original = inputs.fstab_text.clone();
    let plan_for_apply = plan.clone();
    let actions = build_action_audit(&plan_for_apply);
    match apply_in_memory(&original, &plan_for_apply) {
        Ok(_new_text) => {
            let data_conflict = plan_for_apply.subvolumes.iter().any(|s| {
                inputs
                    .mount_point_observations
                    .get(&s.mount_point)
                    .is_some_and(|obs| obs.entry_count.unwrap_or(0) > 0)
            });
            let outcome = if data_conflict {
                MountRepairOutcome::PartiallyRepaired
            } else {
                MountRepairOutcome::Repaired
            };
            MountRepairReport {
                target: Some(inputs.target.clone()),
                plan: Some(plan_for_apply.clone()),
                fstab_transaction: Some(FstabTransaction {
                    original_path: PathBuf::from("/etc/fstab"),
                    backup_path: None,
                    temp_path: None,
                    atomic_replace_succeeded: false,
                    parent_fsynced: false,
                    rollback_attempted: false,
                    rollback_succeeded: false,
                }),
                actions,
                verification: Some(MountVerification::default()),
                cleanup: MountRepairCleanup::default(),
                final_outcome: outcome,
                requires_human_action: data_conflict,
                fully_complete: !data_conflict,
                evidence,
                warnings,
            }
        }
        Err(outcome) => MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan_for_apply),
            fstab_transaction: None,
            actions,
            verification: None,
            cleanup: MountRepairCleanup::default(),
            final_outcome: outcome,
            requires_human_action: true,
            fully_complete: false,
            evidence,
            warnings,
        },
    }
}

fn build_action_audit(plan: &MountRepairPlan) -> Vec<AppliedAction> {
    let mut out = Vec::new();
    for edit in &plan.fstab_edits {
        out.push(AppliedAction::FstabEdited { edit: edit.clone() });
    }
    for sub in &plan.subvolumes {
        out.push(AppliedAction::SubvolumeCreated {
            subvol: sub.subvol.clone(),
        });
    }
    for dir in &plan.directories {
        out.push(AppliedAction::DirectoryCreated {
            mount_point: dir.mount_point.clone(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// observe_target_inputs: read target-local facts (btrfs subvol enum via
// the snapshot engine).
// ---------------------------------------------------------------------------

/// Read the target-local facts the plan needs: fstab text, os-release
/// confirmation, btrfs subvolume enumeration, and mount-point
/// observations. The btrfs enumeration goes through the snapshot engine
/// because the `mount` capability is forbidden from depending on it.
pub fn observe_target_inputs(
    fs: &RealFilesystem,
    top: &Path,
    root: &Path,
    target: MountTargetIdentity,
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
        crate::mount::diagnose::subvolume::CatosConfirmation::Confirmed
    } else {
        crate::mount::diagnose::subvolume::CatosConfirmation::NotConfirmed
    };
    if catos_confirmation != crate::mount::diagnose::subvolume::CatosConfirmation::Confirmed {
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
    let mut subvol_facts = crate::mount::diagnose::subvolume::SubvolFacts::default();
    let mut mount_point_observations = HashMap::new();
    if target.root_fstype == "btrfs" {
        for spec in crate::mount::model::CATOS_STANDARD_SUBVOLS {
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
                .push(crate::mount::diagnose::subvolume::SubvolObservation {
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

// ---------------------------------------------------------------------------
// CLI entry point: privileged apply with btrfs subvolume creation.
// ---------------------------------------------------------------------------

pub fn run_mount_repair_via_cli(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
    authorised: bool,
) -> MountRepairReport {
    let fs = RealFilesystem;
    let (devices, mut warnings) = discover_devices(&fs);
    let Some(root) = select_cli_root(&devices, root_device) else {
        return MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "root device must identify exactly one verified CatOS root",
        );
    };
    let requested_subvol = match (root.filesystem.as_deref(), root_subvolume) {
        (Some("btrfs"), Some(value)) => value,
        (Some("btrfs"), None) => "/@",
        (_, Some(_)) => {
            return MountRepairReport::refused(
                MountRepairOutcome::UnsupportedLayout,
                "--root-subvolume is valid only for Btrfs roots",
            );
        }
        (_, None) => "",
    };
    if root.filesystem.as_deref() == Some("btrfs") && requested_subvol != "/@" {
        return MountRepairReport::refused(
            MountRepairOutcome::UnsupportedLayout,
            "mount repair supports the CatOS standard Btrfs root subvolume /@",
        );
    }
    let Some(device) = root.dev_path.as_deref() else {
        return MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "selected root has no stable device path",
        );
    };

    let running_root = is_running_root_device(root);
    let selected_probe_result = if running_root {
        inspect_running_root().map_err(|message| crate::mount::model::MountError {
            kind: crate::mount::model::MountErrorKind::MountFailed,
            message,
            device_or_path: Some("/".into()),
            errno: None,
            completed_steps: Vec::new(),
            cleanup_complete: true,
            residual_mounts: Vec::new(),
        })
    } else {
        inspect_selected_root(
            root,
            (root.filesystem.as_deref() == Some("btrfs")).then_some(requested_subvol),
        )
    };
    let selected_probe = match selected_probe_result {
        Ok(probe) => probe,
        Err(error) => {
            return MountRepairReport::refused(
                MountRepairOutcome::UnsupportedLayout,
                &format!(
                    "cannot inspect selected target read-only: {}",
                    error.message
                ),
            );
        }
    };
    warnings.extend(selected_probe.warnings.clone());
    if selected_probe.inspection.is_catos_target.status != DetectionStatus::Detected {
        let mut report = MountRepairReport::refused(
            MountRepairOutcome::NotCatos,
            "selected target is not identified as CatOS",
        );
        report.warnings = warnings;
        return report;
    }

    let mut topology_probe = probe_unmounted_candidates(&devices, &selected_probe.fstab);
    warnings.append(&mut topology_probe.warnings);
    let esp = match select_mount_repair_esp(
        &devices,
        &selected_probe.fstab,
        &topology_probe.esps,
        esp_device,
    ) {
        Ok(esp) => esp,
        Err(reason) => {
            let mut report =
                MountRepairReport::refused(MountRepairOutcome::AmbiguousTarget, &reason);
            report.warnings = warnings;
            return report;
        }
    };
    let boot_layout = match detect_boot_mount_layout(
        &selected_probe.fstab,
        &devices,
        device,
        esp.and_then(|device| device.dev_path.as_deref()),
    ) {
        Ok(layout) => layout,
        Err(reason) => {
            let mut report =
                MountRepairReport::refused(MountRepairOutcome::UnsupportedLayout, &reason);
            report.warnings = warnings;
            return report;
        }
    };

    let target = MountTargetIdentity {
        root_device: device.to_path_buf(),
        root_fstype: root.filesystem.clone().unwrap_or_default(),
        root_subvol: (root.filesystem.as_deref() == Some("btrfs"))
            .then(|| requested_subvol.to_string()),
        root_uuid: root.uuid.clone(),
        esp_device: esp.and_then(|device| device.dev_path.clone()),
        esp_uuid: esp.and_then(|device| device.uuid.clone()),
        boot_layout: Some(boot_layout),
    };
    let lock = match DeviceLock::try_acquire(device) {
        Ok(lock) => lock,
        Err(error) => {
            return MountRepairReport::refused(MountRepairOutcome::DeviceChanged, &error.message)
        }
    };
    let mut session = match TargetMountRwSession::mount(
        device,
        root.filesystem.as_deref().unwrap_or_default(),
        running_root,
    ) {
        Ok(session) => session,
        Err(error) => {
            return MountRepairReport::refused(
                MountRepairOutcome::UnsupportedLayout,
                &error.message,
            );
        }
    };
    let top = session.storage_root().to_path_buf();
    let root_path = session.target_root();
    let inputs = match observe_target_inputs(&fs, &top, &root_path, target) {
        Ok(inputs) => inputs,
        Err(reason) => {
            let cleanup = session.cleanup();
            let mut report = MountRepairReport::refused(MountRepairOutcome::NotCatos, &reason);
            report.cleanup = cleanup_into_mount_repair(cleanup);
            report.warnings = warnings;
            drop(lock);
            return report;
        }
    };

    // The btrfs subvolume creation hook: the only snapshot-engine
    // call site in the apply path. Delegated to the confined helper.
    let mut report = execute_mount_repair(&inputs, &top, authorised, &devices, |top_level, subvol| {
        crate::snapshot::execute::btrfs::create_btrfs_subvolume(top_level, subvol)
            .map_err(|error| format!("{error}"))
    });

    // Drive any pending btrfs subvolume rollbacks the pure-mount
    // rollback left for us. execute_mount_repair already recorded the
    // pending list as evidence; here we attempt the actual deletion
    // and merge residuals into the report.
    if report.final_outcome == MountRepairOutcome::RollbackFailed {
        rollback_pending_subvolumes(&mut report, &top);
    }

    let cleanup = session.cleanup();
    report.cleanup = cleanup_into_mount_repair(cleanup);
    if !report.cleanup.all_clean {
        report.final_outcome = MountRepairOutcome::CleanupIncomplete;
        report.requires_human_action = true;
        report.fully_complete = false;
    }
    report.warnings.extend(warnings);
    drop(lock);
    report
}

/// Convert a recovery-domain cleanup summary into the mount-repair
/// cleanup model.
fn cleanup_into_mount_repair(cleanup: CleanupSummary) -> MountRepairCleanup {
    MountRepairCleanup {
        unmounted: cleanup.unmounted,
        residual: cleanup.residual,
        all_clean: cleanup.all_clean,
    }
}

/// Attempt to delete the pending btrfs subvolumes listed in the
/// report's evidence. The pure-mount rollback recorded each pending
/// subvolume as a `ROLLBACK_RESIDUAL` evidence entry; we re-derive
/// them from the plan's subvolumes in reverse order.
fn rollback_pending_subvolumes(report: &mut MountRepairReport, top: &Path) {
    let Some(plan) = report.plan.as_ref() else {
        return;
    };
    let pending: Vec<String> = plan.subvolumes.iter().map(|s| s.subvol.clone()).rev().collect();
    for subvol in pending {
        match crate::snapshot::execute::btrfs::delete_empty_btrfs_subvolume(top, &subvol) {
            Ok(()) => report.actions.push(AppliedAction::SubvolumeRolledBack { subvol }),
            Err(error) => {
                let reason = format!("{error}");
                report.actions.push(AppliedAction::RollbackResidual {
                    resource: subvol.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Boot repair target session: discover + mount the exact target boot
// repair needs, without entering the write/apply flow.
// ---------------------------------------------------------------------------

pub(crate) struct BootRepairTargetSession {
    target: MountTargetIdentity,
    devices: Vec<BlockDevice>,
    root_session: TargetMountRwSession,
    auxiliary_mounts: Vec<PathBuf>,
    _lock: DeviceLock,
}

impl BootRepairTargetSession {
    pub(crate) fn target(&self) -> &MountTargetIdentity {
        &self.target
    }

    pub(crate) fn target_root(&self) -> PathBuf {
        self.root_session.target_root()
    }

    pub(crate) fn devices(&self) -> &[BlockDevice] {
        &self.devices
    }

    pub(crate) fn cleanup(&mut self) -> CleanupSummary {
        let mut cleanup = CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        };
        for mount_point in self.auxiliary_mounts.drain(..).rev() {
            match crate::mount::execute::syscall::umount2(&mount_point, 0) {
                Ok(()) => cleanup.unmounted.push(mount_point.display().to_string()),
                Err(error) => {
                    let detach = crate::mount::execute::syscall::umount2(
                        &mount_point,
                        crate::mount::execute::syscall::mnt_flags::MNT_DETACH,
                    );
                    cleanup.all_clean = false;
                    cleanup.residual.push(match detach {
                        Ok(()) => format!(
                            "{}: umount2 failed ({error}); detached lazily",
                            mount_point.display()
                        ),
                        Err(detach_error) => format!(
                            "{}: umount2 failed ({error}); lazy detach failed ({detach_error})",
                            mount_point.display()
                        ),
                    });
                }
            }
        }
        let root_cleanup = self.root_session.cleanup();
        cleanup.unmounted.extend(root_cleanup.unmounted);
        cleanup.residual.extend(root_cleanup.residual);
        cleanup.all_clean &= root_cleanup.all_clean;
        cleanup
    }
}

/// Discover and mount the exact target required by boot repair without
/// ever entering mount repair's write/apply flow. The returned session
/// owns the shared device lock and every mount it creates.
pub(crate) fn open_boot_repair_target_session(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
) -> Result<BootRepairTargetSession, String> {
    let fs = RealFilesystem;
    let (devices, _) = discover_devices(&fs);
    let root = select_cli_root(&devices, root_device)
        .ok_or_else(|| "root device must identify exactly one verified CatOS root".to_string())?;
    let requested_subvol = match (root.filesystem.as_deref(), root_subvolume) {
        (Some("btrfs"), Some(value)) => value,
        (Some("btrfs"), None) => "/@",
        (_, Some(_)) => return Err("--root-subvolume is valid only for Btrfs roots".into()),
        (_, None) => "",
    };
    if root.filesystem.as_deref() == Some("btrfs") && requested_subvol != "/@" {
        return Err("boot repair supports the CatOS standard Btrfs root subvolume /@".into());
    }
    let root_device_path = root
        .dev_path
        .as_deref()
        .ok_or_else(|| "selected root has no stable device path".to_string())?;
    let running_root = is_running_root_device(root);
    let selected_probe = if running_root {
        inspect_running_root()
    } else {
        inspect_selected_root(
            root,
            (root.filesystem.as_deref() == Some("btrfs")).then_some(requested_subvol),
        )
        .map_err(|error| error.message)
    }
    .map_err(|error| format!("cannot inspect selected target read-only: {error}"))?;
    if selected_probe.inspection.is_catos_target.status != DetectionStatus::Detected {
        return Err("selected target is not identified as CatOS".into());
    }
    let topology_probe = probe_unmounted_candidates(&devices, &selected_probe.fstab);
    let esp = select_mount_repair_esp(
        &devices,
        &selected_probe.fstab,
        &topology_probe.esps,
        esp_device,
    )?;
    let boot_layout = detect_boot_mount_layout(
        &selected_probe.fstab,
        &devices,
        root_device_path,
        esp.and_then(|device| device.dev_path.as_deref()),
    )?;
    let target = MountTargetIdentity {
        root_device: root_device_path.to_path_buf(),
        root_fstype: root.filesystem.clone().unwrap_or_default(),
        root_subvol: (root.filesystem.as_deref() == Some("btrfs"))
            .then(|| requested_subvol.to_string()),
        root_uuid: root.uuid.clone(),
        esp_device: esp.and_then(|device| device.dev_path.clone()),
        esp_uuid: esp.and_then(|device| device.uuid.clone()),
        boot_layout: Some(boot_layout),
    };
    let lock = DeviceLock::try_acquire(root_device_path).map_err(|error| error.message)?;
    let root_session = TargetMountRwSession::mount(
        root_device_path,
        root.filesystem.as_deref().unwrap_or_default(),
        running_root,
    )
    .map_err(|error| error.message.to_string())?;
    let mut session = BootRepairTargetSession {
        target,
        devices,
        root_session,
        auxiliary_mounts: Vec::new(),
        _lock: lock,
    };
    session.mount_runtime_filesystems()?;
    session.mount_boot_layout()?;
    Ok(session)
}

fn boot_runtime_bind_flags(source: &str) -> u64 {
    use crate::mount::execute::syscall::ms_flags;
    match source {
        "/dev" | "/proc" => ms_flags::MS_BIND | ms_flags::MS_REC,
        _ => ms_flags::MS_BIND,
    }
}

struct SyscallAdapter;

impl BootRepairTargetSession {
    fn mount_runtime_filesystems(&mut self) -> Result<(), String> {
        use crate::mount::execute::syscall::{self, ms_flags};
        for source in ["/dev", "/proc", "/sys", "/run"] {
            if !Path::new(source).is_dir() {
                return Err(format!(
                    "required host runtime mount {source} is unavailable"
                ));
            }
            self.bind_host_path(source, source, &syscall::mount)?;
        }
        let efivars = Path::new("/sys/firmware/efi/efivars");
        if efivars.is_dir() {
            self.bind_host_path(
                "/sys/firmware/efi/efivars",
                "/sys/firmware/efi/efivars",
                &syscall::mount,
            )?;
        }
        Ok(())
    }

    fn mount_boot_layout(&mut self) -> Result<(), String> {
        use crate::mount::execute::syscall::{self, ms_flags};
        use crate::mount::model::BootMountLayout;
        let Some(layout) = self.target.boot_layout.clone() else {
            return Err("target boot layout was not detected".into());
        };
        let mount_fn = &syscall::mount;
        match layout {
            BootMountLayout::BootInsideRoot => Ok(()),
            BootMountLayout::EspAtBootEfi { esp_device } => {
                self.mount_device_at(&esp_device, "/boot/efi", None, mount_fn)
            }
            BootMountLayout::EspAtEfi { esp_device } => {
                self.mount_device_at(&esp_device, "/efi", None, mount_fn)
            }
            BootMountLayout::EspAtBoot { esp_device } => {
                self.mount_device_at(&esp_device, "/boot", None, mount_fn)
            }
            BootMountLayout::SeparateBootAndEsp {
                boot_device,
                esp_device,
                esp_mount_point,
            } => {
                self.mount_device_at(&boot_device, "/boot", None, mount_fn)?;
                self.mount_device_at(&esp_device, &esp_mount_point, None, mount_fn)
            }
            BootMountLayout::BootBtrfsSubvolume {
                subvolume,
                esp_device,
                esp_mount_point,
            } => {
                self.mount_device_at(
                    &self.target.root_device.clone(),
                    "/boot",
                    Some(format!("subvol={subvolume}")),
                    mount_fn,
                )?;
                match (esp_device, esp_mount_point) {
                    (Some(device), Some(mount_point)) => {
                        self.mount_device_at(&device, &mount_point, None, mount_fn)
                    }
                    (None, None) => Ok(()),
                    _ => Err("Btrfs /boot layout has incomplete ESP metadata".into()),
                }
            }
        }
    }

    fn mount_device_at(
        &mut self,
        device: &Path,
        target_relative: &str,
        options: Option<String>,
        mount_fn: &impl Fn(Option<&str>, &Path, Option<&str>, u64, Option<&str>) -> Result<(), crate::mount::execute::syscall::SyscallError>,
    ) -> Result<(), String> {
        use crate::mount::execute::syscall::ms_flags;
        let filesystem = self
            .devices
            .iter()
            .find(|candidate| {
                candidate
                    .dev_path
                    .as_deref()
                    .is_some_and(|path| same_block_device(path, device))
            })
            .and_then(|candidate| candidate.filesystem.as_deref())
            .ok_or_else(|| format!("{} has no detected filesystem", device.display()))?;
        let mount_point = self
            .target_root()
            .join(target_relative.trim_start_matches('/'));
        match std::fs::symlink_metadata(&mount_point) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", mount_point.display()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!("{} is not a directory", mount_point.display()));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", mount_point.display())),
        }
        let source = device
            .to_str()
            .ok_or_else(|| format!("{} is not valid UTF-8", device.display()))?;
        mount_fn(
            Some(source),
            &mount_point,
            Some(filesystem),
            ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
            options.as_deref(),
        )
        .map_err(|error| {
            format!(
                "mount {} at {}: {error}",
                device.display(),
                mount_point.display()
            )
        })?;
        self.auxiliary_mounts.push(mount_point);
        Ok(())
    }

    fn bind_host_path(
        &mut self,
        source: &str,
        target_relative: &str,
        mount_fn: &impl Fn(Option<&str>, &Path, Option<&str>, u64, Option<&str>) -> Result<(), crate::mount::execute::syscall::SyscallError>,
    ) -> Result<(), String> {
        use crate::mount::execute::syscall::ms_flags;
        let mount_point = self
            .target_root()
            .join(target_relative.trim_start_matches('/'));
        match std::fs::symlink_metadata(&mount_point) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", mount_point.display()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!("{} is not a directory", mount_point.display()));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", mount_point.display())),
        }
        mount_fn(
            Some(source),
            &mount_point,
            None,
            boot_runtime_bind_flags(source),
            None,
        )
        .map_err(|error| format!("bind mount {source} at {}: {error}", mount_point.display()))?;
        self.auxiliary_mounts.push(mount_point);
        Ok(())
    }
}
