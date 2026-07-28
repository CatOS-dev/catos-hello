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

use crate::mount::diagnose::layout::detect_boot_mount_layout;
use crate::mount::diagnose::target::{
    inspect_running_root, is_running_root_device, same_block_device, select_cli_root_with_cleanup,
    select_mount_repair_esp, MountPointObservation,
};
use crate::mount::execute::repair::execute_mount_repair;
use crate::mount::model::{
    AppliedAction, CleanupReport, FstabDigest, FstabTransaction, MountRepairCleanup,
    MountRepairOutcome, MountRepairPlan, MountRepairReport, MountTargetIdentity, MountVerification,
};
use crate::mount::plan::repair::apply_in_memory as apply_in_memory_pure;
use crate::mount::plan::session::{inspect_selected_root, probe_unmounted_candidates};
use crate::mount::session::TargetMountRwSession;
use crate::snapshot::diagnose::enumerate as btrfs;
use crate::snapshot::model::CleanupSummary;
use crate::target::diagnose::block::discover_devices;
use crate::target::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
use crate::target::execute::lock::DeviceLock;
use crate::target::model::{BlockDevice, DetectionStatus, Warning};
use crate::target::Evidence;

/// Re-export the inputs type so callers (`entry`, Doctor) keep a stable
/// path. The canonical definition lives in `mount::diagnose::target`.
pub use crate::mount::diagnose::target::{diagnose, MountRepairInputs};
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
            final_outcome: MountRepairOutcome::PartiallyRepaired,
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
            let mount_point_observation = if spec.mount_point == "/" {
                None
            } else {
                let observation = observe_mount_point(fs, root, spec.mount_point)?;
                mount_point_observations
                    .insert(spec.mount_point.to_string(), observation);
                Some(observation)
            };
            subvol_facts.observations.push(observe_subvolume_path(
                top,
                spec.subvol,
                listed.iter().any(|item| item.path == spec.subvol),
                mount_point_observation.and_then(|observation| observation.entry_count),
            ));
        }
    }
    for mount_point in ["/boot", "/boot/efi", "/efi"] {
        let observation = observe_mount_point(fs, root, mount_point)?;
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

fn observe_mount_point(
    fs: &RealFilesystem,
    root: &Path,
    mount_point: &str,
) -> Result<MountPointObservation, String> {
    let relative = Path::new(mount_point.trim_start_matches('/'));
    match fs.rooted_metadata(root, relative) {
        Ok(metadata) => Ok(MountPointObservation {
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
        }),
        Err(crate::error::FsError::NotFound) => Ok(MountPointObservation::missing()),
        Err(error) => Err(format!(
            "cannot safely inspect target mount point {mount_point}: {error}"
        )),
    }
}

fn observe_subvolume_path(
    top: &Path,
    subvol: &str,
    exists_as_subvol: bool,
    mount_point_entry_count: Option<usize>,
) -> crate::mount::diagnose::subvolume::SubvolObservation {
    let (exists_as_directory, exists_as_other) = if exists_as_subvol {
        (false, false)
    } else {
        let path = top.join(subvol.trim_start_matches('/'));
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => (false, true),
            Ok(metadata) if metadata.is_dir() => (true, false),
            Ok(_) => (false, true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, false),
            Err(_) => (false, true),
        }
    };
    crate::mount::diagnose::subvolume::SubvolObservation {
        subvol: subvol.to_string(),
        exists_as_subvol,
        exists_as_directory,
        exists_as_other,
        mount_point_entry_count,
    }
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
    let (root, selection_cleanup) = select_cli_root_with_cleanup(&devices, root_device);
    let selection_cleanup = summarize_probe_cleanup(selection_cleanup);
    if !selection_cleanup.all_clean {
        let mut report = MountRepairReport::refused(
            MountRepairOutcome::CleanupIncomplete,
            "automatic root-selection probe cleanup was incomplete",
        );
        report.cleanup = cleanup_into_mount_repair(selection_cleanup);
        return report;
    }
    let Some(root) = root else {
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
    let probe_cleanup = summarize_probe_cleanup(std::mem::take(&mut topology_probe.cleanup));
    if !probe_cleanup.all_clean {
        let mut report = MountRepairReport::refused(
            MountRepairOutcome::CleanupIncomplete,
            "readonly topology probe cleanup was incomplete",
        );
        report.cleanup = cleanup_into_mount_repair(probe_cleanup);
        report.warnings = warnings;
        return report;
    }
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
    if let Err(reason) = validate_rw_target_identity(&target, root, &session) {
        let cleanup = session.cleanup();
        let mut report = MountRepairReport::refused(MountRepairOutcome::DeviceChanged, &reason);
        report.cleanup = cleanup_into_mount_repair(cleanup);
        if !report.cleanup.all_clean {
            report.final_outcome = MountRepairOutcome::CleanupIncomplete;
        }
        return report;
    }
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
    let mut report =
        execute_mount_repair(&inputs, &top, authorised, &devices, |top_level, subvol| {
            crate::snapshot::execute::btrfs::create_btrfs_subvolume(top_level, subvol)
                .map_err(|error| format!("{error}"))
        });

    // Drive any pending btrfs subvolume rollbacks the pure-mount
    // rollback left for us. Pending work is identified explicitly by
    // evidence; it is not treated as a failure until deletion actually
    // fails.
    if report.evidence.iter().any(|item| {
        item.code == "ROLLBACK_RESIDUAL"
            && item.message.contains("pending btrfs subvolume rollback")
    }) {
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

/// Attempt to delete only the btrfs subvolumes this execution actually
/// created. The exact set comes from `SubvolumeCreated` actions rather
/// than the complete plan, because a failure may occur part-way through
/// creation.
fn rollback_pending_subvolumes(report: &mut MountRepairReport, top: &Path) {
    rollback_pending_subvolumes_with(report, |subvol| {
        crate::snapshot::execute::btrfs::delete_empty_btrfs_subvolume(top, subvol)
            .map_err(|error| format!("{error}"))
    });
}

fn rollback_pending_subvolumes_with<F>(report: &mut MountRepairReport, mut delete: F)
where
    F: FnMut(&str) -> Result<(), String>,
{
    let mut completed = std::collections::HashSet::new();
    for action in &report.actions {
        match action {
            AppliedAction::SubvolumeRolledBack { subvol } => {
                completed.insert(subvol.clone());
            }
            AppliedAction::RollbackResidual { resource, .. } => {
                completed.insert(resource.clone());
            }
            _ => {}
        }
    }
    let pending = report
        .actions
        .iter()
        .filter_map(|action| match action {
            AppliedAction::SubvolumeCreated { subvol } if !completed.contains(subvol) => {
                Some(subvol.clone())
            }
            _ => None,
        })
        .rev()
        .collect::<Vec<_>>();

    report.evidence.retain(|item| {
        !(item.code == "ROLLBACK_RESIDUAL"
            && item.message.contains("pending btrfs subvolume rollback"))
    });

    let mut failed = false;
    for subvol in pending {
        match delete(&subvol) {
            Ok(()) => report
                .actions
                .push(AppliedAction::SubvolumeRolledBack { subvol }),
            Err(reason) => {
                failed = true;
                report.actions.push(AppliedAction::RollbackResidual {
                    resource: subvol.clone(),
                    reason: reason.clone(),
                });
                report.evidence.push(crate::target::Evidence::new(
                    "ROLLBACK_RESIDUAL",
                    "repair::mount",
                    format!("{subvol}: {reason}"),
                ));
            }
        }
    }
    if failed {
        report.final_outcome = MountRepairOutcome::RollbackFailed;
        report.requires_human_action = true;
        report.fully_complete = false;
    }
}

// ---------------------------------------------------------------------------
// Boot repair target session: discover + mount the exact target boot
// repair needs, without entering the write/apply flow.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct BootRepairSessionOpenError {
    pub(crate) reason: String,
    pub(crate) cleanup: CleanupSummary,
}

impl BootRepairSessionOpenError {
    fn clean(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            cleanup: CleanupSummary {
                all_clean: true,
                ..CleanupSummary::default()
            },
        }
    }
}

impl std::fmt::Display for BootRepairSessionOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.reason)
    }
}

impl std::error::Error for BootRepairSessionOpenError {}

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
        let auxiliary = cleanup_auxiliary_mounts_with(&mut self.auxiliary_mounts, |path, flags| {
            crate::mount::execute::syscall::umount2(path, flags).map_err(|error| error.to_string())
        });
        merge_cleanup(auxiliary, self.root_session.cleanup())
    }
}

/// Discover and mount the exact target required by boot repair without
/// ever entering mount repair's write/apply flow. The returned session
/// owns the shared device lock and every mount it creates.
pub(crate) fn open_boot_repair_target_session(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
) -> Result<BootRepairTargetSession, BootRepairSessionOpenError> {
    let fs = RealFilesystem;
    let (devices, _) = discover_devices(&fs);
    let (root, selection_cleanup) = select_cli_root_with_cleanup(&devices, root_device);
    let selection_cleanup = summarize_probe_cleanup(selection_cleanup);
    if !selection_cleanup.all_clean {
        return Err(BootRepairSessionOpenError {
            reason: "automatic root-selection probe cleanup was incomplete".into(),
            cleanup: selection_cleanup,
        });
    }
    let root = root.ok_or_else(|| {
        BootRepairSessionOpenError::clean(
            "root device must identify exactly one verified CatOS root",
        )
    })?;
    let requested_subvol = match (root.filesystem.as_deref(), root_subvolume) {
        (Some("btrfs"), Some(value)) => value,
        (Some("btrfs"), None) => "/@",
        (_, Some(_)) => {
            return Err(BootRepairSessionOpenError::clean(
                "--root-subvolume is valid only for Btrfs roots",
            ))
        }
        (_, None) => "",
    };
    if root.filesystem.as_deref() == Some("btrfs") && requested_subvol != "/@" {
        return Err(BootRepairSessionOpenError::clean(
            "boot repair supports the CatOS standard Btrfs root subvolume /@",
        ));
    }
    let root_device_path = root.dev_path.as_deref().ok_or_else(|| {
        BootRepairSessionOpenError::clean("selected root has no stable device path")
    })?;
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
    .map_err(|error| {
        BootRepairSessionOpenError::clean(format!(
            "cannot inspect selected target read-only: {error}"
        ))
    })?;
    if selected_probe.inspection.is_catos_target.status != DetectionStatus::Detected {
        return Err(BootRepairSessionOpenError::clean(
            "selected target is not identified as CatOS",
        ));
    }
    let mut topology_probe = probe_unmounted_candidates(&devices, &selected_probe.fstab);
    let probe_cleanup = summarize_probe_cleanup(std::mem::take(&mut topology_probe.cleanup));
    if !probe_cleanup.all_clean {
        return Err(BootRepairSessionOpenError {
            reason: "readonly topology probe cleanup was incomplete".into(),
            cleanup: probe_cleanup,
        });
    }
    let esp = select_mount_repair_esp(
        &devices,
        &selected_probe.fstab,
        &topology_probe.esps,
        esp_device,
    )
    .map_err(BootRepairSessionOpenError::clean)?;
    let boot_layout = detect_boot_mount_layout(
        &selected_probe.fstab,
        &devices,
        root_device_path,
        esp.and_then(|device| device.dev_path.as_deref()),
    )
    .map_err(BootRepairSessionOpenError::clean)?;
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
    let lock = DeviceLock::try_acquire(root_device_path)
        .map_err(|error| BootRepairSessionOpenError::clean(error.message))?;
    let mut root_session = TargetMountRwSession::mount(
        root_device_path,
        root.filesystem.as_deref().unwrap_or_default(),
        running_root,
    )
    .map_err(|error| BootRepairSessionOpenError::clean(error.message.to_string()))?;
    if let Err(reason) = validate_rw_target_identity(&target, root, &root_session) {
        let cleanup = root_session.cleanup();
        return Err(BootRepairSessionOpenError { reason, cleanup });
    }
    let mut session = BootRepairTargetSession {
        target,
        devices,
        root_session,
        auxiliary_mounts: Vec::new(),
        _lock: lock,
    };
    let initialization = session
        .mount_runtime_filesystems()
        .and_then(|()| session.mount_boot_layout());
    if let Err(reason) = initialization {
        let cleanup = session.cleanup();
        return Err(BootRepairSessionOpenError { reason, cleanup });
    }
    Ok(session)
}

fn validate_rw_target_identity(
    target: &MountTargetIdentity,
    sealed: &BlockDevice,
    session: &TargetMountRwSession,
) -> Result<(), String> {
    let storage_root = session.storage_root();
    let mountinfo_body = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("cannot read mountinfo after target mount: {error}"))?;
    let mounted = crate::mount::diagnose::mountinfo::parse_all(&mountinfo_body)
        .into_iter()
        .filter(|mount| mount.mount_point == storage_root)
        .collect::<Vec<_>>();
    let mounted = match mounted.as_slice() {
        [mounted] => mounted,
        [] => {
            return Err(format!(
                "mounted target {} is absent from mountinfo",
                storage_root.display()
            ))
        }
        _ => {
            return Err(format!(
                "mounted target {} has {} stacked mountinfo entries",
                storage_root.display(),
                mounted.len()
            ))
        }
    };

    let (fresh_devices, _warnings) = discover_devices(&RealFilesystem);
    let fresh = fresh_devices
        .iter()
        .filter(|candidate| match sealed.major_minor.as_deref() {
            Some(major_minor) => candidate.major_minor.as_deref() == Some(major_minor),
            None => candidate.dev_path.as_deref().is_some_and(|path| {
                sealed
                    .dev_path
                    .as_deref()
                    .is_some_and(|sealed_path| same_block_device(path, sealed_path))
            }),
        })
        .collect::<Vec<_>>();
    let fresh = match fresh.as_slice() {
        [fresh] => *fresh,
        [] => {
            return Err(format!(
                "sealed target {} is absent from the fresh block inventory",
                sealed
                    .dev_path
                    .as_deref()
                    .unwrap_or_else(|| Path::new("<unknown>"))
                    .display()
            ))
        }
        _ => {
            return Err(format!(
                "sealed target {} matches {} fresh block records",
                sealed.name,
                fresh.len()
            ))
        }
    };
    compare_mounted_identity(sealed, mounted, fresh)?;

    if target.root_fstype == "btrfs" {
        let validated = crate::snapshot::diagnose::identity::validate_mounted_filesystem(
            storage_root,
            &target.root_device,
        )
        .map_err(|error| format!("cannot validate mounted Btrfs identity: {error}"))?;
        if let Some(expected_fsid) = target.root_uuid.as_deref() {
            if validated.filesystem.fsid != expected_fsid {
                return Err(format!(
                    "mounted Btrfs FSID {} differs from sealed {}",
                    validated.filesystem.fsid, expected_fsid
                ));
            }
        }
        let root_identity = crate::snapshot::diagnose::enumerate::show_subvolume(
            &session.target_root(),
        )
        .map_err(|error| format!("cannot validate mounted Btrfs root subvolume: {error}"))?;
        if let Some(expected_subvolume) = target.root_subvol.as_deref() {
            if root_identity.path != expected_subvolume {
                return Err(format!(
                    "mounted Btrfs root subvolume {} differs from sealed {}",
                    root_identity.path, expected_subvolume
                ));
            }
        }
    }

    let target_root = session.target_root();
    let target_text = target_root
        .to_str()
        .ok_or_else(|| "mounted target root is not valid UTF-8".to_string())?;
    let system_root =
        crate::target::diagnose::system_root::SystemRoot::from_user_input(target_text)
            .map_err(|error| format!("cannot pin mounted target root: {error}"))?;
    let mut inspection_warnings = Vec::new();
    let inspection = crate::target::diagnose::candidate::inspect_target(
        &RealFilesystem,
        &system_root,
        &mut inspection_warnings,
    );
    if inspection.is_catos_target.status != DetectionStatus::Detected {
        return Err(format!(
            "mounted target no longer identifies as CatOS: {}",
            inspection_warnings.join("; ")
        ));
    }
    Ok(())
}

fn compare_mounted_identity(
    sealed: &BlockDevice,
    mounted: &crate::target::mountinfo::MountInfo,
    fresh: &BlockDevice,
) -> Result<(), String> {
    if let Some(expected) = sealed.major_minor.as_deref() {
        // Btrfs mountinfo reports an anonymous superblock device number
        // (commonly 0:NN), not the backing block device's rdev. The fresh
        // block inventory below still has to match the sealed rdev, and the
        // caller additionally validates the mounted Btrfs FSID and root
        // subvolume, so comparing mountinfo's anonymous number would reject
        // every legitimate Btrfs write session.
        if !mounted.fstype.eq_ignore_ascii_case("btrfs") && mounted.major_minor != expected {
            return Err(format!(
                "mounted target major:minor {} differs from sealed {}",
                mounted.major_minor, expected
            ));
        }
        if fresh.major_minor.as_deref() != Some(expected) {
            return Err(format!(
                "fresh target major:minor {:?} differs from sealed {}",
                fresh.major_minor, expected
            ));
        }
    }
    let expected_fstype = sealed
        .filesystem
        .as_deref()
        .ok_or_else(|| "sealed target has no filesystem type".to_string())?;
    if !mounted.fstype.eq_ignore_ascii_case(expected_fstype) {
        return Err(format!(
            "mounted target filesystem {} differs from sealed {}",
            mounted.fstype, expected_fstype
        ));
    }
    if fresh.filesystem.as_deref() != Some(expected_fstype) {
        return Err(format!(
            "fresh target filesystem {:?} differs from sealed {}",
            fresh.filesystem, expected_fstype
        ));
    }
    if let Some(expected_uuid) = sealed.uuid.as_deref() {
        if fresh.uuid.as_deref() != Some(expected_uuid) {
            return Err(format!(
                "fresh target UUID {:?} differs from sealed {}",
                fresh.uuid, expected_uuid
            ));
        }
    }
    Ok(())
}

fn boot_runtime_bind_flags(source: &str) -> u64 {
    use crate::mount::execute::syscall::ms_flags;
    match source {
        "/dev" | "/proc" => ms_flags::MS_BIND | ms_flags::MS_REC,
        _ => ms_flags::MS_BIND,
    }
}

impl BootRepairTargetSession {
    fn mount_runtime_filesystems(&mut self) -> Result<(), String> {
        let target_root = self.target_root();
        mount_runtime_filesystems_with(
            &target_root,
            &mut self.auxiliary_mounts,
            |path| path.is_dir(),
            |source, target, fstype, flags, options| {
                crate::mount::execute::syscall::mount(source, target, fstype, flags, options)
                    .map_err(|error| error.to_string())
            },
        )
    }

    fn mount_boot_layout(&mut self) -> Result<(), String> {
        let target_root = self.target_root();
        mount_boot_layout_with(
            &self.target,
            &target_root,
            &self.devices,
            &mut self.auxiliary_mounts,
            |source, target, fstype, flags, options| {
                crate::mount::execute::syscall::mount(source, target, fstype, flags, options)
                    .map_err(|error| error.to_string())
            },
        )
    }
}

fn mount_runtime_filesystems_with<D, M>(
    target_root: &Path,
    auxiliary_mounts: &mut Vec<PathBuf>,
    mut host_is_dir: D,
    mut mount_fn: M,
) -> Result<(), String>
where
    D: FnMut(&Path) -> bool,
    M: FnMut(Option<&str>, &Path, Option<&str>, u64, Option<&str>) -> Result<(), String>,
{
    for source in ["/dev", "/proc", "/sys", "/run"] {
        if !host_is_dir(Path::new(source)) {
            return Err(format!(
                "required host runtime mount {source} is unavailable"
            ));
        }
        bind_host_path_with(target_root, auxiliary_mounts, source, source, &mut mount_fn)?;
    }
    let efivars = Path::new("/sys/firmware/efi/efivars");
    if host_is_dir(efivars) {
        bind_host_path_with(
            target_root,
            auxiliary_mounts,
            "/sys/firmware/efi/efivars",
            "/sys/firmware/efi/efivars",
            &mut mount_fn,
        )?;
    }
    Ok(())
}

fn mount_boot_layout_with<M>(
    target: &MountTargetIdentity,
    target_root: &Path,
    devices: &[BlockDevice],
    auxiliary_mounts: &mut Vec<PathBuf>,
    mut mount_fn: M,
) -> Result<(), String>
where
    M: FnMut(Option<&str>, &Path, Option<&str>, u64, Option<&str>) -> Result<(), String>,
{
    use crate::mount::model::BootMountLayout;
    let Some(layout) = target.boot_layout.clone() else {
        return Err("target boot layout was not detected".into());
    };
    match layout {
        BootMountLayout::BootInsideRoot => Ok(()),
        BootMountLayout::EspAtBootEfi { esp_device } => mount_device_at_with(
            target_root,
            devices,
            auxiliary_mounts,
            &esp_device,
            "/boot/efi",
            None,
            &mut mount_fn,
        ),
        BootMountLayout::EspAtEfi { esp_device } => mount_device_at_with(
            target_root,
            devices,
            auxiliary_mounts,
            &esp_device,
            "/efi",
            None,
            &mut mount_fn,
        ),
        BootMountLayout::EspAtBoot { esp_device } => mount_device_at_with(
            target_root,
            devices,
            auxiliary_mounts,
            &esp_device,
            "/boot",
            None,
            &mut mount_fn,
        ),
        BootMountLayout::SeparateBootAndEsp {
            boot_device,
            esp_device,
            esp_mount_point,
        } => {
            mount_device_at_with(
                target_root,
                devices,
                auxiliary_mounts,
                &boot_device,
                "/boot",
                None,
                &mut mount_fn,
            )?;
            mount_device_at_with(
                target_root,
                devices,
                auxiliary_mounts,
                &esp_device,
                &esp_mount_point,
                None,
                &mut mount_fn,
            )
        }
        BootMountLayout::BootBtrfsSubvolume {
            subvolume,
            esp_device,
            esp_mount_point,
        } => {
            mount_device_at_with(
                target_root,
                devices,
                auxiliary_mounts,
                &target.root_device,
                "/boot",
                Some(format!("subvol={subvolume}")),
                &mut mount_fn,
            )?;
            match (esp_device, esp_mount_point) {
                (Some(device), Some(mount_point)) => mount_device_at_with(
                    target_root,
                    devices,
                    auxiliary_mounts,
                    &device,
                    &mount_point,
                    None,
                    &mut mount_fn,
                ),
                (None, None) => Ok(()),
                _ => Err("Btrfs /boot layout has incomplete ESP metadata".into()),
            }
        }
    }
}

fn mount_device_at_with<M>(
    target_root: &Path,
    devices: &[BlockDevice],
    auxiliary_mounts: &mut Vec<PathBuf>,
    device: &Path,
    target_relative: &str,
    options: Option<String>,
    mount_fn: &mut M,
) -> Result<(), String>
where
    M: FnMut(Option<&str>, &Path, Option<&str>, u64, Option<&str>) -> Result<(), String>,
{
    use crate::mount::execute::syscall::ms_flags;
    let filesystem = devices
        .iter()
        .find(|candidate| {
            candidate
                .dev_path
                .as_deref()
                .is_some_and(|path| same_block_device(path, device))
        })
        .and_then(|candidate| candidate.filesystem.as_deref())
        .ok_or_else(|| format!("{} has no detected filesystem", device.display()))?;
    let mount_point = target_root.join(target_relative.trim_start_matches('/'));
    validate_boot_mountpoint(&mount_point)?;
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
    auxiliary_mounts.push(mount_point);
    Ok(())
}

fn bind_host_path_with<M>(
    target_root: &Path,
    auxiliary_mounts: &mut Vec<PathBuf>,
    source: &str,
    target_relative: &str,
    mount_fn: &mut M,
) -> Result<(), String>
where
    M: FnMut(Option<&str>, &Path, Option<&str>, u64, Option<&str>) -> Result<(), String>,
{
    let mount_point = target_root.join(target_relative.trim_start_matches('/'));
    validate_boot_mountpoint(&mount_point)?;
    mount_fn(
        Some(source),
        &mount_point,
        None,
        boot_runtime_bind_flags(source),
        None,
    )
    .map_err(|error| format!("bind mount {source} at {}: {error}", mount_point.display()))?;
    auxiliary_mounts.push(mount_point);
    Ok(())
}

fn validate_boot_mountpoint(mount_point: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(mount_point) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("{} is a symlink", mount_point.display()))
        }
        Ok(metadata) if !metadata.is_dir() => {
            Err(format!("{} is not a directory", mount_point.display()))
        }
        Ok(_) => Ok(()),
        Err(error) => Err(format!("cannot inspect {}: {error}", mount_point.display())),
    }
}

fn cleanup_auxiliary_mounts_with<U>(
    auxiliary_mounts: &mut Vec<PathBuf>,
    mut umount_fn: U,
) -> CleanupSummary
where
    U: FnMut(&Path, i32) -> Result<(), String>,
{
    let mut cleanup = CleanupSummary {
        all_clean: true,
        ..CleanupSummary::default()
    };
    for mount_point in auxiliary_mounts.drain(..).rev() {
        match umount_fn(&mount_point, 0) {
            Ok(()) => cleanup.unmounted.push(mount_point.display().to_string()),
            Err(error) => {
                let detach = umount_fn(
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
    cleanup
}

fn summarize_probe_cleanup(cleanups: Vec<CleanupReport>) -> CleanupSummary {
    cleanups.into_iter().fold(
        CleanupSummary {
            all_clean: true,
            ..CleanupSummary::default()
        },
        |summary, cleanup| merge_cleanup(summary, cleanup.into()),
    )
}

fn merge_cleanup(mut auxiliary: CleanupSummary, root: CleanupSummary) -> CleanupSummary {
    auxiliary.unmounted.extend(root.unmounted);
    auxiliary.residual.extend(root.residual);
    auxiliary.all_clean &= root.all_clean;
    auxiliary
}

#[cfg(test)]
mod boot_session_tests {
    use super::*;
    use crate::mount::model::BootMountLayout;
    use crate::target::model::{DeviceClass, DiskKind, PartitionRole};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "catos-boot-session-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            for relative in [
                "dev",
                "proc",
                "sys",
                "run",
                "sys/firmware/efi/efivars",
                "boot",
                "boot/efi",
            ] {
                std::fs::create_dir_all(path.join(relative)).unwrap();
            }
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn device(name: &str, path: &str, filesystem: &str) -> BlockDevice {
        BlockDevice {
            name: name.into(),
            dev_path: Some(PathBuf::from(path)),
            major_minor: None,
            parent: String::new(),
            class: DeviceClass::Partition,
            disk_kind: DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: None,
            size_sectors: None,
            read_only: false,
            removable: false,
            filesystem: Some(filesystem.into()),
            uuid: None,
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: Vec::new(),
            mounted_before_session: false,
            evidence: Vec::new(),
        }
    }

    fn target() -> MountTargetIdentity {
        MountTargetIdentity {
            root_device: PathBuf::from("/dev/root"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("root".into()),
            esp_device: Some(PathBuf::from("/dev/esp")),
            esp_uuid: Some("esp".into()),
            boot_layout: Some(BootMountLayout::SeparateBootAndEsp {
                boot_device: PathBuf::from("/dev/boot"),
                esp_device: PathBuf::from("/dev/esp"),
                esp_mount_point: "/boot/efi".into(),
            }),
        }
    }

    fn mount_info(major_minor: &str, fstype: &str) -> crate::target::mountinfo::MountInfo {
        crate::target::mountinfo::MountInfo {
            mount_id: 1,
            parent_id: 0,
            major_minor: major_minor.into(),
            root: "/".into(),
            mount_point: PathBuf::from("/run/catos-system/sessions/test"),
            vfs_options: vec!["rw".into()],
            optional_fields: Vec::new(),
            fstype: fstype.into(),
            source: "/dev/root".into(),
            super_options: vec!["rw".into()],
        }
    }

    #[test]
    fn mounted_identity_comparison_rejects_major_minor_uuid_and_fstype_drift() {
        let mut sealed = device("root", "/dev/root", "ext4");
        sealed.major_minor = Some("8:2".into());
        sealed.uuid = Some("root-uuid".into());
        let mut fresh = sealed.clone();
        assert!(compare_mounted_identity(&sealed, &mount_info("8:2", "ext4"), &fresh).is_ok());

        assert!(
            compare_mounted_identity(&sealed, &mount_info("8:3", "ext4"), &fresh)
                .unwrap_err()
                .contains("major:minor")
        );
        fresh.uuid = Some("other".into());
        assert!(
            compare_mounted_identity(&sealed, &mount_info("8:2", "ext4"), &fresh)
                .unwrap_err()
                .contains("UUID")
        );
        fresh = sealed.clone();
        assert!(
            compare_mounted_identity(&sealed, &mount_info("8:2", "xfs"), &fresh)
                .unwrap_err()
                .contains("filesystem")
        );
    }

    #[test]
    fn repair_subvolume_observation_carries_mountpoint_entry_count() {
        let top = TempRoot::new();
        std::fs::create_dir_all(top.0.join("@home")).unwrap();
        let observation = observe_subvolume_path(&top.0, "/@home", false, Some(4));
        assert!(observation.exists_as_directory);
        assert!(!observation.exists_as_other);
        assert_eq!(observation.mount_point_entry_count, Some(4));
    }

    #[test]
    fn btrfs_mountinfo_anonymous_device_number_does_not_fake_identity_drift() {
        let mut sealed = device("root", "/dev/root", "btrfs");
        sealed.major_minor = Some("254:1".into());
        sealed.uuid = Some("root-fsid".into());
        let fresh = sealed.clone();

        assert!(compare_mounted_identity(&sealed, &mount_info("0:25", "btrfs"), &fresh,).is_ok());
    }

    #[test]
    fn non_btrfs_mountinfo_device_number_must_still_match() {
        let mut sealed = device("root", "/dev/root", "ext4");
        sealed.major_minor = Some("254:1".into());
        let fresh = sealed.clone();

        assert!(
            compare_mounted_identity(&sealed, &mount_info("0:25", "ext4"), &fresh,)
                .unwrap_err()
                .contains("major:minor")
        );
    }

    #[test]
    fn successful_pending_subvolume_rollback_preserves_original_failure() {
        let mut report = MountRepairReport {
            final_outcome: MountRepairOutcome::VerificationFailed,
            actions: vec![
                AppliedAction::SubvolumeCreated { subvol: "/@home".into() },
                AppliedAction::SubvolumeCreated { subvol: "/@log".into() },
            ],
            evidence: vec![
                crate::target::Evidence::new(
                    "ROLLBACK_RESIDUAL",
                    "repair::mount",
                    "/@home: pending btrfs subvolume rollback",
                ),
                crate::target::Evidence::new(
                    "ROLLBACK_RESIDUAL",
                    "repair::mount",
                    "/@log: pending btrfs subvolume rollback",
                ),
            ],
            ..MountRepairReport::default()
        };
        let mut deleted = Vec::new();

        rollback_pending_subvolumes_with(&mut report, |subvol| {
            deleted.push(subvol.to_string());
            Ok(())
        });

        assert_eq!(deleted, vec!["/@log", "/@home"]);
        assert_eq!(report.final_outcome, MountRepairOutcome::VerificationFailed);
        assert!(report.evidence.iter().all(|item| {
            !(item.code == "ROLLBACK_RESIDUAL"
                && item.message.contains("pending btrfs subvolume rollback"))
        }));
        assert_eq!(
            report
                .actions
                .iter()
                .filter(|action| matches!(action, AppliedAction::SubvolumeRolledBack { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn failed_pending_subvolume_rollback_reports_only_real_residual() {
        let mut report = MountRepairReport {
            final_outcome: MountRepairOutcome::VerificationFailed,
            actions: vec![AppliedAction::SubvolumeCreated {
                subvol: "/@home".into(),
            }],
            evidence: vec![crate::target::Evidence::new(
                "ROLLBACK_RESIDUAL",
                "repair::mount",
                "/@home: pending btrfs subvolume rollback",
            )],
            ..MountRepairReport::default()
        };

        rollback_pending_subvolumes_with(&mut report, |_| Err("still busy".into()));

        assert_eq!(report.final_outcome, MountRepairOutcome::RollbackFailed);
        assert!(report.evidence.iter().any(|item| {
            item.code == "ROLLBACK_RESIDUAL"
                && item.message.contains("/@home: still busy")
        }));
        assert!(report.evidence.iter().all(|item| {
            !item.message.contains("pending btrfs subvolume rollback")
        }));
    }

    #[test]
    fn readonly_probe_cleanup_residual_is_preserved() {
        let cleanup = summarize_probe_cleanup(vec![CleanupReport {
            all_clean: false,
            directory_cleanup_error: Some("probe directory is busy".into()),
            ..CleanupReport::default()
        }]);

        assert!(!cleanup.all_clean);
        assert_eq!(cleanup.residual, vec!["probe directory is busy"]);
    }

    #[test]
    fn every_initialization_failure_cleans_completed_mounts_in_reverse_order() {
        let expected = [
            "dev",
            "proc",
            "sys",
            "run",
            "sys/firmware/efi/efivars",
            "boot",
            "boot/efi",
        ];
        let devices = vec![
            device("boot", "/dev/boot", "ext4"),
            device("esp", "/dev/esp", "vfat"),
        ];

        for fail_at in 0..expected.len() {
            let root = TempRoot::new();
            let mounted = Rc::new(RefCell::new(Vec::<PathBuf>::new()));
            let mounted_for_call = Rc::clone(&mounted);
            let mut calls = 0usize;
            let mut auxiliary = Vec::new();
            let mount_result = mount_runtime_filesystems_with(
                &root.0,
                &mut auxiliary,
                |_| true,
                |_, target, _, _, _| {
                    if calls == fail_at {
                        return Err(format!("injected mount failure at {fail_at}"));
                    }
                    calls += 1;
                    mounted_for_call.borrow_mut().push(target.to_path_buf());
                    Ok(())
                },
            )
            .and_then(|()| {
                mount_boot_layout_with(
                    &target(),
                    &root.0,
                    &devices,
                    &mut auxiliary,
                    |_, target, _, _, _| {
                        if calls == fail_at {
                            return Err(format!("injected mount failure at {fail_at}"));
                        }
                        calls += 1;
                        mounted_for_call.borrow_mut().push(target.to_path_buf());
                        Ok(())
                    },
                )
            });
            assert!(
                mount_result.is_err(),
                "failure window {fail_at} did not fail"
            );

            let unmounted = Rc::new(RefCell::new(Vec::<PathBuf>::new()));
            let unmounted_for_call = Rc::clone(&unmounted);
            let auxiliary_cleanup = cleanup_auxiliary_mounts_with(&mut auxiliary, |path, flags| {
                assert_eq!(flags, 0);
                unmounted_for_call.borrow_mut().push(path.to_path_buf());
                Ok(())
            });
            let root_cleanup = CleanupSummary {
                unmounted: vec!["<root-session>".into()],
                all_clean: true,
                ..CleanupSummary::default()
            };
            let cleanup = merge_cleanup(auxiliary_cleanup, root_cleanup);

            let expected_mounted = expected[..fail_at]
                .iter()
                .map(|relative| root.0.join(relative))
                .collect::<Vec<_>>();
            assert_eq!(
                *mounted.borrow(),
                expected_mounted,
                "failure window {fail_at}"
            );
            let mut expected_unmounted = expected_mounted;
            expected_unmounted.reverse();
            assert_eq!(
                *unmounted.borrow(),
                expected_unmounted,
                "failure window {fail_at}"
            );
            assert_eq!(
                cleanup.unmounted.last().map(String::as_str),
                Some("<root-session>")
            );
            assert!(cleanup.all_clean);
        }
    }

    #[test]
    fn auxiliary_unmount_failure_is_reported_and_root_cleanup_is_preserved() {
        let mut mounts = vec![PathBuf::from("/target/dev"), PathBuf::from("/target/proc")];
        let cleanup = cleanup_auxiliary_mounts_with(&mut mounts, |path, flags| {
            if path == Path::new("/target/proc") && flags == 0 {
                Err("busy".into())
            } else {
                Ok(())
            }
        });
        let cleanup = merge_cleanup(
            cleanup,
            CleanupSummary {
                residual: vec!["root cleanup failed".into()],
                all_clean: false,
                ..CleanupSummary::default()
            },
        );
        assert!(!cleanup.all_clean);
        assert!(cleanup
            .residual
            .iter()
            .any(|item| item.contains("detached lazily")));
        assert!(cleanup
            .residual
            .iter()
            .any(|item| item == "root cleanup failed"));
    }
}
