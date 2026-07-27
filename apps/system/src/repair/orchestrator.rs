//! Orchestrator: turn `catos-repair fs` into a structured
//! [`FsRepairReport`].
//!
//! This is the single entry point the CLI calls. It owns the side
//! effects that the per-fstype flows deliberately do NOT:
//!
//! * device discovery (reused from `probe::block`),
//! * safety evaluation (reused from `fs::safety`),
//! * repair tool dispatch (per-fstype flows in `fs::{diagnose,plan,execute}`),
//! * verification mount (`fs::verify`),
//! * final outcome synthesis.
//!
//! ## Hard contract: no shell, no format, no auto-mount-of-preexisting
//!
//! Every tool invocation goes through the [`FsCommandRunner`] trait,
//! which the real implementation (`RepairRunner`) backs with
//! [`crate::shared::process::run_trusted_tool`]'s fixed-path / minimal-env /
//! bounded-output / deadline contract. There is no `sh -c`, no
//! string-concatenated argv, no auto-format, no auto-unmount of
//! pre-existing mounts.
//!
//! ## Outcome synthesis
//!
//! The repair flow's outcome is decided by combining:
//!
//! 1. The safety verdict (refusals short-circuit everything).
//! 2. The per-fstype flow outcome (Clean / Repaired /
//!    RepairedViaHighRiskFallback / Unrepaired / ToolMissing /
//!    TimedOut).
//! 3. The verification mount outcome (mounted OK / mount failed /
//!    cleanup incomplete).
//!
//! The final `FsRepairOutcome` is the conservative combination. When
//! in doubt, we surface the worse result: a successful repair with a
//! failed verification is `VerificationFailed`, not `Repaired`.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::fs::command::FsCommandRunner;
use crate::fs::diagnose::{self, BtrfsTopology};
use crate::fs::execute::{execute_repair_plan, FlowOutcome, RepairRunner};
use crate::fs::model::{FsRepairOutcome, FsRepairReport, RepairCleanup, RepairTool};
use crate::fs::plan::{build_repair_plan, supports_filesystem};
use crate::fs::safety::{
    authorize_repair_plan, evaluate_safety, RepairTargetSelection, RunningRootDevice,
    SafetyDecision, SafetyVerdict,
};
use crate::fs::verify::{verify, VerificationOutcome};
use crate::mount::plan::session::probe_unmounted_candidates;
use crate::shared::model::evidence::Evidence;
use crate::shared::snapshot_engine::lock::DeviceLock;
use crate::target::diagnose::block::discover_devices;
use crate::target::diagnose::filesystem::RealFilesystem;
use crate::target::model::DetectionStatus;
use crate::target::model::Warning;
use crate::target::model::{BlockDevice, DeviceClass, PartitionRole, RootCandidateConfidence};

/// Run the full `catos-repair fs` flow with the default
/// `RepairRunner`. Used by the CLI in production. Tests call
/// [`run_fs_repair_with`] to inject a fake runner.
pub fn run_fs_repair(selection: RepairTargetSelection) -> FsRepairReport {
    let runner = RepairRunner::new();
    run_fs_repair_with(&runner, selection)
}

/// Testable form: takes any `FsCommandRunner` so behaviour tests can
/// drive the entire flow against fakes. The runner is the ONLY
/// injection point; device discovery, safety evaluation, and
/// verification all use their real implementations because they are
/// pure or use well-bounded helpers.
pub fn run_fs_repair_with<R: FsCommandRunner + ?Sized>(
    runner: &R,
    selection: RepairTargetSelection,
) -> FsRepairReport {
    let fs = RealFilesystem;
    let (devices, device_warnings) = discover_devices(&fs);
    let mut warnings: Vec<Warning> = device_warnings;
    let running_root = read_running_root();

    let mut evidence = Vec::new();
    evidence.push(Evidence::new(
        "DISCOVERY",
        "repair::orchestrator",
        format!("discovered {} block device(s)", devices.len()),
    ));

    let effective_selection = if selection.explicit_device.is_some() {
        selection
    } else {
        let probe = probe_unmounted_candidates(&devices, &[]);
        warnings.extend(probe.warnings);
        match auto_select_catos_root(&devices, &probe.roots) {
            Ok(device) => RepairTargetSelection {
                explicit_device: Some(device),
            },
            Err(candidates) => {
                let mut report = FsRepairReport::refused(
                    FsRepairOutcome::AmbiguousTarget,
                    &ambiguous_message(&candidates),
                );
                report.warnings = warnings;
                report.evidence = evidence;
                report.evidence.push(Evidence::new(
                    "AUTO_DISCOVERY_REFUSED",
                    "repair::orchestrator",
                    "automatic repair requires exactly one high-confidence CatOS root with a matching target fstab entry",
                ));
                return report;
            }
        }
    };

    let decision = evaluate_safety(&devices, &effective_selection, running_root.as_ref());
    evidence.extend(decision.evidence().iter().cloned());

    let verdict = decision.verdict().clone();
    match verdict {
        SafetyVerdict::Proceed {
            device,
            filesystem,
            was_mounted_before_session,
        } => proceed_with_repair::<R>(
            runner,
            device,
            filesystem.as_deref(),
            was_mounted_before_session,
            devices,
            evidence,
            warnings,
            &decision,
        ),
        SafetyVerdict::AmbiguousTarget { candidates } => {
            let mut report = FsRepairReport::refused(
                FsRepairOutcome::AmbiguousTarget,
                &ambiguous_message(&candidates),
            );
            report.warnings = warnings;
            report.evidence.extend(evidence);
            report
        }
        SafetyVerdict::RunningRoot { device } => {
            let mut report = FsRepairReport::refused(
                FsRepairOutcome::RefusedRunningRoot,
                &format!("target {} is the currently-running root", device.display()),
            );
            report.warnings = warnings;
            report.evidence.extend(evidence);
            report
        }
        SafetyVerdict::Mounted {
            device,
            mount_point,
        } => {
            let mut report = FsRepairReport::refused(
                FsRepairOutcome::RefusedMounted,
                &format!(
                    "target {} is already mounted at {}; repair requires an unmounted target",
                    device.display(),
                    mount_point.display()
                ),
            );
            report.warnings = warnings;
            report.evidence.extend(evidence);
            report
        }
        SafetyVerdict::DeviceNotFound { requested } => {
            let mut report = FsRepairReport::refused(
                FsRepairOutcome::AmbiguousTarget,
                &format!(
                    "explicitly-selected device {} was not discovered; specify a valid /dev path or run without an explicit device to use auto-discovery",
                    requested.display()
                ),
            );
            // DeviceNotFound is technically not "ambiguous" but the
            // outcome taxonomy does not have a dedicated code; we
            // surface AmbiguousTarget and the message is precise.
            report.warnings = warnings;
            report.evidence.extend(evidence);
            report
        }
        SafetyVerdict::UnsupportedRole { requested, reason } => {
            let mut report = FsRepairReport {
                target_device: Some(requested.clone()),
                filesystem_type: None,
                was_mounted_before_session: false,
                selected_tool: None,
                attempts: Vec::new(),
                verification_mount: None,
                cleanup: RepairCleanup::default(),
                final_outcome: FsRepairOutcome::Unsupported,
                requires_human_action: true,
                evidence: std::iter::once(Evidence::new(
                    "UNSUPPORTED_ROLE",
                    "fs::safety",
                    reason.clone(),
                ))
                .collect(),
                warnings: Vec::new(),
            };
            report.warnings = warnings;
            report.evidence.extend(evidence);
            report
        }
    }
}

fn auto_select_catos_root(
    devices: &[BlockDevice],
    roots: &[crate::target::model::RootCandidate],
) -> Result<PathBuf, Vec<String>> {
    let candidates: Vec<PathBuf> = roots
        .iter()
        .filter(|root| {
            root.confidence == RootCandidateConfidence::High
                && root.is_catos.status == DetectionStatus::Detected
                && root
                    .evidence
                    .iter()
                    .any(|evidence| evidence.code == "FSTAB_ROOT_MATCH")
        })
        .filter(|root| PathBuf::from(&root.source).is_absolute())
        .map(|root| &root.source)
        .filter_map(|source| {
            devices.iter().find(|device| {
                device.dev_path.as_deref() == Some(Path::new(source))
                    && !device.removable
                    && device.class != DeviceClass::Disk
                    && device.partition_role != PartitionRole::WholeDisk
            })
        })
        .filter_map(|device| device.dev_path.clone())
        .collect();
    match candidates.as_slice() {
        [device] => Ok(device.clone()),
        _ => Err(candidates
            .iter()
            .map(|device| device.display().to_string())
            .collect()),
    }
}

/// Continue after safety cleared us to proceed. Reads the filesystem
/// type, routes to the matching per-fstype flow, runs verification,
/// and synthesises the final outcome.
#[allow(clippy::too_many_arguments)]
fn proceed_with_repair<R: FsCommandRunner + ?Sized>(
    runner: &R,
    device: PathBuf,
    filesystem: Option<&str>,
    was_mounted_before_session: bool,
    all_devices: Vec<BlockDevice>,
    mut evidence: Vec<Evidence>,
    warnings: Vec<Warning>,
    safety_decision: &SafetyDecision,
) -> FsRepairReport {
    let device_str = match device.to_str() {
        Some(s) => s.to_string(),
        None => {
            return FsRepairReport {
                target_device: Some(device),
                filesystem_type: filesystem.map(str::to_string),
                was_mounted_before_session,
                selected_tool: None,
                attempts: Vec::new(),
                verification_mount: None,
                cleanup: RepairCleanup::default(),
                final_outcome: FsRepairOutcome::Unsupported,
                requires_human_action: true,
                evidence: std::iter::once(Evidence::new(
                    "DEVICE_PATH_NOT_UTF8",
                    "repair::orchestrator",
                    "device path is not valid UTF-8; cannot address repair tool".to_string(),
                ))
                .collect(),
                warnings,
            };
        }
    };

    let Some(fstype) = filesystem else {
        // No filesystem signature: refuse as Unsupported. We do not
        // guess a filesystem type to repair.
        return FsRepairReport {
            target_device: Some(device),
            filesystem_type: None,
            was_mounted_before_session,
            selected_tool: None,
            attempts: Vec::new(),
            verification_mount: None,
            cleanup: RepairCleanup::default(),
            final_outcome: FsRepairOutcome::Unsupported,
            requires_human_action: true,
            evidence: std::iter::once(Evidence::new(
                "NO_FILESYSTEM_SIGNATURE",
                "repair::orchestrator",
                format!(
                    "device {device_str} has no identified filesystem signature; refusing to guess a repair tool"
                ),
            ))
            .collect(),
            warnings,
        };
    };

    let Some(tool) = supports_filesystem(fstype) else {
        return FsRepairReport {
            target_device: Some(device),
            filesystem_type: Some(fstype.to_string()),
            was_mounted_before_session,
            selected_tool: None,
            attempts: Vec::new(),
            verification_mount: None,
            cleanup: RepairCleanup::default(),
            final_outcome: FsRepairOutcome::Unsupported,
            requires_human_action: true,
            evidence: std::iter::once(Evidence::new(
                "UNSUPPORTED_FSTYPE",
                "repair::orchestrator",
                format!("fstype {fstype:?} is not in the repair routing table"),
            ))
            .collect(),
            warnings,
        };
    };

    // Discovery-time mount state is not sufficient for a write-capable
    // fsck. Hold an advisory exclusive lock and re-check both the device
    // identity and mount table immediately before any tool invocation.
    let _guard = match RepairTargetGuard::acquire(&device, &all_devices) {
        Ok(guard) => guard,
        Err(reason) => {
            evidence.push(Evidence::new(
                "REPAIR_PREFLIGHT_REFUSED",
                "repair::orchestrator",
                reason,
            ));
            return FsRepairReport {
                target_device: Some(device),
                filesystem_type: Some(fstype.to_string()),
                was_mounted_before_session,
                selected_tool: Some(tool),
                attempts: Vec::new(),
                verification_mount: None,
                cleanup: RepairCleanup::default(),
                final_outcome: FsRepairOutcome::Unrepaired,
                requires_human_action: true,
                evidence,
                warnings,
            };
        }
    };

    let btrfs_topology = if tool == RepairTool::BtrfsCheck {
        match diagnose::btrfs::topology(runner, &device_str) {
            Ok(BtrfsTopology::SingleDevice) => Some(BtrfsTopology::SingleDevice),
            Ok(topology) => {
                let reason = match topology {
                    BtrfsTopology::MultiDevice =>
                        "btrfs filesystem has multiple devices; multi-device Btrfs repair requires manual intervention",
                    BtrfsTopology::Unknown =>
                        "could not verify Btrfs device count; refusing repair rather than risk a multi-device filesystem",
                    BtrfsTopology::SingleDevice => unreachable!(),
                };
                evidence.push(Evidence::new(
                    "BTRFS_TOPOLOGY_REFUSED",
                    "fs::diagnose::btrfs",
                    reason,
                ));
                return FsRepairReport {
                    target_device: Some(device),
                    filesystem_type: Some(fstype.to_string()),
                    was_mounted_before_session,
                    selected_tool: Some(tool),
                    attempts: Vec::new(),
                    verification_mount: None,
                    cleanup: RepairCleanup::default(),
                    final_outcome: FsRepairOutcome::Unsupported,
                    requires_human_action: true,
                    evidence,
                    warnings,
                };
            }
            Err(error) => {
                evidence.push(Evidence::new(
                    "BTRFS_TOPOLOGY_REFUSED",
                    "fs::diagnose::btrfs",
                    format!("could not inspect Btrfs device count: {error}"),
                ));
                return FsRepairReport {
                    target_device: Some(device),
                    filesystem_type: Some(fstype.to_string()),
                    was_mounted_before_session,
                    selected_tool: Some(tool),
                    attempts: Vec::new(),
                    verification_mount: None,
                    cleanup: RepairCleanup::default(),
                    final_outcome: FsRepairOutcome::Unsupported,
                    requires_human_action: true,
                    evidence,
                    warnings,
                };
            }
        }
    } else {
        None
    };

    evidence.push(Evidence::new(
        "ROUTING",
        "repair::orchestrator",
        format!("routed fstype={fstype:?} to tool={:?}", tool),
    ));

    let plan = match build_repair_plan(fstype, &device_str, btrfs_topology) {
        Ok(Some(plan)) => plan,
        Ok(None) => unreachable!("supported filesystem lost its plan route"),
        Err(error) => {
            evidence.push(Evidence::new("FS_PLAN_REFUSED", "fs::plan", error.message));
            return FsRepairReport {
                target_device: Some(device),
                filesystem_type: Some(fstype.to_string()),
                was_mounted_before_session,
                selected_tool: Some(tool),
                attempts: Vec::new(),
                verification_mount: None,
                cleanup: RepairCleanup::default(),
                final_outcome: FsRepairOutcome::Unsupported,
                requires_human_action: true,
                evidence,
                warnings,
            };
        }
    };
    let authorization = match authorize_repair_plan(safety_decision, &plan) {
        Ok(authorization) => authorization,
        Err(error) => {
            evidence.push(Evidence::new(
                "FS_AUTHORIZATION_REFUSED",
                "fs::safety",
                error.message,
            ));
            return FsRepairReport {
                target_device: Some(device),
                filesystem_type: Some(fstype.to_string()),
                was_mounted_before_session,
                selected_tool: Some(tool),
                attempts: Vec::new(),
                verification_mount: None,
                cleanup: RepairCleanup::default(),
                final_outcome: FsRepairOutcome::Unknown,
                requires_human_action: true,
                evidence,
                warnings,
            };
        }
    };
    let flow_result = execute_repair_plan(runner, &plan, &authorization);
    let flow_result = match flow_result {
        Ok(r) => r,
        Err(runner_error) => {
            // Runner-level error (spawn failure, pipe I/O error).
            // We have no attempts to record; surface as Unrepaired.
            return FsRepairReport {
                target_device: Some(device),
                filesystem_type: Some(fstype.to_string()),
                was_mounted_before_session,
                selected_tool: Some(tool),
                attempts: Vec::new(),
                verification_mount: None,
                cleanup: RepairCleanup::default(),
                final_outcome: FsRepairOutcome::Unrepaired,
                requires_human_action: true,
                evidence: {
                    let mut e = evidence;
                    e.push(Evidence::new(
                        "RUNNER_ERROR",
                        "fs::execute::runner",
                        runner_error.message,
                    ));
                    e
                },
                warnings,
            };
        }
    };

    let used_high_risk = flow_result.attempts.iter().any(|a| a.high_risk);

    let mut report = FsRepairReport {
        target_device: Some(device.clone()),
        filesystem_type: Some(fstype.to_string()),
        was_mounted_before_session,
        selected_tool: Some(tool),
        attempts: flow_result.attempts,
        verification_mount: None,
        cleanup: RepairCleanup::default(),
        final_outcome: FsRepairOutcome::Unknown, // set below
        requires_human_action: false,            // set below
        evidence,
        warnings,
    };

    // Synthesise the post-repair outcome from the flow outcome.
    let pre_verification_outcome = match flow_result.outcome {
        FlowOutcome::Clean => FsRepairOutcome::Clean,
        FlowOutcome::Repaired => FsRepairOutcome::Repaired,
        FlowOutcome::RepairedViaHighRiskFallback => FsRepairOutcome::RepairedWithRisk,
        FlowOutcome::ToolMissing => FsRepairOutcome::ToolMissing,
        FlowOutcome::TimedOut => FsRepairOutcome::Unrepaired,
        FlowOutcome::Unrepaired => FsRepairOutcome::Unrepaired,
    };

    // Short-circuit: tool missing and unsupported do not run
    // verification. Everything else does.
    if matches!(
        pre_verification_outcome,
        FsRepairOutcome::ToolMissing | FsRepairOutcome::Unsupported
    ) {
        report.final_outcome = pre_verification_outcome;
        report.requires_human_action = true;
        return report;
    }

    // Refusals never reach here, so verification runs for Clean,
    // Repaired, RepairedWithRisk, Unrepaired. For Unrepaired the
    // verification mount may still help the user understand the
    // state; we run it but keep the outcome Unrepaired.
    let verification = if matches!(pre_verification_outcome, FsRepairOutcome::Unrepaired) {
        // For an already-failed repair, attempting a verification
        // mount on a known-broken filesystem is not informative and
        // can hang the kernel on really broken media. Skip it and
        // surface the unrepaired outcome directly.
        VerificationOutcome::default()
    } else {
        verify(&device, fstype)
    };

    let verification_outcome_for_combine =
        verification.model.mounted && verification.cleanup.all_clean;
    report.verification_mount = Some(verification.model.clone());
    report.cleanup = RepairCleanup {
        unmounted: verification
            .cleanup
            .unmounted
            .iter()
            .map(|r| format!("{} on {}", r.source, r.target.display()))
            .collect(),
        residual: verification
            .cleanup
            .residual
            .iter()
            .map(|r| {
                format!(
                    "{} on {}: {}",
                    r.resource.source,
                    r.resource.target.display(),
                    r.reason
                )
            })
            .collect(),
        all_clean: verification.cleanup.all_clean,
    };
    report.evidence.extend(verification.evidence);

    report.final_outcome = if verification_outcome_for_combine {
        combine_outcomes(pre_verification_outcome)
    } else {
        // Verification did not produce a clean state. Surface the
        // worse result.
        match pre_verification_outcome {
            FsRepairOutcome::Clean
            | FsRepairOutcome::Repaired
            | FsRepairOutcome::RepairedWithRisk => FsRepairOutcome::VerificationFailed,
            other => other,
        }
    };
    report.requires_human_action =
        compute_requires_human_action(report.final_outcome, used_high_risk)
            || !report.cleanup.all_clean;

    report
}

struct RepairTargetGuard {
    _lock: DeviceLock,
}

impl RepairTargetGuard {
    fn acquire(device: &Path, devices: &[BlockDevice]) -> Result<Self, String> {
        let expected_major_minor = devices
            .iter()
            .find(|candidate| candidate.dev_path.as_deref() == Some(device))
            .and_then(|candidate| candidate.major_minor.as_deref())
            .ok_or_else(|| "target has no discovery-time major:minor identity".to_string())?;
        verify_target_unchanged(device, expected_major_minor)?;
        let lock = DeviceLock::try_acquire(device).map_err(|error| {
            format!(
                "cannot acquire shared repair/recovery lock: {}",
                error.message
            )
        })?;
        verify_target_unchanged(device, expected_major_minor)?;
        Ok(Self { _lock: lock })
    }
}

fn verify_target_unchanged(device: &Path, expected_major_minor: &str) -> Result<(), String> {
    let metadata =
        std::fs::metadata(device).map_err(|error| format!("cannot stat target device: {error}"))?;
    let actual_major_minor = format!(
        "{}:{}",
        libc::major(metadata.rdev()),
        libc::minor(metadata.rdev())
    );
    if actual_major_minor != expected_major_minor {
        return Err(format!(
            "target device identity changed from {expected_major_minor} to {actual_major_minor}"
        ));
    }
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("cannot re-read mount table: {error}"))?;
    if crate::mount::diagnose::mountinfo::parse_all(&mountinfo)
        .iter()
        .any(|mount| mount.major_minor == expected_major_minor)
    {
        return Err(format!(
            "target {device:?} is mounted immediately before repair"
        ));
    }
    Ok(())
}

/// Conservative outcome combination: when verification produced a
/// clean state, the pre-verification outcome stands.
fn combine_outcomes(pre: FsRepairOutcome) -> FsRepairOutcome {
    pre
}

fn compute_requires_human_action(outcome: FsRepairOutcome, used_high_risk: bool) -> bool {
    let base = match outcome {
        FsRepairOutcome::Clean | FsRepairOutcome::Repaired => false,
        FsRepairOutcome::RepairedWithRisk
        | FsRepairOutcome::Unrepaired
        | FsRepairOutcome::Unsupported
        | FsRepairOutcome::ToolMissing
        | FsRepairOutcome::VerificationFailed
        | FsRepairOutcome::Unknown
        | FsRepairOutcome::RefusedMounted
        | FsRepairOutcome::RefusedRunningRoot
        | FsRepairOutcome::AmbiguousTarget => true,
    };
    base || used_high_risk
}

fn ambiguous_message(candidates: &[String]) -> String {
    if candidates.is_empty() {
        "no plausible root candidate was discovered; specify a /dev path explicitly".to_string()
    } else {
        format!(
            "multiple equally-plausible root candidates discovered ({}); specify a /dev path explicitly",
            candidates.join(", ")
        )
    }
}

/// Read the currently-running root from `/proc/self/mountinfo`. Used
/// by the orchestrator to refuse repairing the live root.
fn read_running_root() -> Option<RunningRootDevice> {
    let body = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mounts = crate::mount::diagnose::mountinfo::parse_all(&body);
    let root_mount = mounts
        .iter()
        .find(|m| m.mount_point == Path::new("/"))?
        .clone();

    // Resolve alternate paths: the running root device may be
    // addressable via /dev/disk/by-uuid/... as well as /dev/mapper/...
    // We collect every /dev path we can find so the safety check
    // matches the operator's chosen spelling.
    let mut alternate_paths = Vec::new();
    if root_mount.source.starts_with("/dev/") {
        // Try to resolve by-uuid and by-partuuid symlinks pointing
        // at the same major:minor. We do NOT trust the source
        // string alone because it may be a /dev/mapper/... name.
        if let Ok(entries) = std::fs::read_dir("/dev/disk/by-uuid") {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::canonicalize(entry.path()) {
                    if same_device(&target, Path::new(&root_mount.source)) {
                        alternate_paths.push(entry.path());
                    }
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir("/dev/disk/by-partuuid") {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::canonicalize(entry.path()) {
                    if same_device(&target, Path::new(&root_mount.source)) {
                        alternate_paths.push(entry.path());
                    }
                }
            }
        }
    }

    Some(RunningRootDevice {
        mount_point: root_mount.mount_point,
        device: PathBuf::from(root_mount.source),
        alternate_paths,
    })
}

fn same_device(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(am), Ok(bm)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    am.rdev() == bm.rdev()
}
