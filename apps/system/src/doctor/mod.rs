//! `catos-doctor` orchestrator. Read-only aggregated diagnosis that
//! stitches together the existing pure diagnosis surfaces from
//! stages 1–4:
//!
//! * environment / target discovery: phase 1 (`entry::build_report`,
//!   phase2 storage scan)
//! * filesystem: stage 2 (`repair::fs_flows::check_only_for`)
//! * mount layout / fstab: stage 3 (`repair::mount_repair::diagnose`)
//! * boot provider: stage 4 (`repair::boot_repair::detect::detect`)
//! * recovery: stage 4 (`recovery::engine::Engine::load` +
//!   `reconcile_status`, both read-only)
//!
//! ## Hard rules
//!
//! * Doctor NEVER writes to the target. The only resources it may
//!   clean up are mounts it created itself inside its private mount
//!   namespace. See [`DoctorCleanup`].
//! * Doctor NEVER invokes a repair flow. The fs diagnosis uses the
//!   `check_only_for` family (`-n`, `--readonly`, `--dry-run`), not
//!   the repair flow's `-y` / `-a` / `--repair` / `-L` paths.
//! * Doctor NEVER invokes the boot provider's `execute` or `verify`
//!   methods; it only consults the pure `detect()` function and
//!   reads deployed asset files directly.
//! * Doctor NEVER calls `Engine::load_for_write`,
//!   `Engine::load_for_revert`, `Engine::begin`, `Engine::drive`, or
//!   `Engine::revert`. Only the non-locking `Engine::load` +
//!   `reconcile_status` pair is used.
//! * Exit-code scheme B: `overall_status` and the process exit code
//!   are independent. Doctor returns 0 whenever it produced a report,
//!   even if every section found a problem.

use std::path::{Path, PathBuf};

use crate::shared::model::doctor::{
    issue_code, recommendation_code, DoctorCleanup, DoctorEnvironment, DoctorIssue,
    DoctorLimitation, DoctorOverallStatus, DoctorRecommendation, DoctorReport, DoctorSection,
    DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount_repair::{MountProblem, TargetIdentity};
use crate::shared::model::recovery::TransactionRecord;
use crate::shared::snapshot_engine::store;
use crate::repair::boot_repair::detect::{detect, DetectionInputs, DetectionVerdict};
use crate::repair::mount_repair::{MountPointObservation, MountRepairInputs};
use crate::repair::runner::CommandRunner;
use crate::repair::fs_flows::{check_only_for, ReadonlyOutcome, ReadonlyResult};
use crate::repair::subvol_decision::{CatosConfirmation, SubvolFacts};

pub mod target_selection;

use target_selection::TargetSelection;

pub fn run_doctor() -> DoctorReport {
    let runner = crate::repair::runner::TrustedRunner::new();
    run_doctor_with(&runner)
}

pub fn run_doctor_with<R: CommandRunner + ?Sized>(runner: &R) -> DoctorReport {
    let mut report = DoctorReport::default();

    let environment = capture_environment();
    report.environment = environment.clone();

    let selection = target_selection::discover_target();
    report.target = selection.to_target_summary();

    let sections = match selection {
        TargetSelection::None { reason } => handle_no_target(reason, &mut report),
        TargetSelection::Ambiguous { candidates } => {
            handle_ambiguous_target(candidates, &mut report)
        }
        TargetSelection::Identified(target) => {
            run_sections(runner, &target, &environment, &mut report)
        }
    };

    report.sections = sections;
    aggregate(&mut report);
    report.cleanup = DoctorCleanup::clean();
    report
}

fn capture_environment() -> DoctorEnvironment {
    use crate::shared::model::runtime::DetectionStatus;
    let fs = crate::shared::probe::fs_probe::RealFilesystem;
    let runtime = crate::shared::probe::detect_runtime(&fs);
    let primary_mode = runtime.primary_mode();
    let running_root_is_catos =
        matches!(runtime.is_snapshot_boot.status, DetectionStatus::Detected)
            || is_running_root_catos(&fs);
    DoctorEnvironment {
        primary_mode: primary_mode_label(primary_mode),
        running_root_is_catos,
    }
}

fn primary_mode_label(mode: crate::shared::model::runtime::PrimaryRuntimeMode) -> String {
    use crate::shared::model::runtime::PrimaryRuntimeMode::*;
    match mode {
        RunningSystem => "running_system",
        Chroot => "chroot",
        LiveEnvironment => "live_environment",
        Initramfs => "initramfs",
        Unknown => "unknown",
    }
    .to_string()
}

fn is_running_root_catos(fs: &crate::shared::probe::fs_probe::RealFilesystem) -> bool {
    use crate::shared::model::runtime::DetectionStatus;
    let root = match crate::shared::system_root::SystemRoot::from_user_input("/") {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut warnings = Vec::new();
    let inspection = crate::shared::probe::inspect_target(fs, &root, &mut warnings);
    inspection.is_catos_target.status == DetectionStatus::Detected
}

fn run_sections<R: CommandRunner + ?Sized>(
    runner: &R,
    target: &TargetIdentity,
    env: &DoctorEnvironment,
    report: &mut DoctorReport,
) -> Vec<DoctorSection> {
    let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();

    let _ = run_environment_section(&mut sections, env);
    let _ = run_storage_section(&mut sections, target);
    let _ = run_filesystem_section(runner, &mut sections, target, report);
    let _ = run_mount_section(&mut sections, target, report);
    let _ = run_boot_section(&mut sections, target, report);
    let _ = run_secure_boot_section(&mut sections, target, report);
    let _ = run_recovery_section(&mut sections, target, report);

    sections.into_iter().map(|(_, s)| s).collect()
}

fn set_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    id: DoctorSectionId,
    status: DoctorSectionStatus,
) -> &mut DoctorSection {
    let entry = sections
        .iter_mut()
        .find(|(sid, _)| *sid == id)
        .expect("canonical section list is exhaustive");
    entry.1.status = status;
    &mut entry.1
}

fn push_issue(sections: &mut [(DoctorSectionId, DoctorSection)], issue: DoctorIssue) {
    let id = issue.section;
    let entry = sections
        .iter_mut()
        .find(|(sid, _)| *sid == id)
        .expect("canonical section list is exhaustive");
    entry.1.issues.push(issue);
}

fn push_evidence(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    id: DoctorSectionId,
    ev: Evidence,
) {
    let entry = sections
        .iter_mut()
        .find(|(sid, _)| *sid == id)
        .expect("canonical section list is exhaustive");
    entry.1.evidence.push(ev);
}

fn run_environment_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    env: &DoctorEnvironment,
) -> Result<(), ()> {
    let section = set_section(
        sections,
        DoctorSectionId::Environment,
        DoctorSectionStatus::Healthy,
    );
    section.evidence.push(Evidence::new(
        "PRIMARY_MODE",
        "doctor::environment",
        format!("runtime primary mode: {}", env.primary_mode),
    ));
    section.evidence.push(Evidence::new(
        "RUNNING_ROOT_CATOS",
        "doctor::environment",
        format!("running root is CatOS: {}", env.running_root_is_catos),
    ));
    Ok(())
}

fn run_storage_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
) -> Result<(), ()> {
    let section = set_section(
        sections,
        DoctorSectionId::Storage,
        DoctorSectionStatus::Healthy,
    );
    section.evidence.push(Evidence::new(
        "ROOT_DEVICE",
        "doctor::storage",
        format!("root device: {}", target.root_device.display()),
    ));
    if let Some(esp) = target.esp_device.as_deref() {
        section.evidence.push(Evidence::new(
            "ESP_DEVICE",
            "doctor::storage",
            format!("ESP device: {}", esp.display()),
        ));
    }
    Ok(())
}

fn run_filesystem_section<R: CommandRunner + ?Sized>(
    runner: &R,
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Filesystem;
    let fstype = target.root_fstype.as_str();
    let device = match target.root_device.to_str() {
        Some(s) => s.to_string(),
        None => {
            let section = set_section(sections, id, DoctorSectionStatus::Skipped);
            report.limitations.push(DoctorLimitation::new(
                id,
                "DEVICE_PATH_NOT_UTF8",
                "root device path is not valid UTF-8; fs check skipped",
            ));
            section.issues.push(DoctorIssue::new(
                issue_code::FS_CHECK_FAILED,
                DoctorSeverity::Warning,
                id,
                "root device path is not valid UTF-8",
            ));
            return Ok(());
        }
    };

    if is_device_mounted_rw(&target.root_device) {
        let section = set_section(sections, id, DoctorSectionStatus::Skipped);
        report.limitations.push(DoctorLimitation::new(
            id,
            issue_code::FS_OFFLINE_CHECK_REQUIRED,
            "offline fsck requires an unmounted target; current root is mounted RW",
        ));
        let issue = DoctorIssue::new(
            issue_code::FS_OFFLINE_CHECK_REQUIRED,
            DoctorSeverity::Warning,
            id,
            "filesystem check requires an unmounted target; boot a CatOS Live environment to run catos-repair fs",
        )
        .with_recommendation(recommendation_code::BOOT_LIVE_ENVIRONMENT);
        section.issues.push(issue);
        return Ok(());
    }

    let result = match check_only_for(fstype, runner, &device) {
        Ok(Some(result)) => result,
        Ok(None) => {
            set_section(sections, id, DoctorSectionStatus::Skipped);
            report.limitations.push(DoctorLimitation::new(
                id,
                "UNSUPPORTED_FSTYPE",
                format!("fstype {fstype:?} has no read-only check routing"),
            ));
            return Ok(());
        }
        Err(err) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(
                id,
                issue_code::FS_CHECK_FAILED,
                format!("read-only check runner error: {}", err.message),
            ));
            return Ok(());
        }
    };

    push_fs_evidence(sections, id, &result);
    match result.outcome {
        ReadonlyOutcome::Clean => {
            set_section(sections, id, DoctorSectionStatus::Healthy);
        }
        ReadonlyOutcome::CorruptionDetected => {
            let section = set_section(sections, id, DoctorSectionStatus::Critical);
            section.issues.push(
                DoctorIssue::new(
                    issue_code::FS_CORRUPTION_DETECTED,
                    DoctorSeverity::Critical,
                    id,
                    format!(
                        "read-only {} check reported filesystem corruption",
                        result.tool
                    ),
                )
                .with_recommendation(recommendation_code::RUN_CATOS_REPAIR_FS),
            );
        }
        ReadonlyOutcome::ToolMissing => {
            set_section(sections, id, DoctorSectionStatus::Skipped);
            report.limitations.push(DoctorLimitation::new(
                id,
                issue_code::FS_TOOL_MISSING,
                format!("{} binary is not installed on the host", result.tool),
            ));
        }
        ReadonlyOutcome::TimedOut => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(
                id,
                issue_code::FS_CHECK_FAILED,
                format!("{} read-only check timed out", result.tool),
            ));
        }
        ReadonlyOutcome::Ambiguous => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(
                id,
                issue_code::FS_CHECK_FAILED,
                format!(
                    "{} read-only check returned an ambiguous exit code",
                    result.tool
                ),
            ));
        }
    }
    Ok(())
}

fn push_fs_evidence(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    id: DoctorSectionId,
    result: &ReadonlyResult,
) {
    let argv = result.argv.join(" ");
    push_evidence(
        sections,
        id,
        Evidence::new(
            "FS_CHECK",
            format!("repair::fs_flows::{}", result.tool),
            format!("argv: {argv}"),
        )
        .with_value(format!("exit={}", result.exit_code)),
    );
    if let Some(label) = result.label.as_deref() {
        push_evidence(
            sections,
            id,
            Evidence::new("FS_CHECK_LABEL", result.tool, format!("label: {label}")),
        );
    }
    let stdout = String::from_utf8_lossy(&result.stdout);
    if !stdout.trim().is_empty() {
        push_evidence(
            sections,
            id,
            Evidence::new(
                "FS_CHECK_STDOUT",
                result.tool,
                truncate_for_evidence(&stdout),
            )
            .with_value(format!("truncated={}", result.stdout_truncated)),
        );
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    if !stderr.trim().is_empty() {
        push_evidence(
            sections,
            id,
            Evidence::new(
                "FS_CHECK_STDERR",
                result.tool,
                truncate_for_evidence(&stderr),
            )
            .with_value(format!("truncated={}", result.stderr_truncated)),
        );
    }
}

fn truncate_for_evidence(s: &str) -> String {
    const MAX: usize = 400;
    if s.len() <= MAX {
        s.to_string()
    } else {
        let mut out = s[..MAX].to_string();
        out.push('…');
        out
    }
}

fn run_mount_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Mount;
    let inputs = build_mount_inputs(target);
    let problems = crate::repair::mount_repair::diagnose(&inputs);
    push_mount_evidence(sections, id, target);

    let status = derive_mount_section_status(&problems);
    set_section(sections, id, status);

    for problem in &problems {
        let issue = mount_problem_to_issue(problem, id);
        push_issue(sections, issue);
    }

    if problems.iter().any(|p| {
        matches!(
            p,
            MountProblem::MissingSubvolume { .. }
                | MountProblem::MissingMountPoint { .. }
                | MountProblem::MissingStandardEntry { .. }
        )
    }) {
        report.recommendations.push(DoctorRecommendation::new(
            recommendation_code::RUN_CATOS_REPAIR_MOUNT,
            "mount layout is missing standard entries or subvolumes; catos-repair mount can recreate them when authorised",
        ).with_command("catos-repair mount"));
    }
    if problems
        .iter()
        .any(|p| matches!(p, MountProblem::RootUuidMismatch { .. }))
    {
        report.recommendations.push(
            DoctorRecommendation::new(
                recommendation_code::RUN_CATOS_REPAIR_MOUNT,
                "root UUID in fstab does not match the discovered device",
            )
            .with_command("catos-repair mount"),
        );
    }
    Ok(())
}

fn build_mount_inputs(target: &TargetIdentity) -> MountRepairInputs {
    let fstab_text = read_target_fstab(target).unwrap_or_default();
    let catos_confirmation = if target.root_fstype == "btrfs" {
        CatosConfirmation::Confirmed
    } else {
        CatosConfirmation::NotConfirmed
    };
    MountRepairInputs {
        fstab_text,
        target: target.clone(),
        catos_confirmation,
        subvol_facts: SubvolFacts::default(),
        mount_point_observations: collect_mount_point_observations(target),
    }
}

fn read_target_fstab(target: &TargetIdentity) -> Option<String> {
    let root = target_root_path(target);
    std::fs::read_to_string(root.join("etc/fstab")).ok()
}

fn target_root_path(_target: &TargetIdentity) -> PathBuf {
    PathBuf::from("/")
}

fn collect_mount_point_observations(
    target: &TargetIdentity,
) -> std::collections::HashMap<String, MountPointObservation> {
    let mut out = std::collections::HashMap::new();
    if target.root_fstype != "btrfs" {
        return out;
    }
    let root = target_root_path(target);
    for spec in crate::shared::model::mount_repair::CATOS_STANDARD_SUBVOLS {
        if spec.mount_point == "/" {
            continue;
        }
        let rel = spec
            .mount_point
            .strip_prefix('/')
            .unwrap_or(spec.mount_point);
        let path = root.join(rel);
        let obs = observe_path(&path);
        out.insert(spec.mount_point.to_string(), obs);
    }
    out
}

fn observe_path(path: &Path) -> MountPointObservation {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return MountPointObservation::missing(),
    };
    let is_symlink = meta.file_type().is_symlink();
    let is_directory = meta.is_dir();
    let entry_count = if is_directory {
        std::fs::read_dir(path).map(|rd| rd.count()).ok()
    } else {
        None
    };
    MountPointObservation {
        exists: true,
        is_symlink,
        is_directory,
        is_other_object: !is_symlink && !is_directory,
        entry_count,
    }
}

fn derive_mount_section_status(problems: &[MountProblem]) -> DoctorSectionStatus {
    if problems.is_empty() {
        return DoctorSectionStatus::Healthy;
    }
    let any_critical = problems.iter().any(|p| {
        matches!(
            p,
            MountProblem::UnsafeMountPoint { .. } | MountProblem::AmbiguousEsp { .. }
        )
    });
    if any_critical {
        return DoctorSectionStatus::Critical;
    }
    let any_unhealthy = problems.iter().any(|p| {
        matches!(
            p,
            MountProblem::MissingRootEntry
                | MountProblem::RootSourceUnresolvable
                | MountProblem::RootUuidMismatch { .. }
                | MountProblem::RootWrongSubvol { .. }
                | MountProblem::EspUuidMismatch { .. }
                | MountProblem::EspMountPointMismatch { .. }
                | MountProblem::SnapshotsWrongSubvol { .. }
                | MountProblem::MissingSubvolume { .. }
                | MountProblem::MissingMountPoint { .. }
        )
    });
    if any_unhealthy {
        return DoctorSectionStatus::Unhealthy;
    }
    DoctorSectionStatus::Degraded
}

fn mount_problem_to_issue(problem: &MountProblem, section: DoctorSectionId) -> DoctorIssue {
    use MountProblem::*;
    let (code, severity, msg) = match problem {
        UnparseableLine { line, reason } => (
            issue_code::FSTAB_UNPARSEABLE,
            DoctorSeverity::Error,
            format!("fstab line {line} unparseable: {reason}"),
        ),
        MissingRootEntry => (
            issue_code::FSTAB_ROOT_SOURCE_MISMATCH,
            DoctorSeverity::Error,
            "fstab has no entry for /".to_string(),
        ),
        RootSourceUnresolvable => (
            issue_code::FSTAB_ROOT_SOURCE_MISMATCH,
            DoctorSeverity::Error,
            "root source does not resolve to a discovered device".to_string(),
        ),
        RootUuidMismatch { expected, actual } => (
            issue_code::FSTAB_ROOT_SOURCE_MISMATCH,
            DoctorSeverity::Error,
            format!("root UUID mismatch (expected {expected}, got {actual})"),
        ),
        RootWrongSubvol { actual } => (
            issue_code::FSTAB_ROOT_SUBVOLUME_WRONG,
            DoctorSeverity::Error,
            format!("root subvol is {actual}, expected /@"),
        ),
        StandardWrongSubvol {
            mount_point,
            expected,
            actual,
        } => (
            issue_code::STANDARD_SUBVOLUME_MISSING,
            DoctorSeverity::Error,
            format!("{mount_point}: expected subvol {expected}, got {actual}"),
        ),
        MissingStandardEntry {
            mount_point,
            subvol,
        } => (
            issue_code::STANDARD_SUBVOLUME_MISSING,
            DoctorSeverity::Error,
            format!("missing standard entry {mount_point} → {subvol}"),
        ),
        SnapshotsWrongSubvol { actual } => (
            issue_code::STANDARD_SUBVOLUME_MISSING,
            DoctorSeverity::Error,
            format!("/.snapshots subvol is {actual}, expected /@snapshots"),
        ),
        EspUuidMismatch { expected, actual } => (
            issue_code::ESP_UUID_MISMATCH,
            DoctorSeverity::Error,
            format!("ESP UUID mismatch (expected {expected}, got {actual})"),
        ),
        EspMountPointMismatch { expected, actual } => (
            issue_code::ESP_AMBIGUOUS,
            DoctorSeverity::Error,
            format!("ESP mount-point mismatch (expected {expected}, got {actual})"),
        ),
        DuplicateMountPoint { mount_point } => (
            issue_code::FSTAB_UNPARSEABLE,
            DoctorSeverity::Error,
            format!("duplicate fstab entry for {mount_point}"),
        ),
        SwapEntryMistyped => (
            "SWAP_ENTRY_MISTYPED",
            DoctorSeverity::Warning,
            "swap entry is mistyped".to_string(),
        ),
        MissingSubvolume { subvol } => (
            issue_code::STANDARD_SUBVOLUME_MISSING,
            DoctorSeverity::Error,
            format!("standard subvolume {subvol} is missing"),
        ),
        MissingMountPoint { mount_point } => (
            issue_code::STANDARD_SUBVOLUME_MISSING,
            DoctorSeverity::Error,
            format!("standard mount-point {mount_point} is missing"),
        ),
        UnsafeMountPoint {
            mount_point,
            reason,
        } => (
            "UNSAFE_MOUNT_POINT",
            DoctorSeverity::Critical,
            format!("{mount_point}: {reason}"),
        ),
        AmbiguousEsp { candidates } => (
            issue_code::ESP_AMBIGUOUS,
            DoctorSeverity::Critical,
            format!("multiple ESP candidates: {}", candidates.join(", ")),
        ),
        StaleSource { source } => (
            "STALE_SOURCE",
            DoctorSeverity::Warning,
            format!("source {source} no longer exists"),
        ),
    };
    DoctorIssue::new(code, severity, section, msg)
}

fn push_mount_evidence(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    id: DoctorSectionId,
    target: &TargetIdentity,
) {
    push_evidence(
        sections,
        id,
        Evidence::new(
            "ROOT_IDENTITY",
            "repair::mount_repair::diagnose",
            format!(
                "root_device={}, fstype={}, subvol={:?}",
                target.root_device.display(),
                target.root_fstype,
                target.root_subvol
            ),
        ),
    );
    if let Some(layout) = target.boot_layout.as_ref() {
        push_evidence(
            sections,
            id,
            Evidence::new(
                "BOOT_LAYOUT",
                "repair::mount_repair::detect_boot_mount_layout",
                format!("{:?}", layout),
            ),
        );
    }
}

fn run_boot_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Boot;
    let inputs = collect_detection_inputs(target);
    push_boot_evidence(sections, id, &inputs);
    let verdict = detect(&inputs, target);
    match verdict {
        DetectionVerdict::Detected {
            provider,
            method,
            evidence,
        } => {
            for ev in evidence {
                push_evidence(sections, id, provider_evidence_to_evidence(ev));
            }
            push_evidence(
                sections,
                id,
                Evidence::new(
                    "PROVIDER_DETECTED",
                    "repair::boot_repair::detect",
                    format!("provider={} method={:?}", provider.as_str(), method),
                ),
            );
            let assets_ok = inspect_provider_assets(target, provider);
            if assets_ok {
                set_section(sections, id, DoctorSectionStatus::Healthy);
            } else {
                let section = set_section(sections, id, DoctorSectionStatus::Unhealthy);
                section.issues.push(
                    DoctorIssue::new(
                        issue_code::BOOT_ASSET_MISSING,
                        DoctorSeverity::Error,
                        id,
                        format!(
                            "provider {} detected but expected boot assets are missing",
                            provider.as_str()
                        ),
                    )
                    .with_recommendation(recommendation_code::RUN_CATOS_REPAIR_BOOT),
                );
            }
        }
        DetectionVerdict::Conflict {
            providers,
            evidence,
        } => {
            for ev in evidence {
                push_evidence(sections, id, provider_evidence_to_evidence(ev));
            }
            let section = set_section(sections, id, DoctorSectionStatus::Unhealthy);
            section.issues.push(
                DoctorIssue::new(
                    issue_code::BOOT_PROVIDER_CONFLICT,
                    DoctorSeverity::Error,
                    id,
                    format!("conflicting authoritative evidence: {:?}", providers),
                )
                .with_recommendation(recommendation_code::MANUAL_REVIEW),
            );
            report.recommendations.push(DoctorRecommendation::new(
                recommendation_code::MANUAL_REVIEW,
                "target has conflicting bootloader provider evidence; resolve before repair",
            ));
        }
        DetectionVerdict::Ambiguous { evidence } => {
            for ev in evidence {
                push_evidence(sections, id, provider_evidence_to_evidence(ev));
            }
            let section = set_section(sections, id, DoctorSectionStatus::Unknown);
            section.issues.push(
                DoctorIssue::new(
                    issue_code::BOOT_PROVIDER_AMBIGUOUS,
                    DoctorSeverity::Warning,
                    id,
                    "no provider has authoritative target-side evidence",
                )
                .with_recommendation(recommendation_code::MANUAL_REVIEW),
            );
        }
    }
    Ok(())
}

fn collect_detection_inputs(target: &TargetIdentity) -> DetectionInputs {
    let root = target_root_path(target);
    DetectionInputs {
        grub_defaults_catos: read_target_file(&root, "etc/default/grub.d/00-catos.cfg"),
        limine_defaults: read_target_file(&root, "etc/default/limine"),
        kernel_install_catos: read_target_file(
            &root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        ),
        firmware_boot_conf: read_target_file(&root, "etc/catos/firmware-boot.conf"),
        kernel_cmdline: read_target_file(&root, "etc/kernel/cmdline"),
        has_boot_grub: has_target_path(&root, "boot/grub"),
        has_esp_limine_conf: false,
        has_systemd_boot_loader: false,
        has_catos_uki_deployed: false,
        has_efistub_deployed: false,
        installed_packages: Vec::new(),
    }
}

fn inspect_provider_assets(
    target: &TargetIdentity,
    provider: crate::shared::model::boot_repair::ProviderId,
) -> bool {
    let root = target_root_path(target);
    match provider {
        crate::shared::model::boot_repair::ProviderId::Grub => has_target_path(&root, "boot/grub"),
        crate::shared::model::boot_repair::ProviderId::Limine => {
            read_target_file(&root, "etc/default/limine").is_some()
        }
        crate::shared::model::boot_repair::ProviderId::SystemdBoot => {
            read_target_file(&root, "etc/kernel/install.conf.d/20-catos-bootloadu.conf").is_some()
        }
        crate::shared::model::boot_repair::ProviderId::Uki
        | crate::shared::model::boot_repair::ProviderId::Efistub => {
            read_target_file(&root, "etc/catos/firmware-boot.conf").is_some()
        }
    }
}

fn provider_evidence_to_evidence(ev: crate::shared::model::boot_repair::ProviderEvidence) -> Evidence {
    Evidence::new(ev.code, ev.source, ev.message).with_value(format!(
        "provider={} authoritative={}",
        ev.provider.as_str(),
        ev.authoritative
    ))
}

fn push_boot_evidence(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    id: DoctorSectionId,
    inputs: &DetectionInputs,
) {
    let authoritative = [
        inputs.grub_defaults_catos.is_some(),
        inputs.limine_defaults.is_some(),
        inputs.kernel_install_catos.is_some(),
        inputs.firmware_boot_conf.is_some(),
    ];
    let count = authoritative.iter().filter(|b| **b).count();
    push_evidence(
        sections,
        id,
        Evidence::new(
            "DETECTION_INPUTS",
            "repair::boot_repair::detect",
            format!("{count} authoritative provider signal(s) present"),
        ),
    );
}

fn run_secure_boot_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::SecureBoot;
    let root = target_root_path(target);

    let firmware_sb_on = read_target_file(
        Path::new("/"),
        "sys/firmware/efi/efivars/SecureBoot-8be4df61-92ca-11d2-b0b3-00a0c91f6dba",
    )
    .map(|body| secure_boot_enabled_from_efivar(body.as_bytes()))
    .unwrap_or(None);
    let target_marker = read_target_file(&root, "etc/catos/secureboot").is_some();
    let firmware_boot_conf = read_target_file(&root, "etc/catos/firmware-boot.conf");

    push_evidence(
        sections,
        id,
        Evidence::new(
            "FIRMWARE_SECURE_BOOT",
            "doctor::secure_boot",
            format!("firmware runtime state: {:?}", firmware_sb_on),
        ),
    );
    push_evidence(
        sections,
        id,
        Evidence::new(
            "TARGET_POLICY_MARKER",
            "doctor::secure_boot",
            format!("/etc/catos/secureboot present: {target_marker}"),
        ),
    );

    let esp_present = target
        .boot_layout
        .as_ref()
        .and_then(|l| l.esp_mount_point())
        .is_some();
    if !esp_present && firmware_sb_on.is_none() && firmware_boot_conf.is_none() {
        set_section(sections, id, DoctorSectionStatus::NotApplicable);
        report.limitations.push(DoctorLimitation::new(
            id,
            "SECURE_BOOT_NOT_APPLICABLE",
            "target appears to be a BIOS layout; Secure Boot is not applicable",
        ));
        return Ok(());
    }

    let policy_inconsistent = target_marker != firmware_sb_on.unwrap_or(false)
        || (target_marker && firmware_boot_conf.is_none());
    if policy_inconsistent {
        let section = set_section(sections, id, DoctorSectionStatus::Unhealthy);
        section.issues.push(DoctorIssue::new(
            issue_code::SECURE_BOOT_STATE_INCOMPLETE,
            DoctorSeverity::Error,
            id,
            "Secure Boot policy is inconsistent across firmware runtime, target marker, and firmware-boot configuration",
        ));
        report.recommendations.push(DoctorRecommendation::new(
            recommendation_code::RUN_CATOS_REPAIR_BOOT,
            "Secure Boot policy is inconsistent; catos-repair boot can re-apply the target's existing policy",
        ));
    } else {
        set_section(sections, id, DoctorSectionStatus::Healthy);
    }
    Ok(())
}

fn secure_boot_enabled_from_efivar(body: &[u8]) -> Option<bool> {
    body.get(4).map(|b| *b != 0)
}

fn run_recovery_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Recovery;
    if target.root_fstype != "btrfs" {
        set_section(sections, id, DoctorSectionStatus::NotApplicable);
        report.limitations.push(DoctorLimitation::new(
            id,
            "RECOVERY_NOT_APPLICABLE",
            "snapshot recovery is applicable only to Btrfs roots",
        ));
        return Ok(());
    }
    let device = match target.root_device.to_str() {
        Some(s) => s.to_string(),
        None => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            return Ok(());
        }
    };

    let records = match enumerate_recovery_records(&device) {
        Ok(records) if records.is_empty() => {
            set_section(sections, id, DoctorSectionStatus::Healthy);
            push_evidence(
                sections,
                id,
                Evidence::new(
                    "RECOVERY_RECORDS",
                    "doctor::recovery",
                    "no in-flight recovery transactions on target",
                ),
            );
            return Ok(());
        }
        Ok(records) => records,
        Err(message) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(
                id,
                "RECOVERY_INSPECT_FAILED",
                format!("could not enumerate recovery records: {message}"),
            ));
            return Ok(());
        }
    };

    let mut section_status = DoctorSectionStatus::Healthy;
    for record in &records {
        inspect_single_record(sections, report, id, record, &mut section_status);
    }
    set_section(sections, id, section_status);
    Ok(())
}

fn inspect_single_record(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    report: &mut DoctorReport,
    id: DoctorSectionId,
    record: &TransactionRecord,
    section_status: &mut DoctorSectionStatus,
) {
    push_evidence(
        sections,
        id,
        Evidence::new(
            "RECOVERY_RECORD",
            "doctor::recovery",
            format!(
                "transaction {} state={} last_error={:?}",
                record.transaction_id,
                record.state.code(),
                record.last_error.as_ref().map(|e| e.kind.code())
            ),
        ),
    );
    if record.state.is_terminal() {
        if matches!(
            record.state,
            crate::shared::model::recovery::TransactionState::Completed
                | crate::shared::model::recovery::TransactionState::Reverted
        ) {
            if matches!(
                record.state,
                crate::shared::model::recovery::TransactionState::Completed
            ) {
                if let Some(cleanup) = record.last_cleanup.as_ref() {
                    if !cleanup.residual.is_empty() {
                        *section_status = worse_of(*section_status, DoctorSectionStatus::Degraded);
                        push_issue(
                            sections,
                            DoctorIssue::new(
                                issue_code::RECOVERY_CLEANUP_RESIDUAL,
                                DoctorSeverity::Warning,
                                id,
                                format!(
                                    "transaction {} completed but left cleanup residuals",
                                    record.transaction_id
                                ),
                            ),
                        );
                    }
                }
                push_issue(
                    sections,
                    DoctorIssue::new(
                        issue_code::RECOVERY_BACKUP_PRESENT,
                        DoctorSeverity::Info,
                        id,
                        format!(
                            "transaction {} retains a recovery backup (post-success retention is normal)",
                            record.transaction_id
                        ),
                    ),
                );
            }
        } else {
            *section_status = worse_of(*section_status, DoctorSectionStatus::Critical);
            push_issue(
                sections,
                DoctorIssue::new(
                    issue_code::RECOVERY_RECORD_DRIFT,
                    DoctorSeverity::Critical,
                    id,
                    format!(
                        "transaction {} reached terminal state {}",
                        record.transaction_id,
                        record.state.code()
                    ),
                )
                .with_recommendation(recommendation_code::MANUAL_REVIEW),
            );
        }
    } else {
        *section_status = worse_of(*section_status, DoctorSectionStatus::Unhealthy);
        push_issue(
            sections,
            DoctorIssue::new(
                issue_code::RECOVERY_TRANSACTION_INTERRUPTED,
                DoctorSeverity::Error,
                id,
                format!(
                    "transaction {} is in non-terminal state {}",
                    record.transaction_id,
                    record.state.code()
                ),
            )
            .with_recommendation(recommendation_code::RUN_CATOS_RECOVERY_RESUME),
        );
        report.recommendations.push(DoctorRecommendation::new(
            recommendation_code::RUN_CATOS_RECOVERY_RESUME,
            format!(
                "transaction {} is interrupted; catos-recovery resume or revert can complete it",
                record.transaction_id
            ),
        ));
    }
}

fn worse_of(current: DoctorSectionStatus, candidate: DoctorSectionStatus) -> DoctorSectionStatus {
    use DoctorSectionStatus::*;
    fn rank(s: DoctorSectionStatus) -> u8 {
        match s {
            Healthy => 0,
            NotApplicable | Skipped => 1,
            Degraded => 2,
            Unknown => 3,
            Unhealthy => 4,
            Critical => 5,
        }
    }
    if rank(candidate) > rank(current) {
        candidate
    } else {
        current
    }
}

fn enumerate_recovery_records(device: &str) -> Result<Vec<TransactionRecord>, String> {
    let mount_session = mount_btrfs_top_level_ro(device)?;
    let top_level = match mount_session {
        Some(path) => path,
        None => return Ok(Vec::new()),
    };

    let state_dir = top_level.join(".catos-recovery");
    let names = match std::fs::read_dir(&state_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".state.json"))
            .collect::<Vec<_>>(),
        Err(_) => return Ok(Vec::new()),
    };

    let mut records = Vec::new();
    for name in names {
        let path = state_dir.join(&name);
        match store::load_record(&path) {
            Ok(record) => records.push(record),
            Err(_) => continue,
        }
    }
    Ok(records)
}

fn mount_btrfs_top_level_ro(device: &str) -> Result<Option<PathBuf>, String> {
    use crate::shared::mount::namespace::establish_private_namespace;
    use crate::shared::mount::secure_dir::{create_session_dir, SESSION_ROOT_PARENT};
    use crate::shared::mount::syscall::{self, ms_flags};

    if establish_private_namespace().is_err() {
        return Ok(None);
    }
    let session_dir = create_session_dir(Path::new(SESSION_ROOT_PARENT), "doctor-recovery-ro")
        .map_err(|e| format!("cannot create session dir: {e}"))?;
    let mount_root = session_dir.join("top");
    std::fs::create_dir(&mount_root).map_err(|e| format!("cannot mkdir: {e}"))?;
    let result = syscall::mount(
        Some(device),
        &mount_root,
        Some("btrfs"),
        ms_flags::MS_RDONLY | ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
        Some("subvolid=0,ro"),
    );
    if let Err(e) = result {
        let _ = syscall::umount2(&mount_root, 0);
        let _ = crate::shared::mount::secure_dir::remove_session_dir(
            Path::new(SESSION_ROOT_PARENT),
            &session_dir,
        );
        return Err(format!("cannot mount btrfs top-level RO: {e}"));
    }
    Ok(Some(mount_root))
}

fn is_device_mounted_rw(device: &Path) -> bool {
    let body = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mounts = crate::shared::parse::mountinfo::parse_all(&body);
    let dev_str = match device.to_str() {
        Some(s) => s,
        None => return false,
    };
    mounts
        .iter()
        .any(|m| m.source == dev_str && !m.super_options.iter().any(|o| o == "ro"))
}

fn read_target_file(root: &Path, relative: &str) -> Option<String> {
    std::fs::read_to_string(root.join(relative)).ok()
}

fn has_target_path(root: &Path, relative: &str) -> bool {
    std::fs::metadata(root.join(relative))
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

fn handle_no_target(reason: String, report: &mut DoctorReport) -> Vec<DoctorSection> {
    let sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();
    let mut sections = sections;
    let section = set_section(
        &mut sections,
        DoctorSectionId::Environment,
        DoctorSectionStatus::Healthy,
    );
    section.evidence.push(Evidence::new(
        "TARGET_SELECTION",
        "doctor::target_selection",
        format!("target_not_found: {reason}"),
    ));
    push_issue(
        &mut sections,
        DoctorIssue::new(
            issue_code::TARGET_NOT_FOUND,
            DoctorSeverity::Warning,
            DoctorSectionId::Storage,
            format!("no CatOS target identified: {reason}"),
        )
        .with_recommendation(recommendation_code::BOOT_LIVE_ENVIRONMENT),
    );
    report.recommendations.push(DoctorRecommendation::new(
        recommendation_code::BOOT_LIVE_ENVIRONMENT,
        "no CatOS target was identified; boot a CatOS Live environment or specify the target explicitly",
    ));
    sections.into_iter().map(|(_, s)| s).collect()
}

fn handle_ambiguous_target(
    candidates: Vec<String>,
    report: &mut DoctorReport,
) -> Vec<DoctorSection> {
    let sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();
    let mut sections = sections;
    let section = set_section(
        &mut sections,
        DoctorSectionId::Environment,
        DoctorSectionStatus::Healthy,
    );
    section.evidence.push(Evidence::new(
        "TARGET_SELECTION",
        "doctor::target_selection",
        format!("ambiguous_target: candidates={}", candidates.join(",")),
    ));
    push_issue(
        &mut sections,
        DoctorIssue::new(
            issue_code::TARGET_AMBIGUOUS,
            DoctorSeverity::Warning,
            DoctorSectionId::Storage,
            format!(
                "multiple CatOS targets identified: {}",
                candidates.join(", ")
            ),
        )
        .with_recommendation(recommendation_code::MANUAL_REVIEW),
    );
    report.recommendations.push(DoctorRecommendation::new(
        recommendation_code::MANUAL_REVIEW,
        "multiple CatOS targets were identified; resolve ambiguity before any repair",
    ));
    sections.into_iter().map(|(_, s)| s).collect()
}

fn aggregate(report: &mut DoctorReport) {
    let mut overall = DoctorOverallStatus::Healthy;
    let mut complete = true;
    let mut all_issues: Vec<DoctorIssue> = Vec::new();

    for section in &report.sections {
        if let Some(contribution) = section.status.to_overall_contribution() {
            overall = overall.combine(contribution);
        }
        if matches!(
            section.status,
            DoctorSectionStatus::Skipped | DoctorSectionStatus::Unknown
        ) {
            complete = false;
        }
        all_issues.extend(section.issues.iter().cloned());
    }

    if !report.limitations.is_empty() && overall == DoctorOverallStatus::Healthy {
        overall = DoctorOverallStatus::Degraded;
    }

    all_issues.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.section.as_str().cmp(b.section.as_str()))
            .then_with(|| a.code.cmp(&b.code))
    });
    all_issues
        .dedup_by(|a, b| a.code == b.code && a.section == b.section && a.message == b.message);

    report.overall_status = overall;
    report.complete = complete;
    report.issues = all_issues;

    report.evidence.push(Evidence::new(
        "DOCTOR_AGGREGATE",
        "doctor::aggregate",
        format!(
            "overall={} complete={} issues={} limitations={}",
            report.overall_status.as_str(),
            report.complete,
            report.issues.len(),
            report.limitations.len()
        ),
    ));
}

impl DoctorReport {
    pub fn doctor_failed(&self) -> bool {
        !self.cleanup.all_clean
    }
}

/// Public test-only entry point so integration tests can drive the
/// pure aggregation logic without re-implementing it. Production
/// callers use [`run_doctor`].
#[doc(hidden)]
pub fn aggregate_for_tests(report: &mut DoctorReport) {
    aggregate(report);
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::shared::model::doctor::DoctorTargetKind;

    pub fn aggregate_public(report: &mut DoctorReport) {
        aggregate(report);
    }

    #[test]
    fn aggregate_combines_critical_section_to_critical_overall() {
        let mut report = DoctorReport::default();
        report.sections = vec![
            DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Critical),
        ];
        aggregate(&mut report);
        assert_eq!(report.overall_status, DoctorOverallStatus::Critical);
    }

    #[test]
    fn aggregate_degrades_when_only_limitations_exist() {
        let mut report = DoctorReport::default();
        report.sections = DoctorSectionId::all()
            .iter()
            .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Healthy))
            .collect();
        report
            .limitations
            .push(DoctorLimitation::new(DoctorSectionId::Filesystem, "X", "y"));
        aggregate(&mut report);
        assert_eq!(report.overall_status, DoctorOverallStatus::Degraded);
    }

    #[test]
    fn aggregate_sorts_issues_by_severity_then_section_then_code() {
        let mut report = DoctorReport::default();
        let mut fs_section =
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Unhealthy);
        fs_section.issues.push(DoctorIssue::new(
            "AAA",
            DoctorSeverity::Error,
            DoctorSectionId::Filesystem,
            "fs error",
        ));
        let mut boot_section =
            DoctorSection::new(DoctorSectionId::Boot, DoctorSectionStatus::Unhealthy);
        boot_section.issues.push(DoctorIssue::new(
            "BBB",
            DoctorSeverity::Critical,
            DoctorSectionId::Boot,
            "boot critical",
        ));
        report.sections = vec![fs_section, boot_section];
        aggregate(&mut report);
        assert_eq!(report.issues[0].code, "BBB");
        assert_eq!(report.issues[0].severity, DoctorSeverity::Critical);
        assert_eq!(report.issues[1].code, "AAA");
    }

    #[test]
    fn aggregate_dedupes_identical_issues() {
        let mut report = DoctorReport::default();
        let mut section =
            DoctorSection::new(DoctorSectionId::Mount, DoctorSectionStatus::Unhealthy);
        let issue = DoctorIssue::new("X", DoctorSeverity::Error, DoctorSectionId::Mount, "same");
        section.issues.push(issue.clone());
        section.issues.push(issue);
        report.sections = vec![section];
        aggregate(&mut report);
        assert_eq!(report.issues.len(), 1);
    }

    #[test]
    fn aggregate_marks_complete_false_when_a_section_is_skipped() {
        let mut report = DoctorReport::default();
        report.sections = vec![
            DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Skipped),
        ];
        aggregate(&mut report);
        assert!(!report.complete);
    }

    #[test]
    fn doctor_failed_is_false_when_cleanup_is_clean() {
        let report = DoctorReport::default();
        assert!(!report.doctor_failed());
    }

    #[test]
    fn mount_problem_to_issue_preserves_section() {
        let issue = mount_problem_to_issue(&MountProblem::MissingRootEntry, DoctorSectionId::Mount);
        assert_eq!(issue.section, DoctorSectionId::Mount);
        assert_eq!(issue.code, issue_code::FSTAB_ROOT_SOURCE_MISMATCH);
    }

    #[test]
    fn derive_mount_section_status_critical_for_unsafe_mount_point() {
        let problems = vec![MountProblem::UnsafeMountPoint {
            mount_point: "/home".into(),
            reason: "symlink".into(),
        }];
        assert_eq!(
            derive_mount_section_status(&problems),
            DoctorSectionStatus::Critical
        );
    }

    #[test]
    fn derive_mount_section_status_healthy_for_empty() {
        assert_eq!(
            derive_mount_section_status(&[]),
            DoctorSectionStatus::Healthy
        );
    }

    #[test]
    fn target_summary_for_no_target_uses_none_kind() {
        let sel = TargetSelection::None {
            reason: "test".into(),
        };
        let summary = sel.to_target_summary();
        assert_eq!(summary.kind, DoctorTargetKind::None);
    }
}
