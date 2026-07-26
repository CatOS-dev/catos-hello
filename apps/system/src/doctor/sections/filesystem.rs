//! Environment, storage, and filesystem sections.

use crate::shared::model::doctor::{
    issue_code, recommendation_code, DoctorEnvironment, DoctorIssue, DoctorLimitation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount_repair::TargetIdentity;
use crate::repair::fs_flows::{check_only_for, ReadonlyOutcome, ReadonlyResult};
use crate::repair::runner::CommandRunner;

use super::{is_device_mounted_rw, push_evidence, set_section};

pub(in crate::doctor) fn capture_environment() -> DoctorEnvironment {
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

pub(in crate::doctor) fn run_environment_section(
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

pub(in crate::doctor) fn run_storage_section(
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

pub(in crate::doctor) fn run_filesystem_section<R: CommandRunner + ?Sized>(
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
        out.push('\u{2026}');
        out
    }
}
