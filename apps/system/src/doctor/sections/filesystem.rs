//! Environment, storage, and filesystem sections.

use std::path::Path;

use crate::doctor::model::{
    issue_code, recommendation_code, DoctorEnvironment, DoctorIssue, DoctorLimitation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::fs::command::FsCommandRunner;
use crate::fs::diagnose::{btrfs, check_only_for, ReadonlyOutcome, ReadonlyResult};
use crate::target::Evidence;

use super::{is_device_mounted_rw, push_evidence, set_section, MountState};
use crate::doctor::DoctorTargetContext;

pub(in crate::doctor) fn capture_environment() -> DoctorEnvironment {
    use crate::target::model::DetectionStatus;
    let fs = crate::target::diagnose::filesystem::RealFilesystem;
    let runtime = crate::target::diagnose::runtime::detect_runtime(&fs);
    let primary_mode = runtime.primary_mode();
    let running_root_is_catos =
        matches!(runtime.is_snapshot_boot.status, DetectionStatus::Detected)
            || is_running_root_catos(&fs);
    DoctorEnvironment {
        primary_mode: primary_mode_label(primary_mode),
        running_root_is_catos,
    }
}

fn primary_mode_label(mode: crate::target::model::PrimaryRuntimeMode) -> String {
    use crate::target::model::PrimaryRuntimeMode::*;
    match mode {
        RunningSystem => "running_system",
        Chroot => "chroot",
        LiveEnvironment => "live_environment",
        Initramfs => "initramfs",
        Unknown => "unknown",
    }
    .to_string()
}

fn is_running_root_catos(fs: &crate::target::diagnose::filesystem::RealFilesystem) -> bool {
    use crate::target::model::DetectionStatus;
    let root = match crate::target::diagnose::system_root::SystemRoot::from_user_input("/") {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut warnings = Vec::new();
    let inspection = crate::target::diagnose::candidate::inspect_target(fs, &root, &mut warnings);
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
    context: Option<&DoctorTargetContext>,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Storage;
    let Some(context) = context else {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(
            id,
            "TARGET_CONTEXT_UNAVAILABLE",
            "Storage requires the selected readonly Doctor target context",
        ));
        return Ok(());
    };
    let target = &context.target;
    let complete = target.root_device.is_some()
        && target.root_fstype.is_some()
        && target.root_uuid.is_some()
        && (target.root_fstype.as_deref() != Some("btrfs") || target.root_subvol.is_some());
    let section = set_section(
        sections,
        id,
        if complete {
            DoctorSectionStatus::Healthy
        } else {
            DoctorSectionStatus::Unknown
        },
    );
    section.evidence.push(Evidence::new(
        "ROOT_DEVICE",
        "doctor::storage",
        format!(
            "root device: {}",
            target
                .root_device
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<unknown>".to_string())
        ),
    ));
    section.evidence.push(Evidence::new(
        "ROOT_FILESYSTEM",
        "doctor::storage",
        format!(
            "root filesystem: {}",
            target.root_fstype.as_deref().unwrap_or("<unknown>")
        ),
    ));
    section.evidence.push(Evidence::new(
        "ROOT_UUID",
        "doctor::storage",
        format!(
            "root UUID: {}",
            target.root_uuid.as_deref().unwrap_or("<unknown>")
        ),
    ));
    section.evidence.push(Evidence::new(
        "ROOT_SUBVOLUME",
        "doctor::storage",
        format!(
            "root subvolume: {}",
            target.root_subvol.as_deref().unwrap_or("<unknown>")
        ),
    ));
    section.evidence.push(Evidence::new(
        "BTRFS_FSID",
        "doctor::storage",
        format!(
            "Btrfs filesystem ID: {}",
            context
                .candidate
                .filesystem_id
                .as_deref()
                .unwrap_or("<unknown>")
        ),
    ));
    section.evidence.push(Evidence::new(
        "TARGET_INVENTORY",
        "doctor::context",
        format!(
            "shared inventory contains {} block-device records",
            context.devices.len()
        ),
    ));
    match context.boot_layout.as_ref() {
        Ok(crate::mount::model::BootMountLayout::SeparateBootAndEsp { boot_device, .. }) => {
            section.evidence.push(Evidence::new(
                "BOOT_DEVICE",
                "doctor::storage",
                format!("separate /boot device: {}", boot_device.display()),
            ));
        }
        Ok(crate::mount::model::BootMountLayout::EspAtBoot { esp_device }) => {
            section.evidence.push(Evidence::new(
                "BOOT_DEVICE",
                "doctor::storage",
                format!("FAT /boot ESP device: {}", esp_device.display()),
            ));
        }
        Ok(_) => {
            section.evidence.push(Evidence::new(
                "BOOT_DEVICE",
                "doctor::storage",
                format!(
                    "/boot is carried by root device: {}",
                    target
                        .root_device
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string())
                ),
            ));
        }
        Err(error) => report.limitations.push(DoctorLimitation::new(
            id,
            "BOOT_LAYOUT_INCOMPLETE",
            error.clone(),
        )),
    }
    match &context.esp {
        Ok(Some(esp)) => {
            section.evidence.push(Evidence::new(
                "ESP_DEVICE",
                "doctor::storage",
                format!("ESP device: {}", esp.device.display()),
            ));
            section.evidence.push(Evidence::new(
                "ESP_UUID",
                "doctor::storage",
                format!("ESP UUID: {}", esp.uuid.as_deref().unwrap_or("<unknown>")),
            ));
            section.evidence.push(Evidence::new(
                "ESP_MOUNT_POINT",
                "doctor::storage",
                format!("ESP mount point: {}", esp.mount_point),
            ));
        }
        Ok(None) => {
            report.limitations.push(DoctorLimitation::new(
                id,
                "ESP_NOT_DISCOVERED",
                "selected target fstab does not identify an ESP; this is not interpreted as a BIOS conclusion",
            ));
        }
        Err(error) => {
            report.limitations.push(DoctorLimitation::new(
                id,
                "ESP_FACTS_INCOMPLETE",
                error.clone(),
            ));
        }
    }
    if !complete || !matches!(context.esp, Ok(Some(_))) {
        report.limitations.push(DoctorLimitation::new(
            id,
            "STORAGE_FACTS_INCOMPLETE",
            "selected target lacks required root or ESP identity facts",
        ));
        set_section(sections, id, DoctorSectionStatus::Unknown);
    }
    Ok(())
}

pub(in crate::doctor) fn run_filesystem_section<R: FsCommandRunner + ?Sized>(
    runner: &R,
    sections: &mut [(DoctorSectionId, DoctorSection)],
    context: Option<&DoctorTargetContext>,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Filesystem;
    if context.is_none() {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(
            id,
            "TARGET_CONTEXT_UNAVAILABLE",
            "Filesystem requires the selected readonly Doctor target context",
        ));
        return Ok(());
    }
    let target = &context
        .expect("checked selected Doctor target context")
        .target;
    let fstype = match target.root_fstype.as_deref() {
        Some(fstype) => fstype,
        None => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(
                id,
                "ROOT_FILESYSTEM_UNKNOWN",
                "selected target has no root filesystem type; read-only check was not attempted",
            ));
            return Ok(());
        }
    };
    let device = match target.root_device.as_deref().and_then(Path::to_str) {
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

    let mount_state = match target.root_device.as_deref().map(is_device_mounted_rw) {
        Some(Ok(state)) => state,
        Some(Err(error)) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(
                id,
                "MOUNT_STATE_UNAVAILABLE",
                format!("cannot determine whether target is mounted read-write: {error}"),
            ));
            return Ok(());
        }
        None => MountState::NotMounted,
    };
    if mount_state == MountState::MountedRw {
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

    let check = if fstype == "btrfs" && mount_state == MountState::MountedRo {
        btrfs::check_mounted_readonly(runner, &device).map(Some)
    } else {
        check_only_for(fstype, runner, &device)
    };
    let result = match check {
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
            format!("fs::diagnose::{}", result.tool),
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
