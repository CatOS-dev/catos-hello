//! Doctor section orchestrators and shared helpers.

mod boot;
mod filesystem;
mod mount;
mod recovery;

use std::path::{Path, PathBuf};

use crate::doctor::model::{
    recommendation_code, DoctorIssue, DoctorRecommendation, DoctorSection, DoctorSectionId,
    DoctorSectionStatus,
};
use crate::target::Evidence;

pub(in crate::doctor) use boot::{run_boot_section, run_secure_boot_section};
pub(in crate::doctor) use filesystem::{
    capture_environment, run_environment_section, run_filesystem_section, run_storage_section,
};
pub(in crate::doctor) use mount::run_mount_section;
pub(in crate::doctor) use recovery::run_recovery_section;

pub(in crate::doctor) fn set_section(
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

pub(in crate::doctor) fn push_issue(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    issue: DoctorIssue,
) {
    let id = issue.section;
    let entry = sections
        .iter_mut()
        .find(|(sid, _)| *sid == id)
        .expect("canonical section list is exhaustive");
    entry.1.issues.push(issue);
}

pub(in crate::doctor) fn push_evidence(
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

pub(in crate::doctor) fn target_root_path(
    target: &crate::target::model::TargetIdentity,
) -> PathBuf {
    target.root.clone()
}

pub(in crate::doctor) fn target_supports_standard_root_repair(
    target: &crate::target::model::TargetIdentity,
) -> bool {
    match target.root_fstype.as_deref() {
        Some("btrfs") => target.root_subvol.as_deref() == Some("/@"),
        Some(_) => true,
        None => false,
    }
}

pub(in crate::doctor) fn target_bound_repair_command(
    program: &str,
    target: &crate::target::model::TargetIdentity,
    esp_device: Option<&Path>,
) -> Option<String> {
    if !target_supports_standard_root_repair(target) {
        return None;
    }
    let root_device = target.root_device.as_deref()?;
    let mut command = format!(
        "{program} --root-device {}",
        root_device.display()
    );
    if let Some(subvolume) = target.root_subvol.as_deref() {
        command.push_str(" --root-subvolume ");
        command.push_str(subvolume);
    }
    if let Some(esp_device) = esp_device {
        command.push_str(" --esp-device ");
        command.push_str(&esp_device.display().to_string());
    }
    Some(command)
}

pub(in crate::doctor) fn target_repair_recommendation(
    program: &str,
    target: &crate::target::model::TargetIdentity,
    esp_device: Option<&Path>,
    supported_code: &str,
    supported_message: impl Into<String>,
    unsupported_message: impl Into<String>,
) -> DoctorRecommendation {
    if !target_supports_standard_root_repair(target) {
        return DoctorRecommendation::new(
            recommendation_code::MANUAL_REVIEW,
            unsupported_message,
        );
    }
    let recommendation = DoctorRecommendation::new(supported_code, supported_message);
    match target_bound_repair_command(program, target, esp_device) {
        Some(command) => recommendation.with_command(command),
        None => recommendation,
    }
}

pub(in crate::doctor) fn read_target_file(
    root: &Path,
    relative: &str,
) -> Result<Option<String>, String> {
    let rooted = format!("/{}", relative.trim_start_matches('/'));
    match crate::target::execute::confined::read_rooted_file(root, &rooted) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| format!("target file {rooted} is not UTF-8")),
        Err(crate::target::error::FsError::NotFound) => Ok(None),
        Err(error) => Err(format!("cannot read target file {rooted}: {error}")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::doctor) enum MountState {
    MountedRw,
    MountedRo,
    NotMounted,
}

pub(in crate::doctor) fn device_mount_state(device: &Path, body: &str) -> Result<MountState, std::io::Error> {
    let dev_str = device.to_str().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "device path is not UTF-8"))?;
    let mut found = false;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let mount = crate::mount::diagnose::mountinfo::parse_line(line).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed mountinfo line"))?;
        let source = Path::new(&mount.source);
        if mount.source == dev_str
            || crate::mount::diagnose::target::same_block_device(device, source)
        {
            found = true;
            if !mount.is_read_only() {
                return Ok(MountState::MountedRw);
            }
        }
    }
    Ok(if found { MountState::MountedRo } else { MountState::NotMounted })
}

pub(in crate::doctor) fn is_device_mounted_rw(device: &Path) -> Result<MountState, std::io::Error> {
    let body = std::fs::read_to_string("/proc/self/mountinfo")?;
    device_mount_state(device, &body)
}

#[cfg(test)]
mod tests {
    use super::{
        device_mount_state, read_target_file, target_bound_repair_command,
        target_repair_recommendation, target_root_path, MountState,
    };
    use crate::doctor::model::recommendation_code;
    use crate::target::model::TargetIdentity;
    use std::path::PathBuf;

    #[test]
    fn selected_session_root_is_not_replaced_by_live_root() {
        let target = TargetIdentity {
            root: PathBuf::from("/run/catos-target-session/root"),
            ..TargetIdentity::default()
        };

        assert_eq!(
            target_root_path(&target),
            PathBuf::from("/run/catos-target-session/root")
        );
    }

    #[test]
    fn repair_command_preserves_supported_standard_root_and_esp() {
        let target = TargetIdentity {
            root_device: Some(PathBuf::from("/dev/dm-0")),
            root_fstype: Some("btrfs".into()),
            root_subvol: Some("/@".into()),
            ..TargetIdentity::default()
        };
        assert_eq!(
            target_bound_repair_command(
                "catos-repair mount",
                &target,
                Some(std::path::Path::new("/dev/nvme0n1p1")),
            )
            .as_deref(),
            Some(
                "catos-repair mount --root-device /dev/dm-0 --root-subvolume /@ --esp-device /dev/nvme0n1p1"
            )
        );
    }

    #[test]
    fn nonstandard_btrfs_root_uses_manual_review_without_command() {
        let target = TargetIdentity {
            root_device: Some(PathBuf::from("/dev/dm-0")),
            root_fstype: Some("btrfs".into()),
            root_subvol: Some("/@root".into()),
            ..TargetIdentity::default()
        };
        assert!(target_bound_repair_command("catos-repair mount", &target, None).is_none());
        let recommendation = target_repair_recommendation(
            "catos-repair mount",
            &target,
            None,
            recommendation_code::RUN_CATOS_REPAIR_MOUNT,
            "repair automatically",
            "review manually",
        );
        assert_eq!(recommendation.code, recommendation_code::MANUAL_REVIEW);
        assert_eq!(recommendation.message, "review manually");
        assert!(recommendation.command.is_none());
    }

    #[test]
    fn unreadable_target_file_is_an_error_not_absence() {
        let error = read_target_file(std::path::Path::new("/dev/null"), "secureboot")
            .unwrap_err();
        assert!(error.contains("cannot read target file"));
    }

    #[test]
    fn target_file_read_does_not_follow_symlink_outside_selected_root() {
        let root = std::env::temp_dir().join(format!(
            "catos-doctor-confined-{}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "catos-doctor-outside-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secureboot"), "host-secret").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("etc")).unwrap();

        let error = read_target_file(&root, "etc/secureboot").unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(std::fs::read_to_string(outside.join("secureboot")).unwrap(), "host-secret");

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn mount_state_rejects_malformed_mountinfo_and_distinguishes_ro_rw() {
        let malformed = "not mountinfo";
        assert_eq!(device_mount_state(std::path::Path::new("/dev/root"), malformed).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        let ro = "1 0 8:1 / /mnt ro - ext4 /dev/root rw";
        let rw = "1 0 8:1 / /mnt rw - ext4 /dev/root rw";
        assert_eq!(device_mount_state(std::path::Path::new("/dev/root"), ro).unwrap(), MountState::MountedRo);
        assert_eq!(device_mount_state(std::path::Path::new("/dev/root"), rw).unwrap(), MountState::MountedRw);
    }
}
