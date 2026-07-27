//! Doctor section orchestrators and shared helpers.

mod boot;
mod filesystem;
mod mount;
mod recovery;

use std::path::{Path, PathBuf};

use crate::doctor::model::{DoctorIssue, DoctorSection, DoctorSectionId, DoctorSectionStatus};
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

pub(in crate::doctor) fn read_target_file(root: &Path, relative: &str) -> Result<Option<String>, std::io::Error> {
    match std::fs::read_to_string(root.join(relative)) {
        Ok(body) => Ok(Some(body)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
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
        if mount.source == dev_str {
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
    use super::{device_mount_state, read_target_file, target_root_path, MountState};
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
    fn unreadable_target_file_is_an_io_error_not_absence() {
        let error = read_target_file(std::path::Path::new("/dev/null"), "secureboot").unwrap_err();
        assert!(matches!(error.kind(), std::io::ErrorKind::NotADirectory | std::io::ErrorKind::PermissionDenied));
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
