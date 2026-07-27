//! Doctor section orchestrators and shared helpers.

mod boot;
mod filesystem;
mod mount;
mod recovery;

use std::path::{Path, PathBuf};

use crate::shared::model::doctor::{
    DoctorIssue, DoctorSection, DoctorSectionId, DoctorSectionStatus,
};
use crate::shared::model::evidence::Evidence;

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

pub(in crate::doctor) fn target_root_path(_target: &crate::target::model::TargetIdentity) -> PathBuf {
    PathBuf::from("/")
}

pub(in crate::doctor) fn read_target_file(root: &Path, relative: &str) -> Option<String> {
    std::fs::read_to_string(root.join(relative)).ok()
}

pub(in crate::doctor) fn has_target_path(root: &Path, relative: &str) -> bool {
    std::fs::metadata(root.join(relative))
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

pub(in crate::doctor) fn is_device_mounted_rw(device: &Path) -> bool {
    let body = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mounts = crate::mount::diagnose::mountinfo::parse_all(&body);
    let dev_str = match device.to_str() {
        Some(s) => s,
        None => return false,
    };
    mounts
        .iter()
        .any(|m| m.source == dev_str && !m.super_options.iter().any(|o| o == "ro"))
}
