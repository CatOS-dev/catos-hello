//! Mount layout section: fstab validation, subvolume/mount-point checks.

use std::path::Path;
use std::time::Duration;

use crate::doctor::model::{
    issue_code, recommendation_code, DoctorIssue, DoctorRecommendation, DoctorReport,
    DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::mount::diagnose::subvolume::{CatosConfirmation, SubvolFacts, SubvolObservation};
use crate::mount::diagnose::target::{
    diagnose as mount_diagnose, MountPointObservation, MountRepairInputs,
};
use crate::mount::model::{MountProblem, MountTargetIdentity as RepairTargetIdentity};
use crate::target::model::TargetIdentity;
use crate::target::Evidence;

use super::{push_evidence, push_issue, set_section, target_root_path};

pub(in crate::doctor) fn run_mount_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Mount;
    let inputs = match build_mount_inputs(target) {
        Ok(inputs) => inputs,
        Err(message) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(crate::doctor::model::DoctorLimitation::new(
                id,
                "MOUNT_FACTS_INCOMPLETE",
                message,
            ));
            return Ok(());
        }
    };
    let problems = mount_diagnose(&inputs);
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

fn build_mount_inputs(target: &TargetIdentity) -> Result<MountRepairInputs, String> {
    let fstab_text = read_target_fstab(target)?;
    let root_device = target.root_device.clone().ok_or_else(|| "selected target has no root device".to_string())?;
    let root_fstype = target.root_fstype.clone().ok_or_else(|| "selected target has no root filesystem type".to_string())?;
    let catos_confirmation = if target.root_fstype.as_deref() == Some("btrfs") {
        CatosConfirmation::Confirmed
    } else {
        CatosConfirmation::NotConfirmed
    };
    let subvol_facts = if root_fstype == "btrfs" {
        collect_subvolume_facts(&target.root)?
    } else {
        SubvolFacts::default()
    };
    Ok(MountRepairInputs {
        fstab_text,
        target: RepairTargetIdentity {
            root_device,
            root_fstype,
            root_subvol: target.root_subvol.clone(),
            root_uuid: target.root_uuid.clone(),
            esp_device: None,
            esp_uuid: None,
            boot_layout: None,
        },
        catos_confirmation,
        subvol_facts,
        mount_point_observations: collect_mount_point_observations(target),
    })
}

fn read_target_fstab(target: &TargetIdentity) -> Result<String, String> {
    let root = target_root_path(target);
    let path = root.join("etc/fstab");
    std::fs::read_to_string(&path).map_err(|error| format!("cannot read target fstab {}: {error}", path.display()))
}

fn collect_subvolume_facts(root: &Path) -> Result<SubvolFacts, String> {
    let root = root.to_str().ok_or_else(|| "target root path is not UTF-8".to_string())?;
    let output = catos_process::run_trusted_tool(
        "btrfs",
        &["subvolume", "list", "-a", root],
        Duration::from_secs(10),
        64 * 1024,
    )?;
    if !output.success() || output.stdout_truncated {
        return Err(format!("cannot enumerate target Btrfs subvolumes: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let listed: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once(" path ").map(|(_, path)| format!("/{path}")))
        .collect();
    if listed.is_empty() {
        return Err("target Btrfs subvolume enumeration returned no entries".to_string());
    }
    Ok(SubvolFacts {
        observations: crate::mount::model::CATOS_STANDARD_SUBVOLS
            .iter()
            .map(|spec| SubvolObservation {
                subvol: spec.subvol.to_string(),
                exists_as_subvol: listed.iter().any(|path| path == spec.subvol),
                exists_as_directory: false,
                exists_as_other: false,
                mount_point_entry_count: None,
            })
            .collect(),
    })
}

fn collect_mount_point_observations(
    target: &TargetIdentity,
) -> std::collections::HashMap<String, MountPointObservation> {
    let mut out = std::collections::HashMap::new();
    if target.root_fstype.as_deref() != Some("btrfs") {
        return out;
    }
    let root = target_root_path(target);
    for spec in crate::mount::model::CATOS_STANDARD_SUBVOLS {
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

pub(in crate::doctor) fn derive_mount_section_status(
    problems: &[MountProblem],
) -> DoctorSectionStatus {
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

pub(in crate::doctor) fn mount_problem_to_issue(
    problem: &MountProblem,
    section: DoctorSectionId,
) -> DoctorIssue {
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
            format!("missing standard entry {mount_point} \u{2192} {subvol}"),
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
            "mount::diagnose::target::diagnose",
            format!(
                "root_device={}, fstype={}, subvol={:?}",
                target
                    .root_device
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
                target.root_fstype.as_deref().unwrap_or("<unknown>"),
                target.root_subvol
            ),
        ),
    );
    // boot_layout is not discovered on the minimal target::plan path;
    // surfacing it here is an open design point for a later phase.
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
