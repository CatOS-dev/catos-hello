//! Mount layout section: fstab validation, subvolume/mount-point checks.

use std::path::Path;

use crate::shared::model::doctor::{
    issue_code, recommendation_code, DoctorIssue, DoctorRecommendation, DoctorReport,
    DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount_repair::{MountProblem, TargetIdentity as RepairTargetIdentity};
use crate::target::model::TargetIdentity;
use crate::repair::mount_repair::{MountPointObservation, MountRepairInputs};
use crate::repair::subvol_decision::{CatosConfirmation, SubvolFacts};

use super::{push_evidence, push_issue, set_section, target_root_path};

pub(in crate::doctor) fn run_mount_section(
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
    let catos_confirmation = if target.root_fstype.as_deref() == Some("btrfs") {
        CatosConfirmation::Confirmed
    } else {
        CatosConfirmation::NotConfirmed
    };
    MountRepairInputs {
        fstab_text,
        target: repair_identity_from(target),
        catos_confirmation,
        subvol_facts: SubvolFacts::default(),
        mount_point_observations: collect_mount_point_observations(target),
    }
}

/// Construct the rich `repair::mount_repair::TargetIdentity` that
/// [`crate::repair::mount_repair::diagnose`] consumes from the minimal
/// [`TargetIdentity`] Doctor carries. ESP and boot-layout signals are
/// unknown on the `target::plan` path (Doctor does not mount or detect
/// them); they are left `None`. Wiring real ESP/boot-layout discovery
/// into this section is an open design point for a later phase.
fn repair_identity_from(target: &TargetIdentity) -> RepairTargetIdentity {
    RepairTargetIdentity {
        root_device: target.root_device.clone().unwrap_or_default(),
        root_fstype: target.root_fstype.clone().unwrap_or_default(),
        root_subvol: target.root_subvol.clone(),
        root_uuid: target.root_uuid.clone(),
        esp_device: None,
        esp_uuid: None,
        boot_layout: None,
    }
}

fn read_target_fstab(target: &TargetIdentity) -> Option<String> {
    let root = target_root_path(target);
    std::fs::read_to_string(root.join("etc/fstab")).ok()
}

fn collect_mount_point_observations(
    target: &TargetIdentity,
) -> std::collections::HashMap<String, MountPointObservation> {
    let mut out = std::collections::HashMap::new();
    if target.root_fstype.as_deref() != Some("btrfs") {
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

pub(in crate::doctor) fn derive_mount_section_status(problems: &[MountProblem]) -> DoctorSectionStatus {
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

pub(in crate::doctor) fn mount_problem_to_issue(problem: &MountProblem, section: DoctorSectionId) -> DoctorIssue {
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
        StandardWrongSubvol { mount_point, expected, actual } => (
            issue_code::STANDARD_SUBVOLUME_MISSING,
            DoctorSeverity::Error,
            format!("{mount_point}: expected subvol {expected}, got {actual}"),
        ),
        MissingStandardEntry { mount_point, subvol } => (
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
        UnsafeMountPoint { mount_point, reason } => (
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
                target
                    .root_device
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
                target
                    .root_fstype
                    .as_deref()
                    .unwrap_or("<unknown>"),
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
