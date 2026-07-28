//! Mount layout section: fstab validation, subvolume/mount-point checks.

use std::path::Path;
use std::time::Duration;

use crate::doctor::model::{
    issue_code, recommendation_code, DoctorIssue, DoctorReport,
    DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::mount::diagnose::subvolume::{CatosConfirmation, SubvolFacts, SubvolObservation};
use crate::mount::diagnose::target::{
    diagnose as mount_diagnose, MountPointObservation, MountRepairInputs,
};
use crate::mount::model::{MountProblem, MountTargetIdentity as RepairTargetIdentity};
use crate::target::model::TargetIdentity;
use crate::target::Evidence;

use super::{
    push_evidence, push_issue, set_section, target_repair_recommendation, target_root_path,
};
use crate::doctor::DoctorTargetContext;

pub(in crate::doctor) fn run_mount_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    context: Option<&DoctorTargetContext>,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Mount;
    let Some(context) = context else {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report
            .limitations
            .push(crate::doctor::model::DoctorLimitation::new(
                id,
                "TARGET_CONTEXT_UNAVAILABLE",
                "Mount requires the selected readonly Doctor target context",
            ));
        return Ok(());
    };
    let inputs = match build_mount_inputs(context) {
        Ok(inputs) => inputs,
        Err(message) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report
                .limitations
                .push(crate::doctor::model::DoctorLimitation::new(
                    id,
                    "MOUNT_FACTS_INCOMPLETE",
                    message,
                ));
            return Ok(());
        }
    };
    let problems = mount_diagnose(&inputs);
    push_mount_evidence(sections, id, &context.target, &inputs.fstab_text);

    let status = derive_mount_section_status(&problems);
    set_section(sections, id, status);

    for problem in &problems {
        let issue = mount_problem_to_issue(problem, id);
        push_issue(sections, issue);
    }

    let esp_device = context
        .esp
        .as_ref()
        .ok()
        .and_then(|esp| esp.as_ref())
        .map(|esp| esp.device.as_path());
    if problems.iter().any(|p| {
        matches!(
            p,
            MountProblem::MissingSubvolume { .. }
                | MountProblem::MissingMountPoint { .. }
                | MountProblem::MissingStandardEntry { .. }
        )
    }) {
        report.recommendations.push(target_repair_recommendation(
            "catos-repair mount",
            &context.target,
            esp_device,
            recommendation_code::RUN_CATOS_REPAIR_MOUNT,
            "mount layout is missing standard entries or subvolumes; catos-repair mount can recreate them when authorised",
            "mount layout needs repair, but automatic mount repair supports only the CatOS standard Btrfs root /@; review this nonstandard root manually",
        ));
    }
    if problems
        .iter()
        .any(|p| matches!(p, MountProblem::RootUuidMismatch { .. }))
    {
        report.recommendations.push(target_repair_recommendation(
            "catos-repair mount",
            &context.target,
            esp_device,
            recommendation_code::RUN_CATOS_REPAIR_MOUNT,
            "root UUID in fstab does not match the discovered device",
            "root UUID in fstab needs repair, but automatic mount repair supports only the CatOS standard Btrfs root /@; review this nonstandard root manually",
        ));
    }
    Ok(())
}

fn build_mount_inputs(context: &DoctorTargetContext) -> Result<MountRepairInputs, String> {
    let target = &context.target;
    let fstab_text = context.fstab.as_ref().map_err(Clone::clone)?.clone();
    let root_device = target
        .root_device
        .clone()
        .ok_or_else(|| "selected target has no root device".to_string())?;
    let root_fstype = target
        .root_fstype
        .clone()
        .ok_or_else(|| "selected target has no root filesystem type".to_string())?;
    let catos_confirmation = if target.root_fstype.as_deref() == Some("btrfs") {
        CatosConfirmation::Confirmed
    } else {
        CatosConfirmation::NotConfirmed
    };
    let mount_point_observations = collect_mount_point_observations(target)?;
    let subvol_facts = if root_fstype == "btrfs" {
        let top_level = context
            .top_level
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .ok_or_else(|| "selected Btrfs top-level session is unavailable".to_string())?;
        collect_subvolume_facts(top_level.root(), &mount_point_observations)?
    } else {
        SubvolFacts::not_applicable()
    };
    let boot_layout = context.boot_layout.as_ref().map_err(Clone::clone)?.clone();
    let (esp_device, esp_uuid) = match context.esp.as_ref().map_err(Clone::clone)?.as_ref() {
        Some(esp) => (Some(esp.device.clone()), esp.uuid.clone()),
        None => (None, None),
    };
    Ok(MountRepairInputs {
        fstab_text,
        target: RepairTargetIdentity {
            root_device,
            root_fstype,
            root_subvol: target.root_subvol.clone(),
            root_uuid: target.root_uuid.clone(),
            esp_device,
            esp_uuid,
            boot_layout: Some(boot_layout),
        },
        catos_confirmation,
        subvol_facts,
        mount_point_observations,
    })
}

fn collect_subvolume_facts(
    top_level: &Path,
    mount_points: &std::collections::HashMap<String, MountPointObservation>,
) -> Result<SubvolFacts, String> {
    let top_level_text = top_level
        .to_str()
        .ok_or_else(|| "target Btrfs top-level path is not UTF-8".to_string())?;
    let output = catos_process::run_trusted_tool(
        "btrfs",
        &["subvolume", "list", "-a", top_level_text],
        Duration::from_secs(10),
        64 * 1024,
    )?;
    if !output.success() || output.stdout_truncated {
        return Err(format!(
            "cannot enumerate target Btrfs subvolumes: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let listed: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            line.split_once(" path ")
                .map(|(_, path)| format!("/{path}"))
        })
        .collect();
    if listed.is_empty() {
        return Err("target Btrfs subvolume enumeration returned no entries".to_string());
    }
    assemble_subvolume_facts(top_level, &listed, mount_points)
}

fn assemble_subvolume_facts(
    top_level: &Path,
    listed: &[String],
    mount_points: &std::collections::HashMap<String, MountPointObservation>,
) -> Result<SubvolFacts, String> {
    use crate::target::execute::confined::{rooted_path_kind, RootedPathKind};

    let mut observations = Vec::new();
    for spec in crate::mount::model::CATOS_STANDARD_SUBVOLS {
        let exists_as_subvol = listed.iter().any(|path| path == spec.subvol);
        let (exists_as_directory, exists_as_other) = if exists_as_subvol {
            (false, false)
        } else {
            match rooted_path_kind(top_level, spec.subvol) {
                Ok(None) | Err(crate::target::error::FsError::NotFound) => (false, false),
                Ok(Some(RootedPathKind::Directory)) => (true, false),
                Ok(Some(
                    RootedPathKind::Symlink
                    | RootedPathKind::RegularFile
                    | RootedPathKind::Other,
                )) => (false, true),
                Err(error) => {
                    return Err(format!(
                        "cannot safely inspect Btrfs path {}: {error}",
                        spec.subvol
                    ));
                }
            }
        };
        observations.push(SubvolObservation {
            subvol: spec.subvol.to_string(),
            exists_as_subvol,
            exists_as_directory,
            exists_as_other,
            mount_point_entry_count: mount_points
                .get(spec.mount_point)
                .and_then(|observation| observation.entry_count),
        });
    }
    Ok(SubvolFacts { observations })
}

fn collect_mount_point_observations(
    target: &TargetIdentity,
) -> Result<std::collections::HashMap<String, MountPointObservation>, String> {
    let mut out = std::collections::HashMap::new();
    if target.root_fstype.as_deref() != Some("btrfs") {
        return Ok(out);
    }
    let root = target_root_path(target);
    for spec in crate::mount::model::CATOS_STANDARD_SUBVOLS {
        if spec.mount_point == "/" {
            continue;
        }
        let observation = observe_rooted_path(&root, spec.mount_point)?;
        out.insert(spec.mount_point.to_string(), observation);
    }
    Ok(out)
}

fn observe_rooted_path(root: &Path, rooted_path: &str) -> Result<MountPointObservation, String> {
    use crate::target::execute::confined::{rooted_path_kind, RootedPathKind};

    let kind = match rooted_path_kind(root, rooted_path) {
        Ok(kind) => kind,
        Err(crate::target::error::FsError::NotFound) => None,
        Err(error) => {
            return Err(format!(
                "cannot safely inspect target mount point {rooted_path}: {error}"
            ))
        }
    };
    match kind {
        None => Ok(MountPointObservation::missing()),
        Some(RootedPathKind::Symlink) => Ok(MountPointObservation {
            exists: true,
            is_symlink: true,
            is_directory: false,
            is_other_object: false,
            entry_count: None,
        }),
        Some(RootedPathKind::Directory) => {
            let entries = crate::target::execute::confined::list_rooted_directory_names(
                root,
                rooted_path,
            )
            .map_err(|error| {
                format!("cannot list target mount point {rooted_path}: {error}")
            })?;
            Ok(MountPointObservation {
                exists: true,
                is_symlink: false,
                is_directory: true,
                is_other_object: false,
                entry_count: Some(entries.len()),
            })
        }
        Some(RootedPathKind::RegularFile | RootedPathKind::Other) => {
            Ok(MountPointObservation {
                exists: true,
                is_symlink: false,
                is_directory: false,
                is_other_object: true,
                entry_count: None,
            })
        }
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
    fstab: &str,
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
    push_evidence(
        sections,
        id,
        Evidence::new(
            "FSTAB_LOADED",
            "selected-target:/etc/fstab",
            format!("read {} bytes from the selected target fstab", fstab.len()),
        ),
    );
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
    fn rooted_mount_observation_refuses_intermediate_symlink_escape() {
        let root = std::env::temp_dir().join(format!(
            "catos-doctor-mount-root-{}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "catos-doctor-mount-outside-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(outside.join("log")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("var")).unwrap();

        assert!(observe_rooted_path(&root, "/var/log").is_err());

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn subvolume_facts_preserve_occupied_paths_and_mountpoint_data() {
        let top = std::env::temp_dir().join(format!(
            "catos-doctor-subvol-facts-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&top);
        std::fs::create_dir_all(top.join("@home")).unwrap();
        std::fs::write(top.join("@log"), b"occupied").unwrap();
        let mount_points = std::collections::HashMap::from([
            ("/home".to_string(), MountPointObservation::directory(3)),
            ("/var/log".to_string(), MountPointObservation::directory(1)),
        ]);

        let facts = assemble_subvolume_facts(&top, &["/@".into()], &mount_points).unwrap();
        let home = facts.find("/@home").unwrap();
        assert!(home.exists_as_directory);
        assert!(!home.exists_as_other);
        assert_eq!(home.mount_point_entry_count, Some(3));
        let log = facts.find("/@log").unwrap();
        assert!(!log.exists_as_directory);
        assert!(log.exists_as_other);
        assert_eq!(log.mount_point_entry_count, Some(1));

        std::fs::remove_dir_all(top).unwrap();
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
