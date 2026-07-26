//! Output rendering for `catos-repair mount`. Mirrors the repair-fs
//! split: JSON is a thin serde wrapper around the model; human
//! output is plain ASCII. Both render the SAME [`MountRepairReport`]
//! so JSON and human output cannot diverge on the final outcome.

use std::io::Write;

use crate::shared::error::Error;
use crate::model::mount_repair::MountRepairReport;

pub fn render_mount_repair_json(
    report: &MountRepairReport,
    invocation: &str,
    target_root: &std::path::Path,
) -> Result<String, Error> {
    let body = serde_json::json!({
        "schemaVersion": crate::SCHEMA_VERSION,
        "programVersion": crate::PROGRAM_VERSION,
        "invocation": invocation,
        "targetRoot": target_root,
        "kind": "repair_mount",
        "payload": serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
    });
    serde_json::to_string_pretty(&body).map_err(|e| Error::SerializeFailed(e.to_string()))
}

pub fn render_mount_repair_human<W: Write>(
    report: &MountRepairReport,
    out: &mut W,
) -> std::io::Result<()> {
    writeln!(out, "CatOS system backend (repair mount)")?;
    writeln!(out, "  program version : {}", crate::PROGRAM_VERSION)?;
    writeln!(out, "  schema version  : {}", crate::SCHEMA_VERSION)?;
    writeln!(out)?;
    writeln!(out, "Mount repair result")?;
    if let Some(target) = &report.target {
        writeln!(out, "  target device    : {}", target.root_device.display())?;
        writeln!(out, "  root fstype      : {}", target.root_fstype)?;
        if let Some(subvol) = &target.root_subvol {
            writeln!(out, "  root subvol      : {subvol}")?;
        }
        if let Some(uuid) = &target.root_uuid {
            writeln!(out, "  root uuid        : {uuid}")?;
        }
        if let Some(esp) = &target.esp_device {
            writeln!(out, "  esp device       : {}", esp.display())?;
        }
    } else {
        writeln!(out, "  target device    : <not selected>")?;
    }
    writeln!(out, "  final outcome    : {}", report.final_outcome.code())?;
    writeln!(out, "  fully complete   : {}", report.fully_complete)?;
    writeln!(
        out,
        "  requires human action: {}",
        report.requires_human_action
    )?;

    if let Some(plan) = &report.plan {
        writeln!(out, "  Plan")?;
        writeln!(out, "    problems       : {}", plan.problems.len())?;
        for problem in &plan.problems {
            writeln!(out, "      [{}]", problem.code())?;
        }
        writeln!(out, "    fstab edits    : {}", plan.fstab_edits.len())?;
        writeln!(out, "    subvolumes     : {}", plan.subvolumes.len())?;
        for sub in &plan.subvolumes {
            writeln!(out, "      create {} ({})", sub.subvol, sub.reason)?;
        }
        writeln!(out, "    directories    : {}", plan.directories.len())?;
        for dir in &plan.directories {
            writeln!(out, "      mkdir  {} ({})", dir.mount_point, dir.reason)?;
        }
        if !plan.unresolved_conflicts.is_empty() {
            writeln!(
                out,
                "    conflicts      : {}",
                plan.unresolved_conflicts.len()
            )?;
            for conflict in &plan.unresolved_conflicts {
                writeln!(out, "      ! {conflict}")?;
            }
        }
        if !plan.risks.is_empty() {
            writeln!(out, "    risks          : {}", plan.risks.len())?;
            for risk in &plan.risks {
                writeln!(out, "      risk: {risk}")?;
            }
        }
    }

    if !report.actions.is_empty() {
        writeln!(out, "  Actions")?;
        for action in &report.actions {
            match action {
                crate::model::mount_repair::AppliedAction::FstabEdited { edit } => {
                    writeln!(out, "    fstab-edit: {}", edit_reason(edit))?;
                }
                crate::model::mount_repair::AppliedAction::FstabEditSkipped { edit, reason } => {
                    writeln!(out, "    fstab-skip: {} ({reason})", edit_reason(edit))?;
                }
                crate::model::mount_repair::AppliedAction::SubvolumeCreated { subvol } => {
                    writeln!(out, "    subvol-create: {subvol}")?;
                }
                crate::model::mount_repair::AppliedAction::SubvolumeSkipped { subvol, reason } => {
                    writeln!(out, "    subvol-skip: {subvol} ({reason})")?;
                }
                crate::model::mount_repair::AppliedAction::SubvolumeRolledBack { subvol } => {
                    writeln!(out, "    subvol-rollback: {subvol}")?;
                }
                crate::model::mount_repair::AppliedAction::DirectoryCreated { mount_point } => {
                    writeln!(out, "    mkdir: {mount_point}")?;
                }
                crate::model::mount_repair::AppliedAction::DirectorySkipped {
                    mount_point,
                    reason,
                } => {
                    writeln!(out, "    mkdir-skip: {mount_point} ({reason})")?;
                }
                crate::model::mount_repair::AppliedAction::DirectoryRolledBack { mount_point } => {
                    writeln!(out, "    mkdir-rollback: {mount_point}")?;
                }
                crate::model::mount_repair::AppliedAction::RollbackResidual {
                    resource,
                    reason,
                } => {
                    writeln!(out, "    ROLLBACK-RESIDUAL: {resource} ({reason})")?;
                }
            }
        }
    }

    if let Some(txn) = &report.fstab_transaction {
        writeln!(out, "  fstab transaction")?;
        writeln!(
            out,
            "    original path      : {}",
            txn.original_path.display()
        )?;
        if let Some(backup) = &txn.backup_path {
            writeln!(out, "    backup path        : {}", backup.display())?;
        }
        writeln!(
            out,
            "    atomic replace     : {}",
            txn.atomic_replace_succeeded
        )?;
        writeln!(out, "    parent fsynced     : {}", txn.parent_fsynced)?;
        if txn.rollback_attempted {
            writeln!(
                out,
                "    rollback attempted : {} (succeeded={})",
                txn.rollback_attempted, txn.rollback_succeeded
            )?;
        }
    }

    if let Some(verification) = &report.verification {
        writeln!(out, "  Verification")?;
        writeln!(out, "    mounted            : {}", verification.mounted)?;
        if let Some(fstype) = &verification.observed_root_fstype {
            writeln!(out, "    observed fstype    : {fstype}")?;
        }
        for target in &verification.mounted_targets {
            writeln!(out, "    accepted mount     : {target}")?;
        }
        if let Some(msg) = &verification.failure_message {
            writeln!(out, "    failure            : {msg}")?;
        }
    }

    writeln!(out, "  Cleanup")?;
    writeln!(
        out,
        "    unmounted        : {}",
        report.cleanup.unmounted.len()
    )?;
    for entry in &report.cleanup.unmounted {
        writeln!(out, "      ok: {entry}")?;
    }
    writeln!(
        out,
        "    residual         : {}",
        report.cleanup.residual.len()
    )?;
    for entry in &report.cleanup.residual {
        writeln!(out, "      RESIDUAL: {entry}")?;
    }
    writeln!(out, "    all clean        : {}", report.cleanup.all_clean)?;

    if !report.evidence.is_empty() {
        writeln!(out, "  Evidence")?;
        for evidence in &report.evidence {
            writeln!(
                out,
                "    [{}] {}: {}",
                evidence.code, evidence.source, evidence.message
            )?;
        }
    }
    if !report.warnings.is_empty() {
        writeln!(out, "  Warnings")?;
        for warning in &report.warnings {
            writeln!(out, "    [{}] {}", warning.code, warning.message)?;
        }
    }
    Ok(())
}

fn edit_reason(edit: &crate::model::mount_repair::PlannedFstabEdit) -> &str {
    match edit {
        crate::model::mount_repair::PlannedFstabEdit::ReplaceSource { reason, .. }
        | crate::model::mount_repair::PlannedFstabEdit::ReplaceEntry { reason, .. }
        | crate::model::mount_repair::PlannedFstabEdit::AppendEntry { reason, .. }
        | crate::model::mount_repair::PlannedFstabEdit::DropDuplicate { reason, .. } => reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::mount_repair::{
        AppliedAction, FstabTransaction, MountProblem, MountRepairCleanup, MountRepairOutcome,
        MountRepairPlan, MountVerification, PlannedFstabEdit, PlannedSubvolume, TargetIdentity,
    };
    use std::path::PathBuf;

    fn sample_report() -> MountRepairReport {
        MountRepairReport {
            target: Some(TargetIdentity {
                root_device: PathBuf::from("/dev/nvme0n1p2"),
                root_fstype: "btrfs".into(),
                root_subvol: Some("/@".into()),
                root_uuid: Some("abc-123".into()),
                esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
                esp_uuid: Some("DEAD-BEEF".into()),
                boot_layout: None,
            }),
            plan: Some(MountRepairPlan {
                problems: vec![
                    MountProblem::RootWrongSubvol {
                        actual: "/@old".into(),
                    },
                    MountProblem::MissingStandardEntry {
                        mount_point: "/home".into(),
                        subvol: "/@home".into(),
                    },
                ],
                fstab_edits: vec![
                    PlannedFstabEdit::ReplaceEntry {
                        line: 1,
                        new_line: "UUID=abc-123  /  btrfs  defaults,subvol=/@  0 0".into(),
                        reason: "root subvol must be /@".into(),
                    },
                    PlannedFstabEdit::AppendEntry {
                        new_line: "UUID=abc-123  /home  btrfs  defaults,subvol=/@home  0 0".into(),
                        reason: "missing standard entry".into(),
                    },
                ],
                subvolumes: vec![PlannedSubvolume {
                    subvol: "/@home".into(),
                    mount_point: "/home".into(),
                    reason: "missing on disk".into(),
                }],
                ..Default::default()
            }),
            fstab_transaction: Some(FstabTransaction {
                original_path: PathBuf::from("/etc/fstab"),
                backup_path: Some(PathBuf::from("/etc/fstab.catos-repair.bak")),
                temp_path: Some(PathBuf::from("/etc/.fstab.tmp")),
                atomic_replace_succeeded: true,
                parent_fsynced: true,
                rollback_attempted: false,
                rollback_succeeded: false,
            }),
            actions: vec![
                AppliedAction::FstabEdited {
                    edit: PlannedFstabEdit::ReplaceEntry {
                        line: 1,
                        new_line: "stub".into(),
                        reason: "stub".into(),
                    },
                },
                AppliedAction::SubvolumeCreated {
                    subvol: "/@home".into(),
                },
            ],
            verification: Some(MountVerification {
                mounted: true,
                observed_root_fstype: Some("btrfs".into()),
                mounted_targets: Vec::new(),
                failure_message: None,
            }),
            cleanup: MountRepairCleanup {
                unmounted: vec!["/dev/nvme0n1p2 on /run/catos-system/sessions/m1/target".into()],
                residual: vec![],
                all_clean: true,
            },
            final_outcome: MountRepairOutcome::Repaired,
            requires_human_action: false,
            fully_complete: true,
            evidence: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn human_output_has_no_ansi_escapes() {
        let report = sample_report();
        let mut buf = Vec::new();
        render_mount_repair_human(&report, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains('\u{001b}'));
        assert!(s.contains("Mount repair result"));
        assert!(s.contains("final outcome    : repaired"));
    }

    #[test]
    fn json_output_uses_repair_mount_envelope() {
        let report = sample_report();
        let json =
            render_mount_repair_json(&report, "catos-repair", std::path::Path::new("/")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schemaVersion"], 2);
        assert_eq!(value["kind"], "repair_mount");
        assert_eq!(value["payload"]["final_outcome"], "repaired");
        assert_eq!(value["payload"]["actions"][1]["kind"], "subvolume_created");
    }

    #[test]
    fn json_and_human_agree_on_final_outcome() {
        let report = sample_report();
        let json =
            render_mount_repair_json(&report, "catos-repair", std::path::Path::new("/")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let json_outcome = value["payload"]["final_outcome"].as_str().unwrap();
        let mut buf = Vec::new();
        render_mount_repair_human(&report, &mut buf).unwrap();
        let human = String::from_utf8(buf).unwrap();
        let human_line = human
            .lines()
            .find(|line| line.contains("final outcome"))
            .unwrap();
        assert!(
            human_line.contains(json_outcome),
            "human line {human_line:?} did not contain JSON outcome {json_outcome:?}"
        );
    }

    #[test]
    fn data_conflict_outcome_renders_correctly() {
        let mut report = sample_report();
        report.final_outcome = MountRepairOutcome::PartiallyRepaired;
        report.requires_human_action = true;
        report.fully_complete = false;
        let mut buf = Vec::new();
        render_mount_repair_human(&report, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("final outcome    : partially_repaired"));
        assert!(s.contains("fully complete   : false"));
        assert!(s.contains("requires human action: true"));
    }
}
