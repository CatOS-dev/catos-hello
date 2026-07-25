//! Output rendering for phase-3 recovery results (RecoveryListReport,
//! RecoveryInspectReport, RecoveryPlan, TransactionRecord, etc.).
//! Mirrors the phase-1/phase-2 JSON/human split: JSON is a thin serde
//! wrapper, human is plain ASCII.

use std::io::Write;

use crate::error::Error;
use crate::model::recovery::{
    RecoveryError, RecoveryInspectReport, RecoveryListReport, RecoveryPlan, RecoveryStatusReport,
    TransactionRecord,
};
use crate::phase3::Phase3Outcome;

pub fn render_phase3_json(
    outcome: &Phase3Outcome,
    invocation: &str,
    target_root: &std::path::Path,
) -> Result<String, Error> {
    let body = match outcome {
        Phase3Outcome::List(report) => json_envelope(
            invocation,
            target_root,
            "recovery_list",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        Phase3Outcome::Inspect(report) => json_envelope(
            invocation,
            target_root,
            "recovery_inspect",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        Phase3Outcome::Plan(plan) => json_envelope(
            invocation,
            target_root,
            "recovery_plan",
            serde_json::to_value(plan).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        Phase3Outcome::Apply {
            record,
            final_state,
        } => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "record".into(),
                serde_json::to_value(record).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            payload.insert(
                "final_state".into(),
                serde_json::to_value(final_state)
                    .map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            json_envelope(
                invocation,
                target_root,
                "recovery_apply",
                serde_json::Value::Object(payload),
            )
        }
        Phase3Outcome::Status(report) => json_envelope(
            invocation,
            target_root,
            "recovery_status",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        Phase3Outcome::Resume {
            record,
            final_state,
        } => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "record".into(),
                serde_json::to_value(record).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            payload.insert(
                "final_state".into(),
                serde_json::to_value(final_state)
                    .map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            json_envelope(
                invocation,
                target_root,
                "recovery_resume",
                serde_json::Value::Object(payload),
            )
        }
        Phase3Outcome::Revert {
            record,
            final_state,
        } => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "record".into(),
                serde_json::to_value(record).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            payload.insert(
                "final_state".into(),
                serde_json::to_value(final_state)
                    .map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            json_envelope(
                invocation,
                target_root,
                "recovery_revert",
                serde_json::Value::Object(payload),
            )
        }
        Phase3Outcome::Error(error) => json_envelope(
            invocation,
            target_root,
            "error",
            serde_json::to_value(error).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
    };
    serde_json::to_string_pretty(&body).map_err(|e| Error::SerializeFailed(e.to_string()))
}

pub fn render_phase3_human<W: Write>(outcome: &Phase3Outcome, out: &mut W) -> std::io::Result<()> {
    writeln!(out, "CatOS system backend (phase 3, recovery)")?;
    writeln!(out, "  program version : {}", crate::PROGRAM_VERSION)?;
    writeln!(out, "  schema version  : {}", crate::SCHEMA_VERSION)?;
    writeln!(out)?;
    match outcome {
        Phase3Outcome::List(report) => render_list(out, report),
        Phase3Outcome::Inspect(report) => render_inspect(out, report),
        Phase3Outcome::Plan(plan) => render_plan(out, plan),
        Phase3Outcome::Apply {
            record,
            final_state,
        }
        | Phase3Outcome::Resume {
            record,
            final_state,
        }
        | Phase3Outcome::Revert {
            record,
            final_state,
        } => {
            render_record(out, record)?;
            writeln!(out, "  final state      : {:?}", final_state)?;
            Ok(())
        }
        Phase3Outcome::Status(report) => render_status(out, report),
        Phase3Outcome::Error(error) => render_error(out, error),
    }
}

fn render_list<W: Write>(out: &mut W, report: &RecoveryListReport) -> std::io::Result<()> {
    writeln!(out, "Recovery list")?;
    writeln!(out, "  filesystems      : {}", report.filesystems.len())?;
    writeln!(
        out,
        "  readonly snapshots : {}",
        report.readonly_snapshots.len()
    )?;
    for snapshot in &report.readonly_snapshots {
        writeln!(
            out,
            "    {} id={} gen={} ro={}",
            snapshot.path, snapshot.subvolume_id, snapshot.generation, snapshot.read_only
        )?;
    }
    writeln!(out, "  transactions     : {}", report.transactions.len())?;
    for transaction in &report.transactions {
        writeln!(
            out,
            "    {} state={:?} plan={}",
            transaction.transaction_id, transaction.state, transaction.plan_id
        )?;
    }
    render_warnings(out, &report.warnings)
}

fn render_inspect<W: Write>(out: &mut W, report: &RecoveryInspectReport) -> std::io::Result<()> {
    writeln!(out, "Recovery inspect")?;
    writeln!(out, "  filesystem       : fsid={}", report.filesystem.fsid)?;
    writeln!(
        out,
        "  current root     : {} id={} gen={}",
        report.current_root.path, report.current_root.subvolume_id, report.current_root.generation
    )?;
    writeln!(
        out,
        "  source snapshot  : {} id={} gen={} ro={}",
        report.source_snapshot.path,
        report.source_snapshot.subvolume_id,
        report.source_snapshot.generation,
        report.source_snapshot.read_only
    )?;
    writeln!(out, "  finalization     : {:?}", report.finalization)?;
    writeln!(
        out,
        "  boot inside root : {}",
        report.boot_layout.boot_inside_root
    )?;
    writeln!(
        out,
        "  bootloadu present: {}",
        report.boot_layout.bootloadu_detected
    )?;
    render_warnings(out, &report.warnings)
}

fn render_plan<W: Write>(out: &mut W, plan: &RecoveryPlan) -> std::io::Result<()> {
    writeln!(out, "Recovery plan")?;
    writeln!(out, "  plan id          : {}", plan.plan_id)?;
    writeln!(out, "  generated        : unix {}", plan.generated_at_unix)?;
    writeln!(out, "  filesystem       : fsid={}", plan.filesystem.fsid)?;
    writeln!(
        out,
        "  current root     : {} id={} gen={}",
        plan.current_root.path, plan.current_root.subvolume_id, plan.current_root.generation
    )?;
    writeln!(
        out,
        "  source snapshot  : {} id={} gen={} ro={}",
        plan.source_snapshot.path,
        plan.source_snapshot.subvolume_id,
        plan.source_snapshot.generation,
        plan.source_snapshot.read_only
    )?;
    writeln!(out, "  backup path      : {}", plan.backup_root_path)?;
    writeln!(out, "  staging path     : {}", plan.staging_root_path)?;
    writeln!(out, "  finalization     : {:?}", plan.finalization)?;
    writeln!(out, "  predicted steps  :")?;
    for step in &plan.predicted_steps {
        writeln!(out, "    - {step}")?;
    }
    writeln!(out, "  refusal conditions:")?;
    for condition in &plan.refusal_conditions {
        writeln!(out, "    * {condition}")?;
    }
    writeln!(out, "  risks / warnings :")?;
    for risk in &plan.risks_and_warnings {
        writeln!(out, "    ! {risk}")?;
    }
    writeln!(out, "  confirmation     : {}", plan.confirmation_token)?;
    Ok(())
}

fn render_record<W: Write>(out: &mut W, record: &TransactionRecord) -> std::io::Result<()> {
    writeln!(out, "Transaction")?;
    writeln!(out, "  transaction id   : {}", record.transaction_id)?;
    writeln!(out, "  state            : {:?}", record.state)?;
    writeln!(out, "  created          : unix {}", record.created_at_unix)?;
    writeln!(
        out,
        "  last updated     : unix {}",
        record.last_updated_unix
    )?;
    writeln!(out, "  completed steps  :")?;
    for step in &record.completed_steps {
        writeln!(
            out,
            "    [{:?}] unix {} {}",
            step.state, step.completed_at_unix, step.description
        )?;
    }
    if let Some(error) = &record.last_error {
        writeln!(out, "  last error       :")?;
        writeln!(out, "    kind   : {}", error.kind.code())?;
        writeln!(out, "    message: {}", error.message)?;
    }
    Ok(())
}

fn render_status<W: Write>(out: &mut W, report: &RecoveryStatusReport) -> std::io::Result<()> {
    writeln!(out, "Recovery status")?;
    writeln!(out, "  transaction id   : {}", report.transaction_id)?;
    writeln!(out, "  reconciled state : {:?}", report.reconciled_state)?;
    writeln!(out, "  recommendation   : {:?}", report.recommendation)?;
    writeln!(
        out,
        "  backup exists    : {}",
        report.disk_facts.backup_root_exists
    )?;
    writeln!(
        out,
        "  staging exists   : {}",
        report.disk_facts.staging_root_exists
    )?;
    writeln!(
        out,
        "  active root gen  : {:?}",
        report.disk_facts.active_root_generation
    )?;
    render_warnings(out, &report.warnings)
}

fn render_error<W: Write>(out: &mut W, error: &RecoveryError) -> std::io::Result<()> {
    writeln!(out, "Recovery error")?;
    writeln!(out, "  kind             : {}", error.kind.code())?;
    writeln!(out, "  message          : {}", error.message)?;
    if let Some(transaction_id) = &error.transaction_id {
        writeln!(out, "  transaction id   : {transaction_id}")?;
    }
    if let Some(state) = error.current_state {
        writeln!(out, "  current state    : {:?}", state)?;
    }
    writeln!(out, "  resume possible  : {}", error.resume_possible)?;
    writeln!(out, "  revert possible  : {}", error.revert_possible)?;
    writeln!(
        out,
        "  manual required  : {}",
        error.manual_intervention_required
    )?;
    Ok(())
}

fn render_warnings<W: Write>(
    out: &mut W,
    warnings: &[crate::model::inspection::Warning],
) -> std::io::Result<()> {
    if warnings.is_empty() {
        return Ok(());
    }
    writeln!(out, "Warnings")?;
    for w in warnings {
        writeln!(out, "  [{}] {}", w.code, w.message)?;
    }
    Ok(())
}

fn json_envelope(
    invocation: &str,
    target_root: &std::path::Path,
    kind: &str,
    payload: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": crate::SCHEMA_VERSION,
        "programVersion": crate::PROGRAM_VERSION,
        "invocation": invocation,
        "targetRoot": target_root,
        "kind": kind,
        "payload": payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::recovery::{
        BootFinalizationDecision, BootLayout, BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity,
        CatosIdentity, CompletedStep, DiskFacts, FstabRootDefinition, RecoveryRecommendation,
        RecoveryStatusReport, TransactionState,
    };
    use std::path::PathBuf;

    fn sample_plan() -> RecoveryPlan {
        RecoveryPlan {
            schema_version: 1,
            plan_id: "tx-1".into(),
            generated_at_unix: 1000,
            generated_on_host: Some("host".into()),
            filesystem: BtrfsFilesystemIdentity {
                fsid: "fsid-1".into(),
                device_major_minor: "259:2".into(),
                label: None,
            },
            current_root: BtrfsSubvolumeIdentity {
                path: "/@".into(),
                subvolume_id: 256,
                generation: 100,
                read_only: false,
                evidence: vec![],
            },
            source_snapshot: BtrfsSubvolumeIdentity {
                path: "/@/.snapshots/1/snapshot".into(),
                subvolume_id: 300,
                generation: 80,
                read_only: true,
                evidence: vec![],
            },
            target_catos_identity: Some(CatosIdentity::default()),
            boot_layout: BootLayout::default(),
            finalization: BootFinalizationDecision::NotRequired,
            backup_root_path: "/.catos-recovery/backups/tx-1/root-before".into(),
            staging_root_path: "/.catos-recovery/staging/tx-1/new-root".into(),
            fstab_root_definition: FstabRootDefinition {
                source: "/dev/nvme0n1p2".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            },
            predicted_steps: vec!["preflight".into()],
            refusal_conditions: vec!["fsid drift".into()],
            risks_and_warnings: vec![],
            confirmation_token: "v1:tx-1:abc".into(),
            evidence: vec![],
        }
    }

    #[test]
    fn json_plan_envelope_carries_schema_and_kind() {
        let outcome = Phase3Outcome::Plan(sample_plan());
        let j = render_phase3_json(&outcome, "catos-system", std::path::Path::new("/")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["schemaVersion"], 2);
        assert_eq!(v["kind"], "recovery_plan");
        assert_eq!(v["payload"]["plan_id"], "tx-1");
        assert_eq!(v["payload"]["confirmation_token"], "v1:tx-1:abc");
    }

    #[test]
    fn json_error_envelope_carries_structured_fields() {
        let error = RecoveryError::new(
            crate::model::recovery::RecoveryErrorKind::StalePlan,
            "fsid drifted",
        );
        let outcome = Phase3Outcome::Error(error);
        let j = render_phase3_json(&outcome, "catos-system", std::path::Path::new("/")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["kind"], "error");
        assert_eq!(v["payload"]["kind"], "stale_plan");
        assert_eq!(v["payload"]["message"], "fsid drifted");
    }

    #[test]
    fn human_plan_output_has_no_ansi_escapes() {
        let outcome = Phase3Outcome::Plan(sample_plan());
        let mut buf = Vec::new();
        render_phase3_human(&outcome, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains('\u{001b}'));
        assert!(s.contains("Recovery plan"));
        assert!(s.contains("tx-1"));
    }

    #[test]
    fn status_envelope_carries_reconciled_state() {
        let plan = sample_plan();
        let record = TransactionRecord {
            schema_version: 1,
            transaction_id: "tx-1".into(),
            created_at_unix: 1,
            last_updated_unix: 2,
            plan,
            state: TransactionState::Completed,
            completed_steps: vec![CompletedStep {
                state: TransactionState::Completed,
                completed_at_unix: 2,
                description: "done".into(),
            }],
            last_error: None,
            last_disk_facts: Some(DiskFacts {
                backup_root_exists: true,
                staging_root_exists: true,
                active_root_exists: true,
                active_root_generation: Some(100),
                filesystem_fsid: "fsid-1".into(),
            }),
            last_cleanup: None,
        };
        let report = RecoveryStatusReport {
            transaction_id: "tx-1".into(),
            reconciled_state: TransactionState::Completed,
            record,
            disk_facts: DiskFacts {
                backup_root_exists: true,
                staging_root_exists: true,
                active_root_exists: true,
                active_root_generation: Some(100),
                filesystem_fsid: "fsid-1".into(),
            },
            recommendation: RecoveryRecommendation::None,
            warnings: vec![],
        };
        let outcome = Phase3Outcome::Status(report);
        let j = render_phase3_json(&outcome, "catos-system", std::path::Path::new("/")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["kind"], "recovery_status");
        assert_eq!(v["payload"]["reconciled_state"], "completed");
        let _ = PathBuf::new();
    }
}
