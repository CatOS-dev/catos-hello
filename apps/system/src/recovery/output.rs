//! Output rendering for Btrfs recovery results (RecoveryListReport,
//! RecoveryInspectReport, RecoveryPlan, TransactionRecord, etc.).
//! JSON is a thin serde
//! wrapper, human is plain ASCII.

use std::io::Write;

use crate::error::Error;
use crate::recovery::model::{
    RecoveryCleanupReport, RecoveryInspectReport, RecoveryListReport, RecoveryPlanReport,
    RecoveryStatusReport,
};
use crate::recovery::RecoveryOutcome;
use crate::selection_ui::terminal_text;
use crate::snapshot::model::{RecoveryPlan, SnapshotError, TransactionRecord};

pub fn render_recovery_json(
    outcome: &RecoveryOutcome,
    invocation: &str,
    target_root: &std::path::Path,
) -> Result<String, Error> {
    let body = match outcome {
        RecoveryOutcome::List(report) => json_envelope(
            invocation,
            target_root,
            "recovery_list",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        RecoveryOutcome::Inspect(report) => json_envelope(
            invocation,
            target_root,
            "recovery_inspect",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        RecoveryOutcome::Plan(report) => json_envelope(
            invocation,
            target_root,
            "recovery_plan",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        RecoveryOutcome::Apply {
            record,
            final_state,
            cleanup,
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
            payload.insert(
                "cleanup".into(),
                serde_json::to_value(cleanup).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            json_envelope(
                invocation,
                target_root,
                "recovery_apply",
                serde_json::Value::Object(payload),
            )
        }
        RecoveryOutcome::DiscardPlan(report) => json_envelope(
            invocation,
            target_root,
            "recovery_discard_plan",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        RecoveryOutcome::Purge(report) => json_envelope(
            invocation,
            target_root,
            "recovery_purge",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        RecoveryOutcome::Status(report) => json_envelope(
            invocation,
            target_root,
            "recovery_status",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        RecoveryOutcome::Resume {
            record,
            final_state,
            cleanup,
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
            payload.insert(
                "cleanup".into(),
                serde_json::to_value(cleanup).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            json_envelope(
                invocation,
                target_root,
                "recovery_resume",
                serde_json::Value::Object(payload),
            )
        }
        RecoveryOutcome::Revert {
            record,
            final_state,
            cleanup,
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
            payload.insert(
                "cleanup".into(),
                serde_json::to_value(cleanup).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            json_envelope(
                invocation,
                target_root,
                "recovery_revert",
                serde_json::Value::Object(payload),
            )
        }
        RecoveryOutcome::ArgumentError(error) | RecoveryOutcome::Error(error) => json_envelope(
            invocation,
            target_root,
            "error",
            serde_json::to_value(error).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
    };
    serde_json::to_string_pretty(&body).map_err(|e| Error::SerializeFailed(e.to_string()))
}

pub fn render_recovery_human<W: Write>(
    outcome: &RecoveryOutcome,
    out: &mut W,
) -> std::io::Result<()> {
    writeln!(out, "CatOS Btrfs Snapshot Recovery")?;
    writeln!(out, "  program version : {}", crate::PROGRAM_VERSION)?;
    writeln!(out, "  schema version  : {}", crate::SCHEMA_VERSION)?;
    writeln!(out)?;
    match outcome {
        RecoveryOutcome::List(report) => render_list(out, report),
        RecoveryOutcome::Inspect(report) => render_inspect(out, report),
        RecoveryOutcome::Plan(report) => render_plan_report(out, report),
        RecoveryOutcome::Apply {
            record,
            final_state,
            cleanup,
        }
        | RecoveryOutcome::Resume {
            record,
            final_state,
            cleanup,
        }
        | RecoveryOutcome::Revert {
            record,
            final_state,
            cleanup,
        } => {
            render_record(out, record)?;
            writeln!(out, "  final state      : {:?}", final_state)?;
            writeln!(out, "  cleanup          : clean={}", cleanup.all_clean)?;
            for entry in &cleanup.unmounted {
                writeln!(out, "    unmounted: {}", terminal_text(entry))?;
            }
            for entry in &cleanup.residual {
                writeln!(out, "    residual: {}", terminal_text(entry))?;
            }
            Ok(())
        }
        RecoveryOutcome::DiscardPlan(report) => render_cleanup(out, "Discarded pending plan", report),
        RecoveryOutcome::Purge(report) => render_cleanup(out, "Purged recovery transaction", report),
        RecoveryOutcome::Status(report) => render_status(out, report),
        RecoveryOutcome::ArgumentError(error) | RecoveryOutcome::Error(error) => {
            render_error(out, error)
        }
    }
}

fn render_list<W: Write>(out: &mut W, report: &RecoveryListReport) -> std::io::Result<()> {
    writeln!(out, "Recovery list")?;
    if let Some(device) = &report.source_device {
        writeln!(out, "  source device    : {}", terminal_text(device))?;
    }
    if let Some(fsid) = &report.source_filesystem_fsid {
        writeln!(out, "  source FSID      : {}", terminal_text(fsid))?;
    }
    if let Some(cleanup) = &report.mount_cleanup {
        writeln!(out, "  mount cleanup    : clean={}", cleanup.all_clean)?;
        for residual in &cleanup.residual {
            writeln!(out, "    residual: {}", terminal_text(residual))?;
        }
    }
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
            terminal_text(&snapshot.path),
            snapshot.subvolume_id,
            snapshot.generation,
            snapshot.read_only
        )?;
    }
    writeln!(out, "  pending plans    : {}", report.plans.len())?;
    for plan in &report.plans {
        writeln!(
            out,
            "    {} snapshot={} generated={}",
            terminal_text(&plan.plan_id),
            terminal_text(&plan.source_snapshot_path),
            plan.generated_at_unix
        )?;
    }
    writeln!(out, "  transactions     : {}", report.transactions.len())?;
    for transaction in &report.transactions {
        writeln!(
            out,
            "    {} state={:?} plan={}",
            terminal_text(&transaction.transaction_id),
            transaction.state,
            terminal_text(&transaction.plan_id)
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
        terminal_text(&report.current_root.path),
        report.current_root.subvolume_id,
        report.current_root.generation
    )?;
    writeln!(
        out,
        "  source snapshot  : {} id={} gen={} ro={}",
        terminal_text(&report.source_snapshot.path),
        report.source_snapshot.subvolume_id,
        report.source_snapshot.generation,
        report.source_snapshot.read_only
    )?;
    writeln!(
        out,
        "  boot inside root : {}",
        report.boot_layout.boot_inside_root
    )?;
    render_boot_consistency(out, &report.boot_consistency)?;
    render_warnings(out, &report.warnings)
}

fn render_plan_report<W: Write>(out: &mut W, report: &RecoveryPlanReport) -> std::io::Result<()> {
    render_plan(out, &report.plan)?;
    writeln!(
        out,
        "  persisted at     : {}",
        terminal_text(&report.plan_path)
    )?;
    writeln!(
        out,
        "  mount cleanup    : clean={}",
        report.mount_cleanup.all_clean
    )
}

fn render_plan<W: Write>(out: &mut W, plan: &RecoveryPlan) -> std::io::Result<()> {
    writeln!(out, "Recovery plan")?;
    writeln!(out, "  plan id          : {}", terminal_text(&plan.plan_id))?;
    writeln!(out, "  generated        : unix {}", plan.generated_at_unix)?;
    writeln!(
        out,
        "  filesystem       : fsid={}",
        terminal_text(&plan.filesystem.fsid)
    )?;
    writeln!(
        out,
        "  current root     : {} id={} gen={}",
        terminal_text(&plan.current_root.path),
        plan.current_root.subvolume_id,
        plan.current_root.generation
    )?;
    writeln!(
        out,
        "  source snapshot  : {} id={} gen={} ro={}",
        terminal_text(&plan.source_snapshot.path),
        plan.source_snapshot.subvolume_id,
        plan.source_snapshot.generation,
        plan.source_snapshot.read_only
    )?;
    writeln!(
        out,
        "  backup path      : {}",
        terminal_text(&plan.backup_root_path)
    )?;
    writeln!(
        out,
        "  staging path     : {}",
        terminal_text(&plan.staging_root_path)
    )?;
    render_boot_consistency(out, &plan.boot_consistency)?;
    writeln!(out, "  predicted steps  :")?;
    for step in &plan.predicted_steps {
        writeln!(out, "    - {}", terminal_text(step))?;
    }
    writeln!(out, "  refusal conditions:")?;
    for condition in &plan.refusal_conditions {
        writeln!(out, "    * {}", terminal_text(condition))?;
    }
    writeln!(out, "  risks / warnings :")?;
    for risk in &plan.risks_and_warnings {
        writeln!(out, "    ! {}", terminal_text(risk))?;
    }
    writeln!(
        out,
        "  confirmation     : {}",
        terminal_text(&plan.confirmation_token)
    )?;
    Ok(())
}

fn render_boot_consistency<W: Write>(
    out: &mut W,
    report: &crate::boot::model::BootConsistencyReport,
) -> std::io::Result<()> {
    writeln!(out, "  boot consistency : {:?}", report.status)?;
    writeln!(
        out,
        "    read-only={} covers-all={} external-boot={} external-esp={}",
        report.checked_read_only,
        report.root_switch_covers_all_boot_resources,
        report.external_boot,
        report.external_esp
    )?;
    for reason in &report.reasons {
        writeln!(out, "    - {}", terminal_text(reason))?;
    }
    Ok(())
}

fn render_record<W: Write>(out: &mut W, record: &TransactionRecord) -> std::io::Result<()> {
    writeln!(out, "Transaction")?;
    writeln!(
        out,
        "  transaction id   : {}",
        terminal_text(&record.transaction_id)
    )?;
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
            step.state,
            step.completed_at_unix,
            terminal_text(&step.description)
        )?;
    }
    if let Some(error) = &record.last_error {
        writeln!(out, "  last error       :")?;
        writeln!(out, "    kind   : {}", error.kind.code())?;
        writeln!(out, "    message: {}", terminal_text(&error.message))?;
    }
    Ok(())
}

fn render_cleanup<W: Write>(
    out: &mut W,
    heading: &str,
    report: &RecoveryCleanupReport,
) -> std::io::Result<()> {
    writeln!(out, "{heading}")?;
    writeln!(out, "  subject          : {:?}", report.subject)?;
    writeln!(out, "  id               : {}", terminal_text(&report.id))?;
    writeln!(out, "  removed paths    : {}", report.removed_paths.len())?;
    for path in &report.removed_paths {
        writeln!(out, "    - {}", terminal_text(path))?;
    }
    writeln!(
        out,
        "  mount cleanup    : clean={}",
        report.mount_cleanup.all_clean
    )?;
    for residual in &report.mount_cleanup.residual {
        writeln!(out, "    residual: {}", terminal_text(residual))?;
    }
    Ok(())
}

fn render_status<W: Write>(out: &mut W, report: &RecoveryStatusReport) -> std::io::Result<()> {
    writeln!(out, "Recovery status")?;
    writeln!(
        out,
        "  transaction id   : {}",
        terminal_text(&report.transaction_id)
    )?;
    writeln!(out, "  reconciled state : {:?}", report.reconciled_state)?;
    writeln!(out, "  recommendation   : {:?}", report.recommendation)?;
    if let Some(cleanup) = &report.mount_cleanup {
        writeln!(out, "  mount cleanup    : clean={}", cleanup.all_clean)?;
        for residual in &cleanup.residual {
            writeln!(out, "    residual: {}", terminal_text(residual))?;
        }
    }
    if let Some(token) = &report.revert_confirmation_token {
        writeln!(out, "  revert confirm   : {}", terminal_text(token))?;
    }
    if let Some(token) = &report.purge_confirmation_token {
        writeln!(out, "  purge confirm    : {}", terminal_text(token))?;
    }
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
        report
            .disk_facts
            .active_root
            .as_ref()
            .and_then(|f| f.generation)
    )?;
    render_warnings(out, &report.warnings)
}

fn render_error<W: Write>(out: &mut W, error: &SnapshotError) -> std::io::Result<()> {
    writeln!(out, "Recovery error")?;
    writeln!(out, "  kind             : {}", error.kind.code())?;
    writeln!(
        out,
        "  message          : {}",
        terminal_text(&error.message)
    )?;
    if let Some(transaction_id) = &error.transaction_id {
        writeln!(
            out,
            "  transaction id   : {}",
            terminal_text(transaction_id)
        )?;
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
    warnings: &[crate::target::model::Warning],
) -> std::io::Result<()> {
    if warnings.is_empty() {
        return Ok(());
    }
    writeln!(out, "Warnings")?;
    for w in warnings {
        writeln!(
            out,
            "  [{}] {}",
            terminal_text(&w.code),
            terminal_text(&w.message)
        )?;
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
    use crate::boot::model::BootLayout;
    use crate::recovery::model::{RecoveryRecommendation, RecoveryStatusReport};
    use crate::snapshot::model::{
        BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CatosIdentity, CompletedStep, DiskFacts,
        FstabRootDefinition, SubvolumeFacts, TransactionState, RECOVERY_PLAN_SCHEMA_VERSION,
        TX_RECORD_SCHEMA_VERSION,
    };
    use std::path::PathBuf;

    fn sample_plan() -> RecoveryPlan {
        RecoveryPlan {
            schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
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
                uuid: None,
                parent_uuid: None,
                read_only: false,
                evidence: vec![],
            },
            source_snapshot: BtrfsSubvolumeIdentity {
                path: "/@snapshots/1".into(),
                subvolume_id: 300,
                generation: 80,
                uuid: None,
                parent_uuid: None,
                read_only: true,
                evidence: vec![],
            },
            target_catos_identity: Some(CatosIdentity::default()),
            boot_layout: BootLayout::default(),
            boot_consistency: crate::boot::diagnose::layout::evaluate_readonly_consistency(
                &BootLayout::default(),
            ),
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
            nonce: "00".repeat(32),
            plan_digest: "00".repeat(32),
            confirmation_token: "v1:tx-1:abc".into(),
            evidence: vec![],
        }
    }

    fn sample_plan_report() -> RecoveryPlanReport {
        RecoveryPlanReport {
            plan: sample_plan(),
            plan_path: "/.catos-recovery/transactions/tx-1/plan.json".into(),
            mount_cleanup: crate::snapshot::model::CleanupSummary {
                all_clean: true,
                ..Default::default()
            },
        }
    }

    #[test]
    fn json_plan_envelope_carries_schema_and_kind() {
        let outcome = RecoveryOutcome::Plan(sample_plan_report());
        let j = render_recovery_json(&outcome, "catos-system", std::path::Path::new("/")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["schemaVersion"], 2);
        assert_eq!(v["kind"], "recovery_plan");
        assert_eq!(v["payload"]["plan_id"], "tx-1");
        assert_eq!(v["payload"]["schema_version"], 4);
        assert_eq!(v["payload"]["boot_consistency"]["status"], "unknown");
        assert_eq!(v["payload"]["confirmation_token"], "v1:tx-1:abc");
        assert_eq!(
            v["payload"]["plan_path"],
            "/.catos-recovery/transactions/tx-1/plan.json"
        );
    }

    #[test]
    fn json_error_envelope_carries_structured_fields() {
        let error = SnapshotError::new(
            crate::snapshot::model::SnapshotErrorKind::StalePlan,
            "fsid drifted",
        );
        let outcome = RecoveryOutcome::Error(Box::new(error));
        let j = render_recovery_json(&outcome, "catos-system", std::path::Path::new("/")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["kind"], "error");
        assert_eq!(v["payload"]["kind"], "stale_plan");
        assert_eq!(v["payload"]["message"], "fsid drifted");
    }

    #[test]
    fn human_plan_output_has_no_ansi_escapes() {
        let outcome = RecoveryOutcome::Plan(sample_plan_report());
        let mut buf = Vec::new();
        render_recovery_human(&outcome, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains('\u{001b}'));
        assert!(s.contains("Recovery plan"));
        assert!(s.contains("tx-1"));
        assert!(s.contains("boot consistency"));
        assert!(s.contains("Unknown"));
    }

    #[test]
    fn human_renderers_escape_untrusted_terminal_text() {
        let mut plan = sample_plan();
        plan.source_snapshot.path = "/@snapshots/1\nspoof\u{1b}[2J".into();
        plan.risks_and_warnings = vec!["review\rstate\u{202e}txt".into()];
        let mut output = Vec::new();
        render_recovery_human(
            &RecoveryOutcome::Plan(RecoveryPlanReport {
                plan,
                plan_path: "/.catos-recovery/transactions/tx-1/plan.json".into(),
                mount_cleanup: crate::snapshot::model::CleanupSummary {
                    all_clean: true,
                    ..Default::default()
                },
            }),
            &mut output,
        )
        .unwrap();

        let mut error = SnapshotError::new(
            crate::snapshot::model::SnapshotErrorKind::StateRecordCorrupt,
            "bad record\nspoof\u{1b}[2J",
        );
        error.transaction_id = Some("tx\tspoof".into());
        render_error(&mut output, &error).unwrap();
        render_warnings(
            &mut output,
            &[crate::target::model::Warning::new(
                "WARN\u{1b}",
                "warning\nspoof\u{2066}",
            )],
        )
        .unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\u{2066}'));
        assert!(rendered.contains("/@snapshots/1\\nspoof\\u{1b}[2J"));
        assert!(rendered.contains("review\\rstate\\u{202e}txt"));
        assert!(rendered.contains("bad record\\nspoof\\u{1b}[2J"));
        assert!(rendered.contains("tx\\tspoof"));
        assert!(rendered.contains("[WARN\\u{1b}] warning\\nspoof\\u{2066}"));
    }

    #[test]
    fn json_preserves_untrusted_values_for_machine_consumers() {
        let mut plan = sample_plan();
        let raw_path = "/@snapshots/1\nspoof\u{1b}[2J";
        let raw_risk = "review\rstate\u{202e}txt";
        plan.source_snapshot.path = raw_path.into();
        plan.risks_and_warnings = vec![raw_risk.into()];

        let json = render_recovery_json(
            &RecoveryOutcome::Plan(RecoveryPlanReport {
                plan,
                plan_path: "/.catos-recovery/transactions/tx-1/plan.json".into(),
                mount_cleanup: crate::snapshot::model::CleanupSummary {
                    all_clean: true,
                    ..Default::default()
                },
            }),
            "catos-system",
            std::path::Path::new("/"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["payload"]["source_snapshot"]["path"], raw_path);
        assert_eq!(value["payload"]["risks_and_warnings"][0], raw_risk);
    }

    #[test]
    fn status_envelope_carries_reconciled_state() {
        let plan = sample_plan();
        let record = TransactionRecord {
            schema_version: TX_RECORD_SCHEMA_VERSION,
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
                filesystem_fsid: "fsid-1".into(),
                active_root_exists: true,
                active_root: Some(SubvolumeFacts {
                    path: "/@".into(),
                    subvolume_id: Some(256),
                    generation: Some(100),
                    uuid: None,
                    parent_uuid: None,
                    read_only: Some(false),
                }),
                staging_root_exists: true,
                staging_root: None,
                backup_root_exists: true,
                backup: None,
                source_snapshot_exists: true,
                source_snapshot: None,
            }),
            last_cleanup: None,
            purge_progress: None,
        };
        let report = RecoveryStatusReport {
            transaction_id: "tx-1".into(),
            reconciled_state: TransactionState::Completed,
            record,
            disk_facts: DiskFacts {
                filesystem_fsid: "fsid-1".into(),
                active_root_exists: true,
                active_root: Some(SubvolumeFacts {
                    path: "/@".into(),
                    subvolume_id: Some(256),
                    generation: Some(100),
                    uuid: None,
                    parent_uuid: None,
                    read_only: Some(false),
                }),
                staging_root_exists: true,
                staging_root: None,
                backup_root_exists: true,
                backup: None,
                source_snapshot_exists: true,
                source_snapshot: None,
            },
            recommendation: RecoveryRecommendation::None,
            mount_cleanup: Some(crate::snapshot::model::CleanupSummary {
                unmounted: vec!["/run/catos-system/sessions/status/root".into()],
                residual: vec![],
                all_clean: true,
            }),
            revert_confirmation_token: Some("revert-v1:tx-1:abc".into()),
            purge_confirmation_token: Some("purge-v1:tx-1:def".into()),
            warnings: vec![],
        };
        let outcome = RecoveryOutcome::Status(Box::new(report));
        let j = render_recovery_json(&outcome, "catos-system", std::path::Path::new("/")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["kind"], "recovery_status");
        assert_eq!(v["payload"]["reconciled_state"], "completed");
        assert_eq!(
            v["payload"]["revert_confirmation_token"],
            "revert-v1:tx-1:abc"
        );
        assert_eq!(
            v["payload"]["purge_confirmation_token"],
            "purge-v1:tx-1:def"
        );
        let _ = PathBuf::new();
    }
}
