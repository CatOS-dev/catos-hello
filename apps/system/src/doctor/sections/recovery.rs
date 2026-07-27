//! Recovery transaction section: enumerate and assess in-flight
//! snapshot recovery transactions on the target.

use crate::doctor::model::{
    issue_code, recommendation_code, DoctorIssue, DoctorLimitation, DoctorRecommendation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::snapshot::model::TransactionRecord;
use crate::snapshot::store;
use crate::target::Evidence;

use super::{push_evidence, push_issue, set_section};
use crate::doctor::DoctorTargetContext;

#[derive(Debug, Clone)]
struct RecoveryRecordView {
    transaction_id: String,
    state: crate::snapshot::model::TransactionState,
    last_error: Option<crate::snapshot::model::SnapshotError>,
    last_cleanup: Option<crate::snapshot::model::CleanupSummary>,
}

impl RecoveryRecordView {
    fn from_record(record: &TransactionRecord) -> Self {
        Self {
            transaction_id: record.transaction_id.clone(),
            state: record.state,
            last_error: record.last_error.clone(),
            last_cleanup: record.last_cleanup.clone(),
        }
    }
}

pub(in crate::doctor) fn run_recovery_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    context: Option<&DoctorTargetContext>,
    options: Option<&crate::snapshot::execute::engine::EngineOptions>,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Recovery;
    let Some(context) = context else {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(
            id,
            "TARGET_CONTEXT_UNAVAILABLE",
            "Recovery requires the selected readonly Doctor target context",
        ));
        return Ok(());
    };
    run_recovery_for_target(sections, &context.target, options, report)
}

fn run_recovery_for_target(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &crate::target::model::TargetIdentity,
    options: Option<&crate::snapshot::execute::engine::EngineOptions>,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Recovery;
    if target.root_fstype.as_deref() != Some("btrfs") {
        set_section(sections, id, DoctorSectionStatus::NotApplicable);
        report.limitations.push(DoctorLimitation::new(
            id,
            "RECOVERY_NOT_APPLICABLE",
            "snapshot recovery is applicable only to Btrfs roots",
        ));
        return Ok(());
    }
    let transaction_dir = target.root.join(".catos-recovery/transactions");
    let (records, errors) = store::list_records(&transaction_dir);
    if !errors.is_empty() {
        let section = set_section(sections, id, DoctorSectionStatus::Unknown);
        for error in errors {
            let message = format!("cannot inspect recovery transactions at {}: {error}", transaction_dir.display());
            report.limitations.push(DoctorLimitation::new(id, "RECOVERY_INSPECT_FAILED", message.clone()));
            section.issues.push(DoctorIssue::new(
                "RECOVERY_RECORD_UNREADABLE",
                DoctorSeverity::Warning,
                id,
                message,
            ));
        }
        return Ok(());
    }
    let Some(options) = options else {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(id, "RECOVERY_FACTS_INCOMPLETE", "validated readonly Btrfs top-level facts are unavailable"));
        return Ok(());
    };
    if records.is_empty() {
            set_section(sections, id, DoctorSectionStatus::Healthy);
            push_evidence(
                sections,
                id,
                Evidence::new(
                    "RECOVERY_RECORDS",
                    "doctor::recovery",
                    "no in-flight recovery transactions on target",
                ),
            );
            return Ok(());
    }

    let mut section_status = DoctorSectionStatus::Healthy;
    for (_, record) in &records {
        let reconciled = load_and_reconcile_record(&record.transaction_id, || {
            let mut engine = crate::snapshot::execute::engine::Engine::load(options.clone(), &record.transaction_id)
                .map_err(|error| error.to_string())?;
            engine.reconcile_status();
            Ok(RecoveryRecordView::from_record(engine.record()))
        });
        let reconciled = match reconciled {
            Ok(record) => record,
            Err(error) => {
                section_status = DoctorSectionStatus::Unknown;
                report.limitations.push(DoctorLimitation::new(id, "RECOVERY_RECONCILE_FAILED", format!("cannot load {} read-only: {error}", record.transaction_id)));
                push_issue(sections, DoctorIssue::new("RECOVERY_RECONCILE_FAILED", DoctorSeverity::Warning, id, format!("transaction {} could not be read-only reconciled", record.transaction_id)));
                continue;
            }
        };
        inspect_single_record(sections, report, id, &reconciled, &mut section_status);
    }
    set_section(sections, id, section_status);
    Ok(())
}

fn load_and_reconcile_record<F>(transaction_id: &str, load: F) -> Result<RecoveryRecordView, String>
where
    F: FnOnce() -> Result<RecoveryRecordView, String>,
{
    let record = load()?;
    if record.transaction_id != transaction_id {
        return Err(format!("reconciled record id {} does not match requested {transaction_id}", record.transaction_id));
    }
    Ok(record)
}

fn inspect_single_record(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    report: &mut DoctorReport,
    id: DoctorSectionId,
    record: &RecoveryRecordView,
    section_status: &mut DoctorSectionStatus,
) {
    push_evidence(
        sections,
        id,
        Evidence::new(
            "RECOVERY_RECORD",
            "doctor::recovery",
            format!(
                "transaction {} state={} last_error={:?}",
                record.transaction_id,
                record.state.code(),
                record.last_error.as_ref().map(|e| e.kind.code())
            ),
        ),
    );
    if record.state.is_terminal() {
        if matches!(
            record.state,
            crate::snapshot::model::TransactionState::Completed
                | crate::snapshot::model::TransactionState::Reverted
        ) {
            if matches!(
                record.state,
                crate::snapshot::model::TransactionState::Completed
            ) {
                if let Some(cleanup) = record.last_cleanup.as_ref() {
                    if !cleanup.residual.is_empty() {
                        *section_status = worse_of(*section_status, DoctorSectionStatus::Degraded);
                        push_issue(
                            sections,
                            DoctorIssue::new(
                                issue_code::RECOVERY_CLEANUP_RESIDUAL,
                                DoctorSeverity::Warning,
                                id,
                                format!(
                                    "transaction {} completed but left cleanup residuals",
                                    record.transaction_id
                                ),
                            ),
                        );
                    }
                }
                push_issue(
                    sections,
                    DoctorIssue::new(
                        issue_code::RECOVERY_BACKUP_PRESENT,
                        DoctorSeverity::Info,
                        id,
                        format!(
                            "transaction {} retains a recovery backup (post-success retention is normal)",
                            record.transaction_id
                        ),
                    ),
                );
            }
        } else {
            *section_status = worse_of(*section_status, DoctorSectionStatus::Critical);
            push_issue(
                sections,
                DoctorIssue::new(
                    issue_code::RECOVERY_RECORD_DRIFT,
                    DoctorSeverity::Critical,
                    id,
                    format!(
                        "transaction {} reached terminal state {}",
                        record.transaction_id,
                        record.state.code()
                    ),
                )
                .with_recommendation(recommendation_code::MANUAL_REVIEW),
            );
        }
    } else {
        *section_status = worse_of(*section_status, DoctorSectionStatus::Unhealthy);
        push_issue(
            sections,
            DoctorIssue::new(
                issue_code::RECOVERY_TRANSACTION_INTERRUPTED,
                DoctorSeverity::Error,
                id,
                format!(
                    "transaction {} is in non-terminal state {}",
                    record.transaction_id,
                    record.state.code()
                ),
            )
            .with_recommendation(recommendation_code::RUN_CATOS_RECOVERY_RESUME),
        );
        report.recommendations.push(DoctorRecommendation::new(
            recommendation_code::RUN_CATOS_RECOVERY_RESUME,
            format!(
                "transaction {} is interrupted; catos-recovery resume or revert can complete it",
                record.transaction_id
            ),
        ));
    }
}

fn worse_of(current: DoctorSectionStatus, candidate: DoctorSectionStatus) -> DoctorSectionStatus {
    use DoctorSectionStatus::*;
    fn rank(s: DoctorSectionStatus) -> u8 {
        match s {
            Healthy => 0,
            NotApplicable | Skipped => 1,
            Degraded => 2,
            Unknown => 3,
            Unhealthy => 4,
            Critical => 5,
        }
    }
    if rank(candidate) > rank(current) {
        candidate
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::model::TargetIdentity;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn corrupt_transaction_is_reported_not_silently_skipped() {
        let root = std::env::temp_dir().join(format!(
            "catos-doctor-recovery-test-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let transaction = root.join(".catos-recovery/transactions/tx-00000000000000000000000000000000");
        std::fs::create_dir_all(&transaction).unwrap();
        std::fs::write(transaction.join("state.json"), b"not json").unwrap();

        let target = TargetIdentity {
            root: root.clone(),
            root_fstype: Some("btrfs".to_string()),
            root_device: Some(PathBuf::from("/dev/fixture")),
            ..TargetIdentity::default()
        };
        let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
            .iter()
            .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
            .collect();
        let mut report = DoctorReport::default();

        run_recovery_for_target(&mut sections, &target, None, &mut report).unwrap();

        let recovery = sections.iter().find(|(id, _)| *id == DoctorSectionId::Recovery).unwrap();
        assert_eq!(recovery.1.status, DoctorSectionStatus::Unknown);
        assert!(recovery.1.issues.iter().any(|issue| issue.code == "RECOVERY_RECORD_UNREADABLE"));
        assert!(report.limitations.iter().any(|limitation| limitation.code == "RECOVERY_INSPECT_FAILED"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reporting_consumes_reconciled_terminal_record_not_persisted_nonterminal_record() {
        use std::cell::Cell;
        let loads = Cell::new(0);
        let writes = Cell::new(0);
        let persisted = RecoveryRecordView {
            transaction_id: "tx-reconcile".into(),
            state: crate::snapshot::model::TransactionState::Locked,
            last_error: None,
            last_cleanup: None,
        };
        let reconciled = load_and_reconcile_record("tx-reconcile", || {
            loads.set(loads.get() + 1);
            assert!(!persisted.state.is_terminal());
            Ok(RecoveryRecordView {
                state: crate::snapshot::model::TransactionState::Completed,
                ..persisted.clone()
            })
        })
        .expect("reconcile fake must return a record");
        let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
            .iter()
            .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
            .collect();
        let mut report = DoctorReport::default();
        let mut status = DoctorSectionStatus::Healthy;
        inspect_single_record(
            &mut sections,
            &mut report,
            DoctorSectionId::Recovery,
            &reconciled,
            &mut status,
        );

        assert_eq!(loads.get(), 1);
        assert_eq!(writes.get(), 0);
        let recovery = sections.iter().find(|(id, _)| *id == DoctorSectionId::Recovery).unwrap();
        assert!(!recovery.1.issues.iter().any(|issue| issue.code == issue_code::RECOVERY_TRANSACTION_INTERRUPTED));
        assert!(recovery.1.issues.iter().any(|issue| issue.code == issue_code::RECOVERY_BACKUP_PRESENT));
    }
}
