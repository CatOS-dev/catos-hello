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
    let Some(options) = options else {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(
            id,
            "RECOVERY_FACTS_INCOMPLETE",
            "validated readonly Btrfs top-level facts are unavailable",
        ));
        return Ok(());
    };
    let transaction_dir = options.top_level_mount.join(".catos-recovery/transactions");
    let (records, errors) = store::list_records(&transaction_dir);
    if !errors.is_empty() {
        let section = set_section(sections, id, DoctorSectionStatus::Unknown);
        for error in errors {
            let message = format!(
                "cannot inspect recovery transactions at {}: {error}",
                transaction_dir.display()
            );
            report.limitations.push(DoctorLimitation::new(
                id,
                "RECOVERY_INSPECT_FAILED",
                message.clone(),
            ));
            section.issues.push(DoctorIssue::new(
                "RECOVERY_RECORD_UNREADABLE",
                DoctorSeverity::Warning,
                id,
                message,
            ));
        }
        return Ok(());
    }
    let record_ids = records
        .into_iter()
        .map(|(_, record)| record.transaction_id)
        .collect::<Vec<_>>();
    run_recovery_for_target_with(
        sections,
        report,
        || Ok(record_ids),
        |transaction_id| {
            let mut engine =
                crate::snapshot::execute::engine::Engine::load(options.clone(), transaction_id)
                    .map_err(|error| error.to_string())?;
            engine.reconcile_status();
            Ok(RecoveryRecordView::from_record(engine.record()))
        },
    )
}

fn run_recovery_for_target_with<L, R>(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    report: &mut DoctorReport,
    list_records: L,
    mut load_reconcile_read: R,
) -> Result<(), ()>
where
    L: FnOnce() -> Result<Vec<String>, String>,
    R: FnMut(&str) -> Result<RecoveryRecordView, String>,
{
    let id = DoctorSectionId::Recovery;
    let records = match list_records() {
        Ok(records) => records,
        Err(error) => {
            let section = set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(
                id,
                "RECOVERY_INSPECT_FAILED",
                error.clone(),
            ));
            section.issues.push(DoctorIssue::new(
                "RECOVERY_RECORD_UNREADABLE",
                DoctorSeverity::Warning,
                id,
                error,
            ));
            return Ok(());
        }
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
    for transaction_id in &records {
        let reconciled =
            load_and_reconcile_record(transaction_id, || load_reconcile_read(transaction_id));
        let reconciled = match reconciled {
            Ok(record) => record,
            Err(error) => {
                section_status = DoctorSectionStatus::Unknown;
                report.limitations.push(DoctorLimitation::new(
                    id,
                    "RECOVERY_RECONCILE_FAILED",
                    format!("cannot load {transaction_id} read-only: {error}"),
                ));
                push_issue(
                    sections,
                    DoctorIssue::new(
                        "RECOVERY_RECONCILE_FAILED",
                        DoctorSeverity::Warning,
                        id,
                        format!("transaction {transaction_id} could not be read-only reconciled"),
                    ),
                );
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
        return Err(format!(
            "reconciled record id {} does not match requested {transaction_id}",
            record.transaction_id
        ));
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
        let recommendation = DoctorRecommendation::new(
            recommendation_code::RUN_CATOS_RECOVERY_RESUME,
            format!(
                "transaction {} is interrupted; resume or revert can complete it",
                record.transaction_id
            ),
        );
        let recommendation = match report.target.root_device.as_deref() {
            Some(root_device) => {
                let mut command = format!(
                    "catos-recovery resume --root-device {root_device}"
                );
                if let Some(subvolume) = report.target.root_subvolume.as_deref() {
                    command.push_str(" --root-subvolume ");
                    command.push_str(subvolume);
                }
                command.push_str(" --transaction ");
                command.push_str(&record.transaction_id);
                recommendation.with_command(command)
            }
            None => recommendation,
        };
        report.recommendations.push(recommendation);
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
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let transaction =
            root.join(".catos-recovery/transactions/tx-00000000000000000000000000000000");
        std::fs::create_dir_all(&transaction).unwrap();
        std::fs::write(transaction.join("state.json"), b"not json").unwrap();
        let selected_root = root.join("@");
        std::fs::create_dir_all(&selected_root).unwrap();

        let target = TargetIdentity {
            root: selected_root,
            root_fstype: Some("btrfs".to_string()),
            root_device: Some(PathBuf::from("/dev/fixture")),
            ..TargetIdentity::default()
        };
        let options = crate::snapshot::execute::engine::EngineOptions {
            top_level_mount: root.clone(),
            device_path: PathBuf::from("/dev/fixture"),
            validated_filesystem: crate::snapshot::model::BtrfsFilesystemIdentity {
                fsid: "fixture-fsid".into(),
                device_major_minor: "0:0".into(),
                label: None,
            },
        };
        let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
            .iter()
            .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
            .collect();
        let mut report = DoctorReport::default();

        run_recovery_for_target(&mut sections, &target, Some(&options), &mut report).unwrap();

        let recovery = sections
            .iter()
            .find(|(id, _)| *id == DoctorSectionId::Recovery)
            .unwrap();
        assert_eq!(recovery.1.status, DoctorSectionStatus::Unknown);
        assert!(recovery
            .1
            .issues
            .iter()
            .any(|issue| issue.code == "RECOVERY_RECORD_UNREADABLE"));
        assert!(report
            .limitations
            .iter()
            .any(|limitation| limitation.code == "RECOVERY_INSPECT_FAILED"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_transaction_recommendation_contains_resume_command() {
        let record = RecoveryRecordView {
            transaction_id: "tx-00000000000000000000000000000004".into(),
            state: crate::snapshot::model::TransactionState::Locked,
            last_error: None,
            last_cleanup: None,
        };
        let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
            .iter()
            .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
            .collect();
        let mut report = DoctorReport::default();
        report.target.root_device = Some("/dev/vda".into());
        report.target.root_subvolume = Some("/@root".into());
        let mut status = DoctorSectionStatus::Healthy;

        inspect_single_record(
            &mut sections,
            &mut report,
            DoctorSectionId::Recovery,
            &record,
            &mut status,
        );

        assert_eq!(report.recommendations.len(), 1);
        assert_eq!(
            report.recommendations[0].command.as_deref(),
            Some(
                "catos-recovery resume --root-device /dev/vda --root-subvolume /@root --transaction tx-00000000000000000000000000000004"
            )
        );
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
        let recovery = sections
            .iter()
            .find(|(id, _)| *id == DoctorSectionId::Recovery)
            .unwrap();
        assert!(!recovery
            .1
            .issues
            .iter()
            .any(|issue| issue.code == issue_code::RECOVERY_TRANSACTION_INTERRUPTED));
        assert!(recovery
            .1
            .issues
            .iter()
            .any(|issue| issue.code == issue_code::RECOVERY_BACKUP_PRESENT));
    }

    #[test]
    fn full_recovery_adapter_consumes_strict_readonly_fake_pipeline() {
        use std::cell::RefCell;

        struct StrictFake {
            calls: RefCell<Vec<&'static str>>,
            persisted: RecoveryRecordView,
            reconciled: RecoveryRecordView,
        }
        impl StrictFake {
            fn list(&self) -> Result<Vec<String>, String> {
                self.calls.borrow_mut().push("list");
                Ok(vec![self.persisted.transaction_id.clone()])
            }
            fn load_reconcile_read(&self, id: &str) -> Result<RecoveryRecordView, String> {
                assert_eq!(id, self.persisted.transaction_id);
                self.calls
                    .borrow_mut()
                    .extend(["load", "reconcile", "record"]);
                Ok(self.reconciled.clone())
            }
        }

        let fake = StrictFake {
            calls: RefCell::new(Vec::new()),
            persisted: RecoveryRecordView {
                transaction_id: "tx-strict".into(),
                state: crate::snapshot::model::TransactionState::Locked,
                last_error: None,
                last_cleanup: None,
            },
            reconciled: RecoveryRecordView {
                transaction_id: "tx-strict".into(),
                state: crate::snapshot::model::TransactionState::Completed,
                last_error: None,
                last_cleanup: Some(crate::snapshot::model::CleanupSummary::default()),
            },
        };
        let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
            .iter()
            .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
            .collect();
        let mut report = DoctorReport::default();
        run_recovery_for_target_with(
            &mut sections,
            &mut report,
            || fake.list(),
            |id| fake.load_reconcile_read(id),
        )
        .unwrap();

        assert_eq!(
            *fake.calls.borrow(),
            vec!["list", "load", "reconcile", "record"]
        );
        let recovery = sections
            .iter()
            .find(|(id, _)| *id == DoctorSectionId::Recovery)
            .unwrap();
        assert_eq!(recovery.1.status, DoctorSectionStatus::Healthy);
        assert!(!recovery
            .1
            .issues
            .iter()
            .any(|issue| issue.code == issue_code::RECOVERY_TRANSACTION_INTERRUPTED));
        assert!(recovery
            .1
            .issues
            .iter()
            .any(|issue| issue.code == issue_code::RECOVERY_BACKUP_PRESENT));
    }

    #[test]
    fn unconfigured_recovery_engine_fake_fails_explicitly() {
        let configured = false;
        let result = load_and_reconcile_record("tx-unconfigured", || {
            if !configured {
                return Err("fake recovery engine call was not configured".to_string());
            }
            unreachable!("the strict fake must fail before returning a record");
        });

        assert!(matches!(result, Err(message) if message.contains("not configured")));
    }
}
