//! Recovery transaction section: enumerate and assess in-flight
//! snapshot recovery transactions on the target.

use crate::doctor::model::{
    issue_code, recommendation_code, DoctorIssue, DoctorLimitation, DoctorRecommendation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::snapshot::model::TransactionRecord;
use crate::snapshot::store;
use crate::target::model::TargetIdentity;
use crate::target::Evidence;

use super::{push_evidence, push_issue, set_section};

pub(in crate::doctor) fn run_recovery_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
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
        inspect_single_record(sections, report, id, record, &mut section_status);
    }
    set_section(sections, id, section_status);
    Ok(())
}

fn inspect_single_record(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    report: &mut DoctorReport,
    id: DoctorSectionId,
    record: &TransactionRecord,
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
