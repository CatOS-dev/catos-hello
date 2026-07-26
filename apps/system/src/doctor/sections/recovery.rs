//! Recovery transaction section: enumerate and assess in-flight
//! snapshot recovery transactions on the target.

use std::path::{Path, PathBuf};

use crate::shared::model::doctor::{
    issue_code, recommendation_code, DoctorIssue, DoctorLimitation, DoctorRecommendation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount_repair::TargetIdentity;
use crate::shared::model::recovery::TransactionRecord;
use crate::shared::snapshot_engine::store;

use super::{push_evidence, push_issue, set_section};

pub(in crate::doctor) fn run_recovery_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Recovery;
    if target.root_fstype != "btrfs" {
        set_section(sections, id, DoctorSectionStatus::NotApplicable);
        report.limitations.push(DoctorLimitation::new(
            id,
            "RECOVERY_NOT_APPLICABLE",
            "snapshot recovery is applicable only to Btrfs roots",
        ));
        return Ok(());
    }
    let device = match target.root_device.to_str() {
        Some(s) => s.to_string(),
        None => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            return Ok(());
        }
    };

    let records = match enumerate_recovery_records(&device) {
        Ok(records) if records.is_empty() => {
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
        Ok(records) => records,
        Err(message) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(
                id,
                "RECOVERY_INSPECT_FAILED",
                format!("could not enumerate recovery records: {message}"),
            ));
            return Ok(());
        }
    };

    let mut section_status = DoctorSectionStatus::Healthy;
    for record in &records {
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
            crate::shared::model::recovery::TransactionState::Completed
                | crate::shared::model::recovery::TransactionState::Reverted
        ) {
            if matches!(
                record.state,
                crate::shared::model::recovery::TransactionState::Completed
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

fn enumerate_recovery_records(device: &str) -> Result<Vec<TransactionRecord>, String> {
    let mount_session = mount_btrfs_top_level_ro(device)?;
    let top_level = match mount_session {
        Some(path) => path,
        None => return Ok(Vec::new()),
    };

    let state_dir = top_level.join(".catos-recovery");
    let names = match std::fs::read_dir(&state_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".state.json"))
            .collect::<Vec<_>>(),
        Err(_) => return Ok(Vec::new()),
    };

    let mut records = Vec::new();
    for name in names {
        let path = state_dir.join(&name);
        match store::load_record(&path) {
            Ok(record) => records.push(record),
            Err(_) => continue,
        }
    }
    Ok(records)
}

fn mount_btrfs_top_level_ro(device: &str) -> Result<Option<PathBuf>, String> {
    use crate::shared::mount::namespace::establish_private_namespace;
    use crate::shared::mount::secure_dir::{create_session_dir, SESSION_ROOT_PARENT};
    use crate::shared::mount::syscall::{self, ms_flags};

    if establish_private_namespace().is_err() {
        return Ok(None);
    }
    let session_dir = create_session_dir(Path::new(SESSION_ROOT_PARENT), "doctor-recovery-ro")
        .map_err(|e| format!("cannot create session dir: {e}"))?;
    let mount_root = session_dir.join("top");
    std::fs::create_dir(&mount_root).map_err(|e| format!("cannot mkdir: {e}"))?;
    let result = syscall::mount(
        Some(device),
        &mount_root,
        Some("btrfs"),
        ms_flags::MS_RDONLY | ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
        Some("subvolid=0,ro"),
    );
    if let Err(e) = result {
        let _ = syscall::umount2(&mount_root, 0);
        let _ = crate::shared::mount::secure_dir::remove_session_dir(
            Path::new(SESSION_ROOT_PARENT),
            &session_dir,
        );
        return Err(format!("cannot mount btrfs top-level RO: {e}"));
    }
    Ok(Some(mount_root))
}
