//! `catos-doctor` orchestrator. Read-only aggregated diagnosis that
//! stitches together the existing pure diagnosis surfaces from
//! stages 1–4:
//!
//! * environment / target discovery: phase 1 (`entry::build_report`,
//!   phase2 storage scan)
//! * filesystem: stage 2 (`fs::diagnose::check_only_for`)
//! * mount layout / fstab: stage 3 (`repair::mount_repair::diagnose`)
//! * boot provider: stage 4 (`boot::diagnose::provider::detect`)
//! * recovery: stage 4 (`recovery::engine::Engine::load` +
//!   `reconcile_status`, both read-only)
//!
//! ## Hard rules
//!
//! * Doctor NEVER writes to the target. The only resources it may
//!   clean up are mounts it created itself inside its private mount
//!   namespace. See [`DoctorCleanup`].
//! * Target selection does not route through `repair`; Doctor resolves
//!   the target via `target::plan` only. Section-level diagnosis still
//!   consumes repair flows (`check_only_for`, `mount_repair::diagnose`,
//!   `boot::diagnose::provider`) in read-only mode pending later phases that
//!   will move those surfaces under the `target` capability.
//! * Doctor NEVER invokes the boot provider's `execute` or `verify`
//!   methods; it only consults the pure `detect()` function and
//!   reads deployed asset files directly.
//! * Doctor NEVER calls `Engine::load_for_write`,
//!   `Engine::load_for_revert`, `Engine::begin`, `Engine::drive`, or
//!   `Engine::revert`. Only the non-locking `Engine::load` +
//!   `reconcile_status` pair is used.
//! * Exit-code scheme B: `overall_status` and the process exit code
//!   are independent. Doctor returns 0 whenever it produced a report,
//!   even if every section found a problem.

pub mod model;
mod sections;

use crate::doctor::model::{
    issue_code, recommendation_code, DoctorCleanup, DoctorEnvironment, DoctorIssue,
    DoctorOverallStatus, DoctorRecommendation, DoctorReport, DoctorSection, DoctorSectionId,
    DoctorSectionStatus, DoctorSeverity,
};
use crate::fs::command::FsCommandRunner;
use crate::target::Evidence;

pub mod target_selection;
use target_selection::TargetSelection;

pub fn run_doctor() -> DoctorReport {
    let runner = crate::fs::command::TrustedRunner::new();
    let environment = sections::capture_environment();
    let (target, session) = match target_selection::discover_target_session() {
        Ok(value) => value,
        Err(reason) => {
            let mut report = DoctorReport::default();
            report.environment = environment;
            report.sections = handle_no_target(reason, &mut report);
            aggregate(&mut report);
            report.cleanup = DoctorCleanup::clean();
            return report;
        }
    };
    let mut report = DoctorReport::default();
    report.environment = environment.clone();
    report.target = TargetSelection::Identified(target.clone()).to_target_summary();
    report.sections = run_sections(&runner, &target, &environment, &mut report);
    aggregate(&mut report);
    let cleanup = session.cleanup();
    report.cleanup = DoctorCleanup {
        cleaned: if cleanup.unmounted && cleanup.removed { vec![cleanup.mountpoint.display().to_string()] } else { Vec::new() },
        residual: cleanup.error.into_iter().map(|error| format!("{}: {error}", cleanup.mountpoint.display())).collect(),
        all_clean: cleanup.unmounted && cleanup.removed,
    };
    report
}

pub fn run_doctor_with<R: FsCommandRunner + ?Sized>(runner: &R) -> DoctorReport {
    let mut report = DoctorReport::default();

    let environment = sections::capture_environment();
    report.environment = environment.clone();

    let selection = target_selection::discover_target();
    report.target = selection.to_target_summary();

    let sections = match selection {
        TargetSelection::None { reason } => handle_no_target(reason, &mut report),
        TargetSelection::Ambiguous { candidates } => {
            handle_ambiguous_target(candidates, &mut report)
        }
        TargetSelection::Identified(target) => {
            run_sections(runner, &target, &environment, &mut report)
        }
    };

    report.sections = sections;
    aggregate(&mut report);
    report.cleanup = DoctorCleanup::clean();
    report
}

fn run_sections<R: FsCommandRunner + ?Sized>(
    runner: &R,
    target: &crate::target::model::TargetIdentity,
    env: &DoctorEnvironment,
    report: &mut DoctorReport,
) -> Vec<DoctorSection> {
    let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();

    let _ = sections::run_environment_section(&mut sections, env);
    let _ = sections::run_storage_section(&mut sections, target, report);
    let _ = sections::run_filesystem_section(runner, &mut sections, target, report);
    let _ = sections::run_mount_section(&mut sections, target, report);
    let _ = sections::run_boot_section(&mut sections, target, report);
    let _ = sections::run_secure_boot_section(&mut sections, target, report);
    let _ = sections::run_recovery_section(&mut sections, target, report);

    sections.into_iter().map(|(_, s)| s).collect()
}

fn handle_no_target(reason: String, report: &mut DoctorReport) -> Vec<DoctorSection> {
    let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();
    let section = sections::set_section(
        &mut sections,
        DoctorSectionId::Environment,
        DoctorSectionStatus::Healthy,
    );
    section.evidence.push(Evidence::new(
        "TARGET_SELECTION",
        "doctor::target_selection",
        format!("target_not_found: {reason}"),
    ));
    sections::push_issue(
        &mut sections,
        DoctorIssue::new(
            issue_code::TARGET_NOT_FOUND,
            DoctorSeverity::Warning,
            DoctorSectionId::Storage,
            format!("no CatOS target identified: {reason}"),
        )
        .with_recommendation(recommendation_code::BOOT_LIVE_ENVIRONMENT),
    );
    report.recommendations.push(DoctorRecommendation::new(
        recommendation_code::BOOT_LIVE_ENVIRONMENT,
        "no CatOS target was identified; boot a CatOS Live environment or specify the target explicitly",
    ));
    sections.into_iter().map(|(_, s)| s).collect()
}

fn handle_ambiguous_target(
    candidates: Vec<String>,
    report: &mut DoctorReport,
) -> Vec<DoctorSection> {
    let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();
    let section = sections::set_section(
        &mut sections,
        DoctorSectionId::Environment,
        DoctorSectionStatus::Healthy,
    );
    section.evidence.push(Evidence::new(
        "TARGET_SELECTION",
        "doctor::target_selection",
        format!("ambiguous_target: candidates={}", candidates.join(",")),
    ));
    sections::push_issue(
        &mut sections,
        DoctorIssue::new(
            issue_code::TARGET_AMBIGUOUS,
            DoctorSeverity::Warning,
            DoctorSectionId::Storage,
            format!(
                "multiple CatOS targets identified: {}",
                candidates.join(", ")
            ),
        )
        .with_recommendation(recommendation_code::MANUAL_REVIEW),
    );
    report.recommendations.push(DoctorRecommendation::new(
        recommendation_code::MANUAL_REVIEW,
        "multiple CatOS targets were identified; resolve ambiguity before any repair",
    ));
    sections.into_iter().map(|(_, s)| s).collect()
}

fn aggregate(report: &mut DoctorReport) {
    let mut overall = DoctorOverallStatus::Healthy;
    let mut complete = true;
    let mut all_issues: Vec<DoctorIssue> = Vec::new();

    for section in &report.sections {
        if let Some(contribution) = section.status.to_overall_contribution() {
            overall = overall.combine(contribution);
        }
        if matches!(
            section.status,
            DoctorSectionStatus::Skipped | DoctorSectionStatus::Unknown
        ) {
            complete = false;
        }
        all_issues.extend(section.issues.iter().cloned());
    }

    if !report.limitations.is_empty() && overall == DoctorOverallStatus::Healthy {
        overall = DoctorOverallStatus::Degraded;
    }

    all_issues.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.section.as_str().cmp(b.section.as_str()))
            .then_with(|| a.code.cmp(&b.code))
    });
    all_issues
        .dedup_by(|a, b| a.code == b.code && a.section == b.section && a.message == b.message);

    report.overall_status = overall;
    report.complete = complete;
    report.issues = all_issues;

    report.evidence.push(Evidence::new(
        "DOCTOR_AGGREGATE",
        "doctor::aggregate",
        format!(
            "overall={} complete={} issues={} limitations={}",
            report.overall_status.as_str(),
            report.complete,
            report.issues.len(),
            report.limitations.len()
        ),
    ));
}

impl DoctorReport {
    pub fn doctor_failed(&self) -> bool {
        !self.cleanup.all_clean
    }
}

/// Public test-only entry point so integration tests can drive the
/// pure aggregation logic without re-implementing it. Production
/// callers use [`run_doctor`].
#[doc(hidden)]
pub fn aggregate_for_tests(report: &mut DoctorReport) {
    aggregate(report);
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::doctor::model::{DoctorLimitation, DoctorTargetKind};

    pub fn aggregate_public(report: &mut DoctorReport) {
        aggregate(report);
    }

    #[test]
    fn aggregate_combines_critical_section_to_critical_overall() {
        let mut report = DoctorReport::default();
        report.sections = vec![
            DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Critical),
        ];
        aggregate(&mut report);
        assert_eq!(report.overall_status, DoctorOverallStatus::Critical);
    }

    #[test]
    fn aggregate_degrades_when_only_limitations_exist() {
        let mut report = DoctorReport::default();
        report.sections = DoctorSectionId::all()
            .iter()
            .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Healthy))
            .collect();
        report
            .limitations
            .push(DoctorLimitation::new(DoctorSectionId::Filesystem, "X", "y"));
        aggregate(&mut report);
        assert_eq!(report.overall_status, DoctorOverallStatus::Degraded);
    }

    #[test]
    fn aggregate_sorts_issues_by_severity_then_section_then_code() {
        let mut report = DoctorReport::default();
        let mut fs_section =
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Unhealthy);
        fs_section.issues.push(DoctorIssue::new(
            "AAA",
            DoctorSeverity::Error,
            DoctorSectionId::Filesystem,
            "fs error",
        ));
        let mut boot_section =
            DoctorSection::new(DoctorSectionId::Boot, DoctorSectionStatus::Unhealthy);
        boot_section.issues.push(DoctorIssue::new(
            "BBB",
            DoctorSeverity::Critical,
            DoctorSectionId::Boot,
            "boot critical",
        ));
        report.sections = vec![fs_section, boot_section];
        aggregate(&mut report);
        assert_eq!(report.issues[0].code, "BBB");
        assert_eq!(report.issues[0].severity, DoctorSeverity::Critical);
        assert_eq!(report.issues[1].code, "AAA");
    }

    #[test]
    fn aggregate_dedupes_identical_issues() {
        let mut report = DoctorReport::default();
        let mut section =
            DoctorSection::new(DoctorSectionId::Mount, DoctorSectionStatus::Unhealthy);
        let issue = DoctorIssue::new("X", DoctorSeverity::Error, DoctorSectionId::Mount, "same");
        section.issues.push(issue.clone());
        section.issues.push(issue);
        report.sections = vec![section];
        aggregate(&mut report);
        assert_eq!(report.issues.len(), 1);
    }

    #[test]
    fn aggregate_marks_complete_false_when_a_section_is_skipped() {
        let mut report = DoctorReport::default();
        report.sections = vec![
            DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Skipped),
        ];
        aggregate(&mut report);
        assert!(!report.complete);
    }

    #[test]
    fn doctor_failed_is_false_when_cleanup_is_clean() {
        let report = DoctorReport::default();
        assert!(!report.doctor_failed());
    }

    #[test]
    fn target_summary_for_no_target_uses_none_kind() {
        let sel = TargetSelection::None {
            reason: "test".into(),
        };
        let summary = sel.to_target_summary();
        assert_eq!(summary.kind, DoctorTargetKind::None);
    }
}
