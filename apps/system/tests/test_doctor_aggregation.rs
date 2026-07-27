//! Aggregation-logic tests for Doctor. These verify the pure
//! aggregation rules (`overall_status` derivation, issue ordering,
//! dedupe, recommendation linkage) independently of subprocess
//! invocation.

#![allow(clippy::field_reassign_with_default)]

use catos_system::doctor;
use catos_system::doctor::model::{
    issue_code, recommendation_code, DoctorIssue, DoctorLimitation, DoctorOverallStatus,
    DoctorRecommendation, DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus,
    DoctorSeverity,
};

#[test]
fn all_domains_healthy_produces_healthy_overall() {
    let mut report = DoctorReport::default();
    report.sections = DoctorSectionId::all()
        .iter()
        .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Healthy))
        .collect();
    doctor::aggregate_for_tests(&mut report);
    assert_eq!(report.overall_status, DoctorOverallStatus::Healthy);
    assert!(report.complete);
    assert!(report.issues.is_empty());
}

#[test]
fn one_domain_degraded_produces_degraded_overall() {
    let mut report = DoctorReport::default();
    report.sections = vec![
        DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
        DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Degraded),
        DoctorSection::new(DoctorSectionId::Mount, DoctorSectionStatus::Healthy),
    ];
    doctor::aggregate_for_tests(&mut report);
    assert_eq!(report.overall_status, DoctorOverallStatus::Degraded);
}

#[test]
fn one_domain_unhealthy_produces_unhealthy_overall() {
    let mut report = DoctorReport::default();
    report.sections = vec![
        DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
        DoctorSection::new(DoctorSectionId::Mount, DoctorSectionStatus::Unhealthy),
    ];
    doctor::aggregate_for_tests(&mut report);
    assert_eq!(report.overall_status, DoctorOverallStatus::Unhealthy);
}

#[test]
fn critical_recovery_state_dominates_other_sections() {
    let mut report = DoctorReport::default();
    report.sections = vec![
        DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
        DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Unhealthy),
        DoctorSection::new(DoctorSectionId::Recovery, DoctorSectionStatus::Critical),
    ];
    doctor::aggregate_for_tests(&mut report);
    assert_eq!(report.overall_status, DoctorOverallStatus::Critical);
}

#[test]
fn multiple_domains_simultaneously_abnormal_keeps_strongest_signal() {
    let mut report = DoctorReport::default();
    report.sections = vec![
        DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Unhealthy),
        DoctorSection::new(DoctorSectionId::Mount, DoctorSectionStatus::Degraded),
        DoctorSection::new(DoctorSectionId::Boot, DoctorSectionStatus::Critical),
        DoctorSection::new(DoctorSectionId::Recovery, DoctorSectionStatus::Unhealthy),
    ];
    doctor::aggregate_for_tests(&mut report);
    assert_eq!(report.overall_status, DoctorOverallStatus::Critical);
}

#[test]
fn unknown_target_yields_unknown_overall_and_zero_issues_in_sections() {
    let mut report = DoctorReport::default();
    report.sections = vec![DoctorSection::new(
        DoctorSectionId::Storage,
        DoctorSectionStatus::Unknown,
    )];
    doctor::aggregate_for_tests(&mut report);
    assert_eq!(report.overall_status, DoctorOverallStatus::Unknown);
    assert!(!report.complete);
}

#[test]
fn skipped_section_marks_report_incomplete() {
    let mut report = DoctorReport::default();
    report.sections = vec![
        DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
        DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Skipped),
    ];
    doctor::aggregate_for_tests(&mut report);
    assert!(!report.complete);
    assert_eq!(report.overall_status, DoctorOverallStatus::Healthy);
}

#[test]
fn issue_ordering_is_severity_desc_then_section_then_code() {
    let mut report = DoctorReport::default();
    let mut fs = DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Unhealthy);
    fs.issues.push(DoctorIssue::new(
        "FS_A",
        DoctorSeverity::Error,
        DoctorSectionId::Filesystem,
        "fs A",
    ));
    fs.issues.push(DoctorIssue::new(
        "FS_B",
        DoctorSeverity::Info,
        DoctorSectionId::Filesystem,
        "fs B",
    ));
    let mut boot = DoctorSection::new(DoctorSectionId::Boot, DoctorSectionStatus::Critical);
    boot.issues.push(DoctorIssue::new(
        "BOOT_C",
        DoctorSeverity::Critical,
        DoctorSectionId::Boot,
        "boot C",
    ));
    let mut mount = DoctorSection::new(DoctorSectionId::Mount, DoctorSectionStatus::Unhealthy);
    mount.issues.push(DoctorIssue::new(
        "MNT_A",
        DoctorSeverity::Error,
        DoctorSectionId::Mount,
        "mount A",
    ));
    report.sections = vec![fs, boot, mount];
    doctor::aggregate_for_tests(&mut report);
    let codes: Vec<_> = report.issues.iter().map(|i| i.code.as_str()).collect();
    // Critical first; then Error sorted by section name alphabetically
    // (filesystem < mount); then Info last.
    assert_eq!(codes, vec!["BOOT_C", "FS_A", "MNT_A", "FS_B"]);
}

#[test]
fn duplicate_issues_are_deduped() {
    let mut report = DoctorReport::default();
    let mut section = DoctorSection::new(DoctorSectionId::Mount, DoctorSectionStatus::Unhealthy);
    let issue = DoctorIssue::new(
        issue_code::STANDARD_SUBVOLUME_MISSING,
        DoctorSeverity::Error,
        DoctorSectionId::Mount,
        "missing @home",
    );
    section.issues.push(issue.clone());
    section.issues.push(issue);
    report.sections = vec![section];
    doctor::aggregate_for_tests(&mut report);
    assert_eq!(report.issues.len(), 1);
}

#[test]
fn recommendation_links_back_to_issue_code() {
    let mut report = DoctorReport::default();
    let mut section =
        DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Critical);
    section.issues.push(
        DoctorIssue::new(
            issue_code::FS_CORRUPTION_DETECTED,
            DoctorSeverity::Critical,
            DoctorSectionId::Filesystem,
            "corruption",
        )
        .with_recommendation(recommendation_code::RUN_CATOS_REPAIR_FS),
    );
    report.sections = vec![section];
    report.recommendations.push(
        DoctorRecommendation::new(recommendation_code::RUN_CATOS_REPAIR_FS, "fs is corrupt")
            .with_command("catos-repair fs /dev/...")
            .addressing(issue_code::FS_CORRUPTION_DETECTED),
    );
    doctor::aggregate_for_tests(&mut report);
    let rec = report
        .recommendations
        .iter()
        .find(|r| r.code == recommendation_code::RUN_CATOS_REPAIR_FS)
        .unwrap();
    assert!(rec
        .addresses
        .contains(&issue_code::FS_CORRUPTION_DETECTED.to_string()));
    assert_eq!(rec.command.as_deref(), Some("catos-repair fs /dev/..."));
}

#[test]
fn limitations_degrade_otherwise_healthy_report() {
    let mut report = DoctorReport::default();
    report.sections = DoctorSectionId::all()
        .iter()
        .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Healthy))
        .collect();
    report.limitations.push(DoctorLimitation::new(
        DoctorSectionId::Filesystem,
        issue_code::FS_OFFLINE_CHECK_REQUIRED,
        "current root is mounted",
    ));
    doctor::aggregate_for_tests(&mut report);
    assert_eq!(report.overall_status, DoctorOverallStatus::Degraded);
}

#[test]
fn critical_section_status_contributes_critical_overall() {
    assert_eq!(
        DoctorSectionStatus::Critical.to_overall_contribution(),
        Some(DoctorOverallStatus::Critical)
    );
    assert_eq!(
        DoctorSectionStatus::Unhealthy.to_overall_contribution(),
        Some(DoctorOverallStatus::Unhealthy)
    );
    assert_eq!(
        DoctorSectionStatus::Degraded.to_overall_contribution(),
        Some(DoctorOverallStatus::Degraded)
    );
    assert_eq!(DoctorSectionStatus::Skipped.to_overall_contribution(), None);
}
