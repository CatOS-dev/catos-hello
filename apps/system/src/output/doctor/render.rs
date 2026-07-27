//! Renderers for [`DoctorReport`]. Two surfaces:
//!
//! * `render_doctor_human` — plain ASCII text for terminal use.
//!   Avoids colour as the only semantic signal so the output is
//!   readable on no-colour terminals.
//! * `render_doctor_json` — stable JSON. Same data model as the
//!   human view; no log lines, no ANSI escapes, no absolute
//!   temporary paths unless they are themselves evidence.

use std::io::Write;

use crate::doctor::model::{
    DoctorIssue, DoctorOverallStatus, DoctorRecommendation, DoctorReport, DoctorSection,
    DoctorSeverity, DoctorTargetKind,
};
use crate::error::Error;

/// Render the report as human-readable text. Always returns `Ok(())`
/// because Doctor's exit code is decided by [`DoctorReport::doctor_failed`],
/// not by rendering success. A render I/O failure is surfaced via
/// `Error::SerializeFailed` so the caller can still observe it.
pub fn render_doctor_human(report: &DoctorReport, out: &mut dyn Write) -> Result<(), Error> {
    writeln!(out, "CatOS Doctor").map_err(io_err)?;
    writeln!(out, "============").map_err(io_err)?;
    writeln!(out).map_err(io_err)?;

    writeln!(out, "Target").map_err(io_err)?;
    writeln!(out, "------").map_err(io_err)?;
    render_target(report, out)?;
    writeln!(out).map_err(io_err)?;

    writeln!(out, "Overall status").map_err(io_err)?;
    writeln!(out, "--------------").map_err(io_err)?;
    writeln!(out, "status:    {}", report.overall_status.as_str()).map_err(io_err)?;
    writeln!(out, "complete:  {}", report.complete).map_err(io_err)?;
    writeln!(out).map_err(io_err)?;

    for section in &report.sections {
        render_section_human(section, out)?;
    }

    if !report.issues.is_empty() {
        writeln!(out, "Issues").map_err(io_err)?;
        writeln!(out, "------").map_err(io_err)?;
        for issue in &report.issues {
            render_issue_human(issue, out)?;
        }
        writeln!(out).map_err(io_err)?;
    }

    if !report.limitations.is_empty() {
        writeln!(out, "Limitations").map_err(io_err)?;
        writeln!(out, "-----------").map_err(io_err)?;
        for lim in &report.limitations {
            writeln!(
                out,
                "[{}] {}: {}",
                lim.section.as_str(),
                lim.code,
                lim.message
            )
            .map_err(io_err)?;
        }
        writeln!(out).map_err(io_err)?;
    }

    if !report.recommendations.is_empty() {
        writeln!(out, "Recommended actions").map_err(io_err)?;
        writeln!(out, "-------------------").map_err(io_err)?;
        for rec in &report.recommendations {
            render_recommendation_human(rec, out)?;
        }
        writeln!(out).map_err(io_err)?;
    }

    if !report.cleanup.cleaned.is_empty() || !report.cleanup.residual.is_empty() {
        writeln!(out, "Cleanup").map_err(io_err)?;
        writeln!(out, "-------").map_err(io_err)?;
        for c in &report.cleanup.cleaned {
            writeln!(out, "cleaned: {c}").map_err(io_err)?;
        }
        for r in &report.cleanup.residual {
            writeln!(out, "RESIDUAL: {r}").map_err(io_err)?;
        }
        writeln!(out, "all_clean: {}", report.cleanup.all_clean).map_err(io_err)?;
        writeln!(out).map_err(io_err)?;
    }

    Ok(())
}

fn render_target(report: &DoctorReport, out: &mut dyn Write) -> Result<(), Error> {
    let t = &report.target;
    writeln!(out, "kind:          {}", target_kind_label(t.kind)).map_err(io_err)?;
    if let Some(dev) = t.root_device.as_deref() {
        writeln!(out, "root device:   {dev}").map_err(io_err)?;
    }
    if let Some(fs) = t.root_fstype.as_deref() {
        writeln!(out, "root fstype:   {fs}").map_err(io_err)?;
    }
    if let Some(subvol) = t.root_subvolume.as_deref() {
        writeln!(out, "root subvol:   {subvol}").map_err(io_err)?;
    }
    if let Some(esp) = t.esp_device.as_deref() {
        writeln!(out, "ESP device:    {esp}").map_err(io_err)?;
    }
    if let Some(layout) = t.boot_layout.as_deref() {
        writeln!(out, "boot layout:   {layout}").map_err(io_err)?;
    }
    writeln!(out, "primary mode:  {}", report.environment.primary_mode).map_err(io_err)?;
    writeln!(
        out,
        "running root CatOS: {}",
        report.environment.running_root_is_catos
    )
    .map_err(io_err)?;
    Ok(())
}

fn target_kind_label(k: DoctorTargetKind) -> &'static str {
    match k {
        DoctorTargetKind::RunningRoot => "running_root",
        DoctorTargetKind::Offline => "offline",
        DoctorTargetKind::None => "none",
    }
}

fn render_section_human(section: &DoctorSection, out: &mut dyn Write) -> Result<(), Error> {
    writeln!(out, "{}", section.id.heading()).map_err(io_err)?;
    writeln!(out, "{}", "-".repeat(section.id.heading().len())).map_err(io_err)?;
    writeln!(out, "status: {}", section.status.as_str()).map_err(io_err)?;
    for ev in &section.evidence {
        writeln!(
            out,
            "  * {}: {}",
            ev.code,
            ev.message.lines().next().unwrap_or("")
        )
        .map_err(io_err)?;
    }
    for issue in &section.issues {
        render_issue_human(issue, out)?;
    }
    writeln!(out).map_err(io_err)?;
    Ok(())
}

fn render_issue_human(issue: &DoctorIssue, out: &mut dyn Write) -> Result<(), Error> {
    writeln!(
        out,
        "[{}] ({}) {}: {}",
        severity_label(issue.severity),
        issue.section.as_str(),
        issue.code,
        issue.message
    )
    .map_err(io_err)?;
    for ev in &issue.evidence {
        writeln!(out, "    evidence: {}: {}", ev.code, ev.message).map_err(io_err)?;
    }
    if let Some(rec) = issue.recommendation_code.as_deref() {
        writeln!(out, "    next:     {rec}").map_err(io_err)?;
    }
    Ok(())
}

fn render_recommendation_human(
    rec: &DoctorRecommendation,
    out: &mut dyn Write,
) -> Result<(), Error> {
    writeln!(out, "* [{}] {}", rec.code, rec.message).map_err(io_err)?;
    if let Some(cmd) = rec.command.as_deref() {
        writeln!(out, "  command: {cmd}").map_err(io_err)?;
    }
    if !rec.addresses.is_empty() {
        writeln!(out, "  addresses: {}", rec.addresses.join(", ")).map_err(io_err)?;
    }
    Ok(())
}

fn severity_label(s: DoctorSeverity) -> &'static str {
    match s {
        DoctorSeverity::Info => "info",
        DoctorSeverity::Warning => "warn",
        DoctorSeverity::Error => "error",
        DoctorSeverity::Critical => "CRIT",
    }
}

fn io_err(error: std::io::Error) -> Error {
    Error::SerializeFailed(format!("stdout write: {error}"))
}

/// Render the report as stable JSON. Used by `catos-system doctor` for
/// machine consumption. Never invoked by the public `catos-doctor`
/// entry point — the public surface is human-readable only.
pub fn render_doctor_json(report: &DoctorReport) -> Result<String, Error> {
    serde_json::to_string_pretty(report)
        .map_err(|e| Error::SerializeFailed(format!("doctor report serialisation failed: {e}")))
}

/// Exit code for a Doctor run. Per scheme B: 0 whenever Doctor
/// produced a report, even if every section is `critical`; non-zero
/// only when Doctor itself could not complete.
pub fn exit_code_for(report: &DoctorReport) -> i32 {
    if report.doctor_failed() {
        crate::error::exit_code::PROBE_FAILED
    } else {
        crate::error::exit_code::SUCCESS
    }
}

/// Convenience: render the bare status label for tests.
pub fn overall_status_label(status: DoctorOverallStatus) -> &'static str {
    status.as_str()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::doctor::model::{
        DoctorCleanup, DoctorEnvironment, DoctorIssue, DoctorLimitation, DoctorOverallStatus,
        DoctorRecommendation, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
        DoctorTarget, DoctorTargetKind, DOCTOR_SCHEMA_VERSION,
    };
    use crate::target::Evidence;

    fn sample_report() -> DoctorReport {
        let mut report = DoctorReport {
            schema_version: DOCTOR_SCHEMA_VERSION,
            program: "catos-doctor".into(),
            program_version: "0.1.0".into(),
            environment: DoctorEnvironment {
                primary_mode: "running_system".into(),
                running_root_is_catos: true,
            },
            target: DoctorTarget {
                kind: DoctorTargetKind::RunningRoot,
                root_device: Some("/dev/nvme0n1p2".into()),
                root_fstype: Some("btrfs".into()),
                root_subvolume: Some("/@".into()),
                esp_device: Some("/dev/nvme0n1p1".into()),
                boot_layout: Some("esp_at_boot_efi".into()),
            },
            overall_status: DoctorOverallStatus::Unhealthy,
            complete: true,
            sections: vec![
                DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
                DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Critical),
            ],
            issues: vec![DoctorIssue::new(
                "FS_CORRUPTION_DETECTED",
                DoctorSeverity::Critical,
                DoctorSectionId::Filesystem,
                "btrfs check reported corruption",
            )
            .with_evidence(Evidence::new(
                "FS_CHECK_STDOUT",
                "btrfs",
                "checksum verify failed",
            ))],
            limitations: vec![DoctorLimitation::new(
                DoctorSectionId::Boot,
                "BOOT_PROVIDER_AMBIGUOUS",
                "no authoritative evidence",
            )],
            recommendations: vec![DoctorRecommendation::new(
                "RUN_CATOS_REPAIR_FS",
                "filesystem is corrupt; repair required",
            )
            .with_command("catos-repair fs /dev/nvme0n1p2")],
            warnings: Vec::new(),
            cleanup: DoctorCleanup::clean(),
            evidence: Vec::new(),
        };
        report.sections[1].issues.push(DoctorIssue::new(
            "FS_CORRUPTION_DETECTED",
            DoctorSeverity::Critical,
            DoctorSectionId::Filesystem,
            "btrfs check reported corruption",
        ));
        report
    }

    #[test]
    fn human_render_includes_overall_status_target_and_section_headers() {
        let report = sample_report();
        let mut buf = Vec::new();
        render_doctor_human(&report, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("CatOS Doctor"));
        assert!(out.contains("status:    unhealthy"));
        assert!(out.contains("Target"));
        assert!(out.contains("root device:   /dev/nvme0n1p2"));
        assert!(out.contains("Filesystem"));
        assert!(out.contains("status: critical"));
        assert!(out.contains("[CRIT] (filesystem) FS_CORRUPTION_DETECTED"));
    }

    #[test]
    fn human_render_emits_recommendations_and_cleanup() {
        let report = sample_report();
        let mut buf = Vec::new();
        render_doctor_human(&report, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Recommended actions"));
        assert!(out.contains("RUN_CATOS_REPAIR_FS"));
        assert!(out.contains("command: catos-repair fs"));
    }

    #[test]
    fn json_render_round_trips() {
        let report = sample_report();
        let json = render_doctor_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["overall_status"], "unhealthy");
        assert_eq!(parsed["target"]["root_device"], "/dev/nvme0n1p2");
        assert_eq!(parsed["issues"][0]["code"], "FS_CORRUPTION_DETECTED");
    }

    #[test]
    fn exit_code_is_zero_for_unhealthy_report() {
        let report = sample_report();
        assert_eq!(exit_code_for(&report), 0);
    }

    #[test]
    fn exit_code_is_nonzero_when_cleanup_has_residuals() {
        let mut report = sample_report();
        report.cleanup.all_clean = false;
        report.cleanup.residual.push("/tmp/foo".into());
        assert_ne!(exit_code_for(&report), 0);
    }

    #[test]
    fn severity_label_critical_is_short_for_terminal_alignment() {
        assert_eq!(severity_label(DoctorSeverity::Critical), "CRIT");
        assert_eq!(severity_label(DoctorSeverity::Info), "info");
    }
}
