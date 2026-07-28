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
    DoctorOverallStatus, DoctorReport, DoctorSection, DoctorSeverity, DoctorTargetKind,
};
use crate::error::Error;

/// Render the report as human-readable text. Always returns `Ok(())`
/// because Doctor's exit code is decided by [`DoctorReport::doctor_failed`],
/// not by rendering success. A render I/O failure is surfaced via
/// `Error::SerializeFailed` so the caller can still observe it.
pub fn render_doctor_human(report: &DoctorReport, out: &mut dyn Write) -> Result<(), Error> {
    render_doctor_human_with_columns(report, out, 78)
}

pub fn render_doctor_human_with_columns(
    report: &DoctorReport,
    out: &mut dyn Write,
    columns: usize,
) -> Result<(), Error> {
    let layout = TableLayout::for_columns(columns);
    if let Some(failure) = startup_failure(report) {
        writeln!(
            out,
            "{}",
            fit("CatOS Doctor could not start", layout.total_width)
        )
        .map_err(io_err)?;
        writeln!(
            out,
            "Error: {}",
            fit(&failure.message, layout.total_width.saturating_sub(7))
        )
        .map_err(io_err)?;
        if let Some(residual) = report.cleanup.residual.first() {
            writeln!(
                out,
                "Cleanup: {}",
                fit(residual, layout.total_width.saturating_sub(9))
            )
            .map_err(io_err)?;
        }
        return Ok(());
    }

    writeln!(out, "CatOS Doctor").map_err(io_err)?;
    render_table_header(out, &layout, "Item", "Status", "Details")?;
    render_row(
        out,
        &layout,
        "Overall",
        report.overall_status.as_str(),
        &format!(
            "{}; target={}",
            if report.complete {
                "complete"
            } else {
                "partial"
            },
            target_kind_label(report.target.kind)
        ),
    )?;
    for section in &report.sections {
        render_row(
            out,
            &layout,
            section.id.heading(),
            section_status_label(section.status),
            &section_summary(report, section),
        )?;
    }

    if has_findings(report) {
        writeln!(out).map_err(io_err)?;
        writeln!(out, "Findings").map_err(io_err)?;
        render_table_header(out, &layout, "Area", "Level", "Finding")?;
        for issue in &report.issues {
            render_row(
                out,
                &layout,
                issue.section.heading(),
                severity_label(issue.severity),
                &format!("{}: {}", issue.code, issue.message),
            )?;
        }
        for limitation in &report.limitations {
            render_row(
                out,
                &layout,
                limitation.section.heading(),
                "limited",
                &format!("{}: {}", limitation.code, limitation.message),
            )?;
        }
        for warning in &report.warnings {
            render_row(out, &layout, "General", "warn", warning)?;
        }
        for residual in &report.cleanup.residual {
            render_row(out, &layout, "Cleanup", "error", residual)?;
        }
    }

    if !report.recommendations.is_empty() {
        writeln!(out).map_err(io_err)?;
        writeln!(out, "Actions").map_err(io_err)?;
        render_table_header(out, &layout, "Action", "Type", "Command or next step")?;
        for (index, recommendation) in report.recommendations.iter().enumerate() {
            let (kind, detail) = match recommendation.command.as_deref() {
                Some(command) => ("run", command.to_string()),
                None => ("review", recommendation.message.clone()),
            };
            render_wrapped_row(out, &layout, &format!("{}", index + 1), kind, &detail)?;
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct TableLayout {
    item_width: usize,
    status_width: usize,
    detail_width: usize,
    total_width: usize,
}

impl TableLayout {
    fn for_columns(columns: usize) -> Self {
        let total_width = columns.clamp(24, 78);
        let item_width = if total_width >= 50 { 13 } else { 8 };
        let status_width = if total_width >= 42 { 10 } else { 6 };
        let detail_width = total_width
            .saturating_sub(item_width + status_width + 6)
            .max(4);
        Self {
            item_width,
            status_width,
            detail_width,
            total_width: item_width + status_width + detail_width + 6,
        }
    }
}

fn render_table_header(
    out: &mut dyn Write,
    layout: &TableLayout,
    item: &str,
    status: &str,
    details: &str,
) -> Result<(), Error> {
    render_row(out, layout, item, status, details)?;
    writeln!(
        out,
        "{}-+-{}-+-{}",
        "-".repeat(layout.item_width),
        "-".repeat(layout.status_width),
        "-".repeat(layout.detail_width)
    )
    .map_err(io_err)
}

fn render_row(
    out: &mut dyn Write,
    layout: &TableLayout,
    item: &str,
    status: &str,
    details: &str,
) -> Result<(), Error> {
    writeln!(
        out,
        "{:<item_width$} | {:<status_width$} | {}",
        fit(item, layout.item_width),
        fit(status, layout.status_width),
        fit(details, layout.detail_width),
        item_width = layout.item_width,
        status_width = layout.status_width,
    )
    .map_err(io_err)
}

fn render_wrapped_row(
    out: &mut dyn Write,
    layout: &TableLayout,
    item: &str,
    status: &str,
    details: &str,
) -> Result<(), Error> {
    let lines = wrap_words(details, layout.detail_width);
    for (index, line) in lines.iter().enumerate() {
        if index == 0 {
            render_row(out, layout, item, status, line)?;
        } else {
            render_row(out, layout, "", "", line)?;
        }
    }
    Ok(())
}

fn wrap_words(value: &str, width: usize) -> Vec<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in normalized.split(' ') {
        let word_len = word.chars().count();
        if word_len > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let chars = word.chars().collect::<Vec<_>>();
            for chunk in chars.chunks(width) {
                lines.push(chunk.iter().collect());
            }
            continue;
        }
        let projected = current.chars().count() + usize::from(!current.is_empty()) + word_len;
        if projected <= width {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn startup_failure(report: &DoctorReport) -> Option<&crate::doctor::model::DoctorLimitation> {
    report
        .limitations
        .iter()
        .find(|limitation| limitation.code == "DOCTOR_NAMESPACE_UNAVAILABLE")
}

fn has_findings(report: &DoctorReport) -> bool {
    !report.issues.is_empty()
        || !report.limitations.is_empty()
        || !report.warnings.is_empty()
        || !report.cleanup.residual.is_empty()
}

fn target_details(report: &DoctorReport) -> String {
    let target = &report.target;
    let mut parts = Vec::new();
    if let Some(device) = target.root_device.as_deref() {
        parts.push(device.to_string());
    }
    if let Some(fstype) = target.root_fstype.as_deref() {
        parts.push(fstype.to_string());
    }
    if let Some(subvolume) = target.root_subvolume.as_deref() {
        parts.push(subvolume.to_string());
    }
    if let Some(esp) = target.esp_device.as_deref() {
        parts.push(format!("ESP {esp}"));
    }
    if parts.is_empty() {
        "not identified".to_string()
    } else {
        parts.join("; ")
    }
}

fn section_summary(report: &DoctorReport, section: &DoctorSection) -> String {
    let issue_count = report
        .issues
        .iter()
        .filter(|issue| issue.section == section.id)
        .count();
    let limitation_count = report
        .limitations
        .iter()
        .filter(|limitation| limitation.section == section.id)
        .count();
    if issue_count > 0 || limitation_count > 0 {
        let mut parts = Vec::new();
        if issue_count > 0 {
            parts.push(format!("{issue_count} issue{}", plural(issue_count)));
        }
        if limitation_count > 0 {
            parts.push(format!(
                "{limitation_count} unavailable check{}",
                plural(limitation_count)
            ));
        }
        return parts.join("; ");
    }

    match section.id {
        crate::doctor::model::DoctorSectionId::Environment => format!(
            "{}; CatOS root {}",
            empty_as(&report.environment.primary_mode, "unknown mode"),
            yes_no(report.environment.running_root_is_catos)
        ),
        crate::doctor::model::DoctorSectionId::Storage => target_details(report),
        _ => preferred_evidence_message(section)
            .unwrap_or_else(|| default_section_summary(section.status).to_string()),
    }
}

fn preferred_evidence_message(section: &DoctorSection) -> Option<String> {
    use crate::doctor::model::DoctorSectionId;
    let preferred: &[&str] = match section.id {
        DoctorSectionId::Filesystem => &["FS_CHECK_LABEL", "FS_CHECK_STDOUT"],
        DoctorSectionId::Mount => &["FSTAB_LOADED", "ROOT_IDENTITY"],
        DoctorSectionId::Boot => &["PROVIDER_DETECTED", "BOOT_LAYOUT"],
        DoctorSectionId::SecureBoot => &["FIRMWARE_SECURE_BOOT", "TARGET_POLICY_MARKER"],
        DoctorSectionId::Recovery => &["RECOVERY_RECORDS"],
        DoctorSectionId::Environment | DoctorSectionId::Storage => &[],
    };
    for code in preferred {
        if let Some(evidence) = section
            .evidence
            .iter()
            .find(|evidence| evidence.code == *code)
        {
            return Some(evidence.message.clone());
        }
    }
    section
        .evidence
        .first()
        .map(|evidence| evidence.message.clone())
}

fn default_section_summary(status: crate::doctor::model::DoctorSectionStatus) -> &'static str {
    use crate::doctor::model::DoctorSectionStatus;
    match status {
        DoctorSectionStatus::Healthy => "no problems found",
        DoctorSectionStatus::Degraded => "non-blocking concern",
        DoctorSectionStatus::Unhealthy => "repair required",
        DoctorSectionStatus::Critical => "urgent repair required",
        DoctorSectionStatus::Skipped => "check unavailable",
        DoctorSectionStatus::NotApplicable => "not applicable",
        DoctorSectionStatus::Unknown => "not evaluated",
    }
}

fn section_status_label(status: crate::doctor::model::DoctorSectionStatus) -> &'static str {
    use crate::doctor::model::DoctorSectionStatus;
    match status {
        DoctorSectionStatus::NotApplicable => "n/a",
        _ => status.as_str(),
    }
}

fn target_kind_label(kind: DoctorTargetKind) -> &'static str {
    match kind {
        DoctorTargetKind::RunningRoot => "running",
        DoctorTargetKind::Offline => "offline",
        DoctorTargetKind::None => "none",
    }
}

fn severity_label(severity: DoctorSeverity) -> &'static str {
    match severity {
        DoctorSeverity::Info => "info",
        DoctorSeverity::Warning => "warn",
        DoctorSeverity::Error => "error",
        DoctorSeverity::Critical => "CRIT",
    }
}

fn fit(value: &str, width: usize) -> String {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.chars().count() <= width {
        return normalized;
    }
    if width <= 3 {
        return normalized.chars().take(width).collect();
    }
    let mut truncated: String = normalized.chars().take(width - 3).collect();
    truncated.push_str("...");
    truncated
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn empty_as<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
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
    fn human_render_uses_one_compact_row_per_section() {
        let report = sample_report();
        let mut buf = Vec::new();
        render_doctor_human(&report, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Item          | Status"), "{out}");
        assert!(
            out.contains("Overall       | unhealthy  | complete; target=running"),
            "{out}"
        );
        assert!(
            !out.contains("Target        |"),
            "target row duplicates storage: {out}"
        );
        assert_eq!(
            out.matches("/dev/nvme0n1p2").count(),
            1,
            "target details duplicated: {out}"
        );
        assert!(out.contains("Filesystem    | critical"), "{out}");
        assert!(out.contains("FS_CORRUPTION_DETECTED"), "{out}");
        assert!(out.contains("catos-repair fs /dev/nvme0n1p2"), "{out}");
        assert!(
            !out.contains("Filesystem\n----------"),
            "section was expanded vertically: {out}"
        );
        assert_eq!(
            out.matches("FS_CORRUPTION_DETECTED").count(),
            1,
            "issue duplicated: {out}"
        );
    }

    #[test]
    fn healthy_seven_section_summary_fits_without_a_pager() {
        let mut report = sample_report();
        report.overall_status = DoctorOverallStatus::Healthy;
        report.complete = true;
        report.issues.clear();
        report.limitations.clear();
        report.recommendations.clear();
        report.sections = DoctorSectionId::all()
            .iter()
            .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Healthy))
            .collect();
        let mut buf = Vec::new();
        render_doctor_human(&report, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines = out.lines().count();
        assert!(
            lines <= 14,
            "healthy report needs paging ({lines} lines):\n{out}"
        );
        assert!(
            out.lines().all(|line| line.chars().count() <= 80),
            "line exceeds 80 columns:\n{out}"
        );
    }

    #[test]
    fn sixty_column_terminal_never_receives_wider_rows() {
        let report = sample_report();
        let mut buf = Vec::new();
        render_doctor_human_with_columns(&report, &mut buf, 60).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.lines().all(|line| line.chars().count() <= 60),
            "line exceeds terminal width:\n{out}"
        );
        assert!(out.contains("FS_CORRUPTION_DETECTED"), "{out}");
        assert!(out.contains("catos-repair fs"), "{out}");
    }

    #[test]
    fn domain_summary_prefers_conclusions_over_probe_setup() {
        let mut report = sample_report();
        report.issues.clear();
        report.limitations.clear();
        report.recommendations.clear();
        let mut filesystem =
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Healthy);
        filesystem.evidence.push(Evidence::new(
            "FS_CHECK",
            "fs::diagnose",
            "argv: check --readonly --force /dev/vda",
        ));
        filesystem
            .evidence
            .push(Evidence::new("FS_CHECK_LABEL", "btrfs", "label: clean"));
        let mut boot = DoctorSection::new(DoctorSectionId::Boot, DoctorSectionStatus::Healthy);
        boot.evidence.push(Evidence::new(
            "PROVIDER_SIGNAL_COUNT",
            "boot::detect",
            "1 authoritative provider signal(s) present",
        ));
        boot.evidence.push(Evidence::new(
            "PROVIDER_DETECTED",
            "boot::detect",
            "provider=grub method=None",
        ));
        report.sections = vec![filesystem, boot];
        let mut buf = Vec::new();
        render_doctor_human(&report, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Filesystem    | healthy    | label: clean"),
            "{out}"
        );
        assert!(
            out.contains("Boot          | healthy    | provider=grub method=None"),
            "{out}"
        );
        assert!(!out.contains("argv: check --readonly"), "{out}");
        assert!(!out.contains("authoritative provider signal"), "{out}");
    }

    #[test]
    fn action_commands_are_wrapped_but_never_truncated() {
        let mut report = sample_report();
        report.recommendations = vec![DoctorRecommendation::new(
            "RUN_CATOS_RECOVERY_RESUME",
            "resume interrupted recovery",
        )
        .with_command(
            "catos-recovery resume --root-device /dev/vda --transaction tx-00000000000000000000000000000004",
        )];
        let mut buf = Vec::new();
        render_doctor_human(&report, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("catos-recovery resume --root-device /dev/vda"),
            "{out}"
        );
        assert!(
            out.contains("--transaction tx-00000000000000000000000000000004"),
            "{out}"
        );
        assert!(
            !out.contains("catos-recovery resume --root-device /dev..."),
            "{out}"
        );
        assert!(out.lines().all(|line| line.chars().count() <= 80), "{out}");
    }

    #[test]
    fn namespace_failure_is_a_short_error_not_an_unknown_report() {
        let mut report = DoctorReport::default();
        report.sections = DoctorSectionId::all()
            .iter()
            .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Unknown))
            .collect();
        report.limitations.push(DoctorLimitation::new(
            DoctorSectionId::Storage,
            "DOCTOR_NAMESPACE_UNAVAILABLE",
            "cannot establish private mount namespace: operation not permitted",
        ));
        let mut buf = Vec::new();
        render_doctor_human(&report, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Doctor could not start"), "{out}");
        assert!(out.contains("operation not permitted"), "{out}");
        assert!(
            !out.contains("Environment"),
            "fatal error rendered empty sections: {out}"
        );
        assert!(
            out.lines().count() <= 3,
            "fatal error is too verbose: {out}"
        );
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
