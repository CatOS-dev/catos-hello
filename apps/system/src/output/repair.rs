//! Output rendering for `catos-repair fs`. Mirrors the phase-2 /
//! phase-3 split: JSON is a thin serde wrapper around the model;
//! human output is plain ASCII. Both render the SAME
//! [`FsRepairReport`], so JSON and human output cannot diverge on
//! the final outcome or the audit trail.

use std::io::Write;

use crate::error::Error;
use crate::model::repair::FsRepairReport;

/// Render the repair report as JSON. Uses the same envelope as
/// phase-2 and phase-3 reports so consumers parse one shape.
pub fn render_repair_json(
    report: &FsRepairReport,
    invocation: &str,
    target_root: &std::path::Path,
) -> Result<String, Error> {
    let body = serde_json::json!({
        "schemaVersion": crate::SCHEMA_VERSION,
        "programVersion": crate::PROGRAM_VERSION,
        "invocation": invocation,
        "targetRoot": target_root,
        "kind": "repair_fs",
        "payload": serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
    });
    serde_json::to_string_pretty(&body).map_err(|e| Error::SerializeFailed(e.to_string()))
}

/// Render the repair report as plain ASCII text. No ANSI escapes;
/// matches the phase-2 human contract.
pub fn render_repair_human<W: Write>(report: &FsRepairReport, out: &mut W) -> std::io::Result<()> {
    writeln!(out, "CatOS system backend (repair fs)")?;
    writeln!(out, "  program version : {}", crate::PROGRAM_VERSION)?;
    writeln!(out, "  schema version  : {}", crate::SCHEMA_VERSION)?;
    writeln!(out)?;
    writeln!(out, "Repair result")?;
    if let Some(device) = &report.target_device {
        writeln!(out, "  target device     : {}", device.display())?;
    } else {
        writeln!(out, "  target device     : <not selected>")?;
    }
    writeln!(
        out,
        "  filesystem type   : {}",
        report.filesystem_type.as_deref().unwrap_or("<unknown>")
    )?;
    writeln!(
        out,
        "  was mounted before: {}",
        report.was_mounted_before_session
    )?;
    writeln!(
        out,
        "  selected tool     : {}",
        report
            .selected_tool
            .map(|tool| tool.code())
            .unwrap_or("<none>")
    )?;
    writeln!(out, "  final outcome     : {}", report.final_outcome.code())?;
    writeln!(
        out,
        "  high-risk fallback used: {}",
        report.used_high_risk_fallback()
    )?;
    writeln!(
        out,
        "  requires human action: {}",
        report.requires_human_action
    )?;
    writeln!(out, "  attempts          : {}", report.attempts.len())?;
    for (idx, attempt) in report.attempts.iter().enumerate() {
        writeln!(
            out,
            "    [{idx}] {} kind={} tool={} high_risk={} exit_code={} clean={} errors_corrected={} errors_uncorrected={} timed_out={} binary_missing={}",
            attempt.kind.code(),
            attempt.kind.code(),
            attempt.tool.code(),
            attempt.high_risk,
            attempt.exit.raw_code,
            attempt.exit.clean,
            attempt.exit.errors_corrected,
            attempt.exit.errors_uncorrected,
            attempt.exit.timed_out,
            attempt.exit.binary_missing,
        )?;
        writeln!(out, "        argv: {:?}", attempt.argv)?;
        if attempt.stdout_truncated || attempt.stderr_truncated {
            writeln!(
                out,
                "        output truncated: stdout={} stderr={}",
                attempt.stdout_truncated, attempt.stderr_truncated
            )?;
        }
        if !attempt.stdout.is_empty() {
            let indented = indent_block(&attempt.stdout, "        | ");
            writeln!(out, "        stdout:")?;
            write!(out, "{indented}")?;
        }
        if !attempt.stderr.is_empty() {
            let indented = indent_block(&attempt.stderr, "        | ");
            writeln!(out, "        stderr:")?;
            write!(out, "{indented}")?;
        }
        writeln!(out, "        rationale: {}", attempt.rationale)?;
    }

    if let Some(verification) = &report.verification_mount {
        writeln!(out, "  Verification mount")?;
        writeln!(out, "    mounted          : {}", verification.mounted)?;
        if let Some(fstype) = &verification.observed_fstype {
            writeln!(out, "    observed fstype  : {fstype}")?;
        }
        if let Some(message) = &verification.failure_message {
            writeln!(out, "    failure          : {message}")?;
        }
    }

    writeln!(out, "  Cleanup")?;
    writeln!(
        out,
        "    unmounted        : {}",
        report.cleanup.unmounted.len()
    )?;
    for entry in &report.cleanup.unmounted {
        writeln!(out, "      ok: {entry}")?;
    }
    writeln!(
        out,
        "    residual         : {}",
        report.cleanup.residual.len()
    )?;
    for entry in &report.cleanup.residual {
        writeln!(out, "      RESIDUAL: {entry}")?;
    }
    writeln!(out, "    all clean        : {}", report.cleanup.all_clean)?;

    if !report.evidence.is_empty() {
        writeln!(out, "  Evidence")?;
        for evidence in &report.evidence {
            writeln!(
                out,
                "    [{}] {} (source={}): {}",
                evidence.code, evidence.message, evidence.source, evidence.message
            )?;
            if let Some(value) = &evidence.value {
                writeln!(out, "        value: {value}")?;
            }
        }
    }

    if !report.warnings.is_empty() {
        writeln!(out, "  Warnings")?;
        for warning in &report.warnings {
            writeln!(out, "    [{}] {}", warning.code, warning.message)?;
        }
    }

    Ok(())
}

fn indent_block(text: &str, prefix: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        out.push_str(prefix);
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::repair::{
        AttemptKind, ExitInterpretation, FsRepairOutcome, RepairAttempt, RepairCleanup, RepairTool,
        VerificationMount,
    };

    fn sample_report() -> FsRepairReport {
        FsRepairReport {
            target_device: Some(std::path::PathBuf::from("/dev/sda1")),
            filesystem_type: Some("ext4".into()),
            selected_tool: Some(RepairTool::E2fsck),
            final_outcome: FsRepairOutcome::Repaired,
            attempts: vec![RepairAttempt {
                kind: AttemptKind::Repair,
                tool: RepairTool::E2fsck,
                argv: vec!["-y".into(), "-C".into(), "0".into(), "/dev/sda1".into()],
                high_risk: false,
                exit: ExitInterpretation {
                    raw_code: 1,
                    clean: false,
                    errors_corrected: true,
                    reboot_required: false,
                    exited_early: false,
                    errors_uncorrected: false,
                    timed_out: false,
                    binary_missing: false,
                    label: Some("e2fsck-code-1".into()),
                },
                stdout: "errors corrected\n".into(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                rationale: "e2fsck auto-repair".into(),
            }],
            verification_mount: Some(VerificationMount {
                mounted: true,
                observed_fstype: Some("ext4".into()),
                failure_message: None,
            }),
            cleanup: RepairCleanup {
                unmounted: vec!["/dev/sda1 on /run/catos-system/sessions/v1-1/target".into()],
                residual: vec![],
                all_clean: true,
            },
            ..Default::default()
        }
    }

    #[test]
    fn human_output_has_no_ansi_escapes() {
        let report = sample_report();
        let mut buf = Vec::new();
        render_repair_human(&report, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains('\u{001b}'));
        assert!(s.contains("Repair result"));
        assert!(s.contains("final outcome     : repaired"));
    }

    #[test]
    fn json_output_uses_envelope() {
        let report = sample_report();
        let json = render_repair_json(&report, "catos-repair", std::path::Path::new("/")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schemaVersion"], 2);
        assert_eq!(value["kind"], "repair_fs");
        assert_eq!(value["payload"]["final_outcome"], "repaired");
        assert_eq!(value["payload"]["attempts"][0]["tool"], "e2fsck");
        assert_eq!(value["payload"]["attempts"][0]["exit"]["raw_code"], 1);
        assert_eq!(
            value["payload"]["verification_mount"]["observed_fstype"],
            "ext4"
        );
    }

    #[test]
    fn json_and_human_agree_on_final_outcome() {
        // The contract: human and JSON MUST render the same model.
        // We pin this by extracting the outcome from each form and
        // asserting they match.
        let report = sample_report();
        let json = render_repair_json(&report, "catos-repair", std::path::Path::new("/")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let json_outcome = value["payload"]["final_outcome"].as_str().unwrap();

        let mut buf = Vec::new();
        render_repair_human(&report, &mut buf).unwrap();
        let human = String::from_utf8(buf).unwrap();
        let human_line = human
            .lines()
            .find(|line| line.contains("final outcome"))
            .unwrap();
        assert!(
            human_line.contains(json_outcome),
            "human line {human_line:?} did not contain JSON outcome {json_outcome:?}"
        );
    }

    #[test]
    fn high_risk_fallback_is_visible_in_human_output() {
        let mut report = sample_report();
        report.final_outcome = FsRepairOutcome::RepairedWithRisk;
        report.attempts.push(RepairAttempt {
            kind: AttemptKind::HighRiskFallback,
            tool: RepairTool::XfsRepair,
            argv: vec!["-L".into(), "/dev/sda1".into()],
            high_risk: true,
            exit: ExitInterpretation {
                raw_code: 0,
                clean: true,
                errors_corrected: false,
                reboot_required: false,
                exited_early: false,
                errors_uncorrected: false,
                timed_out: false,
                binary_missing: false,
                label: Some("xfs_repair-L-code-0".into()),
            },
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            rationale: "log zeroing fallback".into(),
        });
        let mut buf = Vec::new();
        render_repair_human(&report, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("high_risk=true"));
        assert!(s.contains("high-risk fallback used: true"));
        assert!(s.contains("final outcome     : repaired_with_risk"));
    }
}
