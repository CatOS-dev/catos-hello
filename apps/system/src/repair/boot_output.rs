//! Output rendering for `catos-repair boot`. JSON is a thin serde
//! wrapper around the model; human output is plain ASCII. Both
//! render the SAME [`BootRepairReport`] so JSON and human output
//! cannot diverge on the final outcome.

use std::io::Write;

use crate::boot::model::BootRepairReport;
use crate::error::Error;

pub fn render_boot_repair_json(
    report: &BootRepairReport,
    invocation: &str,
    target_root: &std::path::Path,
) -> Result<String, Error> {
    let body = serde_json::json!({
        "schemaVersion": crate::SCHEMA_VERSION,
        "programVersion": crate::PROGRAM_VERSION,
        "invocation": invocation,
        "targetRoot": target_root,
        "kind": "repair_boot",
        "payload": serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
    });
    serde_json::to_string_pretty(&body).map_err(|e| Error::SerializeFailed(e.to_string()))
}

pub fn render_boot_repair_human<W: Write>(
    report: &BootRepairReport,
    out: &mut W,
) -> std::io::Result<()> {
    writeln!(out, "CatOS Boot Repair")?;
    writeln!(out, "  program version : {}", crate::PROGRAM_VERSION)?;
    writeln!(out, "  schema version  : {}", crate::SCHEMA_VERSION)?;
    writeln!(out)?;
    writeln!(out, "Boot repair result")?;
    if let Some(target) = &report.target {
        writeln!(out, "  target device    : {}", target.root_device.display())?;
        writeln!(out, "  root fstype      : {}", target.root_fstype)?;
        if let Some(subvol) = &target.root_subvol {
            writeln!(out, "  root subvol      : {subvol}")?;
        }
        if let Some(uuid) = &target.root_uuid {
            writeln!(out, "  root uuid        : {uuid}")?;
        }
    } else {
        writeln!(out, "  target device    : <not selected>")?;
    }
    if let Some(platform) = &report.platform {
        writeln!(
            out,
            "  platform         : {}/{}/{}",
            platform.firmware.as_registry_str(),
            platform.architecture.as_str(),
            match platform.partition_table {
                crate::boot::model::PartitionTable::Gpt => "gpt",
                crate::boot::model::PartitionTable::Msdos => "msdos",
                crate::boot::model::PartitionTable::Unknown => "unknown",
            }
        )?;
    }
    if let Some(provider) = report.detected_provider {
        writeln!(out, "  detected provider: {}", provider.as_str())?;
    } else {
        writeln!(out, "  detected provider: <ambiguous>")?;
    }
    if let Some(method) = report.firmware_method {
        writeln!(out, "  firmware method  : {}", method.as_str())?;
    }
    if let Some(cmdline) = &report.kernel_cmdline {
        writeln!(out, "  kernel cmdline   : {cmdline}")?;
    }
    writeln!(out)?;
    writeln!(out, "  final outcome    : {}", report.final_outcome.code())?;
    writeln!(out, "  fully complete   : {}", report.fully_complete)?;
    writeln!(out, "  requires action  : {}", report.requires_human_action)?;
    if !report.cmdline_conflicts.is_empty() {
        writeln!(out)?;
        writeln!(out, "Cmdline conflicts")?;
        for conflict in &report.cmdline_conflicts {
            match conflict {
                crate::boot::model::CmdlineConflict::ConflictingValue {
                    key,
                    existing,
                    proposed,
                } => {
                    writeln!(out, "  {key}: existing={existing} proposed={proposed}")?;
                }
            }
        }
    }
    if !report.actions.is_empty() {
        writeln!(out)?;
        writeln!(out, "Actions")?;
        for action in &report.actions {
            render_action_human(out, action)?;
        }
    }
    if let Some(verification) = &report.verification {
        writeln!(out)?;
        writeln!(out, "Verification")?;
        writeln!(out, "  passed : {}", verification.passed)?;
        if !verification.checks.is_empty() {
            writeln!(out, "  checks : {}", verification.checks.join(", "))?;
        }
        if let Some(message) = &verification.failure_message {
            writeln!(out, "  failure: {message}")?;
        }
    }
    if let Some(secureboot) = &report.secureboot {
        writeln!(out)?;
        writeln!(out, "Secure Boot")?;
        writeln!(
            out,
            "  target policy present : {}",
            secureboot.target_policy_present
        )?;
        writeln!(
            out,
            "  enable invoked       : {}",
            secureboot.enable_invoked
        )?;
        if let Some(fp) = &secureboot.certificate_fingerprint {
            writeln!(out, "  certificate           : {fp}")?;
        }
        writeln!(
            out,
            "  enrollment pending    : {}",
            secureboot.enrollment_pending
        )?;
        if let Some(password) = &secureboot.enrollment_password {
            writeln!(out, "  MokManager password   : {}", password.expose())?;
        }
        if let Some(path) = &secureboot.enrollment_password_path {
            writeln!(out, "  password stored at    : {path}")?;
        }
        if secureboot.enrollment_pending {
            writeln!(
                out,
                "  next boot             : enter the one-time password in MokManager"
            )?;
        }
        if let Some(message) = &secureboot.failure_message {
            writeln!(out, "  failure               : {message}")?;
        }
    }
    if !report.cleanup.all_clean || !report.cleanup.residual.is_empty() {
        writeln!(out)?;
        writeln!(out, "Cleanup")?;
        writeln!(out, "  all clean : {}", report.cleanup.all_clean)?;
        for residual in &report.cleanup.residual {
            writeln!(out, "  residual  : {residual}")?;
        }
    }
    if !report.evidence.is_empty() {
        writeln!(out)?;
        writeln!(out, "Evidence")?;
        for evidence in &report.evidence {
            writeln!(
                out,
                "  [{}] {} ({}): {}",
                evidence.code, evidence.source, evidence.code, evidence.message
            )?;
        }
    }
    Ok(())
}

fn render_action_human<W: Write>(
    out: &mut W,
    action: &crate::boot::model::BootAction,
) -> std::io::Result<()> {
    match action {
        crate::boot::model::BootAction::ConfigWritten {
            target_path,
            backup_path,
            bytes,
        } => {
            if let Some(backup) = backup_path {
                writeln!(
                    out,
                    "  config written     : {target_path} ({bytes} bytes; backup={backup})"
                )?;
            } else {
                writeln!(out, "  config written     : {target_path} ({bytes} bytes)")?;
            }
        }
        crate::boot::model::BootAction::ConfigUnchanged { target_path } => {
            writeln!(out, "  config unchanged   : {target_path}")?;
        }
        crate::boot::model::BootAction::TargetCommand { result } => {
            writeln!(
                out,
                "  command            : {} {} (exit={})",
                result.command.binary,
                result.command.argv.join(" "),
                result.exit_code
            )?;
            if result.binary_missing {
                writeln!(out, "    binary missing   : true")?;
            }
            if result.timed_out {
                writeln!(out, "    timed out        : true")?;
            }
            if result.stdout_truncated || result.stderr_truncated {
                writeln!(
                    out,
                    "    truncated        : stdout={} stderr={}",
                    result.stdout_truncated, result.stderr_truncated
                )?;
            }
        }
        crate::boot::model::BootAction::TargetCommandSkipped { command, reason } => {
            writeln!(
                out,
                "  command skipped    : {} ({})",
                command.binary, reason
            )?;
        }
        crate::boot::model::BootAction::SnapshotStep {
            description,
            result,
        } => {
            if let Some(result) = result {
                writeln!(
                    out,
                    "  snapshot step      : {description} (exit={})",
                    result.exit_code
                )?;
            } else {
                writeln!(out, "  snapshot step      : {description}")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::model::{SecureBootReport, SensitiveString};

    #[test]
    fn mok_password_is_human_only_and_json_reports_its_target_path() {
        let report = BootRepairReport {
            secureboot: Some(SecureBootReport {
                target_policy_present: true,
                enable_invoked: true,
                certificate_fingerprint: Some("AA:BB".into()),
                enrollment_pending: true,
                enrollment_password_generated: true,
                enrollment_password_path: Some(
                    "/var/lib/catos-secureboot/enrollment-password".into(),
                ),
                enrollment_password: Some(SensitiveString::new("SEKRET1234")),
                ..SecureBootReport::default()
            }),
            ..BootRepairReport::default()
        };

        let mut human = Vec::new();
        render_boot_repair_human(&report, &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("SEKRET1234"));
        assert!(human.contains("/var/lib/catos-secureboot/enrollment-password"));

        let json = render_boot_repair_json(&report, "catos-repair boot", std::path::Path::new("/"))
            .unwrap();
        assert!(!json.contains("SEKRET1234"));
        assert!(json.contains("enrollment_password_generated"));
        assert!(json.contains("/var/lib/catos-secureboot/enrollment-password"));
    }
}
