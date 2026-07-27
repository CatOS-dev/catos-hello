//! Human-readable rendering. Plain ASCII; no colour escapes (so output is
//! safe to pipe, redirect, or embed in TUI environments later).

use std::io::Write;

use crate::cli::View;
use crate::target::model::InspectionReport;
use crate::target::model::{Capability, CapabilityStatus};
use crate::target::model::{Detection, DetectionStatus, PrimaryRuntimeMode};
use crate::target::Evidence;

/// Render the report as human-readable text into `out`. The view controls
/// which sections are emitted, matching the JSON contract: `environment`
/// only shows runtime, `capabilities` only shows capabilities, `inspect`
/// shows everything.
pub fn render_human<W: Write>(
    report: &InspectionReport,
    view: View,
    out: &mut W,
) -> std::io::Result<()> {
    writeln!(out, "CatOS system backend (phase 1, read-only)")?;
    writeln!(out, "  program version : {}", report.program_version)?;
    writeln!(out, "  schema version  : {}", report.schema_version)?;
    writeln!(out, "  invocation      : {}", report.invocation)?;
    writeln!(out, "  target root     : {}", report.target_root.display())?;
    writeln!(out)?;

    if view.runtime {
        writeln!(out, "Runtime")?;
        writeln!(
            out,
            "  primary mode    : {}",
            mode_str(report.runtime.primary_mode())
        )?;
        render_detection(out, "is_initramfs      ", &report.runtime.is_initramfs)?;
        render_detection(out, "is_chroot         ", &report.runtime.is_chroot)?;
        render_detection(
            out,
            "is_live_environment",
            &report.runtime.is_live_environment,
        )?;
        render_detection(out, "is_snapshot_boot  ", &report.runtime.is_snapshot_boot)?;
        render_detection(out, "has_systemd       ", &report.runtime.has_systemd)?;
        render_detection(out, "root_is_read_only ", &report.runtime.root_is_read_only)?;
        writeln!(out)?;
    }

    if view.capabilities {
        writeln!(out, "Capabilities")?;
        for cap in &report.capabilities {
            render_capability(out, cap)?;
        }
        writeln!(out)?;
    }

    if view.target {
        writeln!(out, "Target")?;
        writeln!(out, "  root          : {}", report.target.root.display())?;
        if let Some(os) = &report.target.os_release {
            writeln!(
                out,
                "  os-release    : id={:?} name={:?} version={:?}",
                os.id, os.name, os.version
            )?;
        } else {
            writeln!(out, "  os-release    : <none readable>")?;
        }
        writeln!(
            out,
            "  /etc/fstab         present: {}",
            report.target.has_fstab
        )?;
        writeln!(
            out,
            "  /etc/crypttab      present: {}",
            report.target.has_crypttab
        )?;
        writeln!(
            out,
            "  pacman db          present: {}",
            report.target.has_pacman_db
        )?;
        writeln!(
            out,
            "  /usr               present: {}",
            report.target.has_usr
        )?;
        writeln!(
            out,
            "  /boot              present: {}",
            report.target.has_boot
        )?;
        writeln!(
            out,
            "  /efi               present: {}",
            report.target.has_efi
        )?;
        writeln!(
            out,
            "  /boot/efi          present: {}",
            report.target.has_boot_efi
        )?;
        writeln!(
            out,
            "  CatOS target       : {}",
            detection_status_str(&report.target.is_catos_target.status)
        )?;
        if !report.target.tool_paths.is_empty() {
            writeln!(out, "  tools in target:")?;
            for tp in &report.target.tool_paths {
                writeln!(
                    out,
                    "    {:<12} {} ({})",
                    tp.name,
                    tp.path.display(),
                    capability_status_str(&tp.status)
                )?;
                for evidence in &tp.evidence {
                    render_evidence(out, "      ", evidence)?;
                }
            }
        }
        writeln!(out)?;
    }

    if !report.warnings.is_empty() {
        writeln!(out, "Warnings")?;
        for w in &report.warnings {
            writeln!(out, "  [{}] {}", w.code, w.message)?;
        }
    }
    Ok(())
}

fn mode_str(m: PrimaryRuntimeMode) -> &'static str {
    match m {
        PrimaryRuntimeMode::RunningSystem => "running_system",
        PrimaryRuntimeMode::Chroot => "chroot",
        PrimaryRuntimeMode::LiveEnvironment => "live_environment",
        PrimaryRuntimeMode::Initramfs => "initramfs",
        PrimaryRuntimeMode::Unknown => "unknown",
    }
}

fn render_detection<W: Write>(out: &mut W, label: &str, d: &Detection) -> std::io::Result<()> {
    writeln!(out, "  {label}: {}", detection_status_str(&d.status))?;
    for ev in &d.evidence {
        render_evidence(out, "      ", ev)?;
    }
    Ok(())
}

fn render_capability<W: Write>(out: &mut W, cap: &Capability) -> std::io::Result<()> {
    let status = capability_status_str(&cap.status);
    let name = serde_json::to_string(&cap.name).unwrap_or_else(|_| "".into());
    let name = name.trim_matches('"');
    writeln!(out, "  {name:<28} : {status}")?;
    for ev in &cap.evidence {
        render_evidence(out, "      ", ev)?;
    }
    Ok(())
}

fn capability_status_str(status: &CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Available => "available",
        CapabilityStatus::Unavailable => "unavailable",
        CapabilityStatus::Unknown => "unknown",
    }
}

fn render_evidence<W: Write>(out: &mut W, indent: &str, ev: &Evidence) -> std::io::Result<()> {
    writeln!(out, "{indent}[{}] {} ({})", ev.code, ev.message, ev.source)?;
    if let Some(v) = &ev.value {
        let trimmed = v.chars().take(120).collect::<String>();
        writeln!(out, "{indent}  value: {trimmed}")?;
    }
    Ok(())
}

fn detection_status_str(s: &DetectionStatus) -> &'static str {
    match s {
        DetectionStatus::Detected => "detected",
        DetectionStatus::NotDetected => "not_detected",
        DetectionStatus::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::model::RuntimeFacts;
    use crate::target::model::{TargetInspection, Warning};

    fn empty_report() -> InspectionReport {
        InspectionReport {
            schema_version: 2,
            program_version: "0.0.0".to_string(),
            invocation: "catos-system".to_string(),
            target_root: std::path::PathBuf::from("/"),
            runtime: RuntimeFacts::default(),
            capabilities: vec![],
            target: TargetInspection {
                root: std::path::PathBuf::from("/"),
                os_release: None,
                has_fstab: crate::target::model::Presence::Absent,
                has_crypttab: crate::target::model::Presence::Absent,
                has_pacman_db: crate::target::model::Presence::Absent,
                has_usr: crate::target::model::Presence::Absent,
                has_boot: crate::target::model::Presence::Absent,
                has_efi: crate::target::model::Presence::Absent,
                has_boot_efi: crate::target::model::Presence::Absent,
                is_catos_target: Detection::unknown(vec![]),
                tool_paths: vec![],
            },
            warnings: vec![Warning::new("W", "warn")],
        }
    }

    fn full_view() -> View {
        View {
            runtime: true,
            capabilities: true,
            target: true,
        }
    }

    #[test]
    fn human_output_has_no_ansi_escapes() {
        let r = empty_report();
        let mut buf = Vec::new();
        render_human(&r, full_view(), &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains('\u{001b}'), "human output contains ANSI escape");
    }

    #[test]
    fn human_full_output_includes_core_sections() {
        let r = empty_report();
        let mut buf = Vec::new();
        render_human(&r, full_view(), &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Runtime"));
        assert!(s.contains("Capabilities"));
        assert!(s.contains("Target"));
        assert!(s.contains("Warnings"));
    }

    #[test]
    fn human_environment_view_omits_capabilities_and_target() {
        let r = empty_report();
        let mut buf = Vec::new();
        render_human(
            &r,
            View {
                runtime: true,
                capabilities: false,
                target: false,
            },
            &mut buf,
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Runtime"));
        assert!(!s.contains("Capabilities"));
        assert!(!s.contains("Target"));
    }

    #[test]
    fn human_capabilities_view_omits_runtime_and_target() {
        let r = empty_report();
        let mut buf = Vec::new();
        render_human(
            &r,
            View {
                runtime: false,
                capabilities: true,
                target: false,
            },
            &mut buf,
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains("Runtime"));
        assert!(s.contains("Capabilities"));
        assert!(!s.contains("\nTarget"));
    }
}
