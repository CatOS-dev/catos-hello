//! Output rendering for storage and target-inspection results (StorageReport, MountPlan,
//! MountSession). JSON is a thin
//! serde wrapper, human is plain ASCII.

use std::io::Write;

use crate::error::Error;
use crate::mount::model::{CleanupReport, MountPlan, MountSession};
use crate::system::SystemCommandOutcome;
use crate::target::model::StorageReport;

/// Render a storage or target-inspection outcome as JSON. Wraps every variant in a top-level
/// object with the same stable envelope keys as inspection reports:
/// `schemaVersion`, `programVersion`, `invocation`, plus the variant-
/// specific payload.
pub fn render_system_json(
    outcome: &SystemCommandOutcome,
    invocation: &str,
    target_root: &std::path::Path,
) -> Result<String, Error> {
    let body = match outcome {
        SystemCommandOutcome::StorageScan(report) => json_envelope(
            invocation,
            target_root,
            "storage_scan",
            serde_json::to_value(report).map_err(|e| Error::SerializeFailed(e.to_string()))?,
        ),
        SystemCommandOutcome::TargetPlan { plan, warnings } => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "plan".into(),
                serde_json::to_value(plan).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            payload.insert(
                "warnings".into(),
                serde_json::to_value(warnings)
                    .map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            json_envelope(
                invocation,
                target_root,
                "target_plan",
                serde_json::Value::Object(payload),
            )
        }
        SystemCommandOutcome::TargetMount {
            session,
            inspection,
            cleanup,
            warnings,
        } => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "session".into(),
                serde_json::to_value(session).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            payload.insert(
                "inspection".into(),
                serde_json::to_value(inspection)
                    .map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            payload.insert(
                "cleanup".into(),
                serde_json::to_value(cleanup).map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            payload.insert(
                "warnings".into(),
                serde_json::to_value(warnings)
                    .map_err(|e| Error::SerializeFailed(e.to_string()))?,
            );
            json_envelope(
                invocation,
                target_root,
                "target_mount",
                serde_json::Value::Object(payload),
            )
        }
    };
    serde_json::to_string_pretty(&body).map_err(|e| Error::SerializeFailed(e.to_string()))
}

/// Render a storage or target-inspection failure using the same stable envelope as successful
/// reports. Mount failures remain structured for TUI/GUI consumers.
pub fn render_system_error_json(
    error: &Error,
    invocation: &str,
    target_root: &std::path::Path,
) -> Result<String, Error> {
    let detail = match error {
        Error::MountFailed(mount_error) => {
            serde_json::to_value(mount_error).map_err(|e| Error::SerializeFailed(e.to_string()))?
        }
        Error::InvalidArgument { message } => serde_json::json!({ "message": message }),
        Error::InvalidRoot { path, reason } => {
            serde_json::json!({ "path": path, "reason": reason })
        }
        Error::PermissionDenied { path, detail } => {
            serde_json::json!({ "path": path, "detail": detail })
        }
        Error::ProbeFailed { detail } => serde_json::json!({ "detail": detail }),
        Error::SerializeFailed(message) => serde_json::json!({ "message": message }),
    };
    let body = serde_json::json!({
        "schemaVersion": crate::SCHEMA_VERSION,
        "programVersion": crate::PROGRAM_VERSION,
        "invocation": invocation,
        "targetRoot": target_root,
        "kind": "error",
        "error": {
            "code": error.code(),
            "message": error.to_string(),
            "detail": detail,
        },
    });
    serde_json::to_string_pretty(&body).map_err(|e| Error::SerializeFailed(e.to_string()))
}

fn json_envelope(
    invocation: &str,
    target_root: &std::path::Path,
    kind: &str,
    payload: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": crate::SCHEMA_VERSION,
        "programVersion": crate::PROGRAM_VERSION,
        "invocation": invocation,
        "targetRoot": target_root,
        "kind": kind,
        "payload": payload,
    })
}

/// Render a storage or target-inspection outcome as plain ASCII text. Each variant has its own
/// section layout. Mirrors the human renderer's contract: no ANSI, no
/// panic on empty input.
pub fn render_system_human<W: Write>(
    outcome: &SystemCommandOutcome,
    out: &mut W,
) -> std::io::Result<()> {
    writeln!(out, "CatOS Storage and Target Inspection")?;
    writeln!(out, "  program version : {}", crate::PROGRAM_VERSION)?;
    writeln!(out, "  schema version  : {}", crate::SCHEMA_VERSION)?;
    writeln!(out)?;
    match outcome {
        SystemCommandOutcome::StorageScan(report) => render_storage_report(out, report),
        SystemCommandOutcome::TargetPlan { plan, warnings } => {
            render_mount_plan(out, plan)?;
            render_warnings(out, warnings)
        }
        SystemCommandOutcome::TargetMount {
            session,
            inspection,
            cleanup,
            warnings,
        } => {
            render_mount_session(out, session)?;
            render_target_inspection(out, inspection)?;
            render_cleanup_report(out, cleanup)?;
            render_warnings(out, warnings)
        }
    }
}

fn render_storage_report<W: Write>(out: &mut W, report: &StorageReport) -> std::io::Result<()> {
    writeln!(out, "Storage scan")?;
    writeln!(out, "  devices           : {}", report.devices.len())?;
    for d in &report.devices {
        writeln!(
            out,
            "    {} ({}) fstype={} ro={} mounted={}",
            d.name,
            d.dev_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "?".into()),
            d.filesystem.as_deref().unwrap_or("?"),
            d.read_only,
            d.mount_point
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "no".into()),
        )?;
    }
    writeln!(
        out,
        "  root candidates   : {}",
        report.root_candidates.len()
    )?;
    for c in &report.root_candidates {
        writeln!(
            out,
            "    {} confidence={:?} catos={:?} subvol={}",
            c.source,
            c.confidence,
            c.is_catos.status,
            c.subvolume.as_deref().unwrap_or("-"),
        )?;
    }
    writeln!(out, "  esp candidates    : {}", report.esp_candidates.len())?;
    for c in &report.esp_candidates {
        writeln!(out, "    {}", c.source)?;
    }
    if !report.btrfs_subvolumes.is_empty() {
        writeln!(
            out,
            "  btrfs subvolumes  : {}",
            report.btrfs_subvolumes.len()
        )?;
        for subvolume in &report.btrfs_subvolumes {
            writeln!(
                out,
                "    {} id={} kind={:?} default={} ro={}",
                subvolume.path,
                subvolume
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "?".into()),
                subvolume.kind,
                subvolume.is_default,
                subvolume.read_only
            )?;
        }
    }
    if !report.ambiguities.is_empty() {
        writeln!(out, "  ambiguities       : {}", report.ambiguities.len())?;
        for a in &report.ambiguities {
            writeln!(out, "    {:?}: {}", a.kind, a.candidates.join(", "))?;
        }
    }
    render_warnings(out, &report.warnings)
}

fn render_mount_plan<W: Write>(out: &mut W, plan: &MountPlan) -> std::io::Result<()> {
    writeln!(out, "Mount plan")?;
    writeln!(out, "  session root      : {}", plan.session_root.display())?;
    writeln!(out, "  target root       : {}", plan.target_root.display())?;
    if let Some(dev) = &plan.root_device {
        writeln!(out, "  root device       : {dev}")?;
    }
    if let Some(sub) = &plan.root_subvolume {
        writeln!(out, "  root subvolume    : {sub}")?;
    }
    writeln!(out, "  steps             : {}", plan.steps.len())?;
    for s in &plan.steps {
        writeln!(
            out,
            "    [{}] {} -> {} ({}, options={})",
            s.order,
            s.source,
            s.target.display(),
            s.fstype,
            s.options_string(),
        )?;
        for fm in &s.failure_modes {
            writeln!(out, "        failure mode: {fm}")?;
        }
    }
    writeln!(out, "  safety constraints:")?;
    for c in &plan.safety_constraints {
        writeln!(out, "    * {c}")?;
    }
    Ok(())
}

fn render_mount_session<W: Write>(out: &mut W, session: &MountSession) -> std::io::Result<()> {
    writeln!(out, "Mount session")?;
    writeln!(out, "  id                : {}", session.id)?;
    writeln!(out, "  state             : {:?}", session.state)?;
    writeln!(out, "  namespace         : {:?}", session.namespace)?;
    writeln!(
        out,
        "  session root      : {}",
        session.session_root.display()
    )?;
    writeln!(
        out,
        "  target root       : {}",
        session.target_root.display()
    )?;
    writeln!(out, "  active mounts     : {}", session.mounts.len())?;
    for m in &session.mounts {
        writeln!(
            out,
            "    [{}] {} on {} ({}, {})",
            m.order,
            m.source,
            m.target.display(),
            m.fstype,
            m.options,
        )?;
    }
    Ok(())
}

fn render_target_inspection<W: Write>(
    out: &mut W,
    inspection: &crate::target::model::TargetInspection,
) -> std::io::Result<()> {
    writeln!(out, "Target inspection")?;
    writeln!(
        out,
        "  CatOS             : {:?}",
        inspection.is_catos_target.status
    )?;
    writeln!(out, "  fstab             : {:?}", inspection.has_fstab)?;
    writeln!(out, "  pacman database   : {:?}", inspection.has_pacman_db)?;
    writeln!(out, "  /usr              : {:?}", inspection.has_usr)?;
    writeln!(out, "  /boot             : {:?}", inspection.has_boot)?;
    Ok(())
}

fn render_cleanup_report<W: Write>(out: &mut W, cleanup: &CleanupReport) -> std::io::Result<()> {
    writeln!(out, "Cleanup")?;
    writeln!(out, "  unmounted         : {}", cleanup.unmounted.len())?;
    writeln!(out, "  residual          : {}", cleanup.residual.len())?;
    for r in &cleanup.residual {
        writeln!(
            out,
            "    RESIDUAL {} on {}: {} ({})",
            r.resource.source,
            r.resource.target.display(),
            r.reason,
            r.error_code,
        )?;
    }
    if let Some(error) = &cleanup.directory_cleanup_error {
        writeln!(out, "  session directory : cleanup failed: {error}")?;
    }
    writeln!(out, "  all clean         : {}", cleanup.all_clean)?;
    Ok(())
}

fn render_warnings<W: Write>(
    out: &mut W,
    warnings: &[crate::target::model::Warning],
) -> std::io::Result<()> {
    if warnings.is_empty() {
        return Ok(());
    }
    writeln!(out, "Warnings")?;
    let permission_denied_blkid = warnings
        .iter()
        .filter(|warning| {
            warning.code == "BLKID_FAILED"
                && warning.message.to_ascii_lowercase().contains("permission denied")
        })
        .count();
    if permission_denied_blkid > 0 {
        writeln!(
            out,
            "  [BLKID_PERMISSION_DENIED] {permission_denied_blkid} devices could not be "
        )?;
        writeln!(
            out,
            "    probed without administrator privileges; rerun as root for complete metadata"
        )?;
    }
    for warning in warnings {
        if warning.code == "BLKID_FAILED"
            && warning.message.to_ascii_lowercase().contains("permission denied")
        {
            continue;
        }
        writeln!(out, "  [{}] {}", warning.code, warning.message)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::model::StorageReport;

    #[test]
    fn human_system_output_has_no_ansi_escapes() {
        let outcome = SystemCommandOutcome::StorageScan(StorageReport::default());
        let mut buf = Vec::new();
        render_system_human(&outcome, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains('\u{001b}'));
    }

    #[test]
    fn json_system_output_includes_envelope_keys() {
        let outcome = SystemCommandOutcome::StorageScan(StorageReport::default());
        let j = render_system_json(&outcome, "catos-system", std::path::Path::new("/")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["schemaVersion"], 2);
        assert_eq!(v["kind"], "storage_scan");
        assert!(v.get("payload").is_some());
    }

    #[test]
    fn human_warnings_aggregate_repeated_blkid_permission_failures() {
        let warnings = vec![
            crate::target::model::Warning::new(
                "BLKID_FAILED",
                "/usr/bin/blkid failed for /dev/a: Permission denied",
            ),
            crate::target::model::Warning::new(
                "BLKID_FAILED",
                "/usr/bin/blkid failed for /dev/b: Permission denied",
            ),
            crate::target::model::Warning::new("OTHER", "specific diagnostic"),
        ];
        let mut output = Vec::new();
        render_warnings(&mut output, &warnings).unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("2 devices could not be"));
        assert!(rendered.contains("specific diagnostic"));
        assert!(!rendered.contains("/dev/a"));
        assert!(!rendered.contains("/dev/b"));
    }

    #[test]
    fn mount_failure_json_preserves_structured_fields() {
        let error = Error::MountFailed(crate::mount::model::MountError {
            kind: crate::mount::model::MountErrorKind::DeviceNotFound,
            message: "missing device".into(),
            device_or_path: Some("/dev/missing".into()),
            errno: Some(2),
            completed_steps: vec!["root".into()],
            cleanup_complete: true,
            residual_mounts: vec![],
        });
        let json =
            render_system_error_json(&error, "catos-system", std::path::Path::new("/")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["kind"], "error");
        assert_eq!(value["error"]["code"], "device_not_found");
        assert_eq!(value["error"]["detail"]["errno"], 2);
        assert_eq!(value["error"]["detail"]["cleanup_complete"], true);
    }
}
