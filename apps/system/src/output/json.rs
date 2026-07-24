//! JSON rendering. Thin wrapper over serde_json so the JSON contract has a
//! single owner. No ANSI escapes, no progress text, no log lines.

use crate::error::Error;
use crate::model::inspection::InspectionReport;

/// Serialise the report to a pretty-printed JSON string. Errors are converted
/// to [`Error::SerializeFailed`].
pub fn render_json(report: &InspectionReport) -> Result<String, Error> {
    serde_json::to_string_pretty(report).map_err(|e| Error::SerializeFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::capability::{Capability, CapabilityKind, CapabilityStatus};
    use crate::model::evidence::Evidence;
    use crate::model::inspection::{TargetInspection, Warning};
    use crate::model::runtime::{Detection, DetectionStatus, PrimaryRuntimeMode, RuntimeFacts};
    use crate::SCHEMA_VERSION;
    use std::path::PathBuf;

    fn sample_report() -> InspectionReport {
        InspectionReport {
            schema_version: SCHEMA_VERSION,
            program_version: "0.0.0-test".to_string(),
            invocation: "catos-system".to_string(),
            target_root: PathBuf::from("/"),
            runtime: RuntimeFacts {
                is_initramfs: Detection::unknown(vec![]),
                is_chroot: Detection::detected(vec![Evidence::new("TEST", "/", "x")]),
                is_live_environment: Detection::not_detected(vec![]),
                is_snapshot_boot: Detection::unknown(vec![]),
                has_systemd: Detection::detected(vec![]),
                root_is_read_only: Detection::not_detected(vec![]),
            },
            capabilities: vec![Capability {
                name: CapabilityKind::PacmanPresentInTarget,
                status: CapabilityStatus::Unavailable,
                evidence: vec![],
            }],
            target: TargetInspection {
                root: PathBuf::from("/"),
                os_release: None,
                has_fstab: true,
                has_crypttab: false,
                has_pacman_db: true,
                has_usr: true,
                has_boot: true,
                has_efi: false,
                has_boot_efi: false,
                is_catos_target: Detection::unknown(vec![]),
                tool_paths: vec![],
            },
            warnings: vec![Warning::new("W", "warn")],
        }
    }

    #[test]
    fn schema_version_is_one() {
        let r = sample_report();
        let j = render_json(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["schemaVersion"].as_u64(), Some(1));
    }

    #[test]
    fn required_top_level_keys_present() {
        let r = sample_report();
        let j = render_json(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        for key in [
            "schemaVersion",
            "programVersion",
            "invocation",
            "targetRoot",
            "runtime",
            "capabilities",
            "target",
            "warnings",
        ] {
            assert!(v.get(key).is_some(), "missing top-level key {key}");
        }
    }

    #[test]
    fn unknown_status_not_serialised_as_false() {
        let r = sample_report();
        let j = render_json(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["runtime"]["is_initramfs"]["status"], "unknown");
        // Must not be a JSON boolean.
        assert!(v["runtime"]["is_initramfs"]["status"].is_string());
    }

    #[test]
    fn no_ansi_escapes_in_output() {
        let r = sample_report();
        let j = render_json(&r).unwrap();
        // No ESC (0x1b) anywhere.
        assert!(!j.contains('\u{001b}'), "JSON contains ANSI escape");
    }

    #[test]
    fn enum_serialisation_is_snake_case() {
        // Verify a few enum values round-trip with stable strings.
        let s = serde_json::to_string(&CapabilityStatus::Available).unwrap();
        assert_eq!(s, "\"available\"");
        let s = serde_json::to_string(&CapabilityStatus::Unavailable).unwrap();
        assert_eq!(s, "\"unavailable\"");
        let s = serde_json::to_string(&CapabilityStatus::Unknown).unwrap();
        assert_eq!(s, "\"unknown\"");
        let s = serde_json::to_string(&PrimaryRuntimeMode::LiveEnvironment).unwrap();
        assert_eq!(s, "\"live_environment\"");
        let s = serde_json::to_string(&CapabilityKind::ReadProc).unwrap();
        assert_eq!(s, "\"read_proc\"");
        let s = serde_json::to_string(&DetectionStatus::NotDetected).unwrap();
        assert_eq!(s, "\"not_detected\"");
    }
}
