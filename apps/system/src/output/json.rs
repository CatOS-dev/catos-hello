//! JSON rendering. Thin wrapper over serde_json so the JSON contract has a
//! single owner. No ANSI escapes, no progress text, no log lines.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::cli::View;
use crate::shared::error::Error;
use crate::model::inspection::InspectionReport;

/// Serialise the report to a pretty-printed JSON string under the given
/// view. Errors are converted to [`Error::SerializeFailed`].
pub fn render_json(report: &InspectionReport, view: View) -> Result<String, Error> {
    let wrapper = ReportViewSerializer { report, view };
    serde_json::to_string_pretty(&wrapper).map_err(|e| Error::SerializeFailed(e.to_string()))
}

/// Wrapper that, when serialised, emits only the keys selected by the view.
/// We implement Serialize manually because serde derive cannot express
/// "include this field conditionally".
struct ReportViewSerializer<'a> {
    report: &'a InspectionReport,
    view: View,
}

impl<'a> Serialize for ReportViewSerializer<'a> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let view = self.view;
        let r = self.report;
        let mut section_count = 0;
        if view.runtime {
            section_count += 1;
        }
        if view.capabilities {
            section_count += 1;
        }
        if view.target {
            section_count += 1;
        }
        let mut map = s.serialize_map(Some(5 + section_count))?;
        map.serialize_entry("schemaVersion", &r.schema_version)?;
        map.serialize_entry("programVersion", &r.program_version)?;
        map.serialize_entry("invocation", &r.invocation)?;
        map.serialize_entry("targetRoot", &r.target_root)?;
        if view.runtime {
            map.serialize_entry("runtime", &r.runtime)?;
        }
        if view.capabilities {
            map.serialize_entry("capabilities", &r.capabilities)?;
        }
        if view.target {
            map.serialize_entry("target", &r.target)?;
        }
        map.serialize_entry("warnings", &r.warnings)?;
        map.end()
    }
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
                has_fstab: crate::model::Presence::Present,
                has_crypttab: crate::model::Presence::Absent,
                has_pacman_db: crate::model::Presence::Present,
                has_usr: crate::model::Presence::Present,
                has_boot: crate::model::Presence::Present,
                has_efi: crate::model::Presence::Absent,
                has_boot_efi: crate::model::Presence::Absent,
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
    fn schema_version_is_two() {
        let r = sample_report();
        let j = render_json(&r, full_view()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["schemaVersion"].as_u64(), Some(2));
    }

    #[test]
    fn full_view_emits_all_top_level_keys() {
        let r = sample_report();
        let j = render_json(&r, full_view()).unwrap();
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
    fn environment_view_omits_capabilities_and_target() {
        let r = sample_report();
        let v = View {
            runtime: true,
            capabilities: false,
            target: false,
        };
        let j = render_json(&r, v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert!(parsed.get("runtime").is_some_and(|v| v.is_object()));
        assert!(parsed.get("capabilities").is_none());
        assert!(parsed.get("target").is_none());
    }

    #[test]
    fn capabilities_view_omits_runtime_and_target() {
        let r = sample_report();
        let v = View {
            runtime: false,
            capabilities: true,
            target: false,
        };
        let j = render_json(&r, v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert!(parsed.get("runtime").is_none());
        assert!(parsed.get("capabilities").is_some_and(|v| v.is_array()));
        assert!(parsed.get("target").is_none());
    }

    #[test]
    fn inspect_view_emits_all_three_sections() {
        let r = sample_report();
        let v = View {
            runtime: true,
            capabilities: true,
            target: true,
        };
        let j = render_json(&r, v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert!(parsed.get("runtime").is_some_and(|v| v.is_object()));
        assert!(parsed.get("capabilities").is_some_and(|v| v.is_array()));
        assert!(parsed.get("target").is_some_and(|v| v.is_object()));
    }

    #[test]
    fn unconditional_keys_present_in_every_view() {
        let r = sample_report();
        for v in [
            View {
                runtime: true,
                capabilities: false,
                target: false,
            },
            View {
                runtime: false,
                capabilities: true,
                target: false,
            },
            View {
                runtime: false,
                capabilities: false,
                target: true,
            },
        ] {
            let j = render_json(&r, v).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&j).unwrap();
            for key in [
                "schemaVersion",
                "programVersion",
                "invocation",
                "targetRoot",
                "warnings",
            ] {
                assert!(parsed.get(key).is_some(), "missing {key} in view {v:?}");
            }
        }
    }

    #[test]
    fn unknown_status_not_serialised_as_false() {
        let r = sample_report();
        let j = render_json(&r, full_view()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["runtime"]["is_initramfs"]["status"], "unknown");
        assert!(v["runtime"]["is_initramfs"]["status"].is_string());
    }

    #[test]
    fn presence_unknown_not_serialised_as_bool() {
        let mut r = sample_report();
        r.target.has_boot = crate::model::Presence::Unknown;
        let j = render_json(&r, full_view()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["target"]["has_boot"], "unknown");
        assert!(v["target"]["has_boot"].is_string());
    }

    #[test]
    fn no_ansi_escapes_in_output() {
        let r = sample_report();
        for v in [
            View {
                runtime: true,
                capabilities: false,
                target: false,
            },
            View {
                runtime: false,
                capabilities: true,
                target: false,
            },
            View {
                runtime: true,
                capabilities: true,
                target: true,
            },
        ] {
            let j = render_json(&r, v).unwrap();
            assert!(
                !j.contains('\u{001b}'),
                "JSON contains ANSI escape in view {v:?}"
            );
        }
    }

    #[test]
    fn enum_serialisation_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&CapabilityStatus::Available).unwrap(),
            "\"available\""
        );
        assert_eq!(
            serde_json::to_string(&CapabilityStatus::Unavailable).unwrap(),
            "\"unavailable\""
        );
        assert_eq!(
            serde_json::to_string(&CapabilityStatus::Unknown).unwrap(),
            "\"unknown\""
        );
        assert_eq!(
            serde_json::to_string(&PrimaryRuntimeMode::LiveEnvironment).unwrap(),
            "\"live_environment\""
        );
        assert_eq!(
            serde_json::to_string(&CapabilityKind::ReadProc).unwrap(),
            "\"read_proc\""
        );
        assert_eq!(
            serde_json::to_string(&DetectionStatus::NotDetected).unwrap(),
            "\"not_detected\""
        );
        assert_eq!(
            serde_json::to_string(&crate::model::Presence::Present).unwrap(),
            "\"present\""
        );
        assert_eq!(
            serde_json::to_string(&crate::model::Presence::Absent).unwrap(),
            "\"absent\""
        );
        assert_eq!(
            serde_json::to_string(&crate::model::Presence::Unknown).unwrap(),
            "\"unknown\""
        );
    }
}
