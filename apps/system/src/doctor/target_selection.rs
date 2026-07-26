//! Target selection for Doctor. Reuses the stage-3 mount-repair
//! discovery machinery so Doctor's notion of "the target" can never
//! diverge from `catos-repair mount`'s notion.
//!
//! Decision tree (per spec section 四):
//!
//! 1. If the running root is uniquely confirmed as CatOS, select it.
//! 2. Otherwise, perform target discovery. A single high-confidence
//!    CatOS target is selected.
//! 3. Multiple high-confidence targets → `Ambiguous`.
//! 4. Zero targets → `None`.
//!
//! We never fall back to "the first plausible device". The spec is
//! explicit: 不因为 `/dev/sda2` 排在最前就选择它.

use crate::model::doctor::{DoctorTarget, DoctorTargetKind};
use crate::model::mount_repair::{
    BootMountLayout, MountRepairOutcome, MountRepairReport, TargetIdentity,
};
use crate::repair::mount_repair::run_mount_repair_via_cli;

#[derive(Debug, Clone)]
pub enum TargetSelection {
    Identified(TargetIdentity),
    None { reason: String },
    Ambiguous { candidates: Vec<String> },
}

impl TargetSelection {
    pub fn to_target_summary(&self) -> DoctorTarget {
        match self {
            TargetSelection::Identified(target) => target_summary_for(target),
            TargetSelection::None { .. } | TargetSelection::Ambiguous { .. } => DoctorTarget {
                kind: DoctorTargetKind::None,
                ..DoctorTarget::default()
            },
        }
    }
}

fn target_summary_for(target: &TargetIdentity) -> DoctorTarget {
    DoctorTarget {
        kind: DoctorTargetKind::Offline,
        root_device: target.root_device.to_str().map(str::to_string),
        root_fstype: Some(target.root_fstype.clone()),
        root_subvolume: target.root_subvol.clone(),
        esp_device: target
            .esp_device
            .as_deref()
            .and_then(|p| p.to_str())
            .map(str::to_string),
        boot_layout: target.boot_layout.as_ref().map(layout_label),
    }
}

fn layout_label(layout: &BootMountLayout) -> String {
    use BootMountLayout::*;
    match layout {
        EspAtBootEfi { .. } => "esp_at_boot_efi",
        EspAtEfi { .. } => "esp_at_efi",
        EspAtBoot { .. } => "esp_at_boot",
        SeparateBootAndEsp { .. } => "separate_boot_and_esp",
        BootBtrfsSubvolume { .. } => "boot_btrfs_subvolume",
        BootInsideRoot => "boot_inside_root",
    }
    .to_string()
}

pub fn discover_target() -> TargetSelection {
    let report: MountRepairReport = run_mount_repair_via_cli(None, None, None, false);
    translate_mount_report(report)
}

pub(super) fn translate_mount_report(report: MountRepairReport) -> TargetSelection {
    match report.target {
        Some(target) => TargetSelection::Identified(target),
        None => match report.final_outcome {
            MountRepairOutcome::AmbiguousTarget => TargetSelection::Ambiguous {
                candidates: collect_candidate_descriptions(&report),
            },
            MountRepairOutcome::NotCatos => TargetSelection::None {
                reason: "no device on the system was confirmed as a CatOS target".to_string(),
            },
            other => TargetSelection::None {
                reason: format!(
                    "mount-repair discovery returned outcome {} without a target identity",
                    other.code()
                ),
            },
        },
    }
}

fn collect_candidate_descriptions(report: &MountRepairReport) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for evidence in &report.evidence {
        if evidence.code == "AUTO_DISCOVERY_REFUSED" || evidence.code.contains("AMBIGUOUS") {
            out.push(evidence.message.clone());
        }
    }
    if out.is_empty() {
        out.push("multiple CatOS root candidates discovered".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::evidence::Evidence;
    use crate::model::mount_repair::MountRepairCleanup;
    use std::path::PathBuf;

    fn sample_target() -> TargetIdentity {
        TargetIdentity {
            root_device: PathBuf::from("/dev/nvme0n1p2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("root-uuid".into()),
            esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
            esp_uuid: Some("esp-uuid".into()),
            boot_layout: None,
        }
    }

    fn refused_report(outcome: MountRepairOutcome, reason: &str) -> MountRepairReport {
        MountRepairReport {
            target: None,
            plan: None,
            fstab_transaction: None,
            actions: Vec::new(),
            verification: None,
            cleanup: MountRepairCleanup::default(),
            final_outcome: outcome,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new("REFUSED", "test", reason)],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn identified_report_translates_to_identified_selection() {
        let mut report = refused_report(MountRepairOutcome::Clean, "stub");
        report.target = Some(sample_target());
        report.final_outcome = MountRepairOutcome::Clean;
        let sel = translate_mount_report(report);
        assert!(matches!(sel, TargetSelection::Identified(_)));
    }

    #[test]
    fn ambiguous_outcome_translates_to_ambiguous_selection() {
        let report = refused_report(MountRepairOutcome::AmbiguousTarget, "ambiguous");
        let sel = translate_mount_report(report);
        match sel {
            TargetSelection::Ambiguous { candidates } => assert!(!candidates.is_empty()),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn none_outcome_translates_to_none_selection_with_reason() {
        let report = refused_report(MountRepairOutcome::NotCatos, "not catos");
        let sel = translate_mount_report(report);
        match sel {
            TargetSelection::None { reason } => assert!(!reason.is_empty()),
            other => panic!("expected None, got {other:?}"),
        }
    }

    #[test]
    fn target_summary_carries_device_paths_for_identified_target() {
        let sel = TargetSelection::Identified(sample_target());
        let summary = sel.to_target_summary();
        assert_eq!(summary.root_device.as_deref(), Some("/dev/nvme0n1p2"));
        assert_eq!(summary.root_fstype.as_deref(), Some("btrfs"));
        assert_eq!(summary.root_subvolume.as_deref(), Some("/@"));
        assert_eq!(summary.esp_device.as_deref(), Some("/dev/nvme0n1p1"));
    }

    #[test]
    fn target_summary_for_none_uses_none_kind() {
        let sel = TargetSelection::None { reason: "x".into() };
        assert_eq!(sel.to_target_summary().kind, DoctorTargetKind::None);
    }
}
