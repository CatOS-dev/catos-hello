//! Target selection for Doctor.
//!
//! Doctor identifies the target **directly via the `target` capability**,
//! not via `repair::mount_repair`. Target discovery is strictly
//! read-only: we confirm the running root when it identifies as CatOS,
//! and otherwise report `None`. We deliberately do not mount candidate
//! devices here — mounting is `repair`'s job.
//!
//! `TargetSelection` carries the canonical minimal
//! `target::model::TargetIdentity` straight from `target::plan`. No
//! mini→rich field remapping happens here. Downstream sections that
//! previously consumed the richer `shared::model::mount_repair::
//! TargetIdentity` shape now take the minimal identity directly; the
//! ESP / boot-layout signals (which were always `None` on this path,
//! because `target::plan` never discovers them) are open design points
//! to be wired through each section's own capability path in a later
//! phase.

use crate::doctor::model::{DoctorTarget, DoctorTargetKind};
use crate::selection_ui::{select_target, Selection};
use crate::target::discovery::{discover_targets, ProbeCleanup, TargetSession};
use crate::target::model::TargetIdentity;
#[cfg(test)]
use crate::target::plan::{TargetPlan, TargetPlanKind};

pub struct SelectedTargetSession {
    pub target: TargetIdentity,
    pub session: TargetSession,
    pub inventory: Vec<crate::target::model::BlockDevice>,
    pub discovery_cleanup: Vec<ProbeCleanup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetDiscoveryErrorKind {
    NotFound,
    Ambiguous,
    Declined,
    CleanupIncomplete,
    OpenFailed,
}

#[derive(Debug, Clone)]
pub struct TargetDiscoveryError {
    pub kind: TargetDiscoveryErrorKind,
    pub reason: String,
    pub candidates: Vec<String>,
    pub cleanup: Vec<ProbeCleanup>,
}

#[derive(Debug, Clone)]
pub enum TargetSelection {
    Identified(TargetIdentity),
    None { reason: String },
    Ambiguous { candidates: Vec<String> },
}

impl TargetSelection {
    pub fn to_target_summary(&self) -> DoctorTarget {
        match self {
            TargetSelection::Identified(target) => {
                let kind = if target.root_device.as_deref() == Some(std::path::Path::new("/")) {
                    DoctorTargetKind::RunningRoot
                } else {
                    DoctorTargetKind::Offline
                };
                DoctorTarget {
                    kind,
                    root_device: target
                        .root_device
                        .as_deref()
                        .and_then(|p| p.to_str())
                        .map(str::to_string),
                    root_fstype: target.root_fstype.clone(),
                    root_subvolume: target.root_subvol.clone(),
                    esp_device: None,
                    boot_layout: None,
                }
            }
            TargetSelection::None { .. } | TargetSelection::Ambiguous { .. } => DoctorTarget {
                kind: DoctorTargetKind::None,
                ..DoctorTarget::default()
            },
        }
    }
}

pub fn discover_target() -> TargetSelection {
    match select_target(&discover_targets(), "catos-doctor") {
        Selection::Selected(candidate) => TargetSelection::Identified(TargetIdentity {
            // Group 1 deliberately does not retain a probe mount. A later
            // diagnostic session mounts this candidate and replaces this
            // inaccessible sentinel; it prevents any section from silently
            // reading the Live host root meanwhile.
            root: std::path::PathBuf::from("/run/catos-target-unmounted"),
            root_device: Some(candidate.root_device),
            root_fstype: Some(candidate.root_fstype),
            root_subvol: candidate.root_subvolume,
            root_uuid: candidate.root_uuid,
        }),
        Selection::Declined => TargetSelection::None {
            reason: "operator declined the discovered target".into(),
        },
        Selection::Unavailable(reason) => TargetSelection::None { reason },
    }
}

pub fn discover_target_session() -> Result<SelectedTargetSession, TargetDiscoveryError> {
    let report = discover_targets();
    let dirty_cleanup = report
        .cleanup
        .iter()
        .filter(|cleanup| !cleanup.is_clean())
        .map(|cleanup| {
            format!(
                "{}: {}",
                cleanup.mountpoint.display(),
                cleanup
                    .error
                    .as_deref()
                    .unwrap_or("probe mountpoint was not fully removed")
            )
        })
        .collect::<Vec<_>>();
    if !dirty_cleanup.is_empty() {
        return Err(TargetDiscoveryError {
            kind: TargetDiscoveryErrorKind::CleanupIncomplete,
            reason: format!(
                "readonly target discovery cleanup incomplete: {}",
                dirty_cleanup.join("; ")
            ),
            candidates: Vec::new(),
            cleanup: report.cleanup,
        });
    }
    let candidate = match select_target(&report, "catos-doctor") {
        Selection::Selected(candidate) => *candidate,
        Selection::Declined => {
            return Err(TargetDiscoveryError {
                kind: TargetDiscoveryErrorKind::Declined,
                reason: "operator declined the discovered target".into(),
                candidates: Vec::new(),
                cleanup: report.cleanup,
            })
        }
        Selection::Unavailable(reason) => return Err(unavailable_error(report, reason)),
    };
    let session = TargetSession::open(candidate).map_err(|error| TargetDiscoveryError {
        kind: TargetDiscoveryErrorKind::OpenFailed,
        reason: format!("open selected readonly target: {error}"),
        candidates: Vec::new(),
        cleanup: report.cleanup.clone(),
    })?;
    let target = TargetIdentity {
        root: session.root().to_path_buf(),
        root_device: Some(session.candidate().root_device.clone()),
        root_fstype: Some(session.candidate().root_fstype.clone()),
        root_subvol: session.candidate().root_subvolume.clone(),
        root_uuid: session.candidate().root_uuid.clone(),
    };
    Ok(SelectedTargetSession {
        target,
        session,
        inventory: report.inventory,
        discovery_cleanup: report.cleanup,
    })
}

fn unavailable_error(
    report: crate::target::discovery::DiscoveryReport,
    reason: String,
) -> TargetDiscoveryError {
    let candidates = report
        .candidates
        .iter()
        .map(crate::selection_ui::summary)
        .collect::<Vec<_>>();
    TargetDiscoveryError {
        kind: if candidates.is_empty() {
            TargetDiscoveryErrorKind::NotFound
        } else {
            TargetDiscoveryErrorKind::Ambiguous
        },
        reason,
        candidates,
        cleanup: report.cleanup,
    }
}

/// Map a [`TargetPlan`] to a [`TargetSelection`] without any field
/// remapping: the plan's [`TargetIdentity`] flows through unchanged.
#[cfg(test)]
pub(super) fn from_plan(plan: TargetPlan) -> TargetSelection {
    match plan.kind {
        TargetPlanKind::RunningRoot | TargetPlanKind::Offline => match plan.identity {
            Some(identity) => TargetSelection::Identified(identity),
            None => TargetSelection::None {
                reason: "target plan carried no identity".to_string(),
            },
        },
        TargetPlanKind::Ambiguous => TargetSelection::Ambiguous {
            candidates: plan.candidates,
        },
        TargetPlanKind::None => TargetSelection::None {
            reason: if plan.warnings.is_empty() {
                "no device on the system was confirmed as a CatOS target".to_string()
            } else {
                plan.warnings.join("; ")
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn plan(kind: TargetPlanKind, identity: Option<TargetIdentity>) -> TargetPlan {
        TargetPlan {
            kind,
            identity,
            candidates: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn offline_identity() -> TargetIdentity {
        TargetIdentity {
            root: PathBuf::from("/dev/nvme0n1p2"),
            root_device: Some(PathBuf::from("/dev/nvme0n1p2")),
            root_fstype: Some("btrfs".into()),
            root_subvol: Some("/@".into()),
            root_uuid: Some("root-uuid".into()),
        }
    }

    fn candidate(path: &str) -> crate::target::discovery::TargetCandidate {
        crate::target::discovery::TargetCandidate {
            root_device: PathBuf::from(path),
            root_fstype: "btrfs".into(),
            root_uuid: Some(format!("uuid-{path}")),
            root_subvolume: Some("/@".into()),
            root_subvolume_id: Some(256),
            filesystem_id: Some("fsid".into()),
            label: None,
            os_release: crate::target::model::OsRelease {
                pretty_name: Some("CatOS".into()),
                ..Default::default()
            },
            fstab_identity: None,
            currently_mounted: false,
            running_environment_member: false,
            confidence: crate::target::model::RootCandidateConfidence::High,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn unavailable_discovery_with_candidates_is_ambiguous() {
        let report = crate::target::discovery::DiscoveryReport {
            candidates: vec![candidate("/dev/vda"), candidate("/dev/vdb")],
            ..Default::default()
        };
        let error = unavailable_error(
            report,
            "multiple target candidates require an interactive terminal".into(),
        );
        assert_eq!(error.kind, TargetDiscoveryErrorKind::Ambiguous);
        assert_eq!(error.candidates.len(), 2);
        assert!(error.candidates[0].contains("/dev/vda"));
    }

    #[test]
    fn unavailable_discovery_without_candidates_is_not_found() {
        let error = unavailable_error(
            crate::target::discovery::DiscoveryReport::default(),
            "no CatOS candidate".into(),
        );
        assert_eq!(error.kind, TargetDiscoveryErrorKind::NotFound);
        assert!(error.candidates.is_empty());
    }

    #[test]
    fn running_root_plan_yields_identified_selection() {
        let mut p = plan(TargetPlanKind::RunningRoot, None);
        p.identity = Some(TargetIdentity {
            root: PathBuf::from("/"),
            ..TargetIdentity::default()
        });
        let sel = from_plan(p);
        match sel {
            TargetSelection::Identified(t) => assert_eq!(t.root, PathBuf::from("/")),
            other => panic!("expected Identified, got {other:?}"),
        }
    }

    #[test]
    fn ambiguous_plan_yields_ambiguous_selection() {
        let mut p = plan(TargetPlanKind::Ambiguous, None);
        p.candidates = vec!["/dev/sda2".into(), "/dev/sdb2".into()];
        let sel = from_plan(p);
        match sel {
            TargetSelection::Ambiguous { candidates } => assert_eq!(candidates.len(), 2),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn none_plan_yields_none_selection_with_reason() {
        let mut p = plan(TargetPlanKind::None, None);
        p.warnings = vec!["no CatOS root".to_string()];
        let sel = from_plan(p);
        match sel {
            TargetSelection::None { reason } => assert!(reason.contains("no CatOS root")),
            other => panic!("expected None, got {other:?}"),
        }
    }

    #[test]
    fn target_summary_carries_device_paths_for_offline_target() {
        let sel = TargetSelection::Identified(TargetIdentity {
            root_device: Some(PathBuf::from("/dev/nvme0n1p2")),
            root_fstype: Some("btrfs".into()),
            root_subvol: Some("/@".into()),
            ..TargetIdentity::default()
        });
        let summary = sel.to_target_summary();
        assert_eq!(summary.root_device.as_deref(), Some("/dev/nvme0n1p2"));
        assert_eq!(summary.root_fstype.as_deref(), Some("btrfs"));
        assert_eq!(summary.root_subvolume.as_deref(), Some("/@"));
    }

    #[test]
    fn target_summary_for_none_uses_none_kind() {
        use crate::doctor::model::DoctorTargetKind;
        let sel = TargetSelection::None { reason: "x".into() };
        assert_eq!(sel.to_target_summary().kind, DoctorTargetKind::None);
    }

    /// The minimal identity flows through `from_plan` unchanged — no
    /// field remapping, no esp/boot_layout invention.
    #[test]
    fn minimal_identity_flows_through_unchanged() {
        let p = plan(TargetPlanKind::Offline, Some(offline_identity()));
        let sel = from_plan(p);
        match sel {
            TargetSelection::Identified(t) => {
                assert_eq!(
                    t.root_device.as_deref(),
                    Some(std::path::Path::new("/dev/nvme0n1p2"))
                );
                assert_eq!(t.root_fstype.as_deref(), Some("btrfs"));
                assert_eq!(t.root_subvol.as_deref(), Some("/@"));
                assert_eq!(t.root_uuid.as_deref(), Some("root-uuid"));
            }
            other => panic!("expected Identified, got {other:?}"),
        }
    }
}
