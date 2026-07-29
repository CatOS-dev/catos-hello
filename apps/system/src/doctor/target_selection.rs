//! Target selection for Doctor.
//!
//! The shared discovery layer reports both the current process root and
//! offline CatOS installations as facts. Doctor applies its own policy:
//! prefer the confirmed running CatOS root in an installed system or chroot,
//! but select only offline targets from Live and initramfs environments.
//! Offline targets are held on explicit read-only/no-replay mounts; the
//! running root is borrowed directly at `/` and is never remounted.

use crate::doctor::model::{DoctorTarget, DoctorTargetKind};
use crate::selection_ui::{select_target_with_policy, Selection, TargetSelectionPolicy};
use crate::target::discovery::{
    discover_running_root, discover_targets, DiscoveryReport, ProbeCleanup, TargetSession,
};
use crate::target::model::TargetIdentity;

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

pub fn target_summary(target: &TargetIdentity) -> DoctorTarget {
    let kind = if target.root == std::path::Path::new("/") {
        DoctorTargetKind::RunningRoot
    } else {
        DoctorTargetKind::Offline
    };
    DoctorTarget {
        kind,
        root_device: target
            .root_device
            .as_deref()
            .and_then(|path| path.to_str())
            .map(str::to_string),
        root_fstype: target.root_fstype.clone(),
        root_subvolume: target.root_subvol.clone(),
        esp_device: None,
        boot_layout: None,
    }
}

pub fn discover_target_session() -> Result<SelectedTargetSession, TargetDiscoveryError> {
    let policy = current_doctor_selection_policy();
    let report = discover_for_policy(policy);
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
    let candidate = match select_target_with_policy(&report, "catos-doctor", policy) {
        Selection::Selected(candidate) => *candidate,
        Selection::Declined => {
            return Err(TargetDiscoveryError {
                kind: TargetDiscoveryErrorKind::Declined,
                reason: "operator declined the discovered target".into(),
                candidates: Vec::new(),
                cleanup: report.cleanup,
            })
        }
        Selection::Unavailable(reason) => return Err(unavailable_error(report, reason, policy)),
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

fn discover_for_policy(policy: TargetSelectionPolicy) -> DiscoveryReport {
    if policy == TargetSelectionPolicy::PreferRunningRoot {
        let running = discover_running_root();
        if running
            .candidates
            .iter()
            .any(|candidate| candidate.running_environment_member)
        {
            return running;
        }
    }
    discover_targets()
}

fn current_doctor_selection_policy() -> TargetSelectionPolicy {
    let fs = crate::target::diagnose::filesystem::RealFilesystem;
    let runtime = crate::target::diagnose::runtime::detect_runtime(&fs);
    doctor_selection_policy(runtime.primary_mode())
}

fn doctor_selection_policy(
    mode: crate::target::model::PrimaryRuntimeMode,
) -> TargetSelectionPolicy {
    use crate::target::model::PrimaryRuntimeMode;
    match mode {
        PrimaryRuntimeMode::RunningSystem | PrimaryRuntimeMode::Chroot => {
            TargetSelectionPolicy::PreferRunningRoot
        }
        PrimaryRuntimeMode::LiveEnvironment | PrimaryRuntimeMode::Initramfs => {
            TargetSelectionPolicy::OfflineOnly
        }
        PrimaryRuntimeMode::Unknown => TargetSelectionPolicy::PreferRunningRoot,
    }
}

fn unavailable_error(
    report: crate::target::discovery::DiscoveryReport,
    reason: String,
    policy: TargetSelectionPolicy,
) -> TargetDiscoveryError {
    let running_count = report
        .candidates
        .iter()
        .filter(|candidate| candidate.running_environment_member)
        .count();
    let candidates = report
        .candidates
        .iter()
        .filter(|candidate| match policy {
            TargetSelectionPolicy::Any => true,
            TargetSelectionPolicy::OfflineOnly
            | TargetSelectionPolicy::OfflineOnlyAllowUnverified => {
                !candidate.running_environment_member
            }
            TargetSelectionPolicy::PreferRunningRoot if running_count > 1 => {
                candidate.running_environment_member
            }
            TargetSelectionPolicy::PreferRunningRoot => !candidate.running_environment_member,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
            TargetSelectionPolicy::Any,
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
            TargetSelectionPolicy::OfflineOnly,
        );
        assert_eq!(error.kind, TargetDiscoveryErrorKind::NotFound);
        assert!(error.candidates.is_empty());
    }

    #[test]
    fn offline_policy_does_not_report_the_live_root_as_ambiguous() {
        let mut running = candidate("/dev/live-root");
        running.running_environment_member = true;
        running.currently_mounted = true;
        let report = crate::target::discovery::DiscoveryReport {
            candidates: vec![running],
            ..Default::default()
        };
        let error = unavailable_error(
            report,
            "no offline CatOS candidate".into(),
            TargetSelectionPolicy::OfflineOnly,
        );
        assert_eq!(error.kind, TargetDiscoveryErrorKind::NotFound);
        assert!(error.candidates.is_empty());
    }

    #[test]
    fn doctor_policy_prefers_running_root_outside_live_environments() {
        use crate::target::model::PrimaryRuntimeMode;
        assert_eq!(
            doctor_selection_policy(PrimaryRuntimeMode::RunningSystem),
            crate::selection_ui::TargetSelectionPolicy::PreferRunningRoot
        );
        assert_eq!(
            doctor_selection_policy(PrimaryRuntimeMode::Chroot),
            crate::selection_ui::TargetSelectionPolicy::PreferRunningRoot
        );
        assert_eq!(
            doctor_selection_policy(PrimaryRuntimeMode::Unknown),
            crate::selection_ui::TargetSelectionPolicy::PreferRunningRoot
        );
        assert_eq!(
            doctor_selection_policy(PrimaryRuntimeMode::LiveEnvironment),
            crate::selection_ui::TargetSelectionPolicy::OfflineOnly
        );
        assert_eq!(
            doctor_selection_policy(PrimaryRuntimeMode::Initramfs),
            crate::selection_ui::TargetSelectionPolicy::OfflineOnly
        );
    }

    #[test]
    fn target_summary_classifies_root_path_as_running_root() {
        let sel = TargetIdentity {
            root: PathBuf::from("/"),
            root_device: Some(PathBuf::from("/dev/nvme0n1p2")),
            root_fstype: Some("btrfs".into()),
            root_subvol: Some("/@".into()),
            root_uuid: Some("root-uuid".into()),
        };
        assert_eq!(
            target_summary(&sel).kind,
            crate::doctor::model::DoctorTargetKind::RunningRoot
        );
    }

    #[test]
    fn target_summary_carries_device_paths_for_offline_target() {
        let sel = TargetIdentity {
            root_device: Some(PathBuf::from("/dev/nvme0n1p2")),
            root_fstype: Some("btrfs".into()),
            root_subvol: Some("/@".into()),
            ..TargetIdentity::default()
        };
        let summary = target_summary(&sel);
        assert_eq!(summary.root_device.as_deref(), Some("/dev/nvme0n1p2"));
        assert_eq!(summary.root_fstype.as_deref(), Some("btrfs"));
        assert_eq!(summary.root_subvolume.as_deref(), Some("/@"));
    }
}
