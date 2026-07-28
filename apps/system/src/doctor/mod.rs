//! `catos-doctor` orchestrator. Read-only aggregated diagnosis that
//! stitches together the existing pure diagnosis surfaces from
//! stages 1–4:
//!
//! * environment and target discovery: `entry::build_report` and storage scan
//! * filesystem: `fs::diagnose::check_only_for`
//! * mount layout and fstab: `repair::mount_repair::diagnose`
//! * boot provider: `boot::diagnose::provider::detect`
//! * recovery: `recovery::engine::Engine::load` and
//!   `reconcile_status`, both read-only)
//!
//! ## Hard rules
//!
//! * Doctor NEVER writes to the target. The only resources it may
//!   clean up are mounts it created itself inside its private mount
//!   namespace. See [`DoctorCleanup`].
//! * Target selection does not route through `repair`; Doctor resolves
//!   the target via `target::plan` only. Section-level diagnosis still
//!   consumes repair flows (`check_only_for`, `mount_repair::diagnose`,
//!   `boot::diagnose::provider`) in read-only mode pending later phases that
//!   will move those surfaces under the `target` capability.
//! * Doctor NEVER invokes the boot provider's `execute` or `verify`
//!   methods; it only consults the pure `detect()` function and
//!   reads deployed asset files directly.
//! * Doctor NEVER calls `Engine::load_for_write`,
//!   `Engine::load_for_revert`, `Engine::begin`, `Engine::drive`, or
//!   `Engine::revert`. Only the non-locking `Engine::load` +
//!   `reconcile_status` pair is used.
//! * Exit-code scheme B: `overall_status` and the process exit code
//!   are independent. Doctor returns 0 whenever it produced a report,
//!   even if every section found a problem.

pub mod model;
mod sections;

use crate::doctor::model::{
    issue_code, recommendation_code, DoctorCleanup, DoctorEnvironment, DoctorIssue,
    DoctorOverallStatus, DoctorRecommendation, DoctorReport, DoctorSection, DoctorSectionId,
    DoctorSectionStatus, DoctorSeverity, DoctorTarget, DoctorTargetKind,
};
use crate::fs::command::FsCommandRunner;
use crate::target::discovery::{ReadonlySession, TargetCandidate, TargetSession};
use crate::target::Evidence;

pub mod target_selection;
use target_selection::{TargetDiscoveryErrorKind, TargetSelection};

/// The single selected target and its readonly lifetime.  Section code receives
/// this context instead of independently rediscovering a target.
pub(crate) struct DoctorTargetContext {
    pub target: crate::target::model::TargetIdentity,
    pub candidate: TargetCandidate,
    pub fstab: Result<String, String>,
    pub devices: Vec<crate::target::model::BlockDevice>,
    pub esp: Result<Option<DoctorEsp>, String>,
    pub boot_layout: Result<crate::mount::model::BootMountLayout, String>,
    pub boot: Result<Option<ReadonlySession>, String>,
    top_level: Result<Option<ReadonlySession>, String>,
    pub recovery_options: Result<Option<crate::snapshot::execute::engine::EngineOptions>, String>,
    discovery_cleanup: Vec<crate::target::discovery::ProbeCleanup>,
    session: TargetSession,
}

pub(crate) struct ContextOpenError {
    pub cause: String,
    pub cleanup: Vec<crate::target::discovery::ProbeCleanup>,
}

/// A separately mounted ESP that belongs to the selected target.  This is
/// deliberately session-owned: no section may inspect the live host ESP in
/// place of the selected target's one.
pub(crate) struct DoctorEsp {
    pub device: std::path::PathBuf,
    pub uuid: Option<String>,
    pub mount_point: String,
    pub root: ReadonlySession,
}

impl DoctorTargetContext {
    fn new(
        target: crate::target::model::TargetIdentity,
        session: TargetSession,
        devices: Vec<crate::target::model::BlockDevice>,
        discovery_cleanup: Vec<crate::target::discovery::ProbeCleanup>,
    ) -> Result<Self, ContextOpenError> {
        let mut session = Some(session);
        let session_ref = || {
            session
                .as_ref()
                .expect("target session remains owned during context open")
        };
        let candidate = session_ref().candidate().clone();
        let fstab = match sections::read_target_file(&target.root, "etc/fstab") {
            Ok(Some(value)) => value,
            Ok(None) => {
                return Err(context_open_error(
                    "selected target has no /etc/fstab".into(),
                    discovery_cleanup,
                    session.take().expect("target session"),
                    None,
                    None,
                    None,
                ))
            }
            Err(error) => {
                return Err(context_open_error(
                    format!("cannot read selected target fstab: {error}"),
                    discovery_cleanup,
                    session.take().expect("target session"),
                    None,
                    None,
                    None,
                ))
            }
        };
        let mut esp = match open_target_esp(&fstab, &devices) {
            Ok(value) => value,
            Err(error) => {
                return Err(context_open_error(
                    error,
                    discovery_cleanup,
                    session.take().expect("target session"),
                    None,
                    None,
                    None,
                ))
            }
        };
        let boot_layout = match target.root_device.as_deref() {
            Some(root_device) => crate::mount::diagnose::target::detect_boot_mount_layout(
                &crate::mount::diagnose::fstab::parse_all(&fstab),
                &devices,
                root_device,
                esp.as_ref().map(|esp| esp.device.as_path()),
            ),
            None => Err("cannot derive target boot layout without root device".to_string()),
        };
        let boot_layout = match boot_layout {
            Ok(value) => value,
            Err(error) => {
                return Err(context_open_error(
                    error,
                    discovery_cleanup,
                    session.take().expect("target session"),
                    esp,
                    None,
                    None,
                ))
            }
        };
        let boot = open_dependency_with_cleanup(
            || open_target_boot(&boot_layout, &candidate, &devices),
            || {
                let mut cleanup = Vec::new();
                if let Some(esp) = esp.take() {
                    cleanup.push(esp.root.cleanup());
                }
                cleanup.push(session.take().expect("target session").cleanup());
                cleanup
            },
        )?;
        let top_level = if candidate.root_fstype == "btrfs" {
            ReadonlySession::open_with_options(
                &candidate.root_device,
                "btrfs",
                "ro,norecovery,subvolid=5",
            )
            .map(Some)
        } else {
            Ok(None)
        };
        let top_level = match top_level {
            Ok(value) => value,
            Err(error) => {
                return Err(context_open_error(
                    format!("cannot open selected Btrfs top-level: {error}"),
                    discovery_cleanup,
                    session.take().expect("target session"),
                    esp,
                    boot,
                    None,
                ))
            }
        };
        let recovery_options = match &top_level {
            Some(top_level) => crate::snapshot::diagnose::identity::validate_mounted_filesystem(
                top_level.root(),
                &candidate.root_device,
            )
            .map(|validated| {
                Some(crate::snapshot::execute::engine::EngineOptions {
                    top_level_mount: top_level.root().to_path_buf(),
                    device_path: validated.canonical_device,
                    validated_filesystem: validated.filesystem,
                })
            })
            .map_err(|error| format!("cannot validate selected Btrfs top-level: {error}")),
            None => Ok(None),
        };
        Ok(Self {
            target,
            candidate,
            fstab: Ok(fstab),
            devices,
            esp: Ok(esp),
            boot_layout: Ok(boot_layout),
            boot: Ok(boot),
            top_level: Ok(top_level),
            recovery_options,
            discovery_cleanup,
            session: session.take().expect("target session"),
        })
    }

    fn cleanup(self) -> Vec<crate::target::discovery::ProbeCleanup> {
        let mut cleanup = self.discovery_cleanup;
        if let Ok(Some(session)) = self.top_level {
            cleanup.push(session.cleanup());
        }
        if let Ok(Some(session)) = self.boot {
            cleanup.push(session.cleanup());
        }
        if let Ok(Some(esp)) = self.esp {
            cleanup.push(esp.root.cleanup());
        }
        cleanup.push(self.session.cleanup());
        cleanup
    }

    fn target_summary(&self) -> DoctorTarget {
        let esp = self.esp.as_ref().ok().and_then(|value| value.as_ref());
        DoctorTarget {
            kind: if self.candidate.running_environment_member {
                DoctorTargetKind::RunningRoot
            } else {
                DoctorTargetKind::Offline
            },
            root_device: self
                .target
                .root_device
                .as_ref()
                .map(|path| path.display().to_string()),
            root_fstype: self.target.root_fstype.clone(),
            root_subvolume: self.target.root_subvol.clone(),
            esp_device: esp.map(|value| value.device.display().to_string()),
            boot_layout: esp.map(|value| format!("esp:{}", value.mount_point)),
        }
    }
}

fn context_open_error(
    cause: String,
    discovery_cleanup: Vec<crate::target::discovery::ProbeCleanup>,
    session: TargetSession,
    esp: Option<DoctorEsp>,
    boot: Option<ReadonlySession>,
    top_level: Option<ReadonlySession>,
) -> ContextOpenError {
    let mut cleanup = discovery_cleanup;
    if let Some(session) = top_level {
        cleanup.push(session.cleanup());
    }
    if let Some(session) = boot {
        cleanup.push(session.cleanup());
    }
    if let Some(esp) = esp {
        cleanup.push(esp.root.cleanup());
    }
    cleanup.push(session.cleanup());
    ContextOpenError { cause, cleanup }
}

fn open_dependency_with_cleanup<T, O, C>(open: O, cleanup: C) -> Result<T, ContextOpenError>
where
    O: FnOnce() -> Result<T, String>,
    C: FnOnce() -> Vec<crate::target::discovery::ProbeCleanup>,
{
    open().map_err(|cause| ContextOpenError {
        cause,
        cleanup: cleanup(),
    })
}

fn open_target_boot(
    layout: &crate::mount::model::BootMountLayout,
    candidate: &TargetCandidate,
    devices: &[crate::target::model::BlockDevice],
) -> Result<Option<ReadonlySession>, String> {
    use crate::mount::model::BootMountLayout;

    match layout {
        BootMountLayout::SeparateBootAndEsp { boot_device, .. } => {
            let device = devices
                .iter()
                .find(|device| device.dev_path.as_deref() == Some(boot_device.as_path()))
                .ok_or_else(|| {
                    format!(
                        "selected target /boot device {} is absent from shared inventory",
                        boot_device.display()
                    )
                })?;
            let fstype = device.filesystem.as_deref().ok_or_else(|| {
                format!(
                    "selected target /boot device {} has no filesystem type",
                    boot_device.display()
                )
            })?;
            ReadonlySession::open(boot_device, fstype)
                .map(Some)
                .map_err(|error| {
                    format!(
                        "cannot open selected target /boot {} read-only: {error}",
                        boot_device.display()
                    )
                })
        }
        BootMountLayout::BootBtrfsSubvolume { subvolume, .. } => {
            ReadonlySession::open_with_options(
                &candidate.root_device,
                "btrfs",
                &format!("ro,norecovery,subvol={}", subvolume.trim_start_matches('/')),
            )
            .map(Some)
            .map_err(|error| {
                format!(
                    "cannot open selected target /boot subvolume {subvolume} read-only: {error}"
                )
            })
        }
        BootMountLayout::BootInsideRoot
        | BootMountLayout::EspAtBootEfi { .. }
        | BootMountLayout::EspAtEfi { .. }
        | BootMountLayout::EspAtBoot { .. } => Ok(None),
    }
}

fn open_target_esp(
    fstab: &str,
    devices: &[crate::target::model::BlockDevice],
) -> Result<Option<DoctorEsp>, String> {
    let entries: Vec<_> = crate::target::fstab::parse_all(fstab)
        .into_iter()
        .filter(|entry| {
            matches!(entry.target.as_str(), "/efi" | "/boot/efi")
                || (entry.target == "/boot"
                    && matches!(
                        entry.fstype.as_str(),
                        "vfat" | "fat" | "fat32" | "fat16" | "fat12"
                    ))
        })
        .collect();
    match entries.as_slice() {
        [] => Ok(None),
        [entry] => {
            let matches: Vec<_> = devices
                .iter()
                .filter(|device| {
                    crate::target::diagnose::candidate::device_matches_fstab_source(
                        device,
                        &entry.source,
                    )
                })
                .filter(|device| {
                    matches!(
                        device.filesystem.as_deref(),
                        Some("vfat" | "fat" | "fat32" | "fat16" | "fat12")
                    )
                })
                .collect();
            let device = match matches.as_slice() {
                [device] => *device,
                [] => {
                    return Err(format!(
                        "selected target ESP entry {} does not resolve to one FAT device",
                        entry.target
                    ))
                }
                _ => {
                    return Err(format!(
                        "selected target ESP entry {} resolves to multiple FAT devices",
                        entry.target
                    ))
                }
            };
            let path = device
                .dev_path
                .as_ref()
                .ok_or_else(|| "resolved selected target ESP has no device path".to_string())?;
            let fstype = device
                .filesystem
                .as_deref()
                .ok_or_else(|| "resolved selected target ESP has no filesystem type".to_string())?;
            let root = ReadonlySession::open(path, fstype).map_err(|error| {
                format!(
                    "cannot open selected target ESP {} read-only: {error}",
                    path.display()
                )
            })?;
            Ok(Some(DoctorEsp {
                device: path.clone(),
                uuid: device.uuid.clone(),
                mount_point: entry.target.clone(),
                root,
            }))
        }
        _ => Err("selected target fstab has multiple ESP entries".to_string()),
    }
}

pub fn run_doctor() -> DoctorReport {
    let runner = crate::fs::command::TrustedRunner::new();
    let environment = sections::capture_environment();
    if let Err(error) = crate::mount::execute::namespace::establish_private_namespace() {
        return namespace_failure_report(environment, error.to_string());
    }
    let selected = match target_selection::discover_target_session() {
        Ok(value) => value,
        Err(error) => {
            let mut report = DoctorReport {
                environment,
                ..DoctorReport::default()
            };
            report.sections = if error.kind == TargetDiscoveryErrorKind::Ambiguous {
                handle_ambiguous_target(error.candidates, &mut report)
            } else {
                handle_no_target(error.reason.clone(), &mut report)
            };
            report.cleanup = cleanup_report(error.cleanup, None);
            aggregate(&mut report);
            return report;
        }
    };
    let target = selected.target.clone();
    let context = match DoctorTargetContext::new(
        selected.target,
        selected.session,
        selected.inventory,
        selected.discovery_cleanup,
    ) {
        Ok(context) => context,
        Err(error) => {
            let mut report = DoctorReport {
                environment,
                target: TargetSelection::Identified(target).to_target_summary(),
                ..DoctorReport::default()
            };
            report
                .limitations
                .push(crate::doctor::model::DoctorLimitation::new(
                    DoctorSectionId::Storage,
                    "DOCTOR_CONTEXT_OPEN_FAILED",
                    error.cause.clone(),
                ));
            report.cleanup = cleanup_report(error.cleanup, Some(error.cause));
            report.sections = DoctorSectionId::all()
                .iter()
                .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Unknown))
                .collect();
            aggregate(&mut report);
            return report;
        }
    };
    let mut report = DoctorReport {
        environment: environment.clone(),
        target: context.target_summary(),
        ..DoctorReport::default()
    };
    report.evidence.push(Evidence::new(
        "DOCTOR_TARGET_CONTEXT",
        "doctor::context",
        format!(
            "selected candidate {}",
            context.candidate.root_device.display()
        ),
    ));
    if let Err(error) = &context.fstab {
        report
            .limitations
            .push(crate::doctor::model::DoctorLimitation::new(
                DoctorSectionId::Mount,
                "MOUNT_FACTS_INCOMPLETE",
                error.clone(),
            ));
    }
    if let Err(error) = &context.recovery_options {
        report
            .limitations
            .push(crate::doctor::model::DoctorLimitation::new(
                DoctorSectionId::Recovery,
                "RECOVERY_FACTS_INCOMPLETE",
                error.clone(),
            ));
    }
    if let Err(error) = &context.esp {
        report
            .limitations
            .push(crate::doctor::model::DoctorLimitation::new(
                DoctorSectionId::Storage,
                "ESP_FACTS_INCOMPLETE",
                error.clone(),
            ));
    }
    report.sections = run_sections(
        &runner,
        Some(&context),
        context
            .recovery_options
            .as_ref()
            .ok()
            .and_then(Option::as_ref),
        &environment,
        &mut report,
    );
    aggregate(&mut report);
    report.cleanup = cleanup_report(context.cleanup(), None);
    report
}

fn namespace_failure_report(environment: DoctorEnvironment, reason: String) -> DoctorReport {
    let mut report = DoctorReport {
        environment,
        sections: DoctorSectionId::all()
            .iter()
            .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Unknown))
            .collect(),
        ..DoctorReport::default()
    };
    report
        .limitations
        .push(crate::doctor::model::DoctorLimitation::new(
            DoctorSectionId::Storage,
            "DOCTOR_NAMESPACE_UNAVAILABLE",
            format!("cannot establish private mount namespace: {reason}"),
        ));
    report.cleanup = DoctorCleanup::not_required();
    aggregate(&mut report);
    report
}

fn cleanup_report(
    cleanup: Vec<crate::target::discovery::ProbeCleanup>,
    context_failure: Option<String>,
) -> DoctorCleanup {
    let mut residual: Vec<String> = cleanup
        .iter()
        .filter_map(|item| {
            item.error
                .as_ref()
                .map(|error| format!("{}: {error}", item.mountpoint.display()))
        })
        .collect();
    if let Some(failure) = context_failure {
        residual.push(format!("context initialization failed: {failure}"));
    }
    DoctorCleanup {
        cleaned: cleanup
            .iter()
            .filter(|item| item.is_clean())
            .map(|item| item.mountpoint.display().to_string())
            .collect(),
        all_clean: residual.is_empty() && cleanup.iter().all(|item| item.is_clean()),
        residual,
    }
}

#[doc(hidden)]
pub fn run_doctor_with<R: FsCommandRunner + ?Sized>(runner: &R) -> DoctorReport {
    let mut report = DoctorReport::default();

    let environment = sections::capture_environment();
    report.environment = environment.clone();

    let selection = target_selection::discover_target();
    report.target = selection.to_target_summary();

    let sections = match selection {
        TargetSelection::None { reason } => handle_no_target(reason, &mut report),
        TargetSelection::Ambiguous { candidates } => {
            handle_ambiguous_target(candidates, &mut report)
        }
        TargetSelection::Identified(_) => {
            run_sections(runner, None, None, &environment, &mut report)
        }
    };

    report.sections = sections;
    aggregate(&mut report);
    report.cleanup = DoctorCleanup::not_required();
    report
}

fn run_sections<R: FsCommandRunner + ?Sized>(
    runner: &R,
    context: Option<&DoctorTargetContext>,
    recovery_options: Option<&crate::snapshot::execute::engine::EngineOptions>,
    env: &DoctorEnvironment,
    report: &mut DoctorReport,
) -> Vec<DoctorSection> {
    let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();

    let _ = sections::run_environment_section(&mut sections, env);
    let _ = sections::run_storage_section(&mut sections, context, report);
    let _ = sections::run_filesystem_section(runner, &mut sections, context, report);
    let _ = sections::run_mount_section(&mut sections, context, report);
    let _ = sections::run_boot_section(&mut sections, context, report);
    let _ = sections::run_secure_boot_section(&mut sections, context, report);
    let _ = sections::run_recovery_section(&mut sections, context, recovery_options, report);

    sections.into_iter().map(|(_, s)| s).collect()
}

fn handle_no_target(reason: String, report: &mut DoctorReport) -> Vec<DoctorSection> {
    let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();
    let section = sections::set_section(
        &mut sections,
        DoctorSectionId::Environment,
        DoctorSectionStatus::Healthy,
    );
    section.evidence.push(Evidence::new(
        "TARGET_SELECTION",
        "doctor::target_selection",
        format!("target_not_found: {reason}"),
    ));
    sections::push_issue(
        &mut sections,
        DoctorIssue::new(
            issue_code::TARGET_NOT_FOUND,
            DoctorSeverity::Warning,
            DoctorSectionId::Storage,
            format!("no CatOS target identified: {reason}"),
        )
        .with_recommendation(recommendation_code::BOOT_LIVE_ENVIRONMENT),
    );
    report.recommendations.push(DoctorRecommendation::new(
        recommendation_code::BOOT_LIVE_ENVIRONMENT,
        "no CatOS target was identified; boot a CatOS Live environment or specify the target explicitly",
    ));
    sections.into_iter().map(|(_, s)| s).collect()
}

fn handle_ambiguous_target(
    candidates: Vec<String>,
    report: &mut DoctorReport,
) -> Vec<DoctorSection> {
    let mut sections: Vec<(DoctorSectionId, DoctorSection)> = DoctorSectionId::all()
        .iter()
        .map(|id| (*id, DoctorSection::new(*id, DoctorSectionStatus::Unknown)))
        .collect();
    let section = sections::set_section(
        &mut sections,
        DoctorSectionId::Environment,
        DoctorSectionStatus::Healthy,
    );
    section.evidence.push(Evidence::new(
        "TARGET_SELECTION",
        "doctor::target_selection",
        format!("ambiguous_target: candidates={}", candidates.join(",")),
    ));
    sections::push_issue(
        &mut sections,
        DoctorIssue::new(
            issue_code::TARGET_AMBIGUOUS,
            DoctorSeverity::Warning,
            DoctorSectionId::Storage,
            format!(
                "multiple CatOS targets identified: {}",
                candidates.join(", ")
            ),
        )
        .with_recommendation(recommendation_code::MANUAL_REVIEW),
    );
    report.recommendations.push(DoctorRecommendation::new(
        recommendation_code::MANUAL_REVIEW,
        "multiple CatOS targets were identified; resolve ambiguity before any repair",
    ));
    sections.into_iter().map(|(_, s)| s).collect()
}

fn aggregate(report: &mut DoctorReport) {
    let mut overall = DoctorOverallStatus::Healthy;
    let mut complete = true;
    let mut all_issues: Vec<DoctorIssue> = Vec::new();

    for section in &report.sections {
        if let Some(contribution) = section.status.to_overall_contribution() {
            overall = overall.combine(contribution);
        }
        if matches!(
            section.status,
            DoctorSectionStatus::Skipped | DoctorSectionStatus::Unknown
        ) {
            complete = false;
        }
        all_issues.extend(section.issues.iter().cloned());
    }

    if !report.limitations.is_empty() && overall == DoctorOverallStatus::Healthy {
        overall = DoctorOverallStatus::Degraded;
    }

    all_issues.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.section.as_str().cmp(b.section.as_str()))
            .then_with(|| a.code.cmp(&b.code))
    });
    all_issues
        .dedup_by(|a, b| a.code == b.code && a.section == b.section && a.message == b.message);

    report.overall_status = overall;
    report.complete = complete;
    report.issues = all_issues;

    report.evidence.push(Evidence::new(
        "DOCTOR_AGGREGATE",
        "doctor::aggregate",
        format!(
            "overall={} complete={} issues={} limitations={}",
            report.overall_status.as_str(),
            report.complete,
            report.issues.len(),
            report.limitations.len()
        ),
    ));
}

impl DoctorReport {
    pub fn doctor_failed(&self) -> bool {
        !self.cleanup.all_clean || self.target.kind == DoctorTargetKind::None
    }
}

/// Public test-only entry point so integration tests can drive the
/// pure aggregation logic without re-implementing it. Production
/// callers use [`run_doctor`].
#[doc(hidden)]
pub fn aggregate_for_tests(report: &mut DoctorReport) {
    aggregate(report);
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::doctor::model::{DoctorLimitation, DoctorTargetKind};

    pub fn aggregate_public(report: &mut DoctorReport) {
        aggregate(report);
    }

    #[test]
    fn aggregate_combines_critical_section_to_critical_overall() {
        let mut report = DoctorReport::default();
        report.sections = vec![
            DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Critical),
        ];
        aggregate(&mut report);
        assert_eq!(report.overall_status, DoctorOverallStatus::Critical);
    }

    #[test]
    fn aggregate_degrades_when_only_limitations_exist() {
        let mut report = DoctorReport::default();
        report.sections = DoctorSectionId::all()
            .iter()
            .map(|id| DoctorSection::new(*id, DoctorSectionStatus::Healthy))
            .collect();
        report
            .limitations
            .push(DoctorLimitation::new(DoctorSectionId::Filesystem, "X", "y"));
        aggregate(&mut report);
        assert_eq!(report.overall_status, DoctorOverallStatus::Degraded);
    }

    #[test]
    fn aggregate_sorts_issues_by_severity_then_section_then_code() {
        let mut report = DoctorReport::default();
        let mut fs_section =
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Unhealthy);
        fs_section.issues.push(DoctorIssue::new(
            "AAA",
            DoctorSeverity::Error,
            DoctorSectionId::Filesystem,
            "fs error",
        ));
        let mut boot_section =
            DoctorSection::new(DoctorSectionId::Boot, DoctorSectionStatus::Unhealthy);
        boot_section.issues.push(DoctorIssue::new(
            "BBB",
            DoctorSeverity::Critical,
            DoctorSectionId::Boot,
            "boot critical",
        ));
        report.sections = vec![fs_section, boot_section];
        aggregate(&mut report);
        assert_eq!(report.issues[0].code, "BBB");
        assert_eq!(report.issues[0].severity, DoctorSeverity::Critical);
        assert_eq!(report.issues[1].code, "AAA");
    }

    #[test]
    fn aggregate_dedupes_identical_issues() {
        let mut report = DoctorReport::default();
        let mut section =
            DoctorSection::new(DoctorSectionId::Mount, DoctorSectionStatus::Unhealthy);
        let issue = DoctorIssue::new("X", DoctorSeverity::Error, DoctorSectionId::Mount, "same");
        section.issues.push(issue.clone());
        section.issues.push(issue);
        report.sections = vec![section];
        aggregate(&mut report);
        assert_eq!(report.issues.len(), 1);
    }

    #[test]
    fn aggregate_marks_complete_false_when_a_section_is_skipped() {
        let mut report = DoctorReport::default();
        report.sections = vec![
            DoctorSection::new(DoctorSectionId::Environment, DoctorSectionStatus::Healthy),
            DoctorSection::new(DoctorSectionId::Filesystem, DoctorSectionStatus::Skipped),
        ];
        aggregate(&mut report);
        assert!(!report.complete);
    }

    #[test]
    fn doctor_failed_is_false_for_an_identified_target_with_clean_cleanup() {
        let mut report = DoctorReport::default();
        report.target.kind = DoctorTargetKind::Offline;
        report.cleanup = DoctorCleanup::clean();
        assert!(!report.doctor_failed());
    }

    #[test]
    fn doctor_failed_is_true_when_no_target_was_identified() {
        let mut report = DoctorReport::default();
        report.cleanup = DoctorCleanup::clean();
        assert!(report.doctor_failed());
    }

    #[test]
    fn namespace_failure_is_reported_before_target_discovery() {
        let report = namespace_failure_report(
            DoctorEnvironment::default(),
            "operation not permitted".into(),
        );
        assert_eq!(report.target.kind, DoctorTargetKind::None);
        assert!(!report.complete);
        assert!(report
            .limitations
            .iter()
            .any(|item| item.code == "DOCTOR_NAMESPACE_UNAVAILABLE"));
        assert!(report.cleanup.all_clean);
        assert!(report.doctor_failed());
    }

    #[test]
    fn target_summary_for_no_target_uses_none_kind() {
        let sel = TargetSelection::None {
            reason: "test".into(),
        };
        let summary = sel.to_target_summary();
        assert_eq!(summary.kind, DoctorTargetKind::None);
    }

    #[test]
    fn configured_esp_without_inventory_match_fails_closed() {
        let result = open_target_esp("UUID=esp-uuid /efi vfat defaults 0 2\n", &[]);

        assert!(matches!(result, Err(ref error) if error.contains("does not resolve")));
    }

    #[test]
    fn absent_esp_fstab_entry_is_not_replaced_with_a_live_device() {
        let result = open_target_esp("UUID=root / ext4 defaults 0 1\n", &[]).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn boot_open_failure_runs_root_cleanup_and_marks_context_failure() {
        let mut cleanup_called = false;
        let result: Result<(), ContextOpenError> = open_dependency_with_cleanup(
            || Err("boot readonly open failed".to_string()),
            || {
                cleanup_called = true;
                vec![crate::target::discovery::ProbeCleanup {
                    mountpoint: std::path::PathBuf::from("/tmp/root-session"),
                    unmounted: true,
                    removed: true,
                    error: None,
                }]
            },
        );

        let error = match result {
            Ok(()) => panic!("boot failure must not produce a context"),
            Err(error) => error,
        };
        assert!(cleanup_called);
        assert_eq!(error.cause, "boot readonly open failed");
        let report = cleanup_report(error.cleanup, Some(error.cause));
        assert!(!report.all_clean);
        assert!(report
            .residual
            .iter()
            .any(|item| item.contains("context initialization failed")));
    }
}
