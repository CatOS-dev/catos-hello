//! Boot repair application orchestration.
//!
//! This module owns CLI authorisation, target discovery, mount-session
//! lifecycle, cleanup reporting, and composition of the `boot` capability.

use crate::boot::diagnose::target::{
    collect_boot_cmdline_facts, collect_detection_inputs_from_target_root,
    derive_bios_install_disk, detect_partition_table, detect_target_architecture,
};
use crate::boot::execute::repair::run_boot_repair;
use crate::boot::model::{BootRepairOutcome, BootRepairReport, FirmwareClass, PlatformFacts};
use crate::mount::model::MountRepairCleanup;
use crate::target::Evidence;

/// Production CLI entry point for `catos-repair boot`.
pub fn run_boot_repair_via_cli(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
    authorised: bool,
) -> BootRepairReport {
    if !authorised {
        return BootRepairReport::refused(
            BootRepairOutcome::ManualInterventionRequired,
            "boot repair requires explicit CLI authorisation",
        );
    }

    let mut report = run_boot_repair_mounted(root_device, root_subvolume, esp_device);
    if report.final_outcome == BootRepairOutcome::Unknown {
        report.final_outcome = BootRepairOutcome::ManualInterventionRequired;
        report.requires_human_action = true;
    }
    report
}

fn run_boot_repair_mounted(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
) -> BootRepairReport {
    let mut session = match crate::repair::mount::open_boot_repair_target_session(
        root_device,
        root_subvolume,
        esp_device,
    ) {
        Ok(session) => session,
        Err(error) => {
            let all_clean = error.cleanup.all_clean;
            return BootRepairReport {
                cleanup: MountRepairCleanup {
                    unmounted: error.cleanup.unmounted,
                    residual: error.cleanup.residual,
                    all_clean,
                },
                final_outcome: if all_clean {
                    BootRepairOutcome::AmbiguousTarget
                } else {
                    BootRepairOutcome::CleanupIncomplete
                },
                requires_human_action: true,
                fully_complete: false,
                evidence: vec![Evidence::new(
                    "BOOT_SESSION_OPEN_FAILED",
                    "repair::boot::session",
                    error.reason,
                )],
                ..BootRepairReport::default()
            };
        }
    };
    let target = session.target().clone();
    let target_root = session.target_root();

    let architecture = match detect_target_architecture(&target_root) {
        Some(architecture) => architecture,
        None => {
            let cleanup = session.cleanup();
            let all_clean = cleanup.all_clean;
            return BootRepairReport {
                target: Some(target),
                cleanup: MountRepairCleanup {
                    unmounted: cleanup.unmounted,
                    residual: cleanup.residual,
                    all_clean: cleanup.all_clean,
                },
                final_outcome: if all_clean {
                    BootRepairOutcome::AmbiguousTarget
                } else {
                    BootRepairOutcome::CleanupIncomplete
                },
                requires_human_action: true,
                fully_complete: false,
                evidence: vec![Evidence::new(
                    "TARGET_ARCHITECTURE_UNKNOWN",
                    "repair::boot",
                    "target architecture could not be established from target ELF evidence",
                )],
                ..BootRepairReport::default()
            };
        }
    };
    let firmware = if target.esp_device.is_some() {
        FirmwareClass::Efi
    } else {
        FirmwareClass::Bios
    };
    let partition_table = detect_partition_table(&target, session.devices());
    let platform = PlatformFacts {
        firmware,
        architecture,
        partition_table,
    };

    let cmdline_facts = match collect_boot_cmdline_facts(&target, &target_root, session.devices()) {
        Ok(facts) => facts,
        Err(error) => {
            return cmdline_facts_refusal(target, platform, error, session.cleanup());
        }
    };

    let detection = match collect_detection_inputs_from_target_root(&target_root) {
        Ok(detection) => detection,
        Err(error) => {
            return target_facts_refusal(
                target,
                platform,
                "BOOT_TARGET_FACTS_UNREADABLE",
                error,
                session.cleanup(),
            )
        }
    };
    let installed_packages = detection.installed_packages.clone();
    let bios_install_path = derive_bios_install_disk(&target, session.devices());

    let mut report = run_boot_repair(
        &target,
        platform,
        &target_root,
        target
            .boot_layout
            .as_ref()
            .and_then(|layout| layout.esp_mount_point())
            .map(|mount_point| target_root.join(mount_point.trim_start_matches('/')))
            .as_deref(),
        &detection,
        bios_install_path.as_deref(),
        &installed_packages,
        session.devices(),
        &cmdline_facts,
    );
    attach_session_cleanup(&mut report, session.cleanup());
    report
}

fn target_facts_refusal(
    target: crate::mount::model::MountTargetIdentity,
    platform: PlatformFacts,
    code: &str,
    message: String,
    cleanup: crate::snapshot::model::CleanupSummary,
) -> BootRepairReport {
    let all_clean = cleanup.all_clean;
    BootRepairReport {
        target: Some(target),
        platform: Some(platform),
        cleanup: MountRepairCleanup {
            unmounted: cleanup.unmounted,
            residual: cleanup.residual,
            all_clean,
        },
        final_outcome: if all_clean {
            BootRepairOutcome::ManualInterventionRequired
        } else {
            BootRepairOutcome::CleanupIncomplete
        },
        requires_human_action: true,
        fully_complete: false,
        evidence: vec![Evidence::new(code, "repair::boot::target-facts", message)],
        actions: Vec::new(),
        ..BootRepairReport::default()
    }
}

fn cmdline_facts_refusal(
    target: crate::mount::model::MountTargetIdentity,
    platform: PlatformFacts,
    error: crate::boot::model::BootCmdlineFactsError,
    cleanup: crate::snapshot::model::CleanupSummary,
) -> BootRepairReport {
    let mut evidence = error.evidence;
    evidence.push(Evidence::new(
        error.code,
        "repair::boot::cmdline-facts",
        error.message,
    ));
    let all_clean = cleanup.all_clean;
    BootRepairReport {
        target: Some(target),
        platform: Some(platform),
        cleanup: MountRepairCleanup {
            unmounted: cleanup.unmounted,
            residual: cleanup.residual,
            all_clean,
        },
        final_outcome: if all_clean {
            BootRepairOutcome::ManualInterventionRequired
        } else {
            BootRepairOutcome::CleanupIncomplete
        },
        requires_human_action: true,
        fully_complete: false,
        evidence,
        actions: Vec::new(),
        ..BootRepairReport::default()
    }
}

fn attach_session_cleanup(
    report: &mut BootRepairReport,
    cleanup: crate::snapshot::model::CleanupSummary,
) {
    report.cleanup = MountRepairCleanup {
        unmounted: cleanup.unmounted,
        residual: cleanup.residual,
        all_clean: cleanup.all_clean,
    };
    if !report.cleanup.all_clean {
        report.final_outcome = BootRepairOutcome::CleanupIncomplete;
        report.requires_human_action = true;
        report.fully_complete = false;
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    fn report(outcome: BootRepairOutcome) -> BootRepairReport {
        BootRepairReport {
            final_outcome: outcome,
            requires_human_action: true,
            fully_complete: false,
            ..BootRepairReport::default()
        }
    }

    #[test]
    fn provider_execute_failure_still_attaches_clean_session_cleanup() {
        let mut report = report(BootRepairOutcome::PartiallyRepaired);
        attach_session_cleanup(
            &mut report,
            crate::snapshot::model::CleanupSummary {
                unmounted: vec!["/target/run".into(), "/target/root".into()],
                all_clean: true,
                ..Default::default()
            },
        );
        assert_eq!(report.final_outcome, BootRepairOutcome::PartiallyRepaired);
        assert!(report.cleanup.all_clean);
        assert_eq!(report.cleanup.unmounted.len(), 2);
    }

    #[test]
    fn provider_verify_failure_still_attaches_clean_session_cleanup() {
        let mut report = report(BootRepairOutcome::VerificationFailed);
        attach_session_cleanup(
            &mut report,
            crate::snapshot::model::CleanupSummary {
                unmounted: vec!["/target/boot/efi".into(), "/target/root".into()],
                all_clean: true,
                ..Default::default()
            },
        );
        assert_eq!(report.final_outcome, BootRepairOutcome::VerificationFailed);
        assert!(report.cleanup.all_clean);
    }

    #[test]
    fn unresolved_cmdline_facts_refuse_before_any_provider_action() {
        let report = cmdline_facts_refusal(
            crate::mount::model::MountTargetIdentity::default(),
            PlatformFacts {
                firmware: crate::boot::model::FirmwareClass::Efi,
                architecture: crate::boot::model::Architecture::X86_64,
                partition_table: crate::boot::model::PartitionTable::Gpt,
            },
            crate::boot::model::BootCmdlineFactsError {
                code: "ROOT_LUKS_STACK_UNSUPPORTED".into(),
                message: "cannot establish dm-crypt mapper".into(),
                evidence: Vec::new(),
            },
            crate::snapshot::model::CleanupSummary {
                all_clean: true,
                ..Default::default()
            },
        );
        assert_eq!(
            report.final_outcome,
            BootRepairOutcome::ManualInterventionRequired
        );
        assert!(report.actions.is_empty());
        assert!(report
            .evidence
            .iter()
            .any(|item| item.code == "ROOT_LUKS_STACK_UNSUPPORTED"));
    }

    #[test]
    fn dirty_cleanup_overrides_provider_failure_with_cleanup_incomplete() {
        for original in [
            BootRepairOutcome::PartiallyRepaired,
            BootRepairOutcome::VerificationFailed,
        ] {
            let mut report = report(original);
            attach_session_cleanup(
                &mut report,
                crate::snapshot::model::CleanupSummary {
                    residual: vec!["/target/run: busy".into()],
                    all_clean: false,
                    ..Default::default()
                },
            );
            assert_eq!(report.final_outcome, BootRepairOutcome::CleanupIncomplete);
            assert!(report.requires_human_action);
            assert!(!report.fully_complete);
            assert_eq!(report.cleanup.residual, vec!["/target/run: busy"]);
        }
    }
}
