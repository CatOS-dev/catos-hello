//! Boot repair application orchestration.
//!
//! This module owns CLI authorisation, target discovery, mount-session
//! lifecycle, cleanup reporting, and composition of the `boot` capability.

use crate::boot::diagnose::target::{
    collect_detection_inputs_from_target_root, collect_installed_packages_from_target_root,
    derive_bios_install_disk, detect_partition_table, detect_target_architecture,
};
use crate::boot::execute::repair::run_boot_repair;
use crate::boot::model::{BootRepairOutcome, BootRepairReport, FirmwareClass, PlatformFacts};
use crate::mount::model::MountRepairCleanup;
use crate::shared::model::evidence::Evidence;

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
        Err(reason) => {
            return BootRepairReport::refused(BootRepairOutcome::AmbiguousTarget, &reason);
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

    let detection = collect_detection_inputs_from_target_root(&target_root);
    let installed_packages = collect_installed_packages_from_target_root(&target_root);
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
    );
    let cleanup = session.cleanup();
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
    report
}
