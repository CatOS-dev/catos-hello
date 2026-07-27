//! Bootloader provider repair (`catos-repair boot`). Ports the
//! bootloadu Calamares module's behaviour to the static Rust
//! backend, reusing the stage 1–3 target discovery, mount session,
//! device lock, and confined execution layers.
//!
//! ## What this module owns
//!
//! * `boot::plan::registry` — static port of `bootloaders.yaml`.
//! * `boot::plan::cmdline` — kernel cmdline builder + conflict
//!   detection.
//! * `boot::plan::initramfs` — mkinitcpio.conf array management +
//!   kernel discovery.
//! * `boot::diagnose::provider` — evidence-based provider detection.
//! * `boot::execute::target` — fixed allow-list, argv-only
//!   target command executor (replaces `target_env_call`).
//! * `boot::execute::secureboot` — target-policy-preserving Secure
//!   Boot finalisation.
//! * `boot::execute::providers` — per-provider recipe implementations
//!   (GRUB, Limine, systemd-boot, UEFI Firmware family for
//!   UKI/EFI Stub).
//!
//! ## What this module does NOT own
//!
//! * Target discovery, mount session, and device locks: those are
//!   the stage 1–3 surfaces (`repair::mount`,
//!   `catos_mount::session::BtrfsTopLevelRwSession`, `snapshot_engine::lock`).
//! * Bootloader migration: repair restores the provider the target
//!   already uses. It never swaps GRUB for systemd-boot, etc.
//! * Arbitrary chroot / shell API: the only target commands that
//!   may run are in
//!   [`target_exec::ALLOWED_BINARIES`].
//!
//! ## Hard rules
//!
//! * The provider is **detected** from target-side evidence, never
//!   guessed from the live host's installed tools.
//! * Provider recipes run only when the target platform is supported
//!   by the registry's matrix.
//! * Cmdline conflicts are reported, not silently overwritten.
//! * Secure Boot is re-applied only when the target already had a
//!   CatOS Secure Boot policy; the live host's Secure Boot state is
//!   never the trigger.
//! * Partial success from non-atomic operations (EFI NVRAM writes,
//!   bootloader installs, signing) MUST surface as
//!   [`crate::model::BootRepairOutcome::PartiallyRepaired`]
//!   or
//!   [`crate::model::BootRepairOutcome::ManualInterventionRequired`].

use std::path::Path;

use crate::diagnose::provider::{detect, DetectionInputs, DetectionVerdict};
use crate::execute::providers::{build_ctx, build_executor, build_verifier};
use crate::execute::secureboot::{finalize_secure_boot, SecureBootInputs};
use crate::execute::target::{TargetRequest, TargetRunner, TrustedTargetRunner};
use crate::io::read_target_file;
use crate::model::{
    BootRepairOutcome, BootRepairReport, BootVerification, PlatformFacts, SecureBootReport,
};
use crate::plan::cmdline::{build_kernel_cmdline, CmdlineInputs};
use crate::plan::registry as boot_registry;
use catos_mount::model::{MountRepairCleanup, MountTargetIdentity};
use catos_target::Evidence;

pub use crate::execute::providers::ProviderInputs;
pub use crate::plan::initramfs::Kernel;
pub use crate::plan::registry::ProviderProfile;

/// Run the boot-repair flow against an already-mounted target. The
/// caller (the CLI entry point) is responsible for target discovery,
/// mount session, and device locking — exactly the same surfaces
/// `catos-repair mount` uses.
///
/// `target_root` is the path inside the private mount namespace
/// where the target's `/` is visible (e.g. the btrfs `@` subvolume
/// or the plain root mount). `esp_root` is the path where the target
/// ESP is mounted inside the namespace, when applicable.
#[allow(clippy::too_many_arguments)]
pub fn run_boot_repair(
    target: &MountTargetIdentity,
    platform: PlatformFacts,
    target_root: &Path,
    esp_root: Option<&Path>,
    detection: &DetectionInputs,
    bios_install_path: Option<&str>,
    installed_packages: &[String],
    storage_devices: &[catos_target::model::BlockDevice],
) -> BootRepairReport {
    // 1. Detect provider from target evidence.
    let verdict = detect(detection, target);
    let (provider, method, evidence) = match verdict {
        DetectionVerdict::Detected {
            provider,
            method,
            evidence,
        } => (provider, method, evidence),
        DetectionVerdict::Conflict { evidence, .. } => {
            return BootRepairReport {
                target: Some(target.clone()),
                platform: Some(platform),
                provider_evidence: evidence,
                final_outcome: BootRepairOutcome::AmbiguousProvider,
                requires_human_action: true,
                fully_complete: false,
                evidence: vec![Evidence::new(
                    "AMBIGUOUS_PROVIDER",
                    "repair::boot::detect",
                    "multiple providers each have authoritative evidence",
                )],
                ..BootRepairReport::default()
            };
        }
        DetectionVerdict::Ambiguous { evidence } => {
            return BootRepairReport {
                target: Some(target.clone()),
                platform: Some(platform),
                provider_evidence: evidence,
                final_outcome: BootRepairOutcome::AmbiguousProvider,
                requires_human_action: true,
                fully_complete: false,
                evidence: vec![Evidence::new(
                    "AMBIGUOUS_PROVIDER",
                    "repair::boot::detect",
                    "no provider has authoritative target-side evidence",
                )],
                ..BootRepairReport::default()
            };
        }
    };

    // 2. Platform support matrix check.
    if !boot_registry::target_platform_supported(
        provider,
        platform.firmware,
        platform.architecture,
        platform.partition_table,
    ) {
        return BootRepairReport {
            target: Some(target.clone()),
            platform: Some(platform),
            detected_provider: Some(provider),
            firmware_method: method,
            provider_evidence: evidence,
            final_outcome: BootRepairOutcome::Unsupported,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new(
                "UNSUPPORTED_PLATFORM",
                "repair::boot::registry",
                format!(
                    "{} is not supported on {}/{}/{}",
                    provider.as_str(),
                    platform.firmware.as_registry_str(),
                    platform.architecture.as_str(),
                    match platform.partition_table {
                        crate::model::PartitionTable::Gpt => "gpt",
                        crate::model::PartitionTable::Msdos => "msdos",
                        crate::model::PartitionTable::Unknown => "unknown",
                    }
                ),
            )],
            ..BootRepairReport::default()
        };
    }

    // 3. Build the kernel cmdline.
    let existing_cmdline = detection.kernel_cmdline.clone().unwrap_or_default();
    let (cmdline, conflicts) = build_kernel_cmdline(&CmdlineInputs {
        target,
        existing_cmdline: &existing_cmdline,
        has_plymouth: installed_packages.iter().any(|p| p == "plymouth"),
        swap_uuids: &[],
        swap_luks_mappers: &[],
        luks_root: None,
    });
    if !conflicts.is_empty() {
        return BootRepairReport {
            target: Some(target.clone()),
            platform: Some(platform),
            detected_provider: Some(provider),
            firmware_method: method,
            provider_evidence: evidence,
            kernel_cmdline: Some(cmdline),
            cmdline_conflicts: conflicts,
            final_outcome: BootRepairOutcome::ManualInterventionRequired,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new(
                "CMDLINE_CONFLICT",
                "repair::boot::cmdline",
                "target kernel command line conflicts with the verified target identity",
            )],
            ..BootRepairReport::default()
        };
    }

    // 4. Build provider context.
    let esp_mount_point = esp_root
        .and_then(|path| mount_point_for_target(target_root, path))
        .or_else(|| {
            target
                .boot_layout
                .as_ref()
                .and_then(|l| l.esp_mount_point().map(str::to_string))
        });
    let ctx = build_ctx(
        target,
        provider,
        cmdline.clone(),
        esp_mount_point,
        bios_install_path.map(str::to_string),
        platform.architecture,
        "CatOS".to_string(),
        target.root_fstype == "btrfs",
    );

    let efi_device = derive_efi_device(target, storage_devices);
    let snapshot_state = snapshot_repair_state(
        target_root,
        provider,
        &target.root_fstype,
        installed_packages,
    );
    let mkinitcpio_text = read_target_file(target_root, "etc/mkinitcpio.conf").unwrap_or_default();
    let kernels = collect_target_kernels(target_root);
    let mkinitcpio_inputs = crate::plan::initramfs::MkinitcpioInputs {
        existing_config: &mkinitcpio_text,
        root_filesystem: target.root_fstype.clone(),
        has_plymouth: installed_packages
            .iter()
            .any(|package| package == "plymouth"),
        has_crypto_keyfile: catos_target::execute::confined::read_rooted_file(
            target_root,
            "/crypto_keyfile.bin",
        )
        .is_ok(),
        provider,
        root_is_btrfs: target.root_fstype == "btrfs",
        snapshots_enabled: snapshot_state.enabled,
        ..Default::default()
    };
    let mut config_transaction = ConfigTransaction::new(target_root);
    let mut config_actions = match write_provider_configs(
        &mut config_transaction,
        provider,
        &ctx,
        efi_device.as_ref(),
        &mkinitcpio_text,
        &mkinitcpio_inputs,
    ) {
        Ok(actions) => actions,
        Err(message) => {
            let rollback_message = config_transaction.rollback().err();
            return BootRepairReport {
                target: Some(target.clone()),
                platform: Some(platform),
                detected_provider: Some(provider),
                firmware_method: method,
                provider_evidence: evidence,
                kernel_cmdline: Some(cmdline),
                final_outcome: BootRepairOutcome::ManualInterventionRequired,
                requires_human_action: true,
                fully_complete: false,
                evidence: vec![Evidence::new(
                    "CONFIG_WRITE_FAILED",
                    "repair::boot",
                    match rollback_message {
                        Some(rollback) => format!("{message}; rollback failed: {rollback}"),
                        None => message,
                    },
                )],
                ..BootRepairReport::default()
            };
        }
    };
    if let Some(template) = snapshot_state.restore_root_config.as_deref() {
        match write_restored_snapper_config(&mut config_transaction, target_root, template) {
            Ok(actions) => config_actions.extend(actions),
            Err(message) => {
                let rollback_message = config_transaction.rollback().err();
                return BootRepairReport {
                    target: Some(target.clone()),
                    platform: Some(platform),
                    detected_provider: Some(provider),
                    firmware_method: method,
                    provider_evidence: evidence,
                    kernel_cmdline: Some(cmdline),
                    final_outcome: BootRepairOutcome::ManualInterventionRequired,
                    requires_human_action: true,
                    fully_complete: false,
                    evidence: vec![Evidence::new(
                        "SNAPPER_CONFIG_WRITE_FAILED",
                        "repair::boot::snapshot",
                        match rollback_message {
                            Some(rollback) => format!("{message}; rollback failed: {rollback}"),
                            None => message,
                        },
                    )],
                    ..BootRepairReport::default()
                };
            }
        }
    }

    // 5. Run the provider recipe. GRUB rebuilds initramfs inside its
    // provider recipe. Other snapshot-capable providers need an explicit
    // rebuild after the global mkinitcpio configuration was updated.
    let runner = TrustedTargetRunner::for_target(target_root);
    let mut pre_provider_actions = Vec::new();
    let pre_provider_failure =
        if requires_pre_provider_snapshot_initramfs_rebuild(provider, snapshot_state.enabled) {
            let result = runner.invoke(&TargetRequest::new(
                "mkinitcpio",
                vec!["-P".into()],
                "rebuild initramfs with the snapshot overlay hook",
            ));
            let success = !result.binary_missing && !result.timed_out && result.exit_code == 0;
            pre_provider_actions.push(crate::model::BootAction::TargetCommand {
                result: result.clone(),
            });
            (!success).then(|| {
                format!(
                    "mkinitcpio snapshot-overlay rebuild failed (exit={})",
                    result.exit_code
                )
            })
        } else {
            None
        };
    let provider_inputs = ProviderInputs {
        firmware: platform.firmware,
        mkinitcpio_text: &mkinitcpio_text,
        mkinitcpio_inputs,
        kernels: &kernels,
        efi_device,
    };
    let provider_executor = build_executor(provider, provider_inputs.clone());
    let provider_verifier = build_verifier(provider, provider_inputs);
    let exec_result = if let Some(failure) = pre_provider_failure {
        crate::execute::providers::base::ProviderExecutionResult {
            failure: Some(failure),
            ..Default::default()
        }
    } else {
        provider_executor.execute(&ctx, &runner)
    };
    let mut actions = config_actions;
    actions.extend(pre_provider_actions);
    actions.extend(exec_result.actions.into_iter().filter(|action| {
        !matches!(
            action,
            crate::model::BootAction::ConfigWritten { .. }
                | crate::model::BootAction::ConfigUnchanged { .. }
        )
    }));
    let mut verification = BootVerification::default();
    let mut secureboot_report: Option<SecureBootReport> = None;

    let mut warnings = Vec::new();
    let snapshot_execution = if exec_result.failure.is_none() && snapshot_state.enabled {
        run_snapshot_repair(provider, target_root, &runner)
    } else {
        SnapshotExecution::default()
    };
    actions.extend(snapshot_execution.actions);

    let final_outcome = if exec_result.failure.is_some() || snapshot_execution.failure.is_some() {
        if let Err(error) = config_transaction.rollback() {
            warnings.push(catos_target::model::Warning::new(
                "CONFIG_ROLLBACK_FAILED",
                error,
            ));
        }
        BootRepairOutcome::PartiallyRepaired
    } else {
        // 6. Verify.
        let mut verify_result = if provider == crate::model::ProviderId::Grub {
            verify_grub_target(target_root, &kernels)
        } else {
            provider_verifier.verify(&ctx, &runner)
        };
        if matches!(
            provider,
            crate::model::ProviderId::Limine
                | crate::model::ProviderId::SystemdBoot
                | crate::model::ProviderId::Uki
                | crate::model::ProviderId::Efistub
        ) && !target_provider_assets_present(
            provider,
            target_root,
            ctx.esp_mount_point.as_deref(),
            &kernels,
        ) {
            verify_result.passed = false;
            verify_result.verification.passed = false;
            verify_result
                .verification
                .checks
                .push("TARGET_ESP_ASSETS".into());
            verify_result.verification.failure_message = Some(
                "target ESP lacks the provider configuration or boot entries required for boot"
                    .into(),
            );
        }
        actions.extend(verify_result.actions);
        verification = merge_verification(verification, verify_result.verification);
        if !verify_result.passed {
            if let Err(error) = config_transaction.rollback() {
                warnings.push(catos_target::model::Warning::new(
                    "CONFIG_ROLLBACK_FAILED",
                    error,
                ));
            }
            BootRepairOutcome::VerificationFailed
        } else {
            // 7. Secure Boot finalisation (preserves target policy).
            let secureboot_inputs = SecureBootInputs {
                provider,
                target_marker_present: target_secureboot_marker_present(target_root),
                package_present: installed_packages.iter().any(|p| p == "catos-secureboot"),
                signed_artefact_observed: target_signed_catos_efi_present(
                    target_root,
                    ctx.esp_mount_point.as_deref(),
                ),
                previous_payload: None,
            };
            let (report, outcome_override, secureboot_action) =
                finalize_secure_boot(&runner, &secureboot_inputs);
            if let Some(result) = secureboot_action {
                actions.push(crate::model::BootAction::TargetCommand { result });
            }
            secureboot_report = Some(report);
            outcome_override.unwrap_or(BootRepairOutcome::Repaired)
        }
    };

    let fully_complete = matches!(final_outcome, BootRepairOutcome::Repaired)
        || matches!(final_outcome, BootRepairOutcome::Clean);
    let requires_human_action = !fully_complete;

    BootRepairReport {
        target: Some(target.clone()),
        platform: Some(platform),
        detected_provider: Some(provider),
        firmware_method: method,
        provider_evidence: evidence,
        kernel_cmdline: Some(cmdline),
        cmdline_conflicts: conflicts,
        actions,
        verification: Some(verification),
        secureboot: secureboot_report,
        cleanup: MountRepairCleanup::default(),
        final_outcome,
        requires_human_action,
        fully_complete,
        evidence: vec![Evidence::new(
            "PROVIDER_RECIPED",
            "repair::boot",
            format!("{} recipe executed", provider.as_str()),
        )],
        warnings,
    }
}

/// Translate the namespace-private ESP mount path back to the
/// target-side mount point the recipe expects (e.g. `/boot/efi`).
fn mount_point_for_target(target_root: &Path, session_path: &Path) -> Option<String> {
    let target_relative = session_path.strip_prefix(target_root).ok()?;
    let relative = target_relative.to_str()?.trim_start_matches('/');
    if relative.is_empty() {
        None
    } else {
        Some(format!("/{relative}"))
    }
}

fn merge_verification(
    mut existing: BootVerification,
    additional: BootVerification,
) -> BootVerification {
    let has_existing_check = !existing.checks.is_empty();
    existing.checks.extend(additional.checks);
    existing.passed = if has_existing_check {
        existing.passed && additional.passed
    } else {
        additional.passed
    };
    if !additional.passed {
        existing.failure_message = additional.failure_message.or(existing.failure_message);
    }
    existing
}
#[cfg(test)]
use crate::diagnose::target::{
    collect_detection_inputs_from_target_root, derive_bios_install_disk,
    detect_target_architecture, target_regular_file_present,
};
use crate::diagnose::target::{
    collect_target_kernels, derive_efi_device, target_secureboot_marker_present,
    target_signed_catos_efi_present,
};
#[cfg(test)]
use crate::model::FirmwareClass;
use crate::verify::{target_provider_assets_present, verify_grub_target};

use crate::execute::config::{write_provider_configs, ConfigTransaction};
use crate::execute::snapshot::{
    requires_pre_provider_snapshot_initramfs_rebuild, run_snapshot_repair, snapshot_repair_state,
    write_restored_snapper_config, SnapshotExecution,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execute::target::RecordedTargetRunner;
    use crate::model::{Architecture, PartitionTable, ProviderId};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempTargetRoot {
        path: PathBuf,
    }

    impl TempTargetRoot {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "catos-boot-repair-target-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempTargetRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    fn btrfs_target() -> MountTargetIdentity {
        MountTargetIdentity {
            root_device: PathBuf::from("/dev/nvme0n1p2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("root-uuid".into()),
            esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
            esp_uuid: Some("esp-uuid".into()),
            boot_layout: None,
        }
    }

    fn block_device(
        name: &str,
        dev_path: Option<&str>,
        parent: &str,
    ) -> catos_target::model::BlockDevice {
        use catos_target::model::{DeviceClass, DiskKind, PartitionRole};

        catos_target::model::BlockDevice {
            name: name.into(),
            dev_path: dev_path.map(PathBuf::from),
            major_minor: None,
            parent: parent.into(),
            class: if parent.is_empty() {
                DeviceClass::Disk
            } else {
                DeviceClass::Partition
            },
            disk_kind: DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: None,
            size_sectors: None,
            read_only: false,
            removable: false,
            filesystem: Some("btrfs".into()),
            uuid: None,
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: Vec::new(),
            mounted_before_session: false,
            evidence: Vec::new(),
        }
    }

    fn efi_x86_64_gpt() -> PlatformFacts {
        PlatformFacts {
            firmware: FirmwareClass::Efi,
            architecture: Architecture::X86_64,
            partition_table: PartitionTable::Gpt,
        }
    }

    #[test]
    fn mounted_orchestrator_collects_provider_evidence_only_from_target_root() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("etc/default/grub.d")).unwrap();
        fs::create_dir_all(target_root.path.join("boot/grub")).unwrap();
        fs::write(
            target_root.path.join("etc/default/grub.d/00-catos.cfg"),
            "GRUB_DISTRIBUTOR=TargetOnlyCatOS\n",
        )
        .unwrap();

        let evidence = collect_detection_inputs_from_target_root(&target_root.path);

        assert_eq!(
            evidence.grub_defaults_catos.as_deref(),
            Some("GRUB_DISTRIBUTOR=TargetOnlyCatOS\n")
        );
        assert!(evidence.has_boot_grub);
    }

    #[test]
    fn target_detection_collects_deployed_esp_evidence_from_all_supported_mountpoints() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("boot/efi/loader")).unwrap();
        fs::create_dir_all(target_root.path.join("boot/efi/EFI/Linux")).unwrap();
        fs::create_dir_all(target_root.path.join("boot/efi/EFI/CatOS/linux")).unwrap();
        fs::write(
            target_root.path.join("boot/efi/limine.conf"),
            "timeout: 3\n",
        )
        .unwrap();
        fs::write(
            target_root.path.join("boot/efi/loader/loader.conf"),
            "default catos\n",
        )
        .unwrap();
        fs::write(
            target_root.path.join("boot/efi/EFI/Linux/catos-linux.efi"),
            b"uki",
        )
        .unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/EFI/CatOS/linux/vmlinuz.efi"),
            b"kernel",
        )
        .unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/EFI/CatOS/linux/initramfs.img"),
            b"initramfs",
        )
        .unwrap();

        let inputs = collect_detection_inputs_from_target_root(&target_root.path);

        assert!(inputs.has_esp_limine_conf);
        assert!(inputs.has_systemd_boot_loader);
        assert!(inputs.has_catos_uki_deployed);
        assert!(inputs.has_efistub_deployed);
    }

    #[test]
    fn uki_assets_use_the_catos_firmware_tool_output_path() {
        let target_root = TempTargetRoot::new();
        let kernels = vec![Kernel {
            version: "7.1.4-arch1-1".into(),
            package: "linux".into(),
            image: "/usr/lib/modules/7.1.4-arch1-1/vmlinuz".into(),
            initramfs: "/boot/initramfs-linux.img".into(),
        }];
        fs::create_dir_all(target_root.path.join("boot/efi/EFI/Linux")).unwrap();
        fs::write(
            target_root.path.join("boot/efi/EFI/Linux/catos-linux.efi"),
            b"uki",
        )
        .unwrap();

        assert!(target_provider_assets_present(
            ProviderId::Uki,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
    }

    #[test]
    fn efistub_assets_use_per_kernel_catos_directory() {
        let target_root = TempTargetRoot::new();
        let kernels = vec![Kernel {
            version: "7.1.4-arch1-1".into(),
            package: "linux".into(),
            image: "/usr/lib/modules/7.1.4-arch1-1/vmlinuz".into(),
            initramfs: "/boot/initramfs-linux.img".into(),
        }];
        fs::create_dir_all(target_root.path.join("boot/efi/EFI/CatOS/linux")).unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/EFI/CatOS/linux/vmlinuz.efi"),
            b"kernel",
        )
        .unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/EFI/CatOS/linux/initramfs.img"),
            b"initramfs",
        )
        .unwrap();

        assert!(target_provider_assets_present(
            ProviderId::Efistub,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
    }

    #[test]
    fn firmware_provider_requires_target_efi_deployment() {
        let target_root = TempTargetRoot::new();
        let kernels = vec![Kernel {
            version: "7.1.4-arch1-1".into(),
            package: "linux".into(),
            image: "/usr/lib/modules/7.1.4-arch1-1/vmlinuz".into(),
            initramfs: "/boot/initramfs-linux.img".into(),
        }];
        fs::create_dir_all(target_root.path.join("boot/efi/EFI/Linux")).unwrap();

        assert!(!target_provider_assets_present(
            ProviderId::Uki,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
        fs::write(
            target_root.path.join("boot/efi/EFI/Linux/catos-linux.efi"),
            b"\xff\x00efi",
        )
        .unwrap();
        assert!(target_provider_assets_present(
            ProviderId::Uki,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
    }

    #[test]
    fn target_evidence_rejects_symlinked_path_components() {
        let target_root = TempTargetRoot::new();
        let escaped = std::env::temp_dir().join(format!(
            "catos-boot-repair-escaped-{}",
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(escaped.join("default/grub.d")).unwrap();
        fs::write(
            escaped.join("default/grub.d/00-catos.cfg"),
            "GRUB_DISTRIBUTOR=EscapedHostPath\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&escaped, target_root.path.join("etc")).unwrap();

        let evidence = collect_detection_inputs_from_target_root(&target_root.path);
        fs::remove_dir_all(&escaped).unwrap();

        assert!(evidence.grub_defaults_catos.is_none());
        assert!(evidence.limine_defaults.is_none());
    }

    #[test]
    fn session_esp_path_is_translated_to_target_mountpoint() {
        assert_eq!(
            mount_point_for_target(
                Path::new("/run/catos-system/sessions/boot/root"),
                Path::new("/run/catos-system/sessions/boot/root/boot/efi"),
            ),
            Some("/boot/efi".into())
        );
    }

    #[test]
    fn verification_merge_uses_the_first_real_check_as_its_baseline() {
        let merged = merge_verification(
            BootVerification::default(),
            BootVerification {
                passed: true,
                checks: vec!["TARGET_VERIFY".into()],
                failure_message: None,
            },
        );

        assert!(merged.passed);
        assert_eq!(merged.checks, vec!["TARGET_VERIFY"]);
    }

    #[test]
    fn target_architecture_is_read_from_target_elf_metadata() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("usr/lib/systemd")).unwrap();
        let mut elf = vec![0_u8; 20];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
        fs::write(target_root.path.join("usr/lib/systemd/systemd"), elf).unwrap();

        assert_eq!(
            detect_target_architecture(&target_root.path),
            Some(Architecture::Aarch64)
        );
    }

    #[test]
    fn cmdline_conflict_refuses_provider_mutation() {
        let target = btrfs_target();
        let report = run_boot_repair(
            &target,
            efi_x86_64_gpt(),
            Path::new("/mnt/target"),
            Some(Path::new("/mnt/target/boot/efi")),
            &DetectionInputs {
                grub_defaults_catos: Some("GRUB_DISTRIBUTOR=CatOS\n".into()),
                kernel_cmdline: Some("root=UUID=stale-root\n".into()),
                ..DetectionInputs::default()
            },
            None,
            &[],
            &[],
        );

        assert_eq!(
            report.final_outcome,
            BootRepairOutcome::ManualInterventionRequired
        );
        assert!(report.actions.is_empty());
    }

    #[test]
    fn bios_install_disk_comes_from_discovered_parent_device() {
        let target = btrfs_target();
        let root = block_device("nvme0n1p2", Some("/dev/nvme0n1p2"), "nvme0n1");
        let disk = block_device("nvme0n1", Some("/dev/nvme0n1"), "");

        assert_eq!(
            derive_bios_install_disk(&target, &[root, disk]).as_deref(),
            Some("/dev/nvme0n1")
        );
    }

    #[test]
    fn firmware_esp_disk_and_partition_come_from_discovered_storage_model() {
        let target = btrfs_target();
        let mut esp = block_device("nvme0n1p1", Some("/dev/nvme0n1p1"), "nvme0n1");
        esp.partition_number = Some(1);
        let disk = block_device("nvme0n1", Some("/dev/nvme0n1"), "");

        assert_eq!(
            derive_efi_device(&target, &[esp, disk]),
            Some(("/dev/nvme0n1".into(), 1))
        );
    }

    #[test]
    fn grub_verification_inspects_target_generated_configuration() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("boot/grub")).unwrap();
        fs::write(
            target_root.path.join("boot/grub/grub.cfg"),
            "menuentry 'CatOS' {\n linux /vmlinuz-linux root=UUID=root\n initrd /initramfs-linux.img\n}\n",
        )
        .unwrap();

        let kernels = vec![Kernel {
            version: "6.18.0-catos".into(),
            package: "linux-catos".into(),
            image: "/usr/lib/modules/6.18.0-catos/vmlinuz".into(),
            initramfs: "/boot/initramfs-linux.img".into(),
        }];
        assert!(!verify_grub_target(&target_root.path, &kernels).passed);
        fs::write(
            target_root.path.join("boot/initramfs-linux.img"),
            b"\xff\x00initramfs",
        )
        .unwrap();

        let verification = verify_grub_target(&target_root.path, &kernels);

        assert!(verification.passed);
        assert!(verification.verification.passed);
    }

    #[test]
    fn target_regular_file_presence_does_not_read_large_boot_assets() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("boot")).unwrap();
        let file = fs::File::create(target_root.path.join("boot/initramfs-linux.img")).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();

        assert!(target_regular_file_present(
            &target_root.path,
            "boot/initramfs-linux.img"
        ));
    }

    #[test]
    fn grub_verification_accepts_generated_tab_separated_commands() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("boot/grub")).unwrap();
        fs::write(
            target_root.path.join("boot/grub/grub.cfg"),
            "menuentry 'CatOS Linux' {\n\tlinux\t/boot/vmlinuz-linux root=UUID=root rw\n\tinitrd\t/boot/initramfs-linux.img\n}\n",
        )
        .unwrap();
        fs::write(
            target_root.path.join("boot/initramfs-linux.img"),
            b"initramfs",
        )
        .unwrap();
        let kernels = vec![Kernel {
            version: "7.1.4-arch1-1".into(),
            package: "linux".into(),
            image: "/boot/vmlinuz-linux".into(),
            initramfs: "/boot/initramfs-linux.img".into(),
        }];

        assert!(verify_grub_target(&target_root.path, &kernels).passed);
    }

    #[test]
    fn kernel_discovery_reads_target_modules_tree() {
        let target_root = TempTargetRoot::new();
        let module = target_root.path.join("usr/lib/modules/6.18.0-catos");
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("pkgbase"), "linux-catos\n").unwrap();
        fs::write(module.join("vmlinuz"), b"kernel").unwrap();

        let kernels = collect_target_kernels(&target_root.path);

        assert_eq!(kernels.len(), 1);
        assert_eq!(kernels[0].version, "6.18.0-catos");
        assert_eq!(kernels[0].package, "linux-catos");
    }

    #[test]
    fn limine_asset_verification_requires_target_esp_configuration() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("boot/efi")).unwrap();
        fs::write(
            target_root.path.join("boot/efi/limine.conf"),
            "timeout: 5\n",
        )
        .unwrap();

        let kernels = vec![Kernel {
            version: "6.18.0-catos".into(),
            package: "linux-catos".into(),
            image: "/usr/lib/modules/6.18.0-catos/vmlinuz".into(),
            initramfs: "/boot/initramfs-linux-catos.img".into(),
        }];
        assert!(!target_provider_assets_present(
            ProviderId::Limine,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
        fs::create_dir_all(target_root.path.join("etc")).unwrap();
        fs::write(target_root.path.join("etc/machine-id"), "machine-id\n").unwrap();
        fs::create_dir_all(target_root.path.join("boot/efi/machine-id/linux-catos")).unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/machine-id/linux-catos/vmlinuz"),
            b"\xff\x00kernel",
        )
        .unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/machine-id/linux-catos/initramfs"),
            b"initramfs",
        )
        .unwrap();
        assert!(target_provider_assets_present(
            ProviderId::Limine,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
        fs::remove_file(target_root.path.join("boot/efi/limine.conf")).unwrap();
        assert!(!target_provider_assets_present(
            ProviderId::Limine,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
    }

    #[test]
    fn systemd_boot_assets_require_machine_kernel_and_bls_entry() {
        let target_root = TempTargetRoot::new();
        let kernels = vec![Kernel {
            version: "6.18.0-catos".into(),
            package: "linux-catos".into(),
            image: "/usr/lib/modules/6.18.0-catos/vmlinuz".into(),
            initramfs: "/boot/initramfs-linux-catos.img".into(),
        }];
        fs::create_dir_all(target_root.path.join("boot/efi/loader/entries")).unwrap();
        fs::create_dir_all(target_root.path.join("etc")).unwrap();
        fs::write(target_root.path.join("etc/machine-id"), "machine-id\n").unwrap();
        fs::write(
            target_root.path.join("boot/efi/loader/loader.conf"),
            "default CatOS\n",
        )
        .unwrap();

        assert!(!target_provider_assets_present(
            ProviderId::SystemdBoot,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
        fs::create_dir_all(target_root.path.join("boot/efi/machine-id/6.18.0-catos")).unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/machine-id/6.18.0-catos/linux"),
            b"\xff\x00kernel",
        )
        .unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/machine-id/6.18.0-catos/initrd"),
            b"initramfs",
        )
        .unwrap();
        fs::write(
            target_root
                .path
                .join("boot/efi/loader/entries/machine-id-6.18.0-catos.conf"),
            "title CatOS\n",
        )
        .unwrap();
        assert!(target_provider_assets_present(
            ProviderId::SystemdBoot,
            &target_root.path,
            Some("/boot/efi"),
            &kernels,
        ));
    }

    #[test]
    fn firmware_boot_configuration_is_not_a_secureboot_marker() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("etc/catos")).unwrap();
        fs::write(
            target_root.path.join("etc/catos/firmware-boot.conf"),
            "method = uki\n",
        )
        .unwrap();

        assert!(!target_secureboot_marker_present(&target_root.path));
    }

    #[test]
    fn snapshot_repair_requires_target_side_existing_integration_evidence() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("etc/snapper/configs")).unwrap();

        assert!(
            !snapshot_repair_state(
                &target_root.path,
                ProviderId::Grub,
                "btrfs",
                &["snapper".into(), "grub-btrfs".into()]
            )
            .enabled
        );

        fs::write(
            target_root.path.join("etc/snapper/configs/root"),
            "SUBVOLUME=/.snapshots\n",
        )
        .unwrap();
        assert!(
            snapshot_repair_state(
                &target_root.path,
                ProviderId::Grub,
                "btrfs",
                &["snapper".into(), "grub-btrfs".into()]
            )
            .enabled
        );
        assert!(
            !snapshot_repair_state(
                &target_root.path,
                ProviderId::Uki,
                "btrfs",
                &["snapper".into()]
            )
            .enabled
        );
    }

    #[test]
    fn limine_snapshot_configuration_writes_overlay_hook_to_target_mkinitcpio() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("etc")).unwrap();
        let target = btrfs_target();
        let ctx = crate::execute::providers::base::ProviderCtx {
            target: &target,
            provider: ProviderId::Limine,
            cmdline: "root=UUID=root-uuid rw rootflags=subvol=/@".into(),
            esp_mount_point: Some("/boot/efi".into()),
            bios_install_path: None,
            architecture: Architecture::X86_64,
            branding_name: "CatOS".into(),
            root_is_btrfs: true,
        };
        let existing =
            "MODULES=()\nBINARIES=()\nFILES=()\nHOOKS=(base systemd block filesystems)\n";
        fs::write(target_root.path.join("etc/mkinitcpio.conf"), existing).unwrap();
        let inputs = crate::plan::initramfs::MkinitcpioInputs {
            existing_config: existing,
            root_filesystem: "btrfs".into(),
            provider: ProviderId::Limine,
            root_is_btrfs: true,
            snapshots_enabled: true,
            ..Default::default()
        };
        let mut transaction = ConfigTransaction::new(&target_root.path);

        write_provider_configs(
            &mut transaction,
            ProviderId::Limine,
            &ctx,
            None,
            existing,
            &inputs,
        )
        .unwrap();

        let written = read_target_file(&target_root.path, "etc/mkinitcpio.conf").unwrap();
        assert!(written.contains("limine-btrfs-overlayfs"));
    }

    #[test]
    fn non_grub_snapshot_providers_rebuild_initramfs_before_provider_commands() {
        assert!(requires_pre_provider_snapshot_initramfs_rebuild(
            ProviderId::Limine,
            true
        ));
        assert!(requires_pre_provider_snapshot_initramfs_rebuild(
            ProviderId::SystemdBoot,
            true
        ));
        assert!(!requires_pre_provider_snapshot_initramfs_rebuild(
            ProviderId::Grub,
            true
        ));
        assert!(!requires_pre_provider_snapshot_initramfs_rebuild(
            ProviderId::Uki,
            true
        ));
        assert!(!requires_pre_provider_snapshot_initramfs_rebuild(
            ProviderId::Limine,
            false
        ));
    }

    #[test]
    fn snapshot_generate_zero_is_failure_when_target_has_real_snapshots() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join(".snapshots/1/snapshot")).unwrap();
        fs::write(
            target_root.path.join(".snapshots/1/info.xml"),
            "<snapshot><description>acceptance</description></snapshot>",
        )
        .unwrap();
        let runner = RecordedTargetRunner::new()
            .queue_raw(0, b"snapper root ok".to_vec(), Vec::<u8>::new())
            .queue_raw(0, b"timer enabled".to_vec(), Vec::<u8>::new())
            .queue_raw(
                0,
                b"deployed 0 snapshots, 0 kernel sets, 0 objects, 0 bytes".to_vec(),
                Vec::<u8>::new(),
            );

        let result = run_snapshot_repair(ProviderId::Limine, &target_root.path, &runner);

        assert_eq!(
            result.failure.as_deref(),
            Some("generate Limine snapshot entries reported success but deployed zero snapshots")
        );
        let invocations = runner.invocations();
        assert_eq!(
            invocations.len(),
            3,
            "verify must not run after zero deployment"
        );
        assert_eq!(invocations[2].binary, "limine-btrfs");
        assert_eq!(invocations[2].argv, vec!["generate".to_string()]);
    }

    #[test]
    fn ambiguous_provider_when_no_authoritative_evidence() {
        let target = btrfs_target();
        let report = run_boot_repair(
            &target,
            efi_x86_64_gpt(),
            Path::new("/mnt/target"),
            Some(Path::new("/mnt/target/boot/efi")),
            &DetectionInputs::default(),
            None,
            &[],
            &[],
        );
        assert_eq!(report.final_outcome, BootRepairOutcome::AmbiguousProvider);
        assert!(report.requires_human_action);
    }

    #[test]
    fn conflicting_providers_fail_closed() {
        let target = btrfs_target();
        let inputs = DetectionInputs {
            grub_defaults_catos: Some("GRUB_DISTRIBUTOR=CatOS\n".into()),
            limine_defaults: Some("KERNEL_CMDLINE[default]=quiet rw\n".into()),
            ..DetectionInputs::default()
        };
        let report = run_boot_repair(
            &target,
            efi_x86_64_gpt(),
            Path::new("/mnt/target"),
            None,
            &inputs,
            None,
            &[],
            &[],
        );
        assert_eq!(report.final_outcome, BootRepairOutcome::AmbiguousProvider);
    }

    #[test]
    fn unsupported_platform_for_limine_on_aarch64() {
        let target = btrfs_target();
        let inputs = DetectionInputs {
            limine_defaults: Some("KERNEL_CMDLINE[default]=quiet rw\n".into()),
            ..DetectionInputs::default()
        };
        let report = run_boot_repair(
            &target,
            PlatformFacts {
                firmware: FirmwareClass::Efi,
                architecture: Architecture::Aarch64,
                partition_table: PartitionTable::Gpt,
            },
            Path::new("/mnt/target"),
            None,
            &inputs,
            None,
            &[],
            &[],
        );
        assert_eq!(report.final_outcome, BootRepairOutcome::Unsupported);
    }
}
