//! Bootloader provider repair (`catos-repair boot`). Ports the
//! bootloadu Calamares module's behaviour to the static Rust
//! backend, reusing the stage 1–3 target discovery, mount session,
//! device lock, and confined execution layers.
//!
//! ## What this module owns
//!
//! * `boot_repair::registry` — static port of `bootloaders.yaml`.
//! * `boot_repair::cmdline` — kernel cmdline builder + conflict
//!   detection.
//! * `boot_repair::mkinitcpio` — mkinitcpio.conf array management +
//!   kernel discovery.
//! * `boot_repair::detect` — evidence-based provider detection.
//! * `boot_repair::target_exec` — fixed allow-list, argv-only
//!   target command executor (replaces `target_env_call`).
//! * `boot_repair::secureboot` — target-policy-preserving Secure
//!   Boot finalisation.
//! * `boot_repair::providers` — per-provider recipe implementations
//!   (GRUB, Limine, systemd-boot, UEFI Firmware family for
//!   UKI/EFI Stub).
//!
//! ## What this module does NOT own
//!
//! * Target discovery, mount session, and device locks: those are
//!   the stage 1–3 surfaces (`repair::mount_repair`,
//!   `crate::recovery::RecoveryRwSession`, `recovery::lock`).
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
//!   [`crate::shared::model::boot_repair::BootRepairOutcome::PartiallyRepaired`]
//!   or
//!   [`crate::shared::model::boot_repair::BootRepairOutcome::ManualInterventionRequired`].

pub mod cmdline;
pub mod detect;
pub mod mkinitcpio;
pub mod providers;
pub mod registry;
pub mod secureboot;
pub mod target_exec;

use std::path::Path;

use crate::shared::model::boot_repair::{
    BootRepairOutcome, BootRepairReport, BootVerification, FirmwareClass, PlatformFacts,
    SecureBootReport,
};
use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount_repair::{MountRepairCleanup, TargetIdentity};
use crate::repair::boot_repair::cmdline::{build_kernel_cmdline, CmdlineInputs};
use crate::repair::boot_repair::detect::{detect, DetectionInputs, DetectionVerdict};
use crate::repair::boot_repair::providers::{build_ctx, build_provider};
use crate::repair::boot_repair::registry as boot_registry;
use crate::repair::boot_repair::secureboot::{finalize_secure_boot, SecureBootInputs};
use crate::repair::boot_repair::target_exec::{TargetRequest, TargetRunner, TrustedTargetRunner};

pub use mkinitcpio::Kernel;
pub use providers::ProviderInputs;
pub use registry::ProviderProfile;

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
    target: &TargetIdentity,
    platform: PlatformFacts,
    target_root: &Path,
    esp_root: Option<&Path>,
    detection: &DetectionInputs,
    bios_install_path: Option<&str>,
    installed_packages: &[String],
    storage_devices: &[crate::shared::model::storage::BlockDevice],
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
                        crate::shared::model::boot_repair::PartitionTable::Gpt => "gpt",
                        crate::shared::model::boot_repair::PartitionTable::Msdos => "msdos",
                        crate::shared::model::boot_repair::PartitionTable::Unknown => "unknown",
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
    let mkinitcpio_inputs = crate::repair::boot_repair::mkinitcpio::MkinitcpioInputs {
        existing_config: &mkinitcpio_text,
        root_filesystem: target.root_fstype.clone(),
        has_plymouth: installed_packages
            .iter()
            .any(|package| package == "plymouth"),
        has_crypto_keyfile: crate::shared::snapshot_engine::confined::read_rooted_file(
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
            pre_provider_actions.push(crate::shared::model::boot_repair::BootAction::TargetCommand {
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
    let provider_impl = build_provider(
        provider,
        ProviderInputs {
            firmware: platform.firmware,
            mkinitcpio_text: &mkinitcpio_text,
            mkinitcpio_inputs,
            kernels: &kernels,
            efi_device,
        },
    );
    let exec_result = if let Some(failure) = pre_provider_failure {
        let mut result =
            crate::repair::boot_repair::providers::base::ProviderRecipeResult::default();
        result.failure = Some(failure);
        result
    } else {
        provider_impl.execute(&ctx, &runner)
    };
    let mut actions = config_actions;
    actions.extend(pre_provider_actions);
    actions.extend(exec_result.actions.into_iter().filter(|action| {
        !matches!(
            action,
            crate::shared::model::boot_repair::BootAction::ConfigWritten { .. }
                | crate::shared::model::boot_repair::BootAction::ConfigUnchanged { .. }
        )
    }));
    let mut verification = exec_result.verification;
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
            warnings.push(crate::shared::model::inspection::Warning::new(
                "CONFIG_ROLLBACK_FAILED",
                error,
            ));
        }
        BootRepairOutcome::PartiallyRepaired
    } else {
        // 6. Verify.
        let mut verify_result = if provider == crate::shared::model::boot_repair::ProviderId::Grub {
            verify_grub_target(target_root, &kernels)
        } else {
            provider_impl.verify(&ctx, &runner)
        };
        if matches!(
            provider,
            crate::shared::model::boot_repair::ProviderId::Limine
                | crate::shared::model::boot_repair::ProviderId::SystemdBoot
                | crate::shared::model::boot_repair::ProviderId::Uki
                | crate::shared::model::boot_repair::ProviderId::Efistub
        ) && !target_provider_assets_present(
            provider,
            target_root,
            ctx.esp_mount_point.as_deref(),
            &kernels,
        ) {
            verify_result.verified = false;
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
        if !verify_result.verified {
            if let Err(error) = config_transaction.rollback() {
                warnings.push(crate::shared::model::inspection::Warning::new(
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
                actions.push(crate::shared::model::boot_repair::BootAction::TargetCommand { result });
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

/// Production CLI entry point for `catos-repair boot`. Mirrors the
/// shape of [`crate::repair::mount_repair::run_mount_repair_via_cli`]:
/// the caller supplies the same `--root-device` /
/// `--root-subvolume` / `--esp-device` triples that mount repair
/// accepts, and this function performs target discovery, mounts the
/// target inside a private namespace, observes the target's boot
/// evidence, and hands the result to [`run_boot_repair`].
///
/// When `authorised` is `false`, the function still performs
/// discovery and detection but refuses to invoke any provider
/// recipe (used by future Doctor integration).
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

    // Reuse the same mount-repair target discovery and read-write
    // session machinery so device-lock, fstab-aware ESP detection,
    // and private-namespace mount discipline are the same surfaces
    // the stage 1–3 path already verified. We delegate the heavy
    // lifting to a thin wrapper that runs the boot-specific
    // detection against the mounted target.
    let mut report = run_boot_repair_mounted(root_device, root_subvolume, esp_device);
    if report.final_outcome == BootRepairOutcome::Unknown {
        report.final_outcome = BootRepairOutcome::ManualInterventionRequired;
        report.requires_human_action = true;
    }
    report
}

/// Internal: discover + mount the target using the mount-repair
/// discovery, then run boot detection + provider recipe against the
/// mounted target.
fn run_boot_repair_mounted(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
) -> BootRepairReport {
    let mut session = match crate::repair::mount_repair::open_boot_repair_target_session(
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

    // Build platform facts from the discovered target. The live
    // host's uname is used for architecture (repair always runs on
    // the same architecture as the target — there is no
    // cross-arch repair use case). Firmware and partition table are
    // derived from the ESP/boot layout the mount-repair discovery
    // already established.
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

fn detect_target_architecture(root: &Path) -> Option<crate::shared::model::boot_repair::Architecture> {
    let executable =
        crate::shared::snapshot_engine::confined::read_rooted_file(root, "/usr/lib/systemd/systemd").ok()?;
    let machine = executable.get(18..20)?;
    match u16::from_le_bytes([machine[0], machine[1]]) {
        62 => Some(crate::shared::model::boot_repair::Architecture::X86_64),
        183 => Some(crate::shared::model::boot_repair::Architecture::Aarch64),
        _ => None,
    }
}

fn detect_partition_table(
    target: &TargetIdentity,
    devices: &[crate::shared::model::storage::BlockDevice],
) -> crate::shared::model::boot_repair::PartitionTable {
    use crate::shared::model::storage::DiskKind;

    let root = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == target.root_device)
    });
    match root.map(|device| device.disk_kind) {
        Some(DiskKind::Gpt) => crate::shared::model::boot_repair::PartitionTable::Gpt,
        Some(DiskKind::Mbr) => crate::shared::model::boot_repair::PartitionTable::Msdos,
        _ => crate::shared::model::boot_repair::PartitionTable::Unknown,
    }
}

fn derive_bios_install_disk(
    target: &TargetIdentity,
    devices: &[crate::shared::model::storage::BlockDevice],
) -> Option<String> {
    let root = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == target.root_device)
    })?;
    if root.parent.is_empty() {
        return None;
    }
    let matches: Vec<&crate::shared::model::storage::BlockDevice> = devices
        .iter()
        .filter(|device| device.name == root.parent)
        .filter(|device| device.parent.is_empty())
        .filter(|device| device.dev_path.is_some())
        .collect();
    match matches.as_slice() {
        [disk] => disk.dev_path.as_ref()?.to_str().map(str::to_string),
        _ => None,
    }
}

fn derive_efi_device(
    target: &TargetIdentity,
    devices: &[crate::shared::model::storage::BlockDevice],
) -> Option<(String, u32)> {
    let esp_path = target.esp_device.as_deref()?;
    let esp = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == esp_path)
    })?;
    let partition = esp.partition_number?;
    if esp.parent.is_empty() {
        return None;
    }
    let disk = devices
        .iter()
        .find(|device| device.name == esp.parent && device.parent.is_empty())?;
    let disk_path = disk.dev_path.as_ref()?.to_str()?.to_string();
    Some((disk_path, partition))
}

fn collect_detection_inputs_from_target_root(root: &Path) -> DetectionInputs {
    DetectionInputs {
        grub_defaults_catos: read_target_file(root, "etc/default/grub.d/00-catos.cfg"),
        limine_defaults: read_target_file(root, "etc/default/limine"),
        kernel_install_catos: read_target_file(
            root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        ),
        firmware_boot_conf: read_target_file(root, "etc/catos/firmware-boot.conf"),
        kernel_cmdline: read_target_file(root, "etc/kernel/cmdline"),
        has_boot_grub: has_target_path(root, "boot/grub"),
        has_esp_limine_conf: target_regular_file_in_any(
            root,
            &[
                "boot/limine.conf",
                "boot/efi/limine.conf",
                "efi/limine.conf",
            ],
        ),
        has_systemd_boot_loader: target_regular_file_in_any(
            root,
            &[
                "boot/loader/loader.conf",
                "boot/efi/loader/loader.conf",
                "efi/loader/loader.conf",
            ],
        ),
        has_catos_uki_deployed: target_uki_deployed(root),
        has_efistub_deployed: target_efistub_deployed(root),
        installed_packages: Vec::new(),
    }
}

fn collect_installed_packages_from_target_root(root: &Path) -> Vec<String> {
    crate::shared::snapshot_engine::confined::list_rooted_directory_names(root, "/var/lib/pacman/local")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .filter_map(|entry| {
            crate::shared::snapshot_engine::confined::read_rooted_file(
                root,
                &format!("/var/lib/pacman/local/{entry}/desc"),
            )
            .ok()
        })
        .filter_map(|contents| String::from_utf8(contents).ok())
        .filter_map(|contents| pacman_package_name(&contents))
        .collect()
}

fn collect_target_kernels(root: &Path) -> Vec<crate::repair::boot_repair::mkinitcpio::Kernel> {
    let entries = crate::shared::snapshot_engine::confined::list_rooted_directory_names(root, "/usr/lib/modules")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .map(|version| {
            let base = format!("/usr/lib/modules/{version}");
            let pkgbase =
                crate::shared::snapshot_engine::confined::read_rooted_file(root, &format!("{base}/pkgbase"))
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_default();
            let has_vmlinuz = crate::shared::snapshot_engine::confined::rooted_regular_file_size(
                root,
                &format!("{base}/vmlinuz"),
            )
            .ok()
            .flatten()
            .is_some_and(|size| size > 0);
            (version, !pkgbase.is_empty(), has_vmlinuz, pkgbase)
        })
        .collect::<Vec<_>>();
    crate::repair::boot_repair::mkinitcpio::discover_kernels(&entries)
}

fn pacman_package_name(desc: &str) -> Option<String> {
    let mut lines = desc.lines();
    while let Some(line) = lines.next() {
        if line == "%NAME%" {
            return lines
                .next()
                .map(str::to_string)
                .filter(|name| !name.is_empty());
        }
    }
    None
}

fn read_target_file(root: &Path, relative: &str) -> Option<String> {
    crate::shared::snapshot_engine::confined::read_rooted_file(root, &format!("/{relative}"))
        .ok()
        .and_then(|contents| String::from_utf8(contents).ok())
}

fn target_regular_file_present(root: &Path, relative: &str) -> bool {
    crate::shared::snapshot_engine::confined::rooted_regular_file_size(root, &format!("/{relative}"))
        .ok()
        .flatten()
        .is_some_and(|size| size > 0)
}

fn target_regular_file_in_any(root: &Path, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| target_regular_file_present(root, candidate))
}

fn target_uki_deployed(root: &Path) -> bool {
    ["/boot/EFI/Linux", "/boot/efi/EFI/Linux", "/efi/EFI/Linux"]
        .iter()
        .any(|directory| {
            crate::shared::snapshot_engine::confined::list_rooted_directory_names(root, directory)
                .unwrap_or_default()
                .iter()
                .any(|entry| {
                    entry
                        .to_str()
                        .is_some_and(|entry| entry.starts_with("catos-") && entry.ends_with(".efi"))
                })
        })
}

fn target_efistub_deployed(root: &Path) -> bool {
    ["/boot/EFI/CatOS", "/boot/efi/EFI/CatOS", "/efi/EFI/CatOS"]
        .iter()
        .any(|directory| {
            crate::shared::snapshot_engine::confined::list_rooted_directory_names(root, directory)
                .unwrap_or_default()
                .iter()
                .filter_map(|entry| entry.to_str().map(str::to_string))
                .any(|package| {
                    target_regular_file_present(
                        root,
                        &format!(
                            "{}/{package}/vmlinuz.efi",
                            directory.trim_start_matches('/')
                        ),
                    ) && target_regular_file_present(
                        root,
                        &format!(
                            "{}/{package}/initramfs.img",
                            directory.trim_start_matches('/')
                        ),
                    )
                })
        })
}

fn has_target_path(root: &Path, relative: &str) -> bool {
    crate::shared::snapshot_engine::confined::list_rooted_directory_names(root, &format!("/{relative}")).is_ok()
}

#[derive(Debug, Clone, Default)]
struct SnapshotRepairState {
    enabled: bool,
    restore_root_config: Option<String>,
}

/// Snapshot repair is deliberately opt-in from evidence already stored in the
/// target. A Btrfs root alone is not evidence that its owner intended bootable
/// snapshots, so it must never cause us to create a new Snapper setup.
fn snapshot_repair_state(
    target_root: &Path,
    provider: crate::shared::model::boot_repair::ProviderId,
    root_fstype: &str,
    _installed_packages: &[String],
) -> SnapshotRepairState {
    if root_fstype != "btrfs" || boot_registry::snapshot_profile(provider).is_none() {
        return SnapshotRepairState::default();
    }

    if crate::shared::snapshot_engine::confined::read_rooted_file(target_root, "/etc/snapper/configs/root").is_ok()
    {
        return SnapshotRepairState {
            enabled: true,
            restore_root_config: None,
        };
    }

    let template = crate::shared::snapshot_engine::confined::read_rooted_file(
        target_root,
        "/etc/snapper/config-templates/catos-root",
    )
    .ok()
    .and_then(|bytes| String::from_utf8(bytes).ok());
    if has_target_path(target_root, ".snapshots") && template.is_some() {
        return SnapshotRepairState {
            enabled: true,
            restore_root_config: template,
        };
    }

    SnapshotRepairState::default()
}

fn write_restored_snapper_config(
    transaction: &mut ConfigTransaction,
    target_root: &Path,
    template: &str,
) -> Result<Vec<crate::shared::model::boot_repair::BootAction>, String> {
    let current = read_target_file(target_root, "etc/conf.d/snapper");
    let registration = register_snapper_root(current.as_deref())?;
    Ok(vec![
        transaction.write("/etc/snapper/configs/root", template)?,
        transaction.write("/etc/conf.d/snapper", &registration)?,
    ])
}

fn register_snapper_root(existing: Option<&str>) -> Result<String, String> {
    let mut lines = existing
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut found = false;
    for line in &mut lines {
        let trimmed = line.trim_start();
        let Some(value) = trimmed.strip_prefix("SNAPPER_CONFIGS=") else {
            continue;
        };
        let value = value.trim();
        let Some(values) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
            return Err("cannot safely update non-quoted SNAPPER_CONFIGS".into());
        };
        let mut configs = values.split_whitespace().collect::<Vec<_>>();
        if configs.iter().any(|name| {
            name.is_empty()
                || !name.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
                })
        }) {
            return Err("cannot safely update invalid SNAPPER_CONFIGS value".into());
        }
        if !configs.contains(&"root") {
            configs.push("root");
        }
        *line = format!("SNAPPER_CONFIGS=\"{}\"", configs.join(" "));
        found = true;
        break;
    }
    if !found {
        lines.push("SNAPPER_CONFIGS=\"root\"".into());
    }
    Ok(format!("{}\n", lines.join("\n")))
}

#[derive(Default)]
struct SnapshotExecution {
    actions: Vec<crate::shared::model::boot_repair::BootAction>,
    failure: Option<String>,
}

fn requires_pre_provider_snapshot_initramfs_rebuild(
    provider: crate::shared::model::boot_repair::ProviderId,
    snapshots_enabled: bool,
) -> bool {
    snapshots_enabled
        && matches!(
            provider,
            crate::shared::model::boot_repair::ProviderId::Limine
                | crate::shared::model::boot_repair::ProviderId::SystemdBoot
        )
}

fn run_snapshot_repair(
    provider: crate::shared::model::boot_repair::ProviderId,
    target_root: &Path,
    runner: &dyn TargetRunner,
) -> SnapshotExecution {
    use crate::shared::model::boot_repair::ProviderId;

    let mut execution = SnapshotExecution::default();
    let target_has_snapshots = target_snapshot_catalog_has_entries(target_root);
    let mut run = |binary: &str, argv: Vec<String>, description: &str, require_deployment: bool| {
        if execution.failure.is_some() {
            return;
        }
        let result = runner.invoke(&TargetRequest::new(binary, argv, description));
        let success = !result.binary_missing && !result.timed_out && result.exit_code == 0;
        let zero_deployment = require_deployment
            && target_has_snapshots
            && snapshot_generate_reports_zero_deployment(&result);
        execution
            .actions
            .push(crate::shared::model::boot_repair::BootAction::SnapshotStep {
                description: description.into(),
                result: Some(result),
            });
        if !success {
            execution.failure = Some(format!("{description} failed"));
        } else if zero_deployment {
            execution.failure = Some(format!(
                "{description} reported success but deployed zero snapshots"
            ));
        }
    };

    run(
        "snapper",
        vec![
            "--no-dbus".into(),
            "-c".into(),
            "root".into(),
            "get-config".into(),
        ],
        "validate Snapper root configuration",
        false,
    );
    run(
        "systemctl",
        vec!["enable".into(), "snapper-cleanup.timer".into()],
        "enable Snapper cleanup timer",
        false,
    );

    match provider {
        ProviderId::Grub => {
            if snapshot_unit_present(target_root, "grub-btrfsd.service") {
                run(
                    "systemctl",
                    vec!["enable".into(), "grub-btrfsd.service".into()],
                    "enable grub-btrfsd service",
                    false,
                );
            }
            run(
                "grub-mkconfig",
                vec!["-o".into(), "/boot/grub/grub.cfg".into()],
                "regenerate GRUB snapshot entries",
                false,
            );
        }
        ProviderId::Limine => {
            run(
                "limine-btrfs",
                vec!["generate".into()],
                "generate Limine snapshot entries",
                true,
            );
            run(
                "limine-btrfs",
                vec!["verify".into()],
                "verify Limine snapshot entries",
                false,
            );
            if snapshot_unit_present(target_root, "limine-btrfs.service") {
                run(
                    "systemctl",
                    vec!["enable".into(), "limine-btrfs.service".into()],
                    "enable limine-btrfs service",
                    false,
                );
            }
        }
        ProviderId::SystemdBoot => {
            run(
                "sdboot-btrfs",
                vec!["generate".into()],
                "generate systemd-boot snapshot entries",
                true,
            );
            run(
                "sdboot-btrfs",
                vec!["verify".into()],
                "verify systemd-boot snapshot entries",
                false,
            );
            if snapshot_unit_present(target_root, "sdboot-btrfs.service") {
                run(
                    "systemctl",
                    vec!["enable".into(), "sdboot-btrfs.service".into()],
                    "enable sdboot-btrfs service",
                    false,
                );
            }
        }
        ProviderId::Uki | ProviderId::Efistub => {
            execution.failure = Some("snapshot repair requested for unsupported provider".into());
        }
    }
    execution
}

fn target_snapshot_catalog_has_entries(target_root: &Path) -> bool {
    crate::shared::snapshot_engine::confined::list_rooted_directory_names(target_root, "/.snapshots")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .filter(|entry| entry.chars().all(|character| character.is_ascii_digit()))
        .any(|entry| {
            crate::shared::snapshot_engine::confined::rooted_regular_file_size(
                target_root,
                &format!("/.snapshots/{entry}/info.xml"),
            )
            .is_ok()
                && crate::shared::snapshot_engine::confined::list_rooted_directory_names(
                    target_root,
                    &format!("/.snapshots/{entry}/snapshot"),
                )
                .is_ok()
        })
}

fn snapshot_generate_reports_zero_deployment(
    result: &crate::shared::model::boot_repair::TargetCommandResult,
) -> bool {
    let output = result
        .stdout
        .iter()
        .chain(result.stderr.iter())
        .copied()
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&output)
        .to_ascii_lowercase()
        .contains("deployed 0 snapshots")
}

fn snapshot_unit_present(target_root: &Path, unit: &str) -> bool {
    crate::shared::snapshot_engine::confined::read_rooted_file(
        target_root,
        &format!("/usr/lib/systemd/system/{unit}"),
    )
    .is_ok()
        || crate::shared::snapshot_engine::confined::read_rooted_file(
            target_root,
            &format!("/etc/systemd/system/{unit}"),
        )
        .is_ok()
}

struct ConfigTransaction {
    root: std::path::PathBuf,
    changes: Vec<ConfigChange>,
}

struct ConfigChange {
    target_path: String,
    original: Option<Vec<u8>>,
}

impl ConfigTransaction {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            changes: Vec::new(),
        }
    }

    fn write(
        &mut self,
        target_path: &str,
        contents: &str,
    ) -> Result<crate::shared::model::boot_repair::BootAction, String> {
        let parent = Path::new(target_path)
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| format!("invalid target configuration path {target_path:?}"))?;
        crate::shared::snapshot_engine::confined::create_rooted_directory(&self.root, parent)
            .map_err(|error| format!("cannot create target config parent {parent}: {error}"))?;
        let existing = crate::shared::snapshot_engine::confined::read_rooted_file(&self.root, target_path).ok();
        if existing.as_deref() == Some(contents.as_bytes()) {
            return Ok(crate::shared::model::boot_repair::BootAction::ConfigUnchanged {
                target_path: target_path.to_string(),
            });
        }
        let backup_path = existing.as_ref().map(|bytes| {
            let backup_path = format!("{target_path}.catos-repair.backup");
            crate::shared::snapshot_engine::confined::atomic_write_rooted(&self.root, &backup_path, bytes, 0o600)
                .map_err(|error| format!("cannot write backup {backup_path}: {error}"))?;
            Ok::<String, String>(backup_path)
        });
        let backup_path = backup_path.transpose()?;
        crate::shared::snapshot_engine::confined::atomic_write_rooted(
            &self.root,
            target_path,
            contents.as_bytes(),
            0o644,
        )
        .map_err(|error| format!("cannot write target config {target_path}: {error}"))?;
        self.changes.push(ConfigChange {
            target_path: target_path.to_string(),
            original: existing,
        });
        Ok(crate::shared::model::boot_repair::BootAction::ConfigWritten {
            target_path: target_path.to_string(),
            backup_path,
            bytes: contents.len(),
        })
    }

    fn rollback(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        for change in self.changes.drain(..).rev() {
            let result = match change.original {
                Some(original) => crate::shared::snapshot_engine::confined::atomic_write_rooted(
                    &self.root,
                    &change.target_path,
                    &original,
                    0o644,
                ),
                None => {
                    crate::shared::snapshot_engine::confined::remove_rooted_file(&self.root, &change.target_path)
                }
            };
            if let Err(error) = result {
                errors.push(format!("{}: {error}", change.target_path));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn write_provider_configs(
    transaction: &mut ConfigTransaction,
    provider: crate::shared::model::boot_repair::ProviderId,
    ctx: &crate::repair::boot_repair::providers::base::ProviderCtx<'_>,
    efi_device: Option<&(String, u32)>,
    mkinitcpio_text: &str,
    mkinitcpio_inputs: &crate::repair::boot_repair::mkinitcpio::MkinitcpioInputs<'_>,
) -> Result<Vec<crate::shared::model::boot_repair::BootAction>, String> {
    use crate::shared::model::boot_repair::{FirmwareMethod, ProviderId};

    // bootloadu configures mkinitcpio before every provider. Limine and
    // systemd-boot snapshot overlays therefore need the same target config,
    // not only GRUB.
    let arrays = crate::repair::boot_repair::mkinitcpio::compute_arrays(mkinitcpio_inputs);
    let mut actions = vec![transaction.write(
        "/etc/mkinitcpio.conf",
        &crate::repair::boot_repair::mkinitcpio::serialise(mkinitcpio_text, &arrays),
    )?];

    match provider {
        ProviderId::Grub => {
            actions.push(transaction.write(
                "/etc/default/grub.d/00-catos.cfg",
                &crate::repair::boot_repair::providers::grub::build_grub_defaults(ctx),
            )?);
        }
        ProviderId::Limine => {
            actions.push(transaction.write("/etc/kernel/cmdline", &format!("{}\n", ctx.cmdline))?);
            actions.push(transaction.write(
                "/etc/default/limine",
                &crate::repair::boot_repair::providers::limine::build_limine_defaults(ctx),
            )?);
        }
        ProviderId::SystemdBoot => {
            actions.push(transaction.write("/etc/kernel/cmdline", &format!("{}\n", ctx.cmdline))?);
            actions.push(transaction.write(
                "/etc/kernel/install.conf.d/20-catos-bootloadu.conf",
                &crate::repair::boot_repair::providers::systemd_boot::build_install_conf(ctx),
            )?);
        }
        ProviderId::Uki | ProviderId::Efistub => {
            let method = match provider {
                ProviderId::Uki => FirmwareMethod::Uki,
                ProviderId::Efistub => FirmwareMethod::Efistub,
                _ => unreachable!(),
            };
            let efi_device = efi_device.ok_or_else(|| {
                "firmware boot repair requires verified ESP disk and partition facts before writing its configuration"
                    .to_string()
            })?;
            actions.push(transaction.write("/etc/kernel/cmdline", &format!("{}\n", ctx.cmdline))?);
            actions.push(transaction.write(
                "/etc/catos/firmware-boot.conf",
                &crate::repair::boot_repair::providers::firmware::build_firmware_boot_conf(
                    method,
                    ctx,
                    Some(efi_device),
                ),
            )?);
        }
    }
    Ok(actions)
}

fn verify_grub_target(
    target_root: &Path,
    kernels: &[Kernel],
) -> crate::repair::boot_repair::providers::base::ProviderRecipeResult {
    use crate::shared::model::boot_repair::BootVerification;
    use crate::repair::boot_repair::providers::base::ProviderRecipeResult;

    let config = read_target_file(target_root, "boot/grub/grub.cfg");
    let valid = config
        .as_deref()
        .is_some_and(grub_config_has_bootable_linux_entry)
        && kernels.iter().any(|kernel| {
            target_regular_file_present(target_root, kernel.initramfs.trim_start_matches('/'))
        });
    ProviderRecipeResult {
        verified: valid,
        verification: BootVerification {
            passed: valid,
            checks: vec![
                "GRUB_CFG_LINUX_MENUENTRY".into(),
                "GRUB_TARGET_INITRAMFS".into(),
            ],
            failure_message: (!valid).then_some(
                "target GRUB configuration or generated target initramfs is not bootable".into(),
            ),
        },
        ..ProviderRecipeResult::default()
    }
}

fn grub_config_has_bootable_linux_entry(config: &str) -> bool {
    let mut has_menuentry = false;
    let mut has_linux = false;
    let mut has_initrd = false;
    for line in config.lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("menuentry") => has_menuentry = true,
            Some("linux" | "linuxefi") => has_linux = true,
            Some("initrd" | "initrdefi") => has_initrd = true,
            _ => {}
        }
    }
    has_menuentry && has_linux && has_initrd
}

fn target_provider_assets_present(
    provider: crate::shared::model::boot_repair::ProviderId,
    target_root: &Path,
    esp_mount_point: Option<&str>,
    kernels: &[Kernel],
) -> bool {
    use crate::shared::model::boot_repair::ProviderId;

    let Some(esp_mount_point) = esp_mount_point else {
        return false;
    };
    let esp = esp_mount_point.trim_start_matches('/');
    match provider {
        ProviderId::Limine => {
            read_target_file(target_root, &format!("{esp}/limine.conf"))
                .is_some_and(|contents| !contents.trim().is_empty())
                && target_deployed_kernel_assets(
                    target_root,
                    esp,
                    kernels,
                    |kernel| format!("{esp}/{{machine_id}}/{}", kernel.package),
                    "vmlinuz",
                    "initramfs",
                )
        }
        ProviderId::SystemdBoot => {
            read_target_file(target_root, &format!("{esp}/loader/loader.conf"))
                .is_some_and(|contents| !contents.trim().is_empty())
                && target_deployed_kernel_assets(
                    target_root,
                    esp,
                    kernels,
                    |kernel| format!("{esp}/{{machine_id}}/{}", kernel.version),
                    "linux",
                    "initrd",
                )
                && target_systemd_boot_entry_present(target_root, esp, kernels)
        }
        ProviderId::Uki => target_uki_assets_present(target_root, esp, kernels),
        ProviderId::Efistub => target_efistub_assets_present(target_root, esp, kernels),
        ProviderId::Grub => true,
    }
}

fn target_uki_assets_present(target_root: &Path, esp: &str, kernels: &[Kernel]) -> bool {
    !kernels.is_empty()
        && kernels.iter().all(|kernel| {
            target_regular_file_present(
                target_root,
                &format!("{esp}/EFI/Linux/catos-{}.efi", kernel.package),
            )
        })
}

fn target_efistub_assets_present(target_root: &Path, esp: &str, kernels: &[Kernel]) -> bool {
    !kernels.is_empty()
        && kernels.iter().all(|kernel| {
            let directory = format!("{esp}/EFI/CatOS/{}", kernel.package);
            target_regular_file_present(target_root, &format!("{directory}/vmlinuz.efi"))
                && target_regular_file_present(target_root, &format!("{directory}/initramfs.img"))
        })
}

fn target_deployed_kernel_assets(
    target_root: &Path,
    esp: &str,
    kernels: &[Kernel],
    directory: impl Fn(&Kernel) -> String,
    kernel_asset: &str,
    initramfs_asset: &str,
) -> bool {
    let Some(machine_id) = read_target_file(target_root, "etc/machine-id")
        .map(|machine_id| machine_id.trim().to_string())
        .filter(|machine_id| !machine_id.is_empty())
    else {
        return false;
    };
    kernels.iter().any(|kernel| {
        let directory = directory(kernel).replace("{machine_id}", &machine_id);
        target_regular_file_present(target_root, &format!("{directory}/{kernel_asset}"))
            && target_regular_file_present(target_root, &format!("{directory}/{initramfs_asset}"))
            && directory.starts_with(esp)
    })
}

fn target_systemd_boot_entry_present(target_root: &Path, esp: &str, kernels: &[Kernel]) -> bool {
    let Some(machine_id) = read_target_file(target_root, "etc/machine-id")
        .map(|machine_id| machine_id.trim().to_string())
        .filter(|machine_id| !machine_id.is_empty())
    else {
        return false;
    };
    let entries = crate::shared::snapshot_engine::confined::list_rooted_directory_names(
        target_root,
        &format!("/{esp}/loader/entries"),
    )
    .unwrap_or_default();
    kernels.iter().any(|kernel| {
        let prefix = format!("{machine_id}-{}", kernel.version);
        entries.iter().any(|entry| {
            entry
                .to_str()
                .is_some_and(|entry| entry.starts_with(&prefix) && entry.ends_with(".conf"))
        })
    })
}

fn target_secureboot_marker_present(target_root: &Path) -> bool {
    has_target_path(target_root, "etc/catos/secureboot")
        || read_target_file(target_root, "etc/catos/secureboot.conf").is_some()
        || has_target_path(target_root, "var/lib/catos/secureboot")
}

fn target_signed_catos_efi_present(target_root: &Path, esp_mount_point: Option<&str>) -> bool {
    let Some(esp_mount_point) = esp_mount_point else {
        return false;
    };
    let directory = format!("/{}/EFI/CatOS", esp_mount_point.trim_start_matches('/'));
    let entries = crate::shared::snapshot_engine::confined::list_rooted_directory_names(target_root, &directory)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .collect::<Vec<_>>();
    entries.iter().any(|entry| entry.ends_with(".efi"))
        && entries
            .iter()
            .any(|entry| entry.ends_with(".sig") || entry.ends_with(".p7b"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::boot_repair::{Architecture, PartitionTable, ProviderId};
    use crate::repair::boot_repair::target_exec::RecordedTargetRunner;
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

    fn btrfs_target() -> TargetIdentity {
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

    fn block_device(
        name: &str,
        dev_path: Option<&str>,
        parent: &str,
    ) -> crate::shared::model::storage::BlockDevice {
        use crate::shared::model::storage::{DeviceClass, DiskKind, PartitionRole};

        crate::shared::model::storage::BlockDevice {
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
    fn target_config_write_is_atomic_and_records_a_backup() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("etc/default/grub.d")).unwrap();
        fs::write(
            target_root.path.join("etc/default/grub.d/00-catos.cfg"),
            "old\n",
        )
        .unwrap();

        let action = ConfigTransaction::new(&target_root.path)
            .write("/etc/default/grub.d/00-catos.cfg", "new\n")
            .unwrap();

        assert_eq!(
            read_target_file(&target_root.path, "etc/default/grub.d/00-catos.cfg").as_deref(),
            Some("new\n")
        );
        assert_eq!(
            read_target_file(
                &target_root.path,
                "etc/default/grub.d/00-catos.cfg.catos-repair.backup",
            )
            .as_deref(),
            Some("old\n")
        );
        assert!(matches!(
            action,
            crate::shared::model::boot_repair::BootAction::ConfigWritten { .. }
        ));
    }

    #[test]
    fn config_transaction_rolls_back_existing_and_new_files() {
        let target_root = TempTargetRoot::new();
        fs::create_dir_all(target_root.path.join("etc/catos")).unwrap();
        fs::write(target_root.path.join("etc/catos/existing.conf"), "before\n").unwrap();
        let mut transaction = ConfigTransaction::new(&target_root.path);

        transaction
            .write("/etc/catos/existing.conf", "after\n")
            .unwrap();
        transaction.write("/etc/catos/new.conf", "new\n").unwrap();
        transaction.rollback().unwrap();

        assert_eq!(
            read_target_file(&target_root.path, "etc/catos/existing.conf").as_deref(),
            Some("before\n")
        );
        assert!(read_target_file(&target_root.path, "etc/catos/new.conf").is_none());
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
        assert!(!verify_grub_target(&target_root.path, &kernels).verified);
        fs::write(
            target_root.path.join("boot/initramfs-linux.img"),
            b"\xff\x00initramfs",
        )
        .unwrap();

        let verification = verify_grub_target(&target_root.path, &kernels);

        assert!(verification.verified);
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

        assert!(verify_grub_target(&target_root.path, &kernels).verified);
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
        let ctx = crate::repair::boot_repair::providers::base::ProviderCtx {
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
        let inputs = crate::repair::boot_repair::mkinitcpio::MkinitcpioInputs {
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
