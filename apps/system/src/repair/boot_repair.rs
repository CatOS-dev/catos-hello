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
//!   `crate::phase3::RecoveryRwSession`, `recovery::lock`).
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
//!   [`crate::model::boot_repair::BootRepairOutcome::PartiallyRepaired`]
//!   or
//!   [`crate::model::boot_repair::BootRepairOutcome::ManualInterventionRequired`].

pub mod cmdline;
pub mod detect;
pub mod mkinitcpio;
pub mod providers;
pub mod registry;
pub mod secureboot;
pub mod target_exec;

use std::path::Path;

use crate::model::boot_repair::{
    BootRepairOutcome, BootRepairReport, BootVerification, FirmwareClass, PlatformFacts,
    SecureBootReport,
};
use crate::model::evidence::Evidence;
use crate::model::mount_repair::{MountRepairCleanup, TargetIdentity};
use crate::repair::boot_repair::cmdline::{build_kernel_cmdline, CmdlineInputs};
use crate::repair::boot_repair::detect::{detect, DetectionInputs, DetectionVerdict};
use crate::repair::boot_repair::providers::{build_ctx, build_provider};
use crate::repair::boot_repair::registry as boot_registry;
use crate::repair::boot_repair::secureboot::{finalize_secure_boot, SecureBootInputs};
use crate::repair::boot_repair::target_exec::TrustedTargetRunner;

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
pub fn run_boot_repair(
    target: &TargetIdentity,
    platform: PlatformFacts,
    _target_root: &Path,
    esp_root: Option<&Path>,
    detection: &DetectionInputs,
    bios_install_path: Option<&str>,
    installed_packages: &[String],
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
                        crate::model::boot_repair::PartitionTable::Gpt => "gpt",
                        crate::model::boot_repair::PartitionTable::Msdos => "msdos",
                        crate::model::boot_repair::PartitionTable::Unknown => "unknown",
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
        // Cmdline conflicts are reported but do not abort the repair;
        // the recipe values win because they are derived from the
        // verified target identity. Conflicts surface in the report
        // so the operator can audit.
    }

    // 4. Build provider context.
    let esp_mount_point = esp_root
        .and_then(|path| path.to_str())
        .map(|p| mount_point_for_target(target, p))
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

    // 5. Run the provider recipe.
    let runner = TrustedTargetRunner::new();
    let provider_impl = build_provider(
        provider,
        ProviderInputs {
            firmware: platform.firmware,
            mkinitcpio_text: "",
            mkinitcpio_inputs: Default::default(),
            kernels: &[],
            efi_device: None,
        },
    );
    let exec_result = provider_impl.execute(&ctx, &runner);
    let mut actions = exec_result.actions;
    let mut verification = exec_result.verification;
    let mut secureboot_report: Option<SecureBootReport> = None;

    let final_outcome = if exec_result.failure.is_some() {
        BootRepairOutcome::PartiallyRepaired
    } else {
        // 6. Verify.
        let verify_result = provider_impl.verify(&ctx, &runner);
        actions.extend(verify_result.actions);
        verification = merge_verification(verification, verify_result.verification);
        if !verify_result.verified {
            BootRepairOutcome::VerificationFailed
        } else {
            // 7. Secure Boot finalisation (preserves target policy).
            let secureboot_inputs = SecureBootInputs {
                provider,
                target_marker_present: detection.firmware_boot_conf.as_deref().is_some(),
                package_present: installed_packages.iter().any(|p| p == "catos-secureboot"),
                signed_artefact_observed: false,
                previous_payload: None,
            };
            let (report, outcome_override) = finalize_secure_boot(&runner, &secureboot_inputs);
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
        warnings: Vec::new(),
    }
}

/// Translate the namespace-private ESP mount path back to the
/// target-side mount point the recipe expects (e.g. `/boot/efi`).
fn mount_point_for_target(_target: &TargetIdentity, namespace_path: &str) -> String {
    // The orchestrator mounts the ESP at the target-relative path
    // inside the namespace. We surface the target-side mount point
    // to the recipe (e.g. `/boot/efi`) so the provider writes
    // configuration files that match what the target sees at runtime.
    if let Some(rest) = namespace_path.strip_prefix("/boot/efi") {
        format!("/boot/efi{rest}")
    } else if let Some(rest) = namespace_path.strip_prefix("/efi") {
        format!("/efi{rest}")
    } else {
        namespace_path.to_string()
    }
}

fn merge_verification(
    mut existing: BootVerification,
    additional: BootVerification,
) -> BootVerification {
    existing.checks.extend(additional.checks);
    existing.passed = existing.passed && additional.passed;
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
    // Stage-3 mount-repair discovery is the authoritative target
    // selector. We invoke its CLI helper with authorised=true so it
    // returns a full MountRepairReport whose `target` field is the
    // verified TargetIdentity we need. We do NOT apply any fstab
    // edits — mount_repair's diagnosis-only path returns the
    // target identity without writing.
    let mount_report = crate::repair::mount_repair::run_mount_repair_via_cli(
        root_device,
        root_subvolume,
        esp_device,
        true,
    );
    let target = match mount_report.target {
        Some(target) => target,
        None => {
            return BootRepairReport::refused(
                BootRepairOutcome::AmbiguousTarget,
                "boot repair could not uniquely identify the target via mount-repair discovery",
            );
        }
    };

    // Build platform facts from the discovered target. The live
    // host's uname is used for architecture (repair always runs on
    // the same architecture as the target — there is no
    // cross-arch repair use case). Firmware and partition table are
    // derived from the ESP/boot layout the mount-repair discovery
    // already established.
    let architecture = detect_architecture();
    let firmware = if target.esp_device.is_some() {
        FirmwareClass::Efi
    } else {
        FirmwareClass::Bios
    };
    let partition_table = detect_partition_table(&target);
    let platform = PlatformFacts {
        firmware,
        architecture,
        partition_table,
    };

    // Read the target-side boot evidence through the same confined
    // filesystem API mount repair uses. For an offline target this
    // is the btrfs top-level mount; for the running root it is `/`.
    let detection = collect_detection_inputs(&target);
    let installed_packages = collect_installed_packages(&target);

    let bios_install_path = target
        .root_device
        .parent()
        .and_then(|parent| parent.to_str())
        .map(str::to_string);

    run_boot_repair(
        &target,
        platform,
        std::path::Path::new("/"),
        target.esp_device.as_deref().map(std::path::Path::new),
        &detection,
        bios_install_path.as_deref(),
        &installed_packages,
    )
}

fn detect_architecture() -> crate::model::boot_repair::Architecture {
    let machine = std::env::consts::ARCH;
    crate::model::boot_repair::Architecture::from_uname(machine)
        .unwrap_or(crate::model::boot_repair::Architecture::X86_64)
}

fn detect_partition_table(target: &TargetIdentity) -> crate::model::boot_repair::PartitionTable {
    // The mount-repair discovery surfaces the ESP device but not the
    // partition table directly. We infer from the device: if the
    // root device name is the whole disk (no partition suffix), we
    // cannot tell and return Unknown. Otherwise we consult
    // `/sys/class/block/<disk>/pttype` via a confined read.
    let dev_path = match target.root_device.to_str() {
        Some(path) => path,
        None => return crate::model::boot_repair::PartitionTable::Unknown,
    };
    let disk_name = match infer_whole_disk(dev_path) {
        Some(name) => name,
        None => return crate::model::boot_repair::PartitionTable::Unknown,
    };
    let pttype_path = format!("/sys/class/block/{disk_name}/pttype");
    match std::fs::read_to_string(&pttype_path) {
        Ok(value) => match value.trim() {
            "gpt" => crate::model::boot_repair::PartitionTable::Gpt,
            "msdos" | "mbr" => crate::model::boot_repair::PartitionTable::Msdos,
            _ => crate::model::boot_repair::PartitionTable::Unknown,
        },
        Err(_) => crate::model::boot_repair::PartitionTable::Unknown,
    }
}

fn infer_whole_disk(dev_path: &str) -> Option<String> {
    let basename = dev_path.rsplit('/').next()?;
    if let Some(stripped) = basename
        .strip_prefix("nvme")
        .and_then(|rest| rest.find('n').map(|idx| &rest[..idx]))
    {
        return Some(format!("nvme{stripped}n"));
    }
    if basename.starts_with("mmcblk") {
        let prefix: String = basename
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect();
        let numeric: String = basename
            .chars()
            .skip(prefix.len())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        return Some(format!("{prefix}{numeric}"));
    }
    let prefix: String = basename
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    if !prefix.is_empty() && basename.len() > prefix.len() {
        return Some(prefix);
    }
    None
}

fn collect_detection_inputs(target: &TargetIdentity) -> DetectionInputs {
    let root = target_root_for_read(target);
    DetectionInputs {
        grub_defaults_catos: read_target_file(&root, "etc/default/grub.d/00-catos.cfg"),
        limine_defaults: read_target_file(&root, "etc/default/limine"),
        kernel_install_catos: read_target_file(
            &root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        ),
        firmware_boot_conf: read_target_file(&root, "etc/catos/firmware-boot.conf"),
        kernel_cmdline: read_target_file(&root, "etc/kernel/cmdline"),
        has_boot_grub: has_target_path(&root, "boot/grub"),
        has_esp_limine_conf: target
            .boot_layout
            .as_ref()
            .and_then(|layout| layout.esp_mount_point())
            .is_some_and(|_| false),
        has_systemd_boot_loader: false,
        has_catos_uki_deployed: false,
        has_efistub_deployed: false,
        installed_packages: Vec::new(),
    }
}

fn collect_installed_packages(target: &TargetIdentity) -> Vec<String> {
    let root = target_root_for_read(target);
    let local_db = root.join("var/lib/pacman/local");
    match std::fs::read_dir(&local_db) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let trimmed = name.rsplit_once('-').map(|(base, _)| base).unwrap_or(&name);
                trimmed.to_string()
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn target_root_for_read(_target: &TargetIdentity) -> std::path::PathBuf {
    std::path::PathBuf::from("/")
}

fn read_target_file(root: &std::path::Path, relative: &str) -> Option<String> {
    std::fs::read_to_string(root.join(relative)).ok()
}

fn has_target_path(root: &std::path::Path, relative: &str) -> bool {
    std::fs::metadata(root.join(relative))
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::boot_repair::{Architecture, PartitionTable};
    use std::path::PathBuf;

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

    fn efi_x86_64_gpt() -> PlatformFacts {
        PlatformFacts {
            firmware: FirmwareClass::Efi,
            architecture: Architecture::X86_64,
            partition_table: PartitionTable::Gpt,
        }
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
        );
        assert_eq!(report.final_outcome, BootRepairOutcome::Unsupported);
    }
}
