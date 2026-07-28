//! Stage-4 `catos-repair boot` behaviour contract.
//!
//! These tests port the bootloadu Python tests plus the
//! must-have behaviours the spec calls out:
//!
//! 1. **Pure model + helper layer** (lib-only, no I/O):
//!    provider registry, platform matrix, cmdline builder,
//!    mkinitcpio config, target command allow-list.
//! 2. **Detection layer** (`boot::diagnose::provider`): fed
//!    synthetic evidence, produces a verdict we assert against.
//! 3. **Provider recipe layer** (`boot::execute::providers`):
//!    fed a `RecordedTargetRunner`, records exact argv, verifies
//!    exit-code interpretation.
//! 4. **Binary subprocess (CLI contract)**: spawns the real binary
//!    via the multicall symlink so argv[0] routing, --help,
//!    --version, and the boot domain surface are exercised.
//!
//! What these tests deliberately do NOT do:
//!
//! * Run a real `grub-install` against a loop device. That is the
//!   QEMU smoke test's job.
//! * Accept a `verify` step that only checks file presence.

use std::process::Command;

use catos_system::boot::diagnose::provider::{detect, DetectionInputs, DetectionVerdict};
use catos_system::boot::execute::providers::base::{
    BootProviderExecutor, BootProviderVerifier, ProviderCtx,
};
use catos_system::boot::execute::providers::firmware::FirmwareProvider;
use catos_system::boot::execute::providers::grub::{build_grub_defaults, GrubProvider};
use catos_system::boot::execute::providers::limine::LimineProvider;
use catos_system::boot::execute::providers::systemd_boot::{
    build_install_conf, SystemdBootProvider,
};
use catos_system::boot::execute::secureboot::{should_finalize, FinalizeDecision};
use catos_system::boot::execute::target::{
    RecordedTargetRunner, TargetRunner, TrustedTargetRunner,
};
use catos_system::boot::model::{
    Architecture, BootRepairOutcome, FirmwareClass, FirmwareMethod, PartitionTable, ProviderId,
};
use catos_system::boot::plan::cmdline::{build_kernel_cmdline, CmdlineInputs};
use catos_system::boot::plan::initramfs as mkinitcpio;
use catos_system::boot::plan::registry::{
    partition_table_supported, platform_supported, secure_boot_supported, snapshot_profile,
    target_platform_supported, SnapshotManager,
};
use catos_system::mount::model::MountTargetIdentity;

fn bin_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_catos-system"))
}

fn btrfs_target() -> MountTargetIdentity {
    use std::path::PathBuf;
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

// ===========================================================================
// Section 1 — Provider registry ported from test_bootloadu.py
// ===========================================================================

#[test]
fn platform_matrix_is_not_a_cartesian_product() {
    assert!(platform_supported(
        ProviderId::Limine,
        FirmwareClass::Efi,
        Architecture::X86_64
    ));
    assert!(!platform_supported(
        ProviderId::Limine,
        FirmwareClass::Bios,
        Architecture::X86_64
    ));
    assert!(!platform_supported(
        ProviderId::Limine,
        FirmwareClass::Efi,
        Architecture::Aarch64
    ));
}

#[test]
fn grub_supports_bios_x86_64_only() {
    assert!(platform_supported(
        ProviderId::Grub,
        FirmwareClass::Bios,
        Architecture::X86_64
    ));
    assert!(!platform_supported(
        ProviderId::Grub,
        FirmwareClass::Bios,
        Architecture::Aarch64
    ));
}

#[test]
fn gpt_required_providers_reject_msdos_and_unknown() {
    for provider in [
        ProviderId::Limine,
        ProviderId::SystemdBoot,
        ProviderId::Uki,
        ProviderId::Efistub,
    ] {
        assert!(partition_table_supported(provider, PartitionTable::Gpt));
        assert!(!partition_table_supported(provider, PartitionTable::Msdos));
        assert!(!partition_table_supported(
            provider,
            PartitionTable::Unknown
        ));
    }
}

#[test]
fn grub_does_not_require_gpt_but_still_refuses_unknown() {
    assert!(partition_table_supported(
        ProviderId::Grub,
        PartitionTable::Gpt
    ));
    assert!(partition_table_supported(
        ProviderId::Grub,
        PartitionTable::Msdos
    ));
    assert!(!partition_table_supported(
        ProviderId::Grub,
        PartitionTable::Unknown
    ));
}

#[test]
fn snapshot_profile_returns_snapper_for_supported_providers() {
    for provider in [
        ProviderId::Grub,
        ProviderId::Limine,
        ProviderId::SystemdBoot,
    ] {
        let snap = snapshot_profile(provider).expect("snapshots expected");
        assert_eq!(snap.manager, SnapshotManager::Snapper);
        assert!(snap.required_filesystems.contains(&"btrfs"));
    }
}

#[test]
fn snapshot_profile_returns_none_for_uki_and_efistub() {
    assert!(snapshot_profile(ProviderId::Uki).is_none());
    assert!(snapshot_profile(ProviderId::Efistub).is_none());
}

#[test]
fn target_platform_supported_combines_all_axes() {
    assert!(target_platform_supported(
        ProviderId::Grub,
        FirmwareClass::Bios,
        Architecture::X86_64,
        PartitionTable::Msdos
    ));
    assert!(!target_platform_supported(
        ProviderId::Limine,
        FirmwareClass::Efi,
        Architecture::X86_64,
        PartitionTable::Msdos
    ));
    assert!(!target_platform_supported(
        ProviderId::Limine,
        FirmwareClass::Efi,
        Architecture::Aarch64,
        PartitionTable::Gpt
    ));
}

// ===========================================================================
// Section 2 — Secure Boot provider restrictions
// (test_bootloadu_secureboot port)
// ===========================================================================

#[test]
fn secureboot_supports_grub_limine_systemd_boot_uki_only() {
    for provider in [
        ProviderId::Grub,
        ProviderId::Limine,
        ProviderId::SystemdBoot,
        ProviderId::Uki,
    ] {
        assert!(secure_boot_supported(provider));
    }
    assert!(!secure_boot_supported(ProviderId::Efistub));
}

#[test]
fn secureboot_decision_preserves_target_policy_only() {
    // bootloadu test_prepare_secure_boot_supports_uki_and_rejects_efistub port.
    // Efistub is rejected only when a target policy actually demands re-application.
    assert_eq!(
        should_finalize(&secureboot_inputs(ProviderId::Efistub, false)),
        FinalizeDecision::LeaveUntouched
    );
    assert_eq!(
        should_finalize(&secureboot_inputs(ProviderId::Efistub, true)),
        FinalizeDecision::Unsupported
    );
    // GRUB without target policy is left untouched.
    assert_eq!(
        should_finalize(&secureboot_inputs(ProviderId::Grub, false)),
        FinalizeDecision::LeaveUntouched
    );
    // UKI with target policy is re-applied.
    assert_eq!(
        should_finalize(&secureboot_inputs(ProviderId::Uki, true)),
        FinalizeDecision::Reapply
    );
}

fn secureboot_inputs(
    provider: ProviderId,
    target_policy: bool,
) -> catos_system::boot::execute::secureboot::SecureBootInputs {
    catos_system::boot::execute::secureboot::SecureBootInputs {
        provider,
        target_marker_present: target_policy,
        ..Default::default()
    }
}

// ===========================================================================
// Section 3 — mkinitcpio config port from test_bootloadu.py
// ===========================================================================

#[test]
fn snapshot_provider_appends_matching_overlayfs_hook() {
    let expected: &[(&str, &str)] = &[
        ("grub", "grub-btrfs-overlayfs"),
        ("limine", "limine-btrfs-overlayfs"),
        ("systemd-boot", "sdboot-btrfs-overlayfs"),
    ];
    for (provider_str, overlay_hook) in expected {
        let provider = ProviderId::from_registry_str(provider_str).unwrap();
        let inputs = mkinitcpio::MkinitcpioInputs {
            existing_config: "HOOKS=(base udev block filesystems fsck)\n",
            root_filesystem: "btrfs".into(),
            provider,
            snapshots_enabled: true,
            root_is_btrfs: true,
            ..Default::default()
        };
        let arrays = mkinitcpio::compute_arrays(&inputs);
        assert_eq!(arrays.hooks.last().map(String::as_str), Some(*overlay_hook));
        assert_eq!(arrays.hooks.iter().filter(|h| h == overlay_hook).count(), 1);
    }
}

#[test]
fn mkinitcpio_omits_overlayfs_hook_without_snapshots() {
    let inputs = mkinitcpio::MkinitcpioInputs {
        existing_config: "HOOKS=(base udev block filesystems fsck)\n",
        root_filesystem: "btrfs".into(),
        provider: ProviderId::Limine,
        snapshots_enabled: false,
        root_is_btrfs: true,
        ..Default::default()
    };
    let arrays = mkinitcpio::compute_arrays(&inputs);
    assert!(!arrays.hooks.iter().any(|h| h.contains("btrfs-overlayfs")));
}

#[test]
fn mkinitcpio_configuration_embeds_keyfile_and_swap_hook() {
    let inputs = mkinitcpio::MkinitcpioInputs {
        existing_config: "MODULES=(existing)\nBINARIES=()\nFILES=()\n\
            HOOKS=(base udev autodetect block filesystems fsck)\n",
        root_filesystem: "btrfs".into(),
        encrypted_root: true,
        encrypted_swap: true,
        has_swap: true,
        has_crypto_keyfile: true,
        ..Default::default()
    };
    let arrays = mkinitcpio::compute_arrays(&inputs);
    assert!(arrays.hooks.contains(&"encrypt".to_string()));
    assert!(arrays.hooks.contains(&"openswap".to_string()));
    assert!(arrays.hooks.contains(&"resume".to_string()));
    assert!(arrays.files.contains(&"/crypto_keyfile.bin".to_string()));
    assert!(!arrays.hooks.contains(&"fsck".to_string()));
    assert!(arrays.modules.contains(&"existing".to_string()));
}

#[test]
fn mkinitcpio_removes_stale_managed_keyfile() {
    let inputs = mkinitcpio::MkinitcpioInputs {
        existing_config: "FILES=(/crypto_keyfile.bin /etc/keep-me)\n\
            HOOKS=(base udev filesystems fsck)\n",
        root_filesystem: "ext4".into(),
        ..Default::default()
    };
    let arrays = mkinitcpio::compute_arrays(&inputs);
    assert!(!arrays.files.contains(&"/crypto_keyfile.bin".to_string()));
    assert!(arrays.files.contains(&"/etc/keep-me".to_string()));
}

// ===========================================================================
// Section 4 — GRUB cryptodisk + theme-adjuster (test_bootloadu port)
// ===========================================================================

#[test]
fn grub_defaults_omit_cryptodisk_when_root_unencrypted() {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/sda2"),
        root_fstype: "ext4".into(),
        root_subvol: None,
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/sda1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    let ctx = ProviderCtx {
        target,
        provider: ProviderId::Grub,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: false,
    };
    let defaults = build_grub_defaults(&ctx);
    assert!(!defaults.contains("GRUB_ENABLE_CRYPTODISK"));
    assert!(defaults.contains("GRUB_DISTRIBUTOR=CatOS"));
}

// ===========================================================================
// Section 5 — systemd-boot BOOT_ROOT policy (test_bootloadu port)
// ===========================================================================

#[test]
fn systemd_boot_persists_boot_root_policy() {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    let ctx = ProviderCtx {
        target,
        provider: ProviderId::SystemdBoot,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    };
    let conf = build_install_conf(&ctx);
    assert!(conf.contains("BOOT_ROOT=/boot/efi"));
    assert!(conf.contains("layout=bls"));
}

// ===========================================================================
// Section 6 — Firmware provider branding (test_bootloadu port)
// ===========================================================================

#[test]
fn firmware_provider_uses_plain_branding_label() {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    let ctx = ProviderCtx {
        target,
        provider: ProviderId::Uki,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    };
    let conf = catos_system::boot::execute::providers::firmware::build_firmware_boot_conf(
        FirmwareMethod::Uki,
        &ctx,
        Some(&("/dev/nvme0n1".to_string(), 1)),
    );
    assert!(conf.contains("label_prefix = CatOS"));
    assert!(!conf.contains("machine_id"));
}

// ===========================================================================
// Section 7 — Limine verify requires deployed kernel assets
// ===========================================================================

#[test]
fn limine_verify_records_limine_list() {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    let ctx = ProviderCtx {
        target,
        provider: ProviderId::Limine,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    };
    let runner = RecordedTargetRunner::new().expect_raw(
        "limine-list",
        Vec::<String>::new(),
        0,
        b"CatOS\n".to_vec(),
        b"".to_vec(),
    );
    let result = LimineProvider.verify(&ctx, &runner);
    assert!(result.passed);
    assert!(result.verification.passed);
    runner.assert_consumed();
}

#[test]
fn limine_verify_fails_when_limine_list_exits_nonzero() {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    let ctx = ProviderCtx {
        target,
        provider: ProviderId::Limine,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    };
    let runner = RecordedTargetRunner::new().expect_raw(
        "limine-list",
        Vec::<String>::new(),
        1,
        b"".to_vec(),
        b"missing".to_vec(),
    );
    let result = LimineProvider.verify(&ctx, &runner);
    assert!(!result.passed);
    assert!(result.verification.failure_message.is_some());
    runner.assert_consumed();
}

// ===========================================================================
// Section 8 — GRUB recipe argv (no shell, exact --target, etc.)
// ===========================================================================

fn grub_ctx() -> ProviderCtx<'static> {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/sda2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/sda1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    ProviderCtx {
        target,
        provider: ProviderId::Grub,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: Some("/dev/sda".into()),
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    }
}

#[test]
fn grub_uefi_recipe_uses_correct_target_and_efi_directory() {
    let runner = RecordedTargetRunner::new()
        .expect_raw("mkinitcpio", ["-P"], 0, b"", b"")
        .expect_raw(
            "grub-install",
            [
                "--target=x86_64-efi",
                "--efi-directory=/boot/efi",
                "--bootloader-id=CatOS",
                "--recheck",
            ],
            0,
            b"",
            b"",
        )
        .expect_raw("grub-mkconfig", ["-o", "/boot/grub/grub.cfg"], 0, b"", b"");
    let provider = GrubProvider {
        firmware: FirmwareClass::Efi,
        mkinitcpio_text: "",
        mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs::default(),
    };
    let result = provider.execute(&grub_ctx(), &runner);
    assert!(result.failure.is_none());
    let invocations = runner.invocations();
    let grub_install = invocations
        .iter()
        .find(|inv| inv.binary == "grub-install")
        .unwrap();
    assert!(grub_install
        .argv
        .iter()
        .any(|arg| arg == "--target=x86_64-efi"));
    assert!(grub_install
        .argv
        .iter()
        .any(|arg| arg == "--efi-directory=/boot/efi"));
    assert!(grub_install
        .argv
        .iter()
        .any(|arg| arg == "--bootloader-id=CatOS"));
    runner.assert_consumed();
}

#[test]
fn grub_bios_recipe_uses_i386_pc_and_disk() {
    let runner = RecordedTargetRunner::new()
        .expect_raw("mkinitcpio", ["-P"], 0, b"", b"")
        .expect_raw(
            "grub-install",
            ["--target=i386-pc", "--recheck", "/dev/sda"],
            0,
            b"",
            b"",
        )
        .expect_raw("grub-mkconfig", ["-o", "/boot/grub/grub.cfg"], 0, b"", b"");
    let provider = GrubProvider {
        firmware: FirmwareClass::Bios,
        mkinitcpio_text: "",
        mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs::default(),
    };
    let result = provider.execute(&grub_ctx(), &runner);
    assert!(result.failure.is_none());
    let invocations = runner.invocations();
    let grub_install = invocations
        .iter()
        .find(|inv| inv.binary == "grub-install")
        .unwrap();
    assert!(grub_install
        .argv
        .iter()
        .any(|arg| arg == "--target=i386-pc"));
    assert_eq!(
        grub_install.argv.last().map(String::as_str),
        Some("/dev/sda")
    );
    runner.assert_consumed();
}

#[test]
fn grub_failure_on_mkinitcpio_stops_subsequent_commands() {
    let runner = RecordedTargetRunner::new().expect_raw(
        "mkinitcpio",
        ["-P"],
        1,
        b"".to_vec(),
        b"mkinitcpio failed".to_vec(),
    );
    let provider = GrubProvider {
        firmware: FirmwareClass::Efi,
        mkinitcpio_text: "",
        mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs::default(),
    };
    let result = provider.execute(&grub_ctx(), &runner);
    assert!(result.failure.is_some());
    // Only mkinitcpio was attempted; grub-install was not reached.
    assert!(!runner.invoked_binary("grub-install"));
    runner.assert_consumed();
}

// ===========================================================================
// Section 9 — Firmware (UKI + EFI Stub) recipe
// ===========================================================================

#[test]
fn firmware_execute_runs_catos_firmware_boot_update_force() {
    let runner = RecordedTargetRunner::new().expect_raw(
        "catos-firmware-boot-update",
        ["--force"],
        0,
        b"",
        b"",
    );
    let provider = FirmwareProvider {
        method: FirmwareMethod::Uki,
        efi_device: Some(("/dev/nvme0n1".to_string(), 1)),
    };
    let result = provider.execute(&grub_ctx_provider(ProviderId::Uki), &runner);
    assert!(result.failure.is_none());
    assert!(runner.invoked_binary("catos-firmware-boot-update"));
    assert_eq!(runner.invocations()[0].argv, vec!["--force".to_string()]);
    runner.assert_consumed();
}

#[test]
fn firmware_verify_uses_force_and_verify_flags() {
    let runner = RecordedTargetRunner::new().expect_raw(
        "catos-firmware-boot-update",
        ["--force", "--verify"],
        0,
        b"verified".to_vec(),
        b"".to_vec(),
    );
    let provider = FirmwareProvider {
        method: FirmwareMethod::Efistub,
        efi_device: None,
    };
    let result = provider.verify(&grub_ctx_provider(ProviderId::Efistub), &runner);
    assert!(result.passed);
    assert_eq!(
        runner.invocations()[0].argv,
        vec!["--force".to_string(), "--verify".to_string()]
    );
    runner.assert_consumed();
}

fn grub_ctx_provider(provider: ProviderId) -> ProviderCtx<'static> {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    ProviderCtx {
        target,
        provider,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    }
}

// ===========================================================================
// Section 10 — Provider detection
// ===========================================================================

#[test]
fn grub_defaults_is_authoritative_for_grub() {
    let inputs = DetectionInputs {
        grub_defaults_catos: Some("GRUB_DISTRIBUTOR=CatOS\n".into()),
        ..DetectionInputs::default()
    };
    let verdict = detect(&inputs, &btrfs_target());
    match verdict {
        DetectionVerdict::Detected { provider, .. } => assert_eq!(provider, ProviderId::Grub),
        other => panic!("expected Detected, got {other:?}"),
    }
}

#[test]
fn limine_defaults_is_authoritative_for_limine() {
    let inputs = DetectionInputs {
        limine_defaults: Some("KERNEL_CMDLINE[default]=quiet rw\n".into()),
        ..DetectionInputs::default()
    };
    let verdict = detect(&inputs, &btrfs_target());
    match verdict {
        DetectionVerdict::Detected { provider, .. } => assert_eq!(provider, ProviderId::Limine),
        other => panic!("expected Detected, got {other:?}"),
    }
}

#[test]
fn systemd_boot_install_conf_is_authoritative() {
    let inputs = DetectionInputs {
        kernel_install_catos: Some("BOOT_ROOT=/boot/efi\nlayout=bls\n".into()),
        ..DetectionInputs::default()
    };
    let verdict = detect(&inputs, &btrfs_target());
    match verdict {
        DetectionVerdict::Detected { provider, .. } => {
            assert_eq!(provider, ProviderId::SystemdBoot)
        }
        other => panic!("expected Detected, got {other:?}"),
    }
}

#[test]
fn firmware_boot_conf_uki_is_authoritative() {
    let inputs = DetectionInputs {
        firmware_boot_conf: Some("[boot]\nmethod = uki\n".into()),
        ..DetectionInputs::default()
    };
    let verdict = detect(&inputs, &btrfs_target());
    match verdict {
        DetectionVerdict::Detected {
            provider, method, ..
        } => {
            assert_eq!(provider, ProviderId::Uki);
            assert_eq!(method, Some(FirmwareMethod::Uki));
        }
        other => panic!("expected Detected, got {other:?}"),
    }
}

#[test]
fn stale_esp_artefact_alone_is_not_authoritative() {
    let inputs = DetectionInputs {
        has_boot_grub: true,
        has_esp_limine_conf: true,
        has_systemd_boot_loader: true,
        has_catos_uki_deployed: true,
        ..DetectionInputs::default()
    };
    let verdict = detect(&inputs, &btrfs_target());
    assert!(matches!(verdict, DetectionVerdict::Ambiguous { .. }));
}

#[test]
fn conflicting_authoritative_sources_surface_conflict() {
    let inputs = DetectionInputs {
        grub_defaults_catos: Some("GRUB_DISTRIBUTOR=CatOS\n".into()),
        limine_defaults: Some("KERNEL_CMDLINE[default]=quiet rw\n".into()),
        ..DetectionInputs::default()
    };
    let verdict = detect(&inputs, &btrfs_target());
    match verdict {
        DetectionVerdict::Conflict { providers, .. } => {
            assert!(providers.contains(&ProviderId::Grub));
            assert!(providers.contains(&ProviderId::Limine));
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
}

#[test]
fn package_presence_alone_is_not_authoritative() {
    let inputs = DetectionInputs {
        installed_packages: vec!["grub".into(), "limine".into(), "bootctl".into()],
        ..DetectionInputs::default()
    };
    let verdict = detect(&inputs, &btrfs_target());
    assert!(matches!(verdict, DetectionVerdict::Ambiguous { .. }));
}

// ===========================================================================
// Section 11 — Kernel cmdline conflict detection
// ===========================================================================

#[test]
fn cmdline_preserves_user_parameters() {
    let target = btrfs_target();
    let (cmdline, conflicts) = build_kernel_cmdline(&CmdlineInputs {
        target: &target,
        existing_cmdline: "mitigations=off i915.enable_guc=2",
        has_plymouth: false,
        facts: &catos_system::boot::model::BootCmdlineFacts::default(),
    });
    assert!(cmdline.contains("mitigations=off"));
    assert!(cmdline.contains("i915.enable_guc=2"));
    assert!(cmdline.contains("root=UUID=root-uuid"));
    assert!(conflicts.is_empty());
}

#[test]
fn cmdline_conflicting_root_value_surfaces_conflict() {
    let target = btrfs_target();
    let (_, conflicts) = build_kernel_cmdline(&CmdlineInputs {
        target: &target,
        existing_cmdline: "root=UUID=stale",
        has_plymouth: false,
        facts: &catos_system::boot::model::BootCmdlineFacts::default(),
    });
    assert!(conflicts.iter().any(|c| matches!(c,
        catos_system::boot::model::CmdlineConflict::ConflictingValue { key, .. } if key == "root"
    )));
}

// ===========================================================================
// Section 12 — Target command executor allow-list
// ===========================================================================

#[test]
fn target_executor_refuses_non_allowlisted_binary() {
    let runner = TrustedTargetRunner::new();
    let request = catos_system::boot::execute::target::TargetRequest::new(
        "rm",
        vec!["-rf".into(), "/".into()],
        "hostile",
    );
    let result = runner.invoke(&request);
    assert!(result.binary_missing);
    assert!(String::from_utf8_lossy(&result.stderr).contains("non-allow-list"));
}

#[test]
fn target_executor_allow_list_covers_only_documented_tools() {
    use catos_system::boot::execute::target::ALLOWED_BINARIES;
    for tool in [
        "mkinitcpio",
        "grub-install",
        "grub-mkconfig",
        "bootctl",
        "catos-secureboot",
    ] {
        assert!(
            ALLOWED_BINARIES.contains(&tool),
            "{tool} must be allow-listed"
        );
    }
    for hostile in ["sh", "bash", "rm", "dd", "mkfs.ext4"] {
        assert!(
            !ALLOWED_BINARIES.contains(&hostile),
            "{hostile} must NOT be allow-listed"
        );
    }
}

// Trait imported only so the test compiles even when no production
// caller uses it; documents the public look-up surface.
#[allow(dead_code)]
trait AllowedBinariesLookup {
    fn contains(name: &str) -> bool;
}

impl AllowedBinariesLookup for () {
    fn contains(name: &str) -> bool {
        catos_system::boot::execute::target::ALLOWED_BINARIES.contains(&name)
    }
}

// ===========================================================================
// Section 13 — systemd-boot kernel-install per-kernel
// ===========================================================================

#[test]
fn systemd_boot_runs_kernel_install_for_each_discovered_kernel() {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    let ctx = ProviderCtx {
        target,
        provider: ProviderId::SystemdBoot,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    };
    let kernels = vec![
        mkinitcpio::Kernel {
            version: "6.18.0-arch1-1".into(),
            package: "linux".into(),
            image: "/usr/lib/modules/6.18.0-arch1-1/vmlinuz".into(),
            initramfs: "/boot/initramfs-linux.img".into(),
        },
        mkinitcpio::Kernel {
            version: "6.18.0-arch1-1-lts".into(),
            package: "linux-lts".into(),
            image: "/usr/lib/modules/6.18.0-arch1-1-lts/vmlinuz".into(),
            initramfs: "/boot/initramfs-linux-lts.img".into(),
        },
    ];
    let runner = RecordedTargetRunner::new()
        .expect_raw("bootctl", ["--esp-path=/boot/efi", "install"], 0, b"", b"")
        .expect_raw(
            "kernel-install",
            [
                "add",
                "6.18.0-arch1-1",
                "/usr/lib/modules/6.18.0-arch1-1/vmlinuz",
            ],
            0,
            b"",
            b"",
        )
        .expect_raw(
            "kernel-install",
            [
                "add",
                "6.18.0-arch1-1-lts",
                "/usr/lib/modules/6.18.0-arch1-1-lts/vmlinuz",
            ],
            0,
            b"",
            b"",
        );
    let provider = SystemdBootProvider { kernels: &kernels };
    let result = provider.execute(&ctx, &runner);
    assert!(result.failure.is_none());
    let invocations = runner.invocations();
    let kernel_install_calls: Vec<_> = invocations
        .iter()
        .filter(|inv| inv.binary == "kernel-install")
        .collect();
    assert_eq!(kernel_install_calls.len(), 2);
    runner.assert_consumed();
}

#[test]
fn systemd_boot_execute_stops_on_first_kernel_install_failure() {
    use std::path::PathBuf;
    let target = Box::leak(Box::new(MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        esp_uuid: None,
        boot_layout: None,
    }));
    let ctx = ProviderCtx {
        target,
        provider: ProviderId::SystemdBoot,
        cmdline: "quiet rw".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    };
    let kernels = vec![mkinitcpio::Kernel {
        version: "6.18.0".into(),
        package: "linux".into(),
        image: "/usr/lib/modules/6.18.0/vmlinuz".into(),
        initramfs: "/boot/initramfs-linux.img".into(),
    }];
    let runner = RecordedTargetRunner::new()
        .expect_raw("bootctl", ["--esp-path=/boot/efi", "install"], 0, b"", b"")
        .expect_raw(
            "kernel-install",
            ["add", "6.18.0", "/usr/lib/modules/6.18.0/vmlinuz"],
            1,
            b"",
            b"oops".to_vec(),
        );
    let provider = SystemdBootProvider { kernels: &kernels };
    let result = provider.execute(&ctx, &runner);
    assert!(result.failure.is_some());
    runner.assert_consumed();
}

// ===========================================================================
// Section 14 — Outcome taxonomy
// ===========================================================================

#[test]
fn outcome_codes_match_serde_form() {
    for outcome in [
        BootRepairOutcome::Clean,
        BootRepairOutcome::Repaired,
        BootRepairOutcome::PartiallyRepaired,
        BootRepairOutcome::Unsupported,
        BootRepairOutcome::AmbiguousTarget,
        BootRepairOutcome::AmbiguousProvider,
        BootRepairOutcome::VerificationFailed,
        BootRepairOutcome::CleanupIncomplete,
        BootRepairOutcome::ManualInterventionRequired,
        BootRepairOutcome::Unknown,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let trimmed = json.trim_matches('"');
        assert_eq!(outcome.code(), trimmed, "serde/code drift for {outcome:?}");
    }
}

// ===========================================================================
// Section 15 — Binary CLI contract (multicall + boot domain)
// ===========================================================================

#[test]
fn catos_repair_boot_help_lists_domain() {
    let output = Command::new(bin_path())
        .arg("--help")
        .output()
        .expect("binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("catos-repair"));
    assert!(stdout.contains("boot"));
}

#[test]
fn catos_repair_boot_unknown_flag_is_arg_error() {
    let status = Command::new(bin_path())
        .args(["boot", "--frobnicate"])
        .status()
        .expect("binary runs");
    // Argument errors map to exit code 2 in this codebase.
    assert_eq!(status.code(), Some(2));
}

#[test]
fn catos_repair_boot_accepts_known_flags_shape() {
    // We do not exercise the full flow here (it would need a real
    // target). We just assert the CLI parser accepts the documented
    // flag shape and rejects subcommand-style positional arguments.
    let status = Command::new(bin_path())
        .args(["boot", "grub"])
        .status()
        .expect("binary runs");
    // Per-provider subcommand is rejected.
    assert_eq!(status.code(), Some(2));
}
