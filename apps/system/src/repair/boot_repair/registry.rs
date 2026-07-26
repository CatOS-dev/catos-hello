//! Bootloader provider registry: a static port of
//! `usr/share/calamares/catos/bootloaders.yaml`.
//!
//! The data is embedded in the binary rather than read at runtime
//! because catos-system is a fully static binary that must run in
//! initramfs and recovery environments where the Calamares YAML is
//! not installed. The shape mirrors the bootloadu registry so future
//! updates to `bootloaders.yaml` remain a one-place edit (here).
//!
//! ## Hard rules
//!
//! * This module is pure data + pure predicates. No I/O.
//! * The platform support matrix is a real conjunction
//!   (firmware AND architecture AND partition table where required),
//!   never a cartesian product.
//! * Adding a provider is a backward-compatible change here; removing
//!   one is not (the public [`ProviderId`] enum would shrink).

use crate::shared::model::boot_repair::{
    Architecture, FirmwareClass, FirmwareMethod, PartitionTable, ProviderId,
};

/// One row of the per-provider `platforms:` list in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformRow {
    pub firmware: FirmwareClass,
    pub architectures: &'static [Architecture],
}

/// Static profile for one provider. Mirrors the YAML fields
/// bootloadu's `provider_profile()` returns.
#[derive(Debug, Clone, Copy)]
pub struct ProviderProfile {
    pub id: ProviderId,
    pub display_name: &'static str,
    pub platforms: &'static [PlatformRow],
    /// `true` iff every supported platform requires a GPT partition
    /// table. Mirrors `requiredPartitionTableType: [gpt]`.
    pub requires_gpt: bool,
    /// Snapshot manager declared by the provider, or `None` for UKI
    /// and EFI Stub (which the registry marks `snapshots: null`).
    pub snapshots: Option<SnapshotProfile>,
    /// Packages the provider's recipe needs at runtime (subset of
    /// `packages:` and `kernelPackages:`). Recorded so detection can
    /// consult the target's own pacman local DB.
    pub runtime_packages: &'static [&'static str],
}

/// Snapshot support declared by a provider profile. Mirrors the
/// `snapshots:` mapping in `bootloaders.yaml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotProfile {
    pub manager: SnapshotManager,
    pub required_filesystems: &'static [&'static str],
    pub packages: &'static [&'static str],
    /// Initramfs overlayfs hook the mkinitcpio configurator appends
    /// when snapshots are enabled for this provider. Mirrors the
    /// bootloadu `SNAPSHOT_OVERLAY_HOOKS` table.
    pub overlayfs_hook: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotManager {
    Snapper,
}

/// Static port of the bootloadu `secureBoot:` mapping.
pub struct SecureBootProfile {
    pub package: &'static str,
    pub supported_providers: &'static [ProviderId],
}

/// The single source-of-truth registry. Adding a provider means
/// adding a `const` here AND a variant to [`ProviderId`].
pub const REGISTRY: &[ProviderProfile] = &[
    ProviderProfile {
        id: ProviderId::Grub,
        display_name: "GRUB",
        platforms: &[
            PlatformRow {
                firmware: FirmwareClass::Efi,
                architectures: &[Architecture::X86_64, Architecture::Aarch64],
            },
            PlatformRow {
                firmware: FirmwareClass::Bios,
                architectures: &[Architecture::X86_64],
            },
        ],
        requires_gpt: false,
        snapshots: Some(SnapshotProfile {
            manager: SnapshotManager::Snapper,
            required_filesystems: &["btrfs"],
            packages: &["grub-btrfs", "inotify-tools"],
            overlayfs_hook: "grub-btrfs-overlayfs",
        }),
        runtime_packages: &["grub", "efibootmgr", "os-prober"],
    },
    ProviderProfile {
        id: ProviderId::Limine,
        display_name: "Limine",
        platforms: &[PlatformRow {
            firmware: FirmwareClass::Efi,
            architectures: &[Architecture::X86_64],
        }],
        requires_gpt: true,
        snapshots: Some(SnapshotProfile {
            manager: SnapshotManager::Snapper,
            required_filesystems: &["btrfs"],
            packages: &["limine-btrfs"],
            overlayfs_hook: "limine-btrfs-overlayfs",
        }),
        runtime_packages: &["limine", "limine-tool"],
    },
    ProviderProfile {
        id: ProviderId::SystemdBoot,
        display_name: "systemd-boot",
        platforms: &[PlatformRow {
            firmware: FirmwareClass::Efi,
            architectures: &[Architecture::X86_64, Architecture::Aarch64],
        }],
        requires_gpt: true,
        snapshots: Some(SnapshotProfile {
            manager: SnapshotManager::Snapper,
            required_filesystems: &["btrfs"],
            packages: &["sdboot-btrfs"],
            overlayfs_hook: "sdboot-btrfs-overlayfs",
        }),
        runtime_packages: &["catos-systemd-boot-config"],
    },
    ProviderProfile {
        id: ProviderId::Uki,
        display_name: "Unified Kernel Image",
        platforms: &[PlatformRow {
            firmware: FirmwareClass::Efi,
            architectures: &[Architecture::X86_64, Architecture::Aarch64],
        }],
        requires_gpt: true,
        snapshots: None,
        runtime_packages: &["catos-firmware-boot", "systemd-ukify"],
    },
    ProviderProfile {
        id: ProviderId::Efistub,
        display_name: "Linux EFI Stub",
        platforms: &[PlatformRow {
            firmware: FirmwareClass::Efi,
            architectures: &[Architecture::X86_64, Architecture::Aarch64],
        }],
        requires_gpt: true,
        snapshots: None,
        runtime_packages: &["catos-firmware-boot"],
    },
];

/// The static `secureBoot:` mapping ported from the YAML.
pub const SECURE_BOOT: SecureBootProfile = SecureBootProfile {
    package: "catos-secureboot",
    supported_providers: &[
        ProviderId::Grub,
        ProviderId::Limine,
        ProviderId::SystemdBoot,
        ProviderId::Uki,
    ],
};

/// Default provider id when no target evidence is available. Matches
/// the bootloadu `defaultProvider` field. **Only used by install
/// time**; repair never falls back to this — it refuses with
/// [`crate::shared::model::boot_repair::BootRepairOutcome::AmbiguousProvider`]
/// instead.
pub const DEFAULT_PROVIDER: ProviderId = ProviderId::Grub;

/// Look up the static profile for a provider.
pub fn profile(provider: ProviderId) -> &'static ProviderProfile {
    REGISTRY
        .iter()
        .find(|item| item.id == provider)
        .expect("registry entries must exist for every ProviderId variant")
}

/// Platform support matrix. Mirrors bootloadu `platform_supported()`.
/// Returns `false` for an unsupported combination rather than guessing.
pub fn platform_supported(
    provider: ProviderId,
    firmware: FirmwareClass,
    arch: Architecture,
) -> bool {
    let profile = profile(provider);
    profile
        .platforms
        .iter()
        .any(|row| row.firmware == firmware && row.architectures.contains(&arch))
}

/// GPT requirement check. Mirrors bootloadu's
/// `requiredPartitionTableType: [gpt]` enforcement. `Unknown` is
/// always refused — we never guess the partition table type.
pub fn partition_table_supported(provider: ProviderId, table: PartitionTable) -> bool {
    match table {
        PartitionTable::Unknown => false,
        PartitionTable::Gpt => true,
        PartitionTable::Msdos => {
            let profile = profile(provider);
            !profile.requires_gpt
        }
    }
}

/// Combined platform + partition-table check used by the orchestrator
/// before any provider recipe runs.
pub fn target_platform_supported(
    provider: ProviderId,
    firmware: FirmwareClass,
    arch: Architecture,
    table: PartitionTable,
) -> bool {
    platform_supported(provider, firmware, arch) && partition_table_supported(provider, table)
}

/// Mirrors bootloadu `secure_boot_profile()`. Returns `None` for
/// providers the registry marks as unsupported (EFI Stub), so the
/// caller can refuse with [`BootRepairOutcome::Unsupported`].
///
/// [`BootRepairOutcome`]: crate::shared::model::boot_repair::BootRepairOutcome
pub fn secure_boot_supported(provider: ProviderId) -> bool {
    SECURE_BOOT.supported_providers.contains(&provider)
}

/// Map a UEFI firmware method to its provider id. Used by detection
/// when reading `/etc/catos/firmware-boot.conf`.
pub fn provider_for_firmware_method(method: FirmwareMethod) -> ProviderId {
    match method {
        FirmwareMethod::Uki => ProviderId::Uki,
        FirmwareMethod::Efistub => ProviderId::Efistub,
    }
}

/// Snapshot profile lookup for a provider. `None` for UKI / EFI Stub,
/// matching the registry's `snapshots: null`.
pub fn snapshot_profile(provider: ProviderId) -> Option<SnapshotProfile> {
    profile(provider).snapshots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_matrix_is_not_a_cartesian_product() {
        // bootloadu test_platform_matrix_is_not_a_cartesian_product port.
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
        assert!(platform_supported(
            ProviderId::Grub,
            FirmwareClass::Efi,
            Architecture::Aarch64
        ));
    }

    #[test]
    fn gpt_required_providers_reject_msdos_table() {
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
    fn grub_does_not_require_gpt() {
        for table in [PartitionTable::Gpt, PartitionTable::Msdos] {
            assert!(partition_table_supported(ProviderId::Grub, table));
        }
        // Unknown partition table is still refused: we never guess.
        assert!(!partition_table_supported(
            ProviderId::Grub,
            PartitionTable::Unknown
        ));
    }

    #[test]
    fn snapshot_profile_returns_none_for_uki_and_efistub() {
        assert!(snapshot_profile(ProviderId::Uki).is_none());
        assert!(snapshot_profile(ProviderId::Efistub).is_none());
    }

    #[test]
    fn snapshot_profile_returns_snapper_for_grub_limine_systemd_boot() {
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
    fn secureboot_supports_grub_limine_systemd_boot_uki_only() {
        for provider in [
            ProviderId::Grub,
            ProviderId::Limine,
            ProviderId::SystemdBoot,
            ProviderId::Uki,
        ] {
            assert!(
                secure_boot_supported(provider),
                "{provider:?} should be supported"
            );
        }
        assert!(!secure_boot_supported(ProviderId::Efistub));
    }

    #[test]
    fn firmware_method_maps_to_provider() {
        assert_eq!(
            provider_for_firmware_method(FirmwareMethod::Uki),
            ProviderId::Uki
        );
        assert_eq!(
            provider_for_firmware_method(FirmwareMethod::Efistub),
            ProviderId::Efistub
        );
    }

    #[test]
    fn target_platform_supported_combines_all_checks() {
        // GRUB BIOS x86_64 on GPT → supported.
        assert!(target_platform_supported(
            ProviderId::Grub,
            FirmwareClass::Bios,
            Architecture::X86_64,
            PartitionTable::Gpt
        ));
        // GRUB BIOS x86_64 on Msdos → supported (GRUB has no GPT req).
        assert!(target_platform_supported(
            ProviderId::Grub,
            FirmwareClass::Bios,
            Architecture::X86_64,
            PartitionTable::Msdos
        ));
        // Limine UEFI x86_64 on Msdos → refused (Limine requires GPT).
        assert!(!target_platform_supported(
            ProviderId::Limine,
            FirmwareClass::Efi,
            Architecture::X86_64,
            PartitionTable::Msdos
        ));
        // Limine UEFI aarch64 → refused (Limine is x86_64 only).
        assert!(!target_platform_supported(
            ProviderId::Limine,
            FirmwareClass::Efi,
            Architecture::Aarch64,
            PartitionTable::Gpt
        ));
    }
}
