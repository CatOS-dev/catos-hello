//! Provider implementations. Each submodule ports one bootloadu
//! `providers/*.py` to the static Rust backend.

pub mod base;
pub mod firmware;
pub mod grub;
pub mod limine;
pub mod systemd_boot;

use crate::shared::model::boot_repair::{FirmwareMethod, ProviderId};
use crate::mount::model::MountTargetIdentity;
use crate::repair::boot_repair::mkinitcpio::{self, Kernel};
use crate::repair::boot_repair::providers::base::{BootProvider, ProviderCtx};

/// Inputs the orchestrator passes when constructing the provider.
#[derive(Debug, Clone, Default)]
pub struct ProviderInputs<'a> {
    pub firmware: crate::shared::model::boot_repair::FirmwareClass,
    pub mkinitcpio_text: &'a str,
    pub mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs<'a>,
    pub kernels: &'a [Kernel],
    pub efi_device: Option<(String, u32)>,
}

/// Build the provider implementation for `provider`. Returns a boxed
/// trait object so the orchestrator can drive every provider through
/// one code path.
pub fn build_provider<'a>(
    provider: ProviderId,
    inputs: ProviderInputs<'a>,
) -> Box<dyn BootProvider + 'a> {
    match provider {
        ProviderId::Grub => Box::new(grub::GrubProvider {
            firmware: inputs.firmware,
            mkinitcpio_text: inputs.mkinitcpio_text,
            mkinitcpio_inputs: inputs.mkinitcpio_inputs,
        }),
        ProviderId::Limine => Box::new(limine::LimineProvider),
        ProviderId::SystemdBoot => Box::new(systemd_boot::SystemdBootProvider {
            kernels: inputs.kernels,
        }),
        ProviderId::Uki => Box::new(firmware::FirmwareProvider {
            method: FirmwareMethod::Uki,
            efi_device: inputs.efi_device,
        }),
        ProviderId::Efistub => Box::new(firmware::FirmwareProvider {
            method: FirmwareMethod::Efistub,
            efi_device: inputs.efi_device,
        }),
    }
}

/// Convenience: build the [`ProviderCtx`] the orchestrator hands to
/// the provider trait methods.
#[allow(clippy::too_many_arguments)]
pub fn build_ctx<'a>(
    target: &'a MountTargetIdentity,
    provider: ProviderId,
    cmdline: String,
    esp_mount_point: Option<String>,
    bios_install_path: Option<String>,
    architecture: crate::shared::model::boot_repair::Architecture,
    branding_name: String,
    root_is_btrfs: bool,
) -> ProviderCtx<'a> {
    ProviderCtx {
        target,
        provider,
        cmdline,
        esp_mount_point,
        bios_install_path,
        architecture,
        branding_name,
        root_is_btrfs,
    }
}

/// Re-export the runner trait so the orchestrator imports one name.
pub use crate::repair::boot_repair::target_exec::TargetRunner as Runner;
