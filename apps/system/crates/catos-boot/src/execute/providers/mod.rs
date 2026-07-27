//! Provider implementations. Each submodule ports one bootloadu
//! `providers/*.py` to the static Rust backend.

pub mod base;
pub mod firmware;
pub mod grub;
pub mod limine;
pub mod systemd_boot;

use crate::execute::providers::base::{BootProviderExecutor, BootProviderVerifier, ProviderCtx};
use crate::model::{FirmwareMethod, ProviderId};
use crate::plan::initramfs::{self as mkinitcpio, Kernel};
use catos_mount::model::MountTargetIdentity;

/// Inputs used to construct one provider stage implementation.
#[derive(Debug, Clone, Default)]
pub struct ProviderInputs<'a> {
    pub firmware: crate::model::FirmwareClass,
    pub mkinitcpio_text: &'a str,
    pub mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs<'a>,
    pub kernels: &'a [Kernel],
    pub efi_device: Option<(String, u32)>,
}

/// Build the authorised effect surface for `provider`.
pub fn build_executor<'a>(
    provider: ProviderId,
    inputs: ProviderInputs<'a>,
) -> Box<dyn BootProviderExecutor + 'a> {
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

/// Build the read-only postcondition surface for `provider`.
pub fn build_verifier<'a>(
    provider: ProviderId,
    inputs: ProviderInputs<'a>,
) -> Box<dyn BootProviderVerifier + 'a> {
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

/// Build the shared immutable provider context.
#[allow(clippy::too_many_arguments)]
pub fn build_ctx<'a>(
    target: &'a MountTargetIdentity,
    provider: ProviderId,
    cmdline: String,
    esp_mount_point: Option<String>,
    bios_install_path: Option<String>,
    architecture: crate::model::Architecture,
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

/// Re-export the runner trait so capability callers import one name.
pub use crate::execute::target::TargetRunner as Runner;
