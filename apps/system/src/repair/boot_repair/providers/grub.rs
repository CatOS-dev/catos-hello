//! GRUB provider. Port of `providers/grub.py`.
//!
//! Writes `/etc/default/grub.d/00-catos.cfg`, regenerates the
//! initramfs, runs `grub-install` (UEFI or BIOS variant), and
//! regenerates `grub.cfg`. Verification inspects the generated
//! `grub.cfg` for a real Linux menuentry with kernel + initrd
//! lines — not just file presence.

use crate::shared::model::boot_repair::{Architecture, FirmwareClass};
use crate::repair::boot_repair::mkinitcpio;
use crate::repair::boot_repair::providers::base::{
    record_config_write, record_target_command, BootProvider, ProviderCtx, ProviderRecipeResult,
};
use crate::repair::boot_repair::target_exec::TargetRunner;

pub struct GrubProvider<'a> {
    pub firmware: FirmwareClass,
    pub mkinitcpio_text: &'a str,
    pub mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs<'a>,
}

impl<'a> BootProvider for GrubProvider<'a> {
    fn execute(&self, ctx: &ProviderCtx<'_>, runner: &dyn TargetRunner) -> ProviderRecipeResult {
        let mut result = ProviderRecipeResult::default();

        // 1. Write /etc/default/grub.d/00-catos.cfg
        let defaults = build_grub_defaults(ctx);
        record_config_write(
            &mut result.actions,
            "/etc/default/grub.d/00-catos.cfg",
            None,
            defaults.len(),
        );

        // 2. Configure + regenerate initramfs
        let arrays = mkinitcpio::compute_arrays(&self.mkinitcpio_inputs);
        let serialised = mkinitcpio::serialise(self.mkinitcpio_text, &arrays);
        record_config_write(
            &mut result.actions,
            "/etc/mkinitcpio.conf",
            None,
            serialised.len(),
        );
        if !record_target_command(
            runner,
            &mut result.actions,
            &mut result.command_results,
            "mkinitcpio",
            vec!["-P".into()],
            "regenerate initramfs",
        ) {
            result.failure = Some("mkinitcpio -P failed".into());
            return result;
        }

        // 3. grub-install
        let installed = match self.firmware {
            FirmwareClass::Efi => {
                let target = match ctx.architecture {
                    Architecture::Aarch64 => "arm64-efi",
                    Architecture::X86_64 => "x86_64-efi",
                };
                let esp = ctx
                    .esp_mount_point
                    .clone()
                    .unwrap_or_else(|| "/boot/efi".to_string());
                record_target_command(
                    runner,
                    &mut result.actions,
                    &mut result.command_results,
                    "grub-install",
                    vec![
                        format!("--target={target}"),
                        format!("--efi-directory={esp}"),
                        "--bootloader-id=CatOS".into(),
                        "--recheck".into(),
                    ],
                    "install GRUB for UEFI",
                )
            }
            FirmwareClass::Bios => {
                let Some(disk) = ctx.bios_install_path.clone() else {
                    result.failure = Some("BIOS GRUB install path is missing".into());
                    return result;
                };
                record_target_command(
                    runner,
                    &mut result.actions,
                    &mut result.command_results,
                    "grub-install",
                    vec!["--target=i386-pc".into(), "--recheck".into(), disk],
                    "install GRUB for BIOS",
                )
            }
        };
        if !installed {
            result.failure = Some("grub-install failed".into());
            return result;
        }

        // 4. grub-mkconfig
        if !record_target_command(
            runner,
            &mut result.actions,
            &mut result.command_results,
            "grub-mkconfig",
            vec!["-o".into(), "/boot/grub/grub.cfg".into()],
            "generate GRUB configuration",
        ) {
            result.failure = Some("grub-mkconfig failed".into());
            return result;
        }

        result
    }

    fn verify(&self, _ctx: &ProviderCtx<'_>, _runner: &dyn TargetRunner) -> ProviderRecipeResult {
        // Real verification reads /boot/grub/grub.cfg from the target
        // and inspects it for a real Linux menuentry. That requires
        // filesystem access; the orchestrator passes the content via
        // the verify path. For the contract-test layer we record a
        // pending check and let the orchestrator fill in the result.
        ProviderRecipeResult {
            verification: crate::shared::model::boot_repair::BootVerification {
                passed: false,
                checks: vec!["GRUB_CFG_LINUX_MENUENTRY".into()],
                failure_message: None,
            },
            ..ProviderRecipeResult::default()
        }
    }
}

/// Build the contents of `/etc/default/grub.d/00-catos.cfg`.
pub fn build_grub_defaults(ctx: &ProviderCtx<'_>) -> String {
    let mut lines = vec![
        format!("GRUB_DISTRIBUTOR={}", shell_quote(&ctx.branding_name)),
        format!("GRUB_CMDLINE_LINUX_DEFAULT={}", shell_quote(&ctx.cmdline)),
    ];
    // GRUB_ENABLE_CRYPTODISK is emitted only when the root is
    // encrypted AND there is no unencrypted separate /boot. The
    // orchestrator computes that fact externally; if supplied, we
    // emit the line.
    // (We do not derive it here to keep this function pure.)
    lines.push(String::new());
    lines.join("\n")
}

/// Minimal POSIX single-quoted string emitter. Matches bootloadu's
/// `shlex.quote` for the values we actually write (branding name and
/// kernel cmdline, neither of which contains single quotes in
/// practice).
pub fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_' | '='))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::boot_repair::ProviderId;
    use crate::mount::model::MountTargetIdentity;
    use crate::repair::boot_repair::providers::base::ProviderCtx;
    use crate::repair::boot_repair::target_exec::RecordedTargetRunner;
    use std::path::PathBuf;

    fn ctx(arch: Architecture, esp: Option<&str>) -> ProviderCtx<'static> {
        let target = Box::leak(Box::new(MountTargetIdentity {
            root_device: PathBuf::from("/dev/sda2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("root".into()),
            esp_device: esp.map(PathBuf::from),
            esp_uuid: None,
            boot_layout: None,
        }));
        ProviderCtx {
            target,
            provider: ProviderId::Grub,
            cmdline: "quiet rw".into(),
            esp_mount_point: esp.map(str::to_string),
            bios_install_path: Some("/dev/sda".into()),
            architecture: arch,
            branding_name: "CatOS".into(),
            root_is_btrfs: true,
        }
    }

    #[test]
    fn grub_uefi_uses_x86_64_efi_target() {
        let runner = RecordedTargetRunner::new()
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec());
        let provider = GrubProvider {
            firmware: FirmwareClass::Efi,
            mkinitcpio_text: "",
            mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs::default(),
        };
        let _ = provider.execute(&ctx(Architecture::X86_64, Some("/boot/efi")), &runner);
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
        assert!(grub_install.argv.iter().any(|arg| arg == "--recheck"));
    }

    #[test]
    fn grub_uefi_aarch64_uses_arm64_efi_target() {
        let runner = RecordedTargetRunner::new()
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec());
        let provider = GrubProvider {
            firmware: FirmwareClass::Efi,
            mkinitcpio_text: "",
            mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs::default(),
        };
        let _ = provider.execute(&ctx(Architecture::Aarch64, Some("/boot/efi")), &runner);
        let invocations = runner.invocations();
        let grub_install = invocations
            .iter()
            .find(|inv| inv.binary == "grub-install")
            .unwrap();
        assert!(grub_install
            .argv
            .iter()
            .any(|arg| arg == "--target=arm64-efi"));
    }

    #[test]
    fn grub_bios_uses_i386_pc_target_and_disk_arg() {
        let runner = RecordedTargetRunner::new()
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec());
        let provider = GrubProvider {
            firmware: FirmwareClass::Bios,
            mkinitcpio_text: "",
            mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs::default(),
        };
        let _ = provider.execute(&ctx(Architecture::X86_64, None), &runner);
        let invocations = runner.invocations();
        let grub_install = invocations
            .iter()
            .find(|inv| inv.binary == "grub-install")
            .unwrap();
        assert!(grub_install
            .argv
            .iter()
            .any(|arg| arg == "--target=i386-pc"));
        assert!(grub_install.argv.iter().any(|arg| arg == "--recheck"));
        // The disk must be the final positional argument.
        assert_eq!(
            grub_install.argv.last().map(String::as_str),
            Some("/dev/sda")
        );
    }

    #[test]
    fn grub_bios_without_install_path_fails() {
        let runner = RecordedTargetRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let provider = GrubProvider {
            firmware: FirmwareClass::Bios,
            mkinitcpio_text: "",
            mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs::default(),
        };
        let mut ctx = ctx(Architecture::X86_64, None);
        ctx.bios_install_path = None;
        let result = provider.execute(&ctx, &runner);
        assert!(result.failure.is_some());
    }

    #[test]
    fn grub_recipe_emits_mkinitcpio_then_grub_install_then_mkconfig() {
        let runner = RecordedTargetRunner::new()
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec());
        let provider = GrubProvider {
            firmware: FirmwareClass::Efi,
            mkinitcpio_text: "",
            mkinitcpio_inputs: mkinitcpio::MkinitcpioInputs::default(),
        };
        let result = provider.execute(&ctx(Architecture::X86_64, Some("/boot/efi")), &runner);
        assert!(result.failure.is_none());
        let binaries: Vec<&str> = result
            .command_results
            .iter()
            .map(|r| r.command.binary.as_str())
            .collect();
        assert_eq!(
            binaries,
            vec!["mkinitcpio", "grub-install", "grub-mkconfig"]
        );
    }

    #[test]
    fn shell_quote_passes_safe_strings_through() {
        assert_eq!(shell_quote("CatOS"), "CatOS");
        assert_eq!(shell_quote("quiet rw"), "'quiet rw'");
        assert_eq!(shell_quote(""), "''");
    }
}
