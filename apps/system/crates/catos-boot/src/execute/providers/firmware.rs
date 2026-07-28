//! Firmware provider: shared implementation for UKI and EFI Stub.
//! Port of `providers/firmware.py` + `providers/uki.py` +
//! `providers/efistub.py`.
//!
//! Writes `/etc/kernel/cmdline` and `/etc/catos/firmware-boot.conf`,
//! then invokes `catos-firmware-boot-update --force` followed by
//! `catos-firmware-boot-update --force --verify`. The two methods
//! (`uki` and `efistub`) differ only in the `method = ...` field of
//! the configuration file; the same tool drives both.

use crate::execute::providers::base::{
    record_config_write, record_target_command, BootProviderExecutor, BootProviderVerifier,
    ProviderCtx, ProviderExecutionResult, ProviderVerificationResult,
};
use crate::execute::target::TargetRunner;
use crate::model::{BootAction, FirmwareMethod};

pub struct FirmwareProvider {
    pub method: FirmwareMethod,
    /// `(disk, partition)` for the ESP, used to populate
    /// `efi_disk = ...` / `efi_partition = ...` in
    /// `/etc/catos/firmware-boot.conf`. Mirrors bootloadu
    /// `efi_device()`.
    pub efi_device: Option<(String, u32)>,
}

impl BootProviderExecutor for FirmwareProvider {
    fn execute(&self, ctx: &ProviderCtx<'_>, runner: &dyn TargetRunner) -> ProviderExecutionResult {
        let mut result = ProviderExecutionResult::default();
        record_config_write(
            &mut result.actions,
            "/etc/kernel/cmdline",
            None,
            ctx.cmdline.len() + 1,
        );
        let conf = build_firmware_boot_conf(self.method, ctx, self.efi_device.as_ref());
        record_config_write(
            &mut result.actions,
            "/etc/catos/firmware-boot.conf",
            None,
            conf.len(),
        );
        if !record_target_command(
            runner,
            &mut result.actions,
            &mut result.command_results,
            "catos-firmware-boot-update",
            vec!["--force".into()],
            "prepare direct firmware boot artefacts",
        ) {
            result.failure = Some("catos-firmware-boot-update --force failed".into());
            return result;
        }
        result
    }
}

impl BootProviderVerifier for FirmwareProvider {
    fn verify(
        &self,
        _ctx: &ProviderCtx<'_>,
        runner: &dyn TargetRunner,
    ) -> ProviderVerificationResult {
        let mut result = ProviderVerificationResult::default();
        let (cmd_result, _) = crate::execute::providers::base::run_target(
            runner,
            "catos-firmware-boot-update",
            vec!["--force".into(), "--verify".into()],
            "verify direct firmware boot artefacts",
        );
        let success =
            cmd_result.exit_code == 0 && !cmd_result.binary_missing && !cmd_result.timed_out;
        result.verification.passed = success;
        result.passed = success;
        result
            .verification
            .checks
            .push("CATOS_FIRMWARE_BOOT_VERIFY".into());
        if !success {
            result.verification.failure_message = Some(format!(
                "catos-firmware-boot-update --verify failed (exit={})",
                cmd_result.exit_code
            ));
        }
        result
            .actions
            .push(BootAction::TargetCommand { result: cmd_result });
        result
    }
}

/// Build the contents of `/etc/catos/firmware-boot.conf`. Mirrors
/// bootloadu `FirmwareProvider.execute`.
pub fn build_firmware_boot_conf(
    method: FirmwareMethod,
    ctx: &ProviderCtx<'_>,
    efi_device: Option<&(String, u32)>,
) -> String {
    let esp = ctx
        .esp_mount_point
        .clone()
        .unwrap_or_else(|| "/boot/efi".to_string());
    let (disk, partition) = efi_device.cloned().unwrap_or_default();
    let disk_line = if disk.is_empty() {
        "efi_disk = ".to_string()
    } else {
        format!("efi_disk = {disk}")
    };
    let part_line = if partition == 0 {
        "efi_partition = ".to_string()
    } else {
        format!("efi_partition = {partition}")
    };
    [
        "[boot]".to_string(),
        format!("method = {}", method.as_str()),
        format!("esp_path = {esp}"),
        disk_line,
        part_line,
        format!("label_prefix = {}", ctx.branding_name),
        "default_kernel = linux".to_string(),
        String::new(),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execute::providers::base::ProviderCtx;
    use crate::execute::target::RecordedTargetRunner;
    use crate::model::{Architecture, ProviderId};
    use catos_mount::model::MountTargetIdentity;
    use std::path::PathBuf;

    fn ctx() -> ProviderCtx<'static> {
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
            provider: ProviderId::Uki,
            cmdline: "quiet rw".into(),
            esp_mount_point: Some("/boot/efi".into()),
            bios_install_path: None,
            architecture: Architecture::X86_64,
            branding_name: "CatOS".into(),
            root_is_btrfs: true,
        }
    }

    #[test]
    fn firmware_conf_uses_plain_branding_label() {
        // bootloadu test_firmware_provider_uses_plain_branding_label port.
        let conf = build_firmware_boot_conf(
            FirmwareMethod::Uki,
            &ctx(),
            Some(&("/dev/nvme0n1".to_string(), 1)),
        );
        assert!(conf.contains("label_prefix = CatOS"));
        assert!(!conf.contains("machine_id"));
        assert!(conf.contains("method = uki"));
        assert!(conf.contains("efi_disk = /dev/nvme0n1"));
        assert!(conf.contains("efi_partition = 1"));
    }

    #[test]
    fn efistub_method_field_differs_from_uki() {
        let uki_conf = build_firmware_boot_conf(FirmwareMethod::Uki, &ctx(), None);
        let efi_conf = build_firmware_boot_conf(FirmwareMethod::Efistub, &ctx(), None);
        assert!(uki_conf.contains("method = uki"));
        assert!(efi_conf.contains("method = efistub"));
    }

    #[test]
    fn uki_execute_runs_force_update() {
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
        let result = provider.execute(&ctx(), &runner);
        assert!(result.failure.is_none());
        assert!(runner.invoked_binary("catos-firmware-boot-update"));
        let inv = runner.invocations()[0].clone();
        assert_eq!(inv.argv, vec!["--force".to_string()]);
        runner.assert_consumed();
    }

    #[test]
    fn firmware_verify_uses_force_and_verify_flags() {
        let runner = RecordedTargetRunner::new().expect_raw(
            "catos-firmware-boot-update",
            ["--force", "--verify"],
            0,
            b"verified",
            b"",
        );
        let provider = FirmwareProvider {
            method: FirmwareMethod::Efistub,
            efi_device: None,
        };
        let result = provider.verify(&ctx(), &runner);
        assert!(result.passed);
        let inv = runner.invocations()[0].clone();
        assert_eq!(
            inv.argv,
            vec!["--force".to_string(), "--verify".to_string()]
        );
        runner.assert_consumed();
    }

    #[test]
    fn failed_force_update_records_failure() {
        let runner = RecordedTargetRunner::new().expect_raw(
            "catos-firmware-boot-update",
            ["--force"],
            1,
            b"",
            b"missing kernel",
        );
        let provider = FirmwareProvider {
            method: FirmwareMethod::Uki,
            efi_device: None,
        };
        let result = provider.execute(&ctx(), &runner);
        assert!(result.failure.is_some());
        runner.assert_consumed();
    }
}
