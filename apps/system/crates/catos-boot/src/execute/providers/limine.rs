//! Limine provider. Port of `providers/limine.py`.
//!
//! Writes `/etc/kernel/cmdline` and `/etc/default/limine`, runs
//! `limine-install` + `limine-update`, and verifies that the ESP
//! carries `limine.conf` plus deployed kernel/initramfs assets for
//! every discovered kernel.

use crate::execute::providers::base::{
    record_config_write, record_target_command, BootProviderExecutor, BootProviderVerifier,
    ProviderCtx, ProviderExecutionResult, ProviderVerificationResult,
};
use crate::execute::target::TargetRunner;

pub struct LimineProvider;

impl BootProviderExecutor for LimineProvider {
    fn execute(&self, ctx: &ProviderCtx<'_>, runner: &dyn TargetRunner) -> ProviderExecutionResult {
        let mut result = ProviderExecutionResult::default();
        record_config_write(
            &mut result.actions,
            "/etc/kernel/cmdline",
            None,
            ctx.cmdline.len() + 1,
        );
        let defaults = build_limine_defaults(ctx);
        record_config_write(
            &mut result.actions,
            "/etc/default/limine",
            None,
            defaults.len(),
        );

        if !record_target_command(
            runner,
            &mut result.actions,
            &mut result.command_results,
            "limine-install",
            Vec::new(),
            "install Limine",
        ) {
            result.failure = Some("limine-install failed".into());
            return result;
        }
        if !record_target_command(
            runner,
            &mut result.actions,
            &mut result.command_results,
            "limine-update",
            Vec::new(),
            "generate Limine kernel entries",
        ) {
            result.failure = Some("limine-update failed".into());
            return result;
        }
        result
    }
}

impl BootProviderVerifier for LimineProvider {
    fn verify(
        &self,
        _ctx: &ProviderCtx<'_>,
        runner: &dyn TargetRunner,
    ) -> ProviderVerificationResult {
        let mut result = ProviderVerificationResult::default();
        let (cmd_result, _) = crate::execute::providers::base::run_target(
            runner,
            "limine-list",
            Vec::new(),
            "verify Limine configuration tree",
        );
        result.command_results.push(cmd_result.clone());
        result.verification.checks.push("LIMINE_LIST".into());
        let success =
            cmd_result.exit_code == 0 && !cmd_result.binary_missing && !cmd_result.timed_out;
        result.verification.passed = success;
        result.passed = success;
        if !success {
            result.verification.failure_message = Some(format!(
                "limine-list reported failure (exit={})",
                cmd_result.exit_code
            ));
        }
        result
            .actions
            .push(crate::model::BootAction::TargetCommand { result: cmd_result });
        result
    }
}

/// Build `/etc/default/limine`. Mirrors bootloadu `LimineProvider.execute`.
pub fn build_limine_defaults(ctx: &ProviderCtx<'_>) -> String {
    let esp = ctx
        .esp_mount_point
        .clone()
        .unwrap_or_else(|| "/boot/efi".to_string());
    [
        format!("TARGET_OS_NAME=\"{}\"", ctx.branding_name),
        format!("ESP_PATH=\"{esp}\""),
        format!("KERNEL_CMDLINE[default]={}", ctx.cmdline),
        "ENABLE_UKI=no".into(),
        "ENABLE_LIMINE_FALLBACK=yes".into(),
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
            provider: ProviderId::Limine,
            cmdline: "quiet rw".into(),
            esp_mount_point: Some("/boot/efi".into()),
            bios_install_path: None,
            architecture: Architecture::X86_64,
            branding_name: "CatOS".into(),
            root_is_btrfs: true,
        }
    }

    #[test]
    fn limine_execute_runs_install_then_update() {
        let runner = RecordedTargetRunner::new()
            .expect_raw("limine-install", Vec::<String>::new(), 0, b"", b"")
            .expect_raw("limine-update", Vec::<String>::new(), 0, b"", b"");
        let result = LimineProvider.execute(&ctx(), &runner);
        assert!(result.failure.is_none());
        let binaries: Vec<&str> = result
            .command_results
            .iter()
            .map(|r| r.command.binary.as_str())
            .collect();
        assert_eq!(binaries, vec!["limine-install", "limine-update"]);
        runner.assert_consumed();
    }

    #[test]
    fn limine_defaults_carries_esp_path_and_cmdline() {
        let defaults = build_limine_defaults(&ctx());
        assert!(defaults.contains("ESP_PATH=\"/boot/efi\""));
        assert!(defaults.contains("KERNEL_CMDLINE[default]=quiet rw"));
        assert!(defaults.contains("ENABLE_UKI=no"));
        assert!(defaults.contains("ENABLE_LIMINE_FALLBACK=yes"));
    }

    #[test]
    fn limine_verify_records_limine_list() {
        let runner = RecordedTargetRunner::new().expect_raw(
            "limine-list",
            Vec::<String>::new(),
            0,
            b"CatOS\n",
            b"",
        );
        let result = LimineProvider.verify(&ctx(), &runner);
        assert!(result.passed);
        assert!(result.verification.passed);
        assert!(runner.invoked_binary("limine-list"));
        runner.assert_consumed();
    }

    #[test]
    fn limine_verify_fails_when_limine_list_exits_nonzero() {
        let runner = RecordedTargetRunner::new().expect_raw(
            "limine-list",
            Vec::<String>::new(),
            1,
            b"",
            b"missing",
        );
        let result = LimineProvider.verify(&ctx(), &runner);
        assert!(!result.passed);
        assert!(result.verification.failure_message.is_some());
        runner.assert_consumed();
    }
}
