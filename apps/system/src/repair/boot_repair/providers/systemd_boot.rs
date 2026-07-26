//! systemd-boot provider. Port of `providers/systemd_boot.py`.
//!
//! Writes `/etc/kernel/cmdline` and
//! `/etc/kernel/install.conf.d/20-catos-bootloadu.conf`, runs
//! `bootctl --esp-path=<ESP> install`, then `kernel-install add
//! <VERSION> <IMAGE>` for each discovered kernel. Verification calls
//! `bootctl --esp-path=<ESP> is-installed`.

use crate::model::boot_repair::BootAction;
use crate::repair::boot_repair::mkinitcpio::Kernel;
use crate::repair::boot_repair::providers::base::{
    record_config_write, record_target_command, BootProvider, ProviderCtx, ProviderRecipeResult,
};
use crate::repair::boot_repair::target_exec::TargetRunner;

pub struct SystemdBootProvider<'a> {
    pub kernels: &'a [Kernel],
}

impl<'a> BootProvider for SystemdBootProvider<'a> {
    fn execute(&self, ctx: &ProviderCtx<'_>, runner: &dyn TargetRunner) -> ProviderRecipeResult {
        let mut result = ProviderRecipeResult::default();
        record_config_write(
            &mut result.actions,
            "/etc/kernel/cmdline",
            None,
            ctx.cmdline.len() + 1,
        );
        let policy = build_install_conf(ctx);
        record_config_write(
            &mut result.actions,
            "/etc/kernel/install.conf.d/20-catos-bootloadu.conf",
            None,
            policy.len(),
        );

        let esp = ctx
            .esp_mount_point
            .clone()
            .unwrap_or_else(|| "/boot/efi".to_string());
        if !record_target_command(
            runner,
            &mut result.actions,
            &mut result.command_results,
            "bootctl",
            vec![format!("--esp-path={esp}"), "install".into()],
            "install systemd-boot",
        ) {
            result.failure = Some("bootctl install failed".into());
            return result;
        }
        for kernel in self.kernels {
            let argv = vec!["add".into(), kernel.version.clone(), kernel.image.clone()];
            if !record_target_command(
                runner,
                &mut result.actions,
                &mut result.command_results,
                "kernel-install",
                argv,
                "install kernel",
            ) {
                result.failure = Some(format!("kernel-install add {} failed", kernel.package));
                return result;
            }
        }
        result
    }

    fn verify(&self, ctx: &ProviderCtx<'_>, runner: &dyn TargetRunner) -> ProviderRecipeResult {
        let esp = ctx
            .esp_mount_point
            .clone()
            .unwrap_or_else(|| "/boot/efi".to_string());
        let mut result = ProviderRecipeResult::default();
        let (cmd_result, _) = crate::repair::boot_repair::providers::base::run_target(
            runner,
            "bootctl",
            vec![format!("--esp-path={esp}"), "is-installed".into()],
            "verify systemd-boot installation",
        );
        let success =
            cmd_result.exit_code == 0 && !cmd_result.binary_missing && !cmd_result.timed_out;
        result.verification.passed = success;
        result.verified = success;
        result
            .verification
            .checks
            .push("BOOTCTL_IS_INSTALLED".into());
        if !success {
            result.verification.failure_message = Some(format!(
                "bootctl is-installed reported failure (exit={})",
                cmd_result.exit_code
            ));
        }
        result
            .actions
            .push(BootAction::TargetCommand { result: cmd_result });
        result
    }
}

/// Build the contents of
/// `/etc/kernel/install.conf.d/20-catos-bootloadu.conf`. Mirrors
/// bootloadu `SystemdBootProvider.execute`.
pub fn build_install_conf(ctx: &ProviderCtx<'_>) -> String {
    let esp = ctx
        .esp_mount_point
        .clone()
        .unwrap_or_else(|| "/boot/efi".to_string());
    format!("BOOT_ROOT={esp}\nlayout=bls\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::boot_repair::{Architecture, ProviderId};
    use crate::model::mount_repair::TargetIdentity;
    use crate::repair::boot_repair::providers::base::ProviderCtx;
    use crate::repair::boot_repair::target_exec::RecordedTargetRunner;
    use std::path::PathBuf;

    fn ctx() -> ProviderCtx<'static> {
        let target = Box::leak(Box::new(TargetIdentity {
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
            provider: ProviderId::SystemdBoot,
            cmdline: "quiet rw".into(),
            esp_mount_point: Some("/boot/efi".into()),
            bios_install_path: None,
            architecture: Architecture::X86_64,
            branding_name: "CatOS".into(),
            root_is_btrfs: true,
        }
    }

    fn kernels() -> Vec<Kernel> {
        vec![
            Kernel {
                version: "6.18.0-arch1-1".into(),
                package: "linux".into(),
                image: "/usr/lib/modules/6.18.0-arch1-1/vmlinuz".into(),
                initramfs: "/boot/initramfs-linux.img".into(),
            },
            Kernel {
                version: "6.18.0-arch1-1-lts".into(),
                package: "linux-lts".into(),
                image: "/usr/lib/modules/6.18.0-arch1-1-lts/vmlinuz".into(),
                initramfs: "/boot/initramfs-linux-lts.img".into(),
            },
        ]
    }

    #[test]
    fn install_conf_persists_boot_root_and_bls_layout() {
        let conf = build_install_conf(&ctx());
        assert!(conf.contains("BOOT_ROOT=/boot/efi"));
        assert!(conf.contains("layout=bls"));
    }

    #[test]
    fn execute_runs_kernel_install_for_each_kernel() {
        let kernels = kernels();
        let runner = RecordedTargetRunner::new()
            // bootctl install
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            // kernel-install add linux
            .queue_raw(0, b"".to_vec(), b"".to_vec())
            // kernel-install add linux-lts
            .queue_raw(0, b"".to_vec(), b"".to_vec());
        let provider = SystemdBootProvider { kernels: &kernels };
        let result = provider.execute(&ctx(), &runner);
        assert!(result.failure.is_none());
        let invocations = runner.invocations();
        let kernel_install_calls: Vec<&crate::repair::boot_repair::target_exec::TargetRequest> =
            invocations
                .iter()
                .filter(|inv| inv.binary == "kernel-install")
                .collect();
        assert_eq!(kernel_install_calls.len(), 2);
        assert_eq!(kernel_install_calls[0].argv[0], "add");
        assert_eq!(
            kernel_install_calls[0].argv[2],
            "/usr/lib/modules/6.18.0-arch1-1/vmlinuz"
        );
        assert_eq!(kernel_install_calls[1].argv[1], "6.18.0-arch1-1-lts");
    }

    #[test]
    fn execute_stops_on_first_kernel_install_failure() {
        let kernels = kernels();
        let runner = RecordedTargetRunner::new()
            .queue_raw(0, b"".to_vec(), b"".to_vec()) // bootctl install
            .queue_raw(1, b"".to_vec(), b"oops".to_vec()); // first kernel-install
        let provider = SystemdBootProvider { kernels: &kernels };
        let result = provider.execute(&ctx(), &runner);
        assert!(result.failure.is_some());
        // Only the first kernel-install was attempted.
        assert_eq!(
            runner
                .invocations()
                .iter()
                .filter(|inv| inv.binary == "kernel-install")
                .count(),
            1
        );
    }

    #[test]
    fn verify_uses_correct_esp_path_flag() {
        let runner = RecordedTargetRunner::new().queue_raw(0, b"yes".to_vec(), b"".to_vec());
        let provider = SystemdBootProvider { kernels: &[] };
        let result = provider.verify(&ctx(), &runner);
        assert!(result.verified);
        let invocations = runner.invocations();
        let bootctl = invocations
            .iter()
            .find(|inv| inv.binary == "bootctl")
            .unwrap();
        assert!(bootctl.argv.iter().any(|arg| arg == "--esp-path=/boot/efi"));
        assert!(bootctl.argv.iter().any(|arg| arg == "is-installed"));
    }
}
