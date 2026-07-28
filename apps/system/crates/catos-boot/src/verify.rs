//! Read-only postcondition verification for boot repair.

use std::path::Path;

use crate::diagnose::target::target_regular_file_present;
use crate::execute::providers::base::ProviderVerificationResult;
use crate::io::read_target_file;
use crate::plan::initramfs::Kernel;
pub fn verify_grub_target(target_root: &Path, kernels: &[Kernel]) -> ProviderVerificationResult {
    use crate::model::BootVerification;

    let config = read_target_file(target_root, "boot/grub/grub.cfg");
    let valid = config
        .as_deref()
        .is_some_and(grub_config_has_bootable_linux_entry)
        && !kernels.is_empty()
        && kernels.iter().all(|kernel| {
            target_regular_file_present(target_root, kernel.initramfs.trim_start_matches('/'))
        });
    ProviderVerificationResult {
        passed: valid,
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
        ..ProviderVerificationResult::default()
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

pub fn target_provider_assets_present(
    provider: crate::model::ProviderId,
    target_root: &Path,
    esp_mount_point: Option<&str>,
    kernels: &[Kernel],
) -> bool {
    use crate::model::ProviderId;

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
    !kernels.is_empty()
        && kernels.iter().all(|kernel| {
            let directory = directory(kernel).replace("{machine_id}", &machine_id);
            target_regular_file_present(target_root, &format!("{directory}/{kernel_asset}"))
                && target_regular_file_present(
                    target_root,
                    &format!("{directory}/{initramfs_asset}"),
                )
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
    let entries = catos_target::execute::confined::list_rooted_directory_names(
        target_root,
        &format!("/{esp}/loader/entries"),
    )
    .unwrap_or_default();
    !kernels.is_empty()
        && kernels.iter().all(|kernel| {
            let prefix = format!("{machine_id}-{}", kernel.version);
            entries.iter().any(|entry| {
                entry
                    .to_str()
                    .is_some_and(|entry| entry.starts_with(&prefix) && entry.ends_with(".conf"))
            })
        })
}
