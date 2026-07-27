//! Target-side inspection and post-repair verification helpers.

use std::path::Path;
use crate::repair::boot_repair::detect::DetectionInputs;
use crate::repair::boot_repair::mkinitcpio::Kernel;
use crate::shared::model::mount_repair::TargetIdentity;
use super::{has_target_path, read_target_file};

pub(super) fn detect_target_architecture(root: &Path) -> Option<crate::shared::model::boot_repair::Architecture> {
    let executable =
        crate::target::execute::confined::read_rooted_file(root, "/usr/lib/systemd/systemd").ok()?;
    let machine = executable.get(18..20)?;
    match u16::from_le_bytes([machine[0], machine[1]]) {
        62 => Some(crate::shared::model::boot_repair::Architecture::X86_64),
        183 => Some(crate::shared::model::boot_repair::Architecture::Aarch64),
        _ => None,
    }
}

pub(super) fn detect_partition_table(
    target: &TargetIdentity,
    devices: &[crate::target::model::BlockDevice],
) -> crate::shared::model::boot_repair::PartitionTable {
    use crate::target::model::DiskKind;

    let root = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == target.root_device)
    });
    match root.map(|device| device.disk_kind) {
        Some(DiskKind::Gpt) => crate::shared::model::boot_repair::PartitionTable::Gpt,
        Some(DiskKind::Mbr) => crate::shared::model::boot_repair::PartitionTable::Msdos,
        _ => crate::shared::model::boot_repair::PartitionTable::Unknown,
    }
}

pub(super) fn derive_bios_install_disk(
    target: &TargetIdentity,
    devices: &[crate::target::model::BlockDevice],
) -> Option<String> {
    let root = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == target.root_device)
    })?;
    if root.parent.is_empty() {
        return None;
    }
    let matches: Vec<&crate::target::model::BlockDevice> = devices
        .iter()
        .filter(|device| device.name == root.parent)
        .filter(|device| device.parent.is_empty())
        .filter(|device| device.dev_path.is_some())
        .collect();
    match matches.as_slice() {
        [disk] => disk.dev_path.as_ref()?.to_str().map(str::to_string),
        _ => None,
    }
}

pub(super) fn derive_efi_device(
    target: &TargetIdentity,
    devices: &[crate::target::model::BlockDevice],
) -> Option<(String, u32)> {
    let esp_path = target.esp_device.as_deref()?;
    let esp = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == esp_path)
    })?;
    let partition = esp.partition_number?;
    if esp.parent.is_empty() {
        return None;
    }
    let disk = devices
        .iter()
        .find(|device| device.name == esp.parent && device.parent.is_empty())?;
    let disk_path = disk.dev_path.as_ref()?.to_str()?.to_string();
    Some((disk_path, partition))
}

pub(super) fn collect_detection_inputs_from_target_root(root: &Path) -> DetectionInputs {
    DetectionInputs {
        grub_defaults_catos: read_target_file(root, "etc/default/grub.d/00-catos.cfg"),
        limine_defaults: read_target_file(root, "etc/default/limine"),
        kernel_install_catos: read_target_file(
            root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        ),
        firmware_boot_conf: read_target_file(root, "etc/catos/firmware-boot.conf"),
        kernel_cmdline: read_target_file(root, "etc/kernel/cmdline"),
        has_boot_grub: has_target_path(root, "boot/grub"),
        has_esp_limine_conf: target_regular_file_in_any(
            root,
            &[
                "boot/limine.conf",
                "boot/efi/limine.conf",
                "efi/limine.conf",
            ],
        ),
        has_systemd_boot_loader: target_regular_file_in_any(
            root,
            &[
                "boot/loader/loader.conf",
                "boot/efi/loader/loader.conf",
                "efi/loader/loader.conf",
            ],
        ),
        has_catos_uki_deployed: target_uki_deployed(root),
        has_efistub_deployed: target_efistub_deployed(root),
        installed_packages: Vec::new(),
    }
}

pub(super) fn collect_installed_packages_from_target_root(root: &Path) -> Vec<String> {
    crate::target::execute::confined::list_rooted_directory_names(root, "/var/lib/pacman/local")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .filter_map(|entry| {
            crate::target::execute::confined::read_rooted_file(
                root,
                &format!("/var/lib/pacman/local/{entry}/desc"),
            )
            .ok()
        })
        .filter_map(|contents| String::from_utf8(contents).ok())
        .filter_map(|contents| pacman_package_name(&contents))
        .collect()
}

pub(super) fn collect_target_kernels(root: &Path) -> Vec<crate::repair::boot_repair::mkinitcpio::Kernel> {
    let entries = crate::target::execute::confined::list_rooted_directory_names(root, "/usr/lib/modules")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .map(|version| {
            let base = format!("/usr/lib/modules/{version}");
            let pkgbase =
                crate::target::execute::confined::read_rooted_file(root, &format!("{base}/pkgbase"))
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_default();
            let has_vmlinuz = crate::target::execute::confined::rooted_regular_file_size(
                root,
                &format!("{base}/vmlinuz"),
            )
            .ok()
            .flatten()
            .is_some_and(|size| size > 0);
            (version, !pkgbase.is_empty(), has_vmlinuz, pkgbase)
        })
        .collect::<Vec<_>>();
    crate::repair::boot_repair::mkinitcpio::discover_kernels(&entries)
}

fn pacman_package_name(desc: &str) -> Option<String> {
    let mut lines = desc.lines();
    while let Some(line) = lines.next() {
        if line == "%NAME%" {
            return lines
                .next()
                .map(str::to_string)
                .filter(|name| !name.is_empty());
        }
    }
    None
}

pub(super) fn target_regular_file_present(root: &Path, relative: &str) -> bool {
    crate::target::execute::confined::rooted_regular_file_size(root, &format!("/{relative}"))
        .ok()
        .flatten()
        .is_some_and(|size| size > 0)
}

pub(super) fn target_regular_file_in_any(root: &Path, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| target_regular_file_present(root, candidate))
}

pub(super) fn target_uki_deployed(root: &Path) -> bool {
    ["/boot/EFI/Linux", "/boot/efi/EFI/Linux", "/efi/EFI/Linux"]
        .iter()
        .any(|directory| {
            crate::target::execute::confined::list_rooted_directory_names(root, directory)
                .unwrap_or_default()
                .iter()
                .any(|entry| {
                    entry
                        .to_str()
                        .is_some_and(|entry| entry.starts_with("catos-") && entry.ends_with(".efi"))
                })
        })
}

pub(super) fn target_efistub_deployed(root: &Path) -> bool {
    ["/boot/EFI/CatOS", "/boot/efi/EFI/CatOS", "/efi/EFI/CatOS"]
        .iter()
        .any(|directory| {
            crate::target::execute::confined::list_rooted_directory_names(root, directory)
                .unwrap_or_default()
                .iter()
                .filter_map(|entry| entry.to_str().map(str::to_string))
                .any(|package| {
                    target_regular_file_present(
                        root,
                        &format!(
                            "{}/{package}/vmlinuz.efi",
                            directory.trim_start_matches('/')
                        ),
                    ) && target_regular_file_present(
                        root,
                        &format!(
                            "{}/{package}/initramfs.img",
                            directory.trim_start_matches('/')
                        ),
                    )
                })
        })
}
pub(super) fn verify_grub_target(
    target_root: &Path,
    kernels: &[Kernel],
) -> crate::repair::boot_repair::providers::base::ProviderRecipeResult {
    use crate::shared::model::boot_repair::BootVerification;
    use crate::repair::boot_repair::providers::base::ProviderRecipeResult;

    let config = read_target_file(target_root, "boot/grub/grub.cfg");
    let valid = config
        .as_deref()
        .is_some_and(grub_config_has_bootable_linux_entry)
        && kernels.iter().any(|kernel| {
            target_regular_file_present(target_root, kernel.initramfs.trim_start_matches('/'))
        });
    ProviderRecipeResult {
        verified: valid,
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
        ..ProviderRecipeResult::default()
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

pub(super) fn target_provider_assets_present(
    provider: crate::shared::model::boot_repair::ProviderId,
    target_root: &Path,
    esp_mount_point: Option<&str>,
    kernels: &[Kernel],
) -> bool {
    use crate::shared::model::boot_repair::ProviderId;

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
    kernels.iter().any(|kernel| {
        let directory = directory(kernel).replace("{machine_id}", &machine_id);
        target_regular_file_present(target_root, &format!("{directory}/{kernel_asset}"))
            && target_regular_file_present(target_root, &format!("{directory}/{initramfs_asset}"))
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
    let entries = crate::target::execute::confined::list_rooted_directory_names(
        target_root,
        &format!("/{esp}/loader/entries"),
    )
    .unwrap_or_default();
    kernels.iter().any(|kernel| {
        let prefix = format!("{machine_id}-{}", kernel.version);
        entries.iter().any(|entry| {
            entry
                .to_str()
                .is_some_and(|entry| entry.starts_with(&prefix) && entry.ends_with(".conf"))
        })
    })
}

pub(super) fn target_secureboot_marker_present(target_root: &Path) -> bool {
    has_target_path(target_root, "etc/catos/secureboot")
        || read_target_file(target_root, "etc/catos/secureboot.conf").is_some()
        || has_target_path(target_root, "var/lib/catos/secureboot")
}

pub(super) fn target_signed_catos_efi_present(target_root: &Path, esp_mount_point: Option<&str>) -> bool {
    let Some(esp_mount_point) = esp_mount_point else {
        return false;
    };
    let directory = format!("/{}/EFI/CatOS", esp_mount_point.trim_start_matches('/'));
    let entries = crate::target::execute::confined::list_rooted_directory_names(target_root, &directory)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .collect::<Vec<_>>();
    entries.iter().any(|entry| entry.ends_with(".efi"))
        && entries
            .iter()
            .any(|entry| entry.ends_with(".sig") || entry.ends_with(".p7b"))
}
