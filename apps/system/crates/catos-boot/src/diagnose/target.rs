//! Target-side inspection and post-repair verification helpers.

use crate::diagnose::provider::DetectionInputs;
use crate::io::{has_target_path, read_target_file};
use catos_mount::model::MountTargetIdentity;
use std::path::Path;

pub fn detect_target_architecture(root: &Path) -> Option<crate::model::Architecture> {
    let executable =
        catos_target::execute::confined::read_rooted_file(root, "/usr/lib/systemd/systemd").ok()?;
    let machine = executable.get(18..20)?;
    match u16::from_le_bytes([machine[0], machine[1]]) {
        62 => Some(crate::model::Architecture::X86_64),
        183 => Some(crate::model::Architecture::Aarch64),
        _ => None,
    }
}

pub fn detect_partition_table(
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
) -> crate::model::PartitionTable {
    use catos_target::model::DiskKind;

    let root = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == target.root_device)
    });
    match root.map(|device| device.disk_kind) {
        Some(DiskKind::Gpt) => crate::model::PartitionTable::Gpt,
        Some(DiskKind::Mbr) => crate::model::PartitionTable::Msdos,
        _ => crate::model::PartitionTable::Unknown,
    }
}

pub fn derive_bios_install_disk(
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
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
    let matches: Vec<&catos_target::model::BlockDevice> = devices
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

pub fn derive_efi_device(
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
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

pub fn collect_detection_inputs_from_target_root(root: &Path) -> DetectionInputs {
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

pub fn collect_installed_packages_from_target_root(root: &Path) -> Vec<String> {
    catos_target::execute::confined::list_rooted_directory_names(root, "/var/lib/pacman/local")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .filter_map(|entry| {
            catos_target::execute::confined::read_rooted_file(
                root,
                &format!("/var/lib/pacman/local/{entry}/desc"),
            )
            .ok()
        })
        .filter_map(|contents| String::from_utf8(contents).ok())
        .filter_map(|contents| pacman_package_name(&contents))
        .collect()
}

pub fn collect_target_kernels(root: &Path) -> Vec<crate::plan::initramfs::Kernel> {
    let entries =
        catos_target::execute::confined::list_rooted_directory_names(root, "/usr/lib/modules")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| entry.into_string().ok())
            .map(|version| {
                let base = format!("/usr/lib/modules/{version}");
                let pkgbase = catos_target::execute::confined::read_rooted_file(
                    root,
                    &format!("{base}/pkgbase"),
                )
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default();
                let has_vmlinuz = catos_target::execute::confined::rooted_regular_file_size(
                    root,
                    &format!("{base}/vmlinuz"),
                )
                .ok()
                .flatten()
                .is_some_and(|size| size > 0);
                (version, !pkgbase.is_empty(), has_vmlinuz, pkgbase)
            })
            .collect::<Vec<_>>();
    crate::plan::initramfs::discover_kernels(&entries)
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

pub fn target_regular_file_present(root: &Path, relative: &str) -> bool {
    catos_target::execute::confined::rooted_regular_file_size(root, &format!("/{relative}"))
        .ok()
        .flatten()
        .is_some_and(|size| size > 0)
}

pub fn target_regular_file_in_any(root: &Path, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| target_regular_file_present(root, candidate))
}

pub fn target_uki_deployed(root: &Path) -> bool {
    ["/boot/EFI/Linux", "/boot/efi/EFI/Linux", "/efi/EFI/Linux"]
        .iter()
        .any(|directory| {
            catos_target::execute::confined::list_rooted_directory_names(root, directory)
                .unwrap_or_default()
                .iter()
                .any(|entry| {
                    entry
                        .to_str()
                        .is_some_and(|entry| entry.starts_with("catos-") && entry.ends_with(".efi"))
                })
        })
}

pub fn target_efistub_deployed(root: &Path) -> bool {
    ["/boot/EFI/CatOS", "/boot/efi/EFI/CatOS", "/efi/EFI/CatOS"]
        .iter()
        .any(|directory| {
            catos_target::execute::confined::list_rooted_directory_names(root, directory)
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
pub fn target_secureboot_marker_present(target_root: &Path) -> bool {
    has_target_path(target_root, "etc/catos/secureboot")
        || read_target_file(target_root, "etc/catos/secureboot.conf").is_some()
        || has_target_path(target_root, "var/lib/catos/secureboot")
}

pub fn target_signed_catos_efi_present(target_root: &Path, esp_mount_point: Option<&str>) -> bool {
    let Some(esp_mount_point) = esp_mount_point else {
        return false;
    };
    let directory = format!("/{}/EFI/CatOS", esp_mount_point.trim_start_matches('/'));
    let entries =
        catos_target::execute::confined::list_rooted_directory_names(target_root, &directory)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| entry.into_string().ok())
            .collect::<Vec<_>>();
    entries.iter().any(|entry| entry.ends_with(".efi"))
        && entries
            .iter()
            .any(|entry| entry.ends_with(".sig") || entry.ends_with(".p7b"))
}
