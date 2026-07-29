//! Read-only postcondition verification for boot repair.

use std::path::Path;

use crate::diagnose::target::target_regular_file_present;
use crate::execute::providers::base::ProviderVerificationResult;
use crate::io::{read_target_file, read_target_file_checked};
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
    let mut in_menuentry = false;
    let mut has_linux = false;
    let mut has_initrd = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !in_menuentry {
            if trimmed.split_whitespace().next() == Some("menuentry") && trimmed.ends_with('{') {
                in_menuentry = true;
                has_linux = false;
                has_initrd = false;
            }
            continue;
        }
        if trimmed == "}" {
            if has_linux && has_initrd {
                return true;
            }
            in_menuentry = false;
            continue;
        }
        match trimmed.split_whitespace().next() {
            Some("linux" | "linuxefi") => has_linux = true,
            Some("initrd" | "initrdefi") => has_initrd = true,
            _ => {}
        }
    }
    false
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
            let Some(machine_id) = target_machine_id(target_root) else {
                return false;
            };
            read_target_file(target_root, &format!("{esp}/limine.conf")).is_some_and(|contents| {
                !contents.trim().is_empty()
                    && kernels.iter().all(|kernel| {
                        limine_config_has_kernel_entry(
                            &contents,
                            &machine_id,
                            &kernel.package,
                            |reference| {
                                target_limine_boot_asset_present(target_root, esp, reference)
                            },
                        )
                    })
            }) && target_deployed_kernel_assets(
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

fn target_machine_id(target_root: &Path) -> Option<String> {
    read_target_file(target_root, "etc/machine-id")
        .map(|machine_id| machine_id.trim().to_string())
        .filter(|machine_id| is_valid_machine_id(machine_id))
}

fn is_valid_machine_id(machine_id: &str) -> bool {
    let bytes = machine_id.as_bytes();
    bytes.len() == 32
        && bytes.iter().any(|byte| *byte != b'0')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn target_deployed_kernel_assets(
    target_root: &Path,
    esp: &str,
    kernels: &[Kernel],
    directory: impl Fn(&Kernel) -> String,
    kernel_asset: &str,
    initramfs_asset: &str,
) -> bool {
    let Some(machine_id) = target_machine_id(target_root) else {
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

#[derive(Default)]
struct LimineEntryAssets {
    active: bool,
    protocol_seen: bool,
    protocol_linux: bool,
    kernel_path_seen: bool,
    kernel_path_matches: bool,
    initramfs_path_matches: bool,
    invalid: bool,
}

impl LimineEntryAssets {
    fn complete(&self) -> bool {
        self.active
            && !self.invalid
            && self.protocol_linux
            && self.kernel_path_matches
            && self.initramfs_path_matches
    }
}

fn limine_config_has_kernel_entry(
    contents: &str,
    machine_id: &str,
    package: &str,
    mut asset_present: impl FnMut(&str) -> bool,
) -> bool {
    let expected_kernel = format!("boot():/{machine_id}/{package}/vmlinuz");
    let expected_initramfs = format!("boot():/{machine_id}/{package}/initramfs");
    let mut entry = LimineEntryAssets::default();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('/') {
            if entry.complete() {
                return true;
            }
            entry = LimineEntryAssets {
                active: true,
                ..LimineEntryAssets::default()
            };
            continue;
        }
        if !entry.active || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((directive, raw_value)) = trimmed.split_once(':') else {
            continue;
        };
        let value = raw_value.trim();
        let value_is_single_token = !value.is_empty() && value.split_whitespace().count() == 1;
        match directive.trim() {
            "protocol" => {
                if entry.protocol_seen || !value_is_single_token {
                    entry.invalid = true;
                } else {
                    entry.protocol_seen = true;
                    entry.protocol_linux = value == "linux";
                }
            }
            "path" | "kernel_path" => {
                if entry.kernel_path_seen
                    || !value_is_single_token
                    || !target_limine_reference_is_safe(value)
                    || !asset_present(value)
                {
                    entry.invalid = true;
                } else {
                    entry.kernel_path_seen = true;
                    entry.kernel_path_matches =
                        limine_asset_reference_matches(value, &expected_kernel);
                }
            }
            "module_path" => {
                if !value_is_single_token
                    || !target_limine_reference_is_safe(value)
                    || !asset_present(value)
                {
                    entry.invalid = true;
                } else if limine_asset_reference_matches(value, &expected_initramfs) {
                    entry.initramfs_path_matches = true;
                }
            }
            _ => {}
        }
    }

    entry.complete()
}

fn limine_asset_reference_matches(value: &str, expected: &str) -> bool {
    limine_reference_without_hash(value).is_some_and(|reference| reference == expected)
}

fn limine_reference_without_hash(value: &str) -> Option<&str> {
    match value.split_once('#') {
        None if !value.is_empty() => Some(value),
        Some((reference, hash))
            if !reference.is_empty()
                && hash.len() == 128
                && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Some(reference)
        }
        _ => None,
    }
}

fn target_limine_reference_is_safe(value: &str) -> bool {
    let Some(reference) = limine_reference_without_hash(value) else {
        return false;
    };
    let Some(relative) = reference.strip_prefix("boot():/") else {
        return false;
    };
    !relative.is_empty()
        && relative
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn target_limine_boot_asset_present(target_root: &Path, esp: &str, value: &str) -> bool {
    if !target_limine_reference_is_safe(value) {
        return false;
    }
    let Some(reference) = limine_reference_without_hash(value) else {
        return false;
    };
    let Some(relative) = reference.strip_prefix("boot():/") else {
        return false;
    };
    target_regular_file_present(target_root, &format!("{esp}/{relative}"))
}

fn target_systemd_boot_entry_present(target_root: &Path, esp: &str, kernels: &[Kernel]) -> bool {
    let Some(machine_id) = target_machine_id(target_root) else {
        return false;
    };
    let esp_rooted = format!("/{}", esp.trim_matches('/'));
    let entries = catos_target::execute::confined::list_rooted_directory_names(
        target_root,
        &format!("{esp_rooted}/loader/entries"),
    )
    .unwrap_or_default();
    !kernels.is_empty()
        && kernels.iter().all(|kernel| {
            let prefix = format!("{machine_id}-{}", kernel.version);
            entries.iter().any(|entry| {
                let Some(entry) = entry.to_str() else {
                    return false;
                };
                if !entry.starts_with(&prefix) || !entry.ends_with(".conf") {
                    return false;
                }
                let entry_relative = format!("{}/loader/entries/{entry}", esp.trim_matches('/'));
                read_target_file_checked(target_root, &entry_relative)
                    .ok()
                    .flatten()
                    .is_some_and(|contents| {
                        systemd_boot_entry_references_assets(
                            &contents,
                            &machine_id,
                            &kernel.version,
                        )
                    })
            })
        })
}

fn systemd_boot_entry_references_assets(contents: &str, machine_id: &str, version: &str) -> bool {
    let expected_linux = format!("/{machine_id}/{version}/linux");
    let expected_initrd = format!("/{machine_id}/{version}/initrd");
    let mut has_linux = false;
    let mut has_initrd = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let Some(directive) = fields.next() else {
            continue;
        };
        match directive {
            "linux" => {
                let Some(path) = fields.next() else {
                    return false;
                };
                if fields.next().is_some() || has_linux || path != expected_linux {
                    return false;
                }
                has_linux = true;
            }
            "initrd" => {
                let Some(path) = fields.next() else {
                    return false;
                };
                if fields.next().is_some() {
                    return false;
                }
                if path == expected_initrd {
                    has_initrd = true;
                }
            }
            _ => {}
        }
    }
    has_linux && has_initrd
}

#[cfg(test)]
mod tests {
    use super::{
        grub_config_has_bootable_linux_entry, is_valid_machine_id, limine_config_has_kernel_entry,
        systemd_boot_entry_references_assets,
    };

    const MACHINE_ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn machine_id_requires_nonzero_lowercase_32_digit_hex() {
        assert!(is_valid_machine_id(MACHINE_ID));
        assert!(!is_valid_machine_id("machine-id"));
        assert!(!is_valid_machine_id("00000000000000000000000000000000"));
        assert!(!is_valid_machine_id("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!is_valid_machine_id("0123456789abcdef0123456789abcdeg"));
    }

    #[test]
    fn limine_kernel_and_initramfs_must_share_one_linux_entry() {
        let split = format!(
            "/+CatOS\n  //kernel-only\n  protocol: linux\n  path: boot():/{MACHINE_ID}/linux/vmlinuz\n  //initrd-only\n  protocol: linux\n  module_path: boot():/{MACHINE_ID}/linux/initramfs\n"
        );

        assert!(!limine_config_has_kernel_entry(
            &split,
            MACHINE_ID,
            "linux",
            |_| true
        ));
    }

    #[test]
    fn limine_kernel_entry_accepts_hashes_and_extra_microcode() {
        let hash = "a".repeat(128);
        let config = format!(
            "/+CatOS\n  //linux\n  protocol: linux\n  module_path: boot():/amd-ucode.img\n  module_path: boot():/{MACHINE_ID}/linux/initramfs#{hash}\n  path: boot():/{MACHINE_ID}/linux/vmlinuz#{hash}\n"
        );

        assert!(limine_config_has_kernel_entry(
            &config,
            MACHINE_ID,
            "linux",
            |_| true
        ));
    }

    #[test]
    fn limine_kernel_entry_rejects_a_missing_extra_module_asset() {
        let config = format!(
            "/+CatOS\n  //linux\n  protocol: linux\n  module_path: boot():/amd-ucode.img\n  module_path: boot():/{MACHINE_ID}/linux/initramfs\n  path: boot():/{MACHINE_ID}/linux/vmlinuz\n"
        );

        assert!(!limine_config_has_kernel_entry(
            &config,
            MACHINE_ID,
            "linux",
            |reference| !reference.contains("amd-ucode.img")
        ));
    }

    #[test]
    fn limine_kernel_entry_rejects_invalid_hash_or_duplicate_kernel_path() {
        let invalid_hash = format!(
            "/+CatOS\n  //linux\n  protocol: linux\n  module_path: boot():/{MACHINE_ID}/linux/initramfs#bad\n  path: boot():/{MACHINE_ID}/linux/vmlinuz#bad\n"
        );
        let duplicate = format!(
            "/+CatOS\n  //linux\n  protocol: linux\n  module_path: boot():/{MACHINE_ID}/linux/initramfs\n  path: boot():/{MACHINE_ID}/linux/vmlinuz\n  kernel_path: boot():/{MACHINE_ID}/linux/vmlinuz\n"
        );

        assert!(!limine_config_has_kernel_entry(
            &invalid_hash,
            MACHINE_ID,
            "linux",
            |_| true
        ));
        assert!(!limine_config_has_kernel_entry(
            &duplicate,
            MACHINE_ID,
            "linux",
            |_| true
        ));
    }

    #[test]
    fn systemd_boot_entry_rejects_trailing_linux_tokens() {
        let entry = "linux /machine-id/6.18.0/linux extra\ninitrd /machine-id/6.18.0/initrd\n";

        assert!(!systemd_boot_entry_references_assets(
            entry,
            "machine-id",
            "6.18.0"
        ));
    }

    #[test]
    fn systemd_boot_entry_rejects_duplicate_or_conflicting_linux_directives() {
        let duplicate = "linux /machine-id/6.18.0/linux\nlinux /machine-id/6.18.0/linux\ninitrd /machine-id/6.18.0/initrd\n";
        let conflicting = "linux /machine-id/6.18.0/linux\nlinux /other/linux\ninitrd /machine-id/6.18.0/initrd\n";

        assert!(!systemd_boot_entry_references_assets(
            duplicate,
            "machine-id",
            "6.18.0"
        ));
        assert!(!systemd_boot_entry_references_assets(
            conflicting,
            "machine-id",
            "6.18.0"
        ));
    }

    #[test]
    fn systemd_boot_entry_allows_additional_valid_initrd_assets() {
        let entry = "linux /machine-id/6.18.0/linux\ninitrd /intel-ucode.img\ninitrd /machine-id/6.18.0/initrd\n";

        assert!(systemd_boot_entry_references_assets(
            entry,
            "machine-id",
            "6.18.0"
        ));
    }

    #[test]
    fn grub_verification_rejects_commands_split_across_menuentries() {
        let config = "menuentry 'kernel only' {\n linux /vmlinuz-linux root=UUID=root\n}\nmenuentry 'initrd only' {\n initrd /initramfs-linux.img\n}\n";

        assert!(!grub_config_has_bootable_linux_entry(config));
    }

    #[test]
    fn grub_verification_rejects_commands_outside_the_menuentry() {
        let config = "menuentry 'empty' {\n}\nlinux /vmlinuz-linux root=UUID=root\ninitrd /initramfs-linux.img\n";

        assert!(!grub_config_has_bootable_linux_entry(config));
    }

    #[test]
    fn grub_verification_accepts_one_complete_menuentry() {
        let config = "menuentry 'CatOS' {\n linuxefi /vmlinuz-linux root=UUID=root\n initrdefi /initramfs-linux.img\n}\n";

        assert!(grub_config_has_bootable_linux_entry(config));
    }
}
