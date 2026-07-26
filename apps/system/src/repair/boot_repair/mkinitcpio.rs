//! mkinitcpio configuration + kernel discovery. Port of
//! `providers/base.configure_mkinitcpio`, `discover_kernels`, and
//! `build_initramfs` from the bootloadu Calamares module.
//!
//! ## What this module owns
//!
//! * Pure parsing/serialisation of mkinitcpio array lines
//!   (`HOOKS=(...)`, `MODULES=(...)`, etc.) — no I/O.
//! * Snapshot-overlay hook routing: each provider that supports
//!   bootable snapshots contributes its own overlayfs hook name
//!   (`grub-btrfs-overlayfs`, `limine-btrfs-overlayfs`,
//!   `sdboot-btrfs-overlayfs`).
//! * [`Kernel`] discovery: enumerates `/usr/lib/modules/<version>/`
//!   directories that have both a `pkgbase` and `vmlinuz` file.
//!
//! ## Hard rules
//!
//! * No I/O. All filesystem reads happen through the confined
//!   [`crate::recovery::confined`] API in the orchestrator. This
//!   module only transforms bytes.
//! * The HOOKS array the builder emits MUST match the bootloadu
//!   ordering: `base udev autodetect microcode modconf kms keyboard
//!   keymap consolefont block [plymouth] [usr] [encrypt] [lvm2]
//!   [openswap] [resume] filesystems [fsck] [<overlayfs_hook>]`.
//! * The `/crypto_keyfile.bin` entry in FILES is removed and only
//!   re-added when the encrypted-root + non-unencrypted-/boot
//!   precondition holds, mirroring bootloadu's
//!   `has_unencrypted_separate_boot` check.

use crate::model::boot_repair::ProviderId;
use crate::repair::boot_repair::registry;

/// One row of the mkinitcpio arrays the configurator manages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MkinitcpioArrays {
    pub hooks: Vec<String>,
    pub modules: Vec<String>,
    pub files: Vec<String>,
    pub binaries: Vec<String>,
}

/// Inputs the orchestrator supplies from target observations. All
/// filesystem facts come from the stage 1–3 discovery or the
/// confined target reader.
#[derive(Debug, Clone, Default)]
pub struct MkinitcpioInputs<'a> {
    /// Verbatim text of the target's `/etc/mkinitcpio.conf`.
    pub existing_config: &'a str,
    /// Target root filesystem type (`btrfs`, `ext4`, ...).
    pub root_filesystem: String,
    /// Whether the root filesystem is on a LUKS-mapped device.
    pub encrypted_root: bool,
    /// Whether the target has an unencrypted separate `/boot`.
    pub has_unencrypted_separate_boot: bool,
    /// Whether the target has a separate `/usr` filesystem.
    pub has_separate_usr: bool,
    /// Whether the target has any swap.
    pub has_swap: bool,
    /// Whether the target's swap is on a LUKS-mapped device.
    pub encrypted_swap: bool,
    /// Whether the target uses LVM.
    pub uses_lvm: bool,
    /// Whether the target has Plymouth installed (mkinitcpio HOOK).
    pub has_plymouth: bool,
    /// Whether `/crypto_keyfile.bin` exists inside the target root.
    pub has_crypto_keyfile: bool,
    /// Provider currently selected for boot repair. Used to look up
    /// the snapshot-overlay hook when `snapshots_enabled` is true.
    pub provider: ProviderId,
    /// Whether bootable snapshots are enabled for this provider on
    /// this target.
    pub snapshots_enabled: bool,
    /// Whether the target root is Btrfs (snapshot overlayfs requires it).
    pub root_is_btrfs: bool,
}

/// Parse an existing mkinitcpio.conf into arrays. Unknown lines are
/// discarded; only `HOOKS=(...)`, `MODULES=(...)`, `FILES=(...)`,
/// `BINARIES=(...)` are extracted. Mirrors bootloadu
/// `_mkinitcpio_arrays`.
pub fn parse_arrays(config_text: &str) -> MkinitcpioArrays {
    let mut arrays = MkinitcpioArrays::default();
    for line in config_text.lines() {
        let trimmed = line.trim_start();
        let Some((key, value)) = split_array_line(trimmed) else {
            continue;
        };
        let target = match key {
            "HOOKS" => &mut arrays.hooks,
            "MODULES" => &mut arrays.modules,
            "FILES" => &mut arrays.files,
            "BINARIES" => &mut arrays.binaries,
            _ => continue,
        };
        *target = shell_split(value);
    }
    arrays
}

/// Split a `KEY=(value)` mkinitcpio line into `(KEY, value)` without
/// the surrounding parens.
fn split_array_line(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    let key = &line[..eq];
    let rest = line[eq + 1..].trim_start();
    if !rest.starts_with('(') {
        return None;
    }
    let inner_start = 1;
    let inner_end = rest.rfind(')').unwrap_or(rest.len());
    Some((key.trim(), &rest[inner_start..inner_end]))
}

/// Minimal POSIX-style splitter for mkinitcpio array bodies. Handles
/// double-quoted entries (e.g. `FILES=("/crypto_keyfile.bin")`) the
/// same way shlex.split does for bootloadu.
fn shell_split(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in value.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            '\\' => {} // POSIX collapsing; we don't preserve escapes.
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Compute the new mkinitcpio arrays from inputs. Mirrors
/// bootloadu `configure_mkinitcpio` decision tree, parameterised by
/// the snapshot-overlay hook for the active provider.
pub fn compute_arrays(inputs: &MkinitcpioInputs<'_>) -> MkinitcpioArrays {
    let parsed = parse_arrays(inputs.existing_config);
    let mut arrays = parsed.clone();
    // Always strip the managed keyfile first; only re-add when the
    // encrypted-root + non-unencrypted-/boot precondition holds.
    arrays.files.retain(|entry| entry != "/crypto_keyfile.bin");

    // Snapshot repair must not silently migrate an existing systemd
    // initramfs back to the BusyBox/udev family. Current CatOS snapshot hooks
    // have a native systemd path using systemd-volatile-root; preserving the
    // target's family is both safer and required for real snapshot switch-root.
    if inputs.snapshots_enabled && parsed.hooks.iter().any(|hook| hook == "systemd") {
        let uses_btrfs = inputs.root_is_btrfs || inputs.root_filesystem == "btrfs";
        let mut hooks = parsed
            .hooks
            .into_iter()
            .filter(|hook| {
                hook != "udev"
                    && !matches!(
                        hook.as_str(),
                        "grub-btrfs-overlayfs"
                            | "limine-btrfs-overlayfs"
                            | "sdboot-btrfs-overlayfs"
                    )
                    && !(uses_btrfs && hook == "fsck")
            })
            .collect::<Vec<_>>();
        if !hooks.iter().any(|hook| hook == "base") {
            hooks.insert(0, "base".into());
        }
        if !hooks.iter().any(|hook| hook == "systemd") {
            hooks.insert(1, "systemd".into());
        }
        if !hooks.iter().any(|hook| hook == "filesystems") {
            hooks.push("filesystems".into());
        }
        if inputs.encrypted_root
            && !inputs.has_unencrypted_separate_boot
            && inputs.has_crypto_keyfile
        {
            arrays.files.push("/crypto_keyfile.bin".into());
        }
        if inputs.root_is_btrfs {
            if let Some(snapshot) = registry::snapshot_profile(inputs.provider) {
                hooks.push(snapshot.overlayfs_hook.to_string());
            }
        }
        arrays.hooks = dedupe(hooks);
        arrays.modules = dedupe(arrays.modules);
        arrays.binaries = dedupe(arrays.binaries);
        arrays.files = dedupe(arrays.files);
        return arrays;
    }

    let mut hooks = vec![
        "base".to_string(),
        "udev".to_string(),
        "autodetect".to_string(),
        "microcode".to_string(),
        "modconf".to_string(),
        "kms".to_string(),
        "keyboard".to_string(),
        "keymap".to_string(),
        "consolefont".to_string(),
        "block".to_string(),
    ];
    if inputs.has_plymouth {
        hooks.push("plymouth".into());
    }
    if inputs.has_separate_usr {
        hooks.push("usr".into());
    }
    if inputs.encrypted_root {
        hooks.push("encrypt".into());
        if !inputs.has_unencrypted_separate_boot && inputs.has_crypto_keyfile {
            arrays.files.push("/crypto_keyfile.bin".into());
        }
    }
    if inputs.uses_lvm {
        hooks.push("lvm2".into());
    }
    if inputs.encrypted_root && inputs.encrypted_swap {
        hooks.push("openswap".into());
    }
    if inputs.has_swap {
        hooks.push("resume".into());
    }
    hooks.push("filesystems".into());
    let uses_btrfs = inputs.root_is_btrfs || inputs.root_filesystem == "btrfs";
    if !uses_btrfs {
        hooks.push("fsck".into());
    }

    if inputs.snapshots_enabled {
        if !inputs.root_is_btrfs {
            // bootloadu raises BootloaduError here; the orchestrator
            // refuses before reaching compute_arrays when the
            // provider's snapshot profile requires btrfs. We leave
            // the hook unset defensively.
        } else if let Some(snap) = registry::snapshot_profile(inputs.provider) {
            hooks.push(snap.overlayfs_hook.to_string());
        }
    }

    arrays.hooks = dedupe(hooks);
    arrays.modules = dedupe(arrays.modules);
    arrays.binaries = dedupe(arrays.binaries);
    arrays.files = dedupe(arrays.files);
    arrays
}

fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(move |item| seen.insert(item.clone()))
        .collect()
}

/// Serialise the arrays back into mkinitcpio.conf text. Preserves
/// unrelated lines verbatim; only replaces the four managed arrays.
/// Missing arrays are appended in the canonical bootloadu order
/// (`MODULES`, `BINARIES`, `FILES`, `HOOKS`). Mirrors bootloadu
/// `_write_mkinitcpio_arrays`.
pub fn serialise(existing_text: &str, arrays: &MkinitcpioArrays) -> String {
    let mut remaining: [(&str, &Vec<String>); 4] = [
        ("MODULES", &arrays.modules),
        ("BINARIES", &arrays.binaries),
        ("FILES", &arrays.files),
        ("HOOKS", &arrays.hooks),
    ];
    let mut output = String::new();
    for line in existing_text.lines() {
        let trimmed = line.trim_start();
        match split_array_line(trimmed) {
            Some((key, _)) => {
                let pos = remaining.iter().position(|(k, _)| *k == key);
                if let Some(index) = pos {
                    let (key, values) = remaining[index];
                    output.push_str(&format_array_line(key, values));
                    output.push('\n');
                    remaining[index].0 = "";
                } else {
                    output.push_str(line);
                    output.push('\n');
                }
            }
            None => {
                output.push_str(line);
                output.push('\n');
            }
        }
    }
    for (key, values) in remaining {
        if key.is_empty() {
            continue;
        }
        output.push_str(&format_array_line(key, values));
        output.push('\n');
    }
    output
}

fn format_array_line(key: &str, values: &[String]) -> String {
    format!("{key}=({})", values.join(" "))
}

/// One discovered kernel. Mirrors bootloadu `Kernel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kernel {
    pub version: String,
    pub package: String,
    /// Target-relative image path, e.g.
    /// `/usr/lib/modules/6.18.0/vmlinuz`.
    pub image: String,
    /// Target-relative initramfs path, e.g.
    /// `/boot/initramfs-linux.img`.
    pub initramfs: String,
}

/// Discover installed kernels from a list of directory entries under
/// `/usr/lib/modules`. Each entry must be a `(name, has_pkgbase,
/// has_vmlinuz)` triple; the orchestrator obtains the list through
/// the confined target reader.
pub fn discover_kernels(modules_entries: &[(String, bool, bool, String)]) -> Vec<Kernel> {
    let mut kernels: Vec<Kernel> = modules_entries
        .iter()
        .filter(|(name, has_pkgbase, has_vmlinuz, pkgbase)| {
            *has_pkgbase
                && *has_vmlinuz
                && !pkgbase.trim().is_empty()
                && name.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .map(|(name, _, _, pkgbase)| Kernel {
            version: name.clone(),
            package: pkgbase.trim().to_string(),
            image: format!("/usr/lib/modules/{name}/vmlinuz"),
            initramfs: format!("/boot/initramfs-{}.img", pkgbase.trim()),
        })
        .collect();
    kernels.sort_by(|a, b| a.version.cmp(&b.version));
    kernels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_provider_appends_matching_overlayfs_hook() {
        // bootloadu test_snapshot_provider_appends_matching_overlayfs_hook port.
        let expected: &[(&str, &str)] = &[
            ("grub", "grub-btrfs-overlayfs"),
            ("limine", "limine-btrfs-overlayfs"),
            ("systemd-boot", "sdboot-btrfs-overlayfs"),
        ];
        for (provider_str, overlay_hook) in expected {
            let provider = ProviderId::from_registry_str(provider_str).unwrap();
            let inputs = MkinitcpioInputs {
                existing_config: "HOOKS=(base udev block filesystems fsck)\n",
                root_filesystem: "btrfs".into(),
                provider,
                snapshots_enabled: true,
                root_is_btrfs: true,
                ..MkinitcpioInputs::default()
            };
            let arrays = compute_arrays(&inputs);
            assert_eq!(arrays.hooks.last().map(String::as_str), Some(*overlay_hook));
            assert_eq!(arrays.hooks.iter().filter(|h| h == overlay_hook).count(), 1);
        }
    }

    #[test]
    fn snapshot_repair_preserves_existing_systemd_initramfs_family() {
        let inputs = MkinitcpioInputs {
            existing_config:
                "HOOKS=(base systemd microcode modconf keyboard keymap block filesystems fsck)\n",
            root_filesystem: "btrfs".into(),
            provider: ProviderId::Limine,
            snapshots_enabled: true,
            root_is_btrfs: true,
            ..MkinitcpioInputs::default()
        };

        let arrays = compute_arrays(&inputs);

        assert!(arrays.hooks.contains(&"systemd".to_string()));
        assert!(!arrays.hooks.contains(&"udev".to_string()));
        assert!(arrays.hooks.contains(&"limine-btrfs-overlayfs".to_string()));
        assert_eq!(
            arrays
                .hooks
                .iter()
                .filter(|hook| *hook == "systemd")
                .count(),
            1
        );
    }

    #[test]
    fn mkinitcpio_omits_overlayfs_hook_without_snapshots() {
        // bootloadu test_mkinitcpio_omits_overlayfs_hook_without_snapshots port.
        let inputs = MkinitcpioInputs {
            existing_config: "HOOKS=(base udev block filesystems fsck)\n",
            root_filesystem: "btrfs".into(),
            provider: ProviderId::Limine,
            snapshots_enabled: false,
            root_is_btrfs: true,
            ..MkinitcpioInputs::default()
        };
        let arrays = compute_arrays(&inputs);
        assert!(!arrays.hooks.iter().any(|h| h.contains("btrfs-overlayfs")));
    }

    #[test]
    fn mkinitcpio_configuration_embeds_keyfile_and_swap_hook() {
        // bootloadu test_mkinitcpio_configuration_embeds_keyfile_and_swap_hook port.
        let inputs = MkinitcpioInputs {
            existing_config: "MODULES=(existing)\nBINARIES=()\nFILES=()\n\
                HOOKS=(base udev autodetect block filesystems fsck)\n",
            root_filesystem: "btrfs".into(),
            encrypted_root: true,
            encrypted_swap: true,
            has_swap: true,
            has_crypto_keyfile: true,
            ..MkinitcpioInputs::default()
        };
        let arrays = compute_arrays(&inputs);
        assert!(arrays.hooks.contains(&"encrypt".to_string()));
        assert!(arrays.hooks.contains(&"openswap".to_string()));
        assert!(arrays.hooks.contains(&"resume".to_string()));
        assert!(arrays.files.contains(&"/crypto_keyfile.bin".to_string()));
        assert!(!arrays.hooks.contains(&"fsck".to_string()));
        assert!(arrays.modules.contains(&"existing".to_string()));
    }

    #[test]
    fn mkinitcpio_removes_stale_managed_keyfile() {
        // bootloadu test_mkinitcpio_removes_stale_managed_keyfile port.
        let inputs = MkinitcpioInputs {
            existing_config: "FILES=(/crypto_keyfile.bin /etc/keep-me)\n\
                HOOKS=(base udev filesystems fsck)\n",
            root_filesystem: "ext4".into(),
            ..MkinitcpioInputs::default()
        };
        let arrays = compute_arrays(&inputs);
        assert!(!arrays.files.contains(&"/crypto_keyfile.bin".to_string()));
        assert!(arrays.files.contains(&"/etc/keep-me".to_string()));
    }

    #[test]
    fn serialise_preserves_unrelated_lines() {
        let existing = "# header\nMODULES=(old)\nHOOKS=(base)\n# trailing\n";
        let arrays = MkinitcpioArrays {
            modules: vec!["new".into()],
            hooks: vec!["base".into(), "udev".into()],
            files: vec![],
            binaries: vec![],
        };
        let serialised = serialise(existing, &arrays);
        assert!(serialised.starts_with("# header\n"));
        assert!(serialised.contains("MODULES=(new)"));
        assert!(serialised.contains("HOOKS=(base udev)"));
        assert!(serialised.contains("# trailing"));
    }

    #[test]
    fn serialise_appends_missing_arrays_in_canonical_order() {
        let existing = "# header only\n";
        let arrays = MkinitcpioArrays {
            modules: vec![],
            hooks: vec!["base".into()],
            files: vec!["/crypto_keyfile.bin".into()],
            binaries: vec![],
        };
        let serialised = serialise(existing, &arrays);
        let hooks_pos = serialised.find("HOOKS=").unwrap();
        let files_pos = serialised.find("FILES=").unwrap();
        let modules_pos = serialised.find("MODULES=").unwrap();
        assert!(modules_pos < files_pos);
        assert!(files_pos < hooks_pos);
    }

    #[test]
    fn discover_kernels_filters_extramodules_and_unpopulated_dirs() {
        let entries = vec![
            (
                "6.18.0-arch1-1".to_string(),
                true,
                true,
                "linux".to_string(),
            ),
            ("extramodules".to_string(), true, true, "linux".to_string()),
            ("6.17.0".to_string(), false, true, "linux".to_string()),
            ("6.16.0".to_string(), true, false, "linux".to_string()),
            ("6.18.1".to_string(), true, true, "  ".to_string()),
        ];
        let kernels = discover_kernels(&entries);
        assert_eq!(kernels.len(), 1);
        assert_eq!(kernels[0].version, "6.18.0-arch1-1");
        assert_eq!(kernels[0].package, "linux");
        assert_eq!(kernels[0].image, "/usr/lib/modules/6.18.0-arch1-1/vmlinuz");
        assert_eq!(kernels[0].initramfs, "/boot/initramfs-linux.img");
    }

    #[test]
    fn uki_and_efistub_never_get_overlayfs_hook_even_with_snapshots() {
        for provider in [ProviderId::Uki, ProviderId::Efistub] {
            let inputs = MkinitcpioInputs {
                existing_config: "HOOKS=(base)\n",
                root_filesystem: "btrfs".into(),
                provider,
                snapshots_enabled: true,
                root_is_btrfs: true,
                ..MkinitcpioInputs::default()
            };
            let arrays = compute_arrays(&inputs);
            assert!(
                !arrays.hooks.iter().any(|h| h.contains("overlayfs")),
                "UKI/EFI Stub must not get an overlayfs hook"
            );
        }
    }
}
