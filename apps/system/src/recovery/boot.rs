//! Boot / ESP layout detection.
//!
//! This module is purely descriptive: it inspects a mounted snapshot
//! and records what boot resources it carries (`/boot` location, ESP,
//! UKIs, kernel modules, initramfs). Recovery does NOT act on this
//! information to update any bootloader — a future phase may consult
//! it as part of a read-only boot-consistency check that refuses the
//! first persistent write if external boot resources disagree with
//! the new root.
//!
//! We DO NOT reimplement any bootloader logic here. The module only
//! inspects the source snapshot's `/boot` and `/usr/lib/modules` and
//! reads the source fstab to discover separate `/boot`/ESP mounts.
//!
//! Boot detection runs against a real mounted snapshot path (the
//! btrfs toplevel mounted read-only inside a private namespace). We
//! use std::fs directly because the snapshot path is real; the
//! openat2 confinement in `probe::fs_probe` exists for hostile
//! unmounted targets, not for paths we ourselves just mounted.

use std::path::Path;

use crate::model::fstab::{FstabEntry, FstabEntryKind, FstabSource};
use crate::model::recovery::BootLayout;

/// Detect the boot layout of a mounted snapshot / root candidate.
///
/// `mounted_root` is the absolute path where the source snapshot (or
/// the current root, for inspect) is mounted. `fstab` is the parsed
/// fstab of that target.
pub fn detect_layout(mounted_root: &Path, fstab: &[FstabEntry]) -> BootLayout {
    let boot_inside_root = is_real_dir(&mounted_root.join("boot"));
    let mut boot_separate_filesystem = false;
    let mut boot_separate_subvolume = false;
    let mut esp_mount_point: Option<String> = None;
    let mut esp_device: Option<String> = None;

    for entry in fstab {
        match entry.kind {
            FstabEntryKind::Boot => {
                if entry.fstype == "btrfs" {
                    let subvol = entry
                        .options
                        .iter()
                        .any(|o| o.starts_with("subvol=") || o.starts_with("subvolid="));
                    if subvol {
                        boot_separate_subvolume = true;
                    } else {
                        boot_separate_filesystem = true;
                    }
                } else {
                    boot_separate_filesystem = true;
                }
            }
            _ => {
                if matches!(entry.target.as_str(), "/boot/efi" | "/efi" | "/boot")
                    && matches!(
                        entry.fstype.as_str(),
                        "vfat" | "fat" | "fat32" | "fat16" | "fat12"
                    )
                {
                    esp_mount_point = Some(entry.target.clone());
                    if let FstabSource::Path(p) = &entry.source {
                        esp_device = Some(p.clone());
                    }
                }
            }
        }
    }

    let mut uki_paths = Vec::new();
    let mut kernel_versions = Vec::new();
    let mut has_initramfs = false;

    if boot_inside_root {
        uki_paths = find_uki_files(mounted_root);
        kernel_versions = find_kernel_versions(mounted_root);
        has_initramfs = has_initramfs_files(mounted_root);
    }

    // The "boot inside root" flag is exclusive: if the fstab also
    // surfaces a separate /boot, we trust the fstab and demote.
    let boot_inside_root =
        boot_inside_root && !boot_separate_filesystem && !boot_separate_subvolume;

    BootLayout {
        boot_inside_root,
        boot_separate_filesystem,
        boot_separate_subvolume,
        esp_mount_point,
        esp_device,
        uki_paths,
        kernel_versions,
        has_initramfs,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (std::fs; the source snapshot is a real mounted path)
// ---------------------------------------------------------------------------

fn is_real_dir(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.is_dir() && !meta.file_type().is_symlink(),
        Err(_) => false,
    }
}

fn find_uki_files(root: &Path) -> Vec<String> {
    let mut uki = Vec::new();
    for top in ["boot/EFI", "EFI", "boot/efi/EFI", "efi/EFI"] {
        let abs = root.join(top);
        collect_uki_recursive(&abs, &mut uki, 0);
        if uki.len() >= 64 {
            return uki;
        }
    }
    uki
}

fn collect_uki_recursive(abs: &Path, out: &mut Vec<String>, depth: u32) {
    if depth > 4 || out.len() >= 64 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(abs) else {
        return;
    };
    for entry in entries.flatten().take(128) {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            collect_uki_recursive(&path, out, depth + 1);
            continue;
        }
        if meta.is_file() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name.ends_with(".efi") {
                    if let Some(s) = path.to_str() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
}

fn find_kernel_versions(root: &Path) -> Vec<String> {
    let path = root.join("usr/lib/modules");
    let Ok(entries) = std::fs::read_dir(&path) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Kernel dirs look like `6.1.0-arch1-1` or `5.15.80-1` —
            // version strings that begin with a digit and contain a
            // dot. We require the leading digit to disqualify
            // extraneous dirs like `extramodules`.
            if name.chars().next().is_some_and(|c| c.is_ascii_digit()) && name.contains('.') {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out.into_iter().take(32).collect()
}

fn has_initramfs_files(root: &Path) -> bool {
    let path = root.join("boot");
    let Ok(entries) = std::fs::read_dir(&path) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("initramfs-") || name.starts_with("initrd-"))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fstab::{FstabEntry, FstabEntryKind, FstabSource};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "catos-boot-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// `detect_layout` must downgrade `boot_inside_root=true` to false
    /// if the fstab ALSO surfaces a separate /boot. Guards against a
    /// plan that lies about what will happen to boot resources.
    #[test]
    fn detect_layout_demotes_inside_root_when_separate_fstab_exists() {
        let root = scratch("demote");
        std::fs::create_dir_all(root.join("boot")).unwrap();
        let fstab = vec![FstabEntry {
            source: FstabSource::Path("/dev/sda1".into()),
            target: "/boot".into(),
            fstype: "ext4".into(),
            options: vec!["defaults".into()],
            dump: 0,
            pass: 2,
            kind: FstabEntryKind::Boot,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let layout = detect_layout(&root, &fstab);
        assert!(!layout.boot_inside_root);
        assert!(layout.boot_separate_filesystem);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_layout_finds_uki_and_kernel_dirs() {
        let root = scratch("uki");
        std::fs::create_dir_all(root.join("boot/EFI/CatOS")).unwrap();
        std::fs::write(root.join("boot/EFI/CatOS/catos-linux.efi"), b"fake uki").unwrap();
        std::fs::create_dir_all(root.join("usr/lib/modules/6.1.0-arch1-1")).unwrap();
        std::fs::write(root.join("boot/initramfs-catOS.img"), b"initramfs").unwrap();
        let layout = detect_layout(&root, &[]);
        assert!(layout.boot_inside_root);
        assert!(layout.has_initramfs);
        assert!(layout
            .uki_paths
            .iter()
            .any(|p| p.ends_with("catos-linux.efi")));
        assert!(layout.kernel_versions.iter().any(|v| v == "6.1.0-arch1-1"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_layout_detects_esp_from_fstab() {
        let root = scratch("esp");
        std::fs::create_dir_all(root.join("boot/efi/EFI")).unwrap();
        let fstab = vec![FstabEntry {
            source: FstabSource::Path("/dev/nvme0n1p1".into()),
            target: "/boot/efi".into(),
            fstype: "vfat".into(),
            options: vec!["defaults".into()],
            dump: 0,
            pass: 2,
            kind: FstabEntryKind::OtherLocal,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let layout = detect_layout(&root, &fstab);
        assert_eq!(layout.esp_mount_point.as_deref(), Some("/boot/efi"));
        assert_eq!(layout.esp_device.as_deref(), Some("/dev/nvme0n1p1"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
