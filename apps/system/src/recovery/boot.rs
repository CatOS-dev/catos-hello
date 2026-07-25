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

use crate::model::fstab::{FstabEntry, FstabSource};
use crate::model::recovery::{
    BootConsistencyReport, BootConsistencyStatus, BootLayout, RecoveryError, RecoveryErrorKind,
};

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
        let is_fat = matches!(
            entry.fstype.as_str(),
            "vfat" | "fat" | "fat32" | "fat16" | "fat12"
        );
        if matches!(entry.target.as_str(), "/boot/efi" | "/efi")
            || (entry.target == "/boot" && is_fat)
        {
            esp_mount_point = Some(entry.target.clone());
            esp_device = Some(fstab_source_string(&entry.source));
        }

        // An ESP below /boot does not mean the /boot directory itself
        // is external. Only an entry mounted exactly at /boot changes
        // whether the root exchange covers /boot.
        if entry.target != "/boot" {
            continue;
        }
        if entry.fstype == "btrfs"
            && entry
                .options
                .iter()
                .any(|option| option.starts_with("subvol=") || option.starts_with("subvolid="))
        {
            boot_separate_subvolume = true;
        } else {
            boot_separate_filesystem = true;
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

/// Derive the phase-3 boot gate from metadata observed through a
/// read-only target mount. The check is deliberately conservative: a
/// root-only exchange is supported only when every observed boot
/// resource lives inside the root subvolume.
pub fn evaluate_readonly_consistency(layout: &BootLayout) -> BootConsistencyReport {
    let external_boot = layout.boot_separate_filesystem || layout.boot_separate_subvolume;
    let external_esp = layout.esp_mount_point.is_some() || layout.esp_device.is_some();
    let mut reasons = Vec::new();

    let (status, root_switch_covers_all_boot_resources) = if external_boot || external_esp {
        if layout.boot_separate_filesystem {
            reasons.push(
                "/boot is a separate filesystem and is not covered by the root exchange".into(),
            );
        }
        if layout.boot_separate_subvolume {
            reasons.push(
                "/boot is a separate btrfs subvolume and is not covered by the root exchange"
                    .into(),
            );
        }
        if external_esp {
            reasons.push(
                "the ESP is outside the root subvolume and phase 3 performs no ESP writes".into(),
            );
        }
        (BootConsistencyStatus::Unsupported, false)
    } else if layout.boot_inside_root {
        reasons.push("all observed boot resources move with the root subvolume exchange".into());
        (BootConsistencyStatus::Consistent, true)
    } else {
        reasons.push(
            "no authoritative root-contained or external boot topology was established".into(),
        );
        (BootConsistencyStatus::Unknown, false)
    };

    BootConsistencyReport {
        status,
        checked_read_only: true,
        root_switch_covers_all_boot_resources,
        external_boot,
        external_esp,
        reasons,
    }
}

/// Refuse the first persistent recovery write unless the read-only
/// report proves that the root exchange covers all boot resources.
pub fn require_boot_consistency(report: &BootConsistencyReport) -> Result<(), RecoveryError> {
    match report.status {
        BootConsistencyStatus::Consistent
            if report.checked_read_only && report.root_switch_covers_all_boot_resources =>
        {
            Ok(())
        }
        BootConsistencyStatus::Inconsistent => Err(RecoveryError::new(
            RecoveryErrorKind::BootConsistencyInconsistent,
            format!(
                "boot resources are inconsistent: {}",
                report.reasons.join("; ")
            ),
        )),
        BootConsistencyStatus::Unsupported => Err(RecoveryError::new(
            RecoveryErrorKind::UnsupportedExternalBootLayout,
            format!(
                "external boot resources are not supported by root-only recovery: {}",
                report.reasons.join("; ")
            ),
        )),
        BootConsistencyStatus::Unknown | BootConsistencyStatus::Consistent => {
            Err(RecoveryError::new(
                RecoveryErrorKind::BootConsistencyUnknown,
                format!(
                    "boot consistency was not established safely: {}",
                    report.reasons.join("; ")
                ),
            ))
        }
    }
}

fn fstab_source_string(source: &FstabSource) -> String {
    match source {
        FstabSource::Uuid(value) => format!("UUID={value}"),
        FstabSource::PartUuid(value) => format!("PARTUUID={value}"),
        FstabSource::Label(value) => format!("LABEL={value}"),
        FstabSource::PartLabel(value) => format!("PARTLABEL={value}"),
        FstabSource::Path(value) | FstabSource::Pseudo(value) => value.clone(),
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
            kind: FstabEntryKind::Boot,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let layout = detect_layout(&root, &fstab);
        assert_eq!(layout.esp_mount_point.as_deref(), Some("/boot/efi"));
        assert_eq!(layout.esp_device.as_deref(), Some("/dev/nvme0n1p1"));
        assert!(
            !layout.boot_separate_filesystem,
            "an ESP mounted below /boot must not imply that /boot itself is separate"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn readonly_consistency_accepts_only_root_contained_boot_resources() {
        let report = evaluate_readonly_consistency(&BootLayout {
            boot_inside_root: true,
            kernel_versions: vec!["6.12.1-catos".into()],
            has_initramfs: true,
            ..BootLayout::default()
        });
        assert_eq!(
            report.status,
            crate::model::recovery::BootConsistencyStatus::Consistent
        );
        assert!(report.checked_read_only);
        assert!(report.root_switch_covers_all_boot_resources);
        require_boot_consistency(&report).unwrap();
    }

    #[test]
    fn readonly_consistency_refuses_external_boot_and_esp() {
        for layout in [
            BootLayout {
                boot_separate_filesystem: true,
                ..BootLayout::default()
            },
            BootLayout {
                boot_separate_subvolume: true,
                ..BootLayout::default()
            },
            BootLayout {
                boot_inside_root: true,
                esp_mount_point: Some("/boot/efi".into()),
                esp_device: Some("/dev/nvme0n1p1".into()),
                ..BootLayout::default()
            },
        ] {
            let report = evaluate_readonly_consistency(&layout);
            assert_eq!(
                report.status,
                crate::model::recovery::BootConsistencyStatus::Unsupported
            );
            let error = require_boot_consistency(&report).unwrap_err();
            assert_eq!(
                error.kind,
                crate::model::recovery::RecoveryErrorKind::UnsupportedExternalBootLayout
            );
        }
    }

    #[test]
    fn readonly_consistency_fails_closed_when_boot_topology_is_unknown() {
        let report = evaluate_readonly_consistency(&BootLayout::default());
        assert_eq!(
            report.status,
            crate::model::recovery::BootConsistencyStatus::Unknown
        );
        let error = require_boot_consistency(&report).unwrap_err();
        assert_eq!(
            error.kind,
            crate::model::recovery::RecoveryErrorKind::BootConsistencyUnknown
        );
    }
}
