//! Mount target diagnosis + selection: the pure fstab/layout/device
//! reasoning shared by Doctor's mount section and `catos-repair mount`.
//!
//! This module is dependency-clean: it depends only on `catos-target` and
//! sibling Mount modules. The disk-touching observation path
//! (`observe_target_inputs`) that enumerates btrfs subvolumes via the
//! snapshot engine is deliberately NOT housed here — it stays in the
//! repair orchestration layer, because the `mount` capability must
//! not depend on the snapshot capability.

use std::collections::HashMap;
use std::path::Path;

use crate::diagnose::fstab::{parse_all_with_diagnostics, FstabEntry, FstabEntryKind, FstabSource};
use crate::diagnose::subvolume::{
    decide_all, history_from_entries, CatosConfirmation, SubvolDecision, SubvolFacts,
};
use crate::model::{CleanupReport, MountProblem, MountTargetIdentity};
use crate::plan::session::{probe_unmounted_candidates, SelectedTargetProbe};
use catos_target::diagnose::candidate::{device_matches_fstab_source, inspect_target};
use catos_target::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
use catos_target::diagnose::system_root::SystemRoot;
use catos_target::model::DetectionStatus;
use catos_target::model::Warning;
use catos_target::model::{
    BlockDevice, DeviceClass, EspCandidate, PartitionRole, RootCandidateConfidence,
};

// Re-export the layout helpers this module's callers reach for through
// the diagnose surface, so the old `super::{is_fat_fstype, ...}` paths
// resolve from a single place.
pub use crate::diagnose::layout::{
    detect_boot_mount_layout, is_fat_device, is_fat_fstype, same_device_records,
};

/// Inputs to [`diagnose`] / the mount-repair plan builder. Built by the
/// caller from the parsed fstab, the btrfs probe, and the device
/// discovery layer. Pure data so tests can construct it directly.
#[derive(Debug, Clone, Default)]
pub struct MountRepairInputs {
    /// Verbatim original fstab text.
    pub fstab_text: String,
    /// Target identity observed at plan time.
    pub target: MountTargetIdentity,
    /// Whether `/etc/os-release` (or equivalent) confirmed the
    /// target as CatOS.
    pub catos_confirmation: CatosConfirmation,
    /// Btrfs subvolume facts observed on the target root btrfs
    /// filesystem.
    pub subvol_facts: SubvolFacts,
    /// Mount-point directory observations, keyed by absolute path
    /// (e.g. `/home`, `/boot/efi`). Each entry describes whether
    /// the path exists, is a directory, is a symlink, etc.
    pub mount_point_observations: HashMap<String, MountPointObservation>,
}

/// What the probe saw at a mount-point path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MountPointObservation {
    pub exists: bool,
    pub is_symlink: bool,
    pub is_directory: bool,
    pub is_other_object: bool,
    pub entry_count: Option<usize>,
}

impl MountPointObservation {
    pub fn missing() -> Self {
        Self {
            exists: false,
            ..Default::default()
        }
    }
    pub fn directory(entry_count: usize) -> Self {
        Self {
            exists: true,
            is_directory: true,
            entry_count: Some(entry_count),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Pure fstab/mount diagnosis
// ---------------------------------------------------------------------------

/// Produce the same `MountProblem` list that Doctor's mount section and
/// `catos-repair mount` consume. Pure: a function of [`MountRepairInputs`]
/// alone, so the two surfaces cannot disagree.
pub fn diagnose(inputs: &MountRepairInputs) -> Vec<MountProblem> {
    let mut problems = Vec::new();
    let (entries, diagnostics) = parse_all_with_diagnostics(&inputs.fstab_text);
    for diag in &diagnostics {
        problems.push(MountProblem::UnparseableLine {
            line: diag.line,
            reason: format!("{:?}", diag.kind),
        });
    }

    // Root entry.
    let root_entries: Vec<&FstabEntry> = entries.iter().filter(|e| e.target == "/").collect();
    if root_entries.is_empty() {
        problems.push(MountProblem::MissingRootEntry);
    } else if root_entries.len() > 1 {
        problems.push(MountProblem::DuplicateMountPoint {
            mount_point: "/".into(),
        });
    } else if let Some(root) = root_entries.first() {
        // Verify UUID matches when both sides are known.
        if let (Some(expected), FstabSource::Uuid(actual)) =
            (inputs.target.root_uuid.as_ref(), &root.source)
        {
            if expected != actual {
                problems.push(MountProblem::RootUuidMismatch {
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
        }
        // Btrfs root must point at /@.
        if root.fstype == "btrfs" {
            let actual_subvol = root
                .options
                .iter()
                .find_map(|o| o.strip_prefix("subvol=").map(str::to_string));
            match actual_subvol {
                None => {
                    problems.push(MountProblem::RootWrongSubvol {
                        actual: "<missing>".into(),
                    });
                }
                Some(s) if s != "/@" => {
                    problems.push(MountProblem::RootWrongSubvol { actual: s });
                }
                _ => {}
            }
        }
    }

    // Standard CatOS entries exist only on Btrfs installations.
    if inputs.target.root_fstype == "btrfs" {
        for spec in crate::model::CATOS_STANDARD_SUBVOLS {
            if spec.mount_point == "/" {
                continue;
            }
            let matching: Vec<&FstabEntry> = entries
                .iter()
                .filter(|e| e.target == spec.mount_point)
                .collect();
            if matching.is_empty() {
                // Missing standard entry is a problem only on confirmed
                // CatOS targets OR when fstab history of subvol presence
                // suggests it should exist.
                if inputs.catos_confirmation == CatosConfirmation::Confirmed
                    || inputs
                        .subvol_facts
                        .find(spec.subvol)
                        .is_some_and(|o| o.exists_as_subvol)
                {
                    problems.push(MountProblem::MissingStandardEntry {
                        mount_point: spec.mount_point.to_string(),
                        subvol: spec.subvol.to_string(),
                    });
                }
                continue;
            }
            if matching.len() > 1 {
                problems.push(MountProblem::DuplicateMountPoint {
                    mount_point: spec.mount_point.to_string(),
                });
                continue;
            }
            let entry = matching[0];
            let actual_subvol = entry
                .options
                .iter()
                .find_map(|o| o.strip_prefix("subvol=").map(str::to_string));
            if entry.fstype == "btrfs" && actual_subvol.as_deref() != Some(spec.subvol) {
                if spec.mount_point == "/.snapshots" {
                    problems.push(MountProblem::SnapshotsWrongSubvol {
                        actual: actual_subvol.unwrap_or_default(),
                    });
                } else {
                    problems.push(MountProblem::StandardWrongSubvol {
                        mount_point: spec.mount_point.to_string(),
                        expected: spec.subvol.to_string(),
                        actual: actual_subvol.unwrap_or_default(),
                    });
                }
            }
        }
    }

    // ESP entry.
    diagnose_esp(&entries, inputs, &mut problems);

    // Swap entries: never modify, but flag obvious mis-typing.
    for entry in &entries {
        if entry.kind == FstabEntryKind::Swap && entry.fstype != "swap" {
            problems.push(MountProblem::SwapEntryMistyped);
        }
    }

    if inputs.target.root_fstype == "btrfs" {
        // Subvolume / mount-point presence (from the btrfs probe and
        // mount-point observations).
        let decisions = decide_all(
            &history_from_entries(&entries),
            &inputs.subvol_facts,
            inputs.catos_confirmation,
        );
        for decision in &decisions {
            match decision {
                SubvolDecision::AlreadyExists { .. }
                | SubvolDecision::Create { .. }
                | SubvolDecision::RefuseNoHistory { .. } => {}
                SubvolDecision::CreateWithDataConflict { subvol, .. } => {
                    problems.push(MountProblem::MissingSubvolume {
                        subvol: subvol.clone(),
                    });
                }
                SubvolDecision::RefuseOccupied { subvol, reason } => {
                    problems.push(MountProblem::UnsafeMountPoint {
                        mount_point: subvol.clone(),
                        reason: reason.clone(),
                    });
                }
            }
        }

        // Mount-point directory observations. Only flag missing /
        // unsafe mount points when the spec authorises caring about
        // them: confirmed CatOS target OR the fstab references the
        // mount point.
        let history = history_from_entries(&entries);
        for spec in crate::model::CATOS_STANDARD_SUBVOLS {
            if spec.mount_point == "/" {
                continue;
            }
            let authorised = inputs.catos_confirmation == CatosConfirmation::Confirmed
                || history.has_any_entry_for(spec.mount_point)
                || entries.iter().any(|e| e.target == spec.mount_point);
            if !authorised {
                continue;
            }
            let obs = inputs
                .mount_point_observations
                .get(spec.mount_point)
                .copied()
                .unwrap_or_else(MountPointObservation::missing);
            if !obs.exists {
                problems.push(MountProblem::MissingMountPoint {
                    mount_point: spec.mount_point.to_string(),
                });
            } else if obs.is_symlink {
                problems.push(MountProblem::UnsafeMountPoint {
                    mount_point: spec.mount_point.to_string(),
                    reason: "mount-point path is a symlink; refusing to follow".into(),
                });
            } else if obs.is_other_object {
                problems.push(MountProblem::UnsafeMountPoint {
                    mount_point: spec.mount_point.to_string(),
                    reason: "mount-point path is a non-directory object".into(),
                });
            }
        }
    }

    problems
}

pub fn diagnose_esp(
    entries: &[FstabEntry],
    inputs: &MountRepairInputs,
    problems: &mut Vec<MountProblem>,
) {
    let Some(layout) = inputs.target.boot_layout.as_ref() else {
        return;
    };
    let Some(esp_mount_point) = layout.esp_mount_point() else {
        return;
    };
    let matching: Vec<&FstabEntry> = entries
        .iter()
        .filter(|entry| entry.target == esp_mount_point)
        .collect();
    if matching.len() != 1 {
        problems.push(MountProblem::AmbiguousEsp {
            candidates: matching
                .iter()
                .map(|entry| format!("{}:{:?}", entry.target, entry.source))
                .collect(),
        });
        return;
    }
    let entry = matching[0];
    if !is_fat_fstype(&entry.fstype) {
        problems.push(MountProblem::EspMountPointMismatch {
            expected: esp_mount_point.to_string(),
            actual: format!("{} ({})", entry.target, entry.fstype),
        });
        return;
    }
    if let (Some(expected), FstabSource::Uuid(actual)) =
        (inputs.target.esp_uuid.as_ref(), &entry.source)
    {
        if actual != expected {
            problems.push(MountProblem::EspUuidMismatch {
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// CLI target selection helpers (pure device reasoning)
// ---------------------------------------------------------------------------

pub fn select_mount_repair_esp<'a>(
    devices: &'a [BlockDevice],
    fstab: &[FstabEntry],
    candidates: &[EspCandidate],
    explicit: Option<&str>,
) -> Result<Option<&'a BlockDevice>, String> {
    let candidate_for = |device: &BlockDevice| {
        let source = device.dev_path.as_deref();
        candidates
            .iter()
            .find(|candidate| source.is_some_and(|path| candidate.source == path.to_string_lossy()))
    };
    let valid = |device: &BlockDevice| {
        is_fat_device(device)
            && (matches!(device.partition_role, PartitionRole::Esp)
                || candidate_for(device)
                    .is_some_and(|candidate| candidate.signals.has_efi_directory))
    };

    if let Some(requested) = explicit {
        let device = devices
            .iter()
            .find(|device| {
                device
                    .dev_path
                    .as_deref()
                    .is_some_and(|path| same_block_device(path, Path::new(requested)))
            })
            .ok_or_else(|| "explicit ESP is not a discovered block device".to_string())?;
        if !valid(device) {
            return Err(
                "explicit ESP must be FAT and have GPT ESP type or an EFI directory".into(),
            );
        }
        return Ok(Some(device));
    }

    let esp_entries: Vec<&FstabEntry> = fstab
        .iter()
        .filter(|entry| {
            matches!(entry.target.as_str(), "/boot/efi" | "/efi")
                || (entry.target == "/boot" && is_fat_fstype(&entry.fstype))
        })
        .collect();
    if esp_entries.len() > 1 {
        return Err("target fstab contains multiple ESP mount entries".into());
    }
    if let Some(entry) = esp_entries.first() {
        let resolved: Vec<&BlockDevice> = devices
            .iter()
            .filter(|device| device_matches_fstab_source(device, &entry.source))
            .filter(|device| valid(device))
            .collect();
        match resolved.as_slice() {
            [device] => return Ok(Some(*device)),
            [] => {
                let probed: Vec<&BlockDevice> = devices
                    .iter()
                    .filter(|device| valid(device))
                    .filter(|device| {
                        candidate_for(device).is_some_and(|candidate| {
                            candidate.confidence == RootCandidateConfidence::High
                        })
                    })
                    .collect();
                return match probed.as_slice() {
                    [device] => Ok(Some(*device)),
                    [] => Err(format!(
                        "ESP entry {} is stale and no validated ESP candidate exists",
                        entry.target
                    )),
                    _ => {
                        Err("ESP entry is stale and multiple validated ESP candidates exist".into())
                    }
                };
            }
            _ => return Err("ESP fstab source resolves to multiple devices".into()),
        }
    }

    // No ESP entry means the layout may genuinely be BIOS/boot-inside-root.
    Ok(None)
}

pub fn select_cli_root<'a>(
    devices: &'a [BlockDevice],
    root_device: Option<&str>,
) -> Option<&'a BlockDevice> {
    select_cli_root_with_cleanup(devices, root_device).0
}

/// Select a CLI root while preserving cleanup from any temporary automatic
/// discovery probes. Write-capable callers must inspect every cleanup report
/// before proceeding.
pub fn select_cli_root_with_cleanup<'a>(
    devices: &'a [BlockDevice],
    root_device: Option<&str>,
) -> (Option<&'a BlockDevice>, Vec<CleanupReport>) {
    match root_device {
        Some(requested) => (
            devices.iter().find(|device| {
                device
                    .dev_path
                    .as_ref()
                    .is_some_and(|path| same_block_device(path, Path::new(requested)))
                    && supported_mount_repair_root(device.filesystem.as_deref())
                    && (!device.mounted_before_session || is_running_root_device(device))
            }),
            Vec::new(),
        ),
        None => {
            if let Some(running) = auto_select_running_root(devices) {
                return (Some(running), Vec::new());
            }
            let probes = probe_unmounted_candidates(devices, &[]);
            let cleanup = probes.cleanup;
            if cleanup.iter().any(|report| !report.all_clean) {
                return (None, cleanup);
            }
            (
                auto_select_cli_root_from_candidates(devices, &probes.roots),
                cleanup,
            )
        }
    }
}

pub fn is_running_root_device(device: &BlockDevice) -> bool {
    device.mount_point.as_deref() == Some(Path::new("/"))
        || device
            .mounts
            .iter()
            .any(|mount| mount.mount_point == Path::new("/"))
}

pub fn auto_select_running_root(devices: &[BlockDevice]) -> Option<&BlockDevice> {
    let os_release = std::fs::read_to_string("/etc/os-release").ok()?;
    let is_catos = os_release.lines().any(|line| {
        line.trim()
            .strip_prefix("ID=")
            .is_some_and(|value| value.trim_matches(['\"', '\'']) == "catos")
    });
    if !is_catos {
        return None;
    }
    let fstab_text = std::fs::read_to_string("/etc/fstab").ok()?;
    let (fstab, diagnostics) = parse_all_with_diagnostics(&fstab_text);
    if !diagnostics.is_empty() {
        return None;
    }
    let root_entries: Vec<&FstabEntry> = fstab.iter().filter(|entry| entry.target == "/").collect();
    let [root_entry] = root_entries.as_slice() else {
        return None;
    };
    let matches: Vec<&BlockDevice> = devices
        .iter()
        .filter(|device| is_running_root_device(device))
        .filter(|device| supported_mount_repair_root(device.filesystem.as_deref()))
        .filter(|device| device_matches_fstab_source(device, &root_entry.source))
        .collect();
    match matches.as_slice() {
        [device] => Some(*device),
        _ => None,
    }
}

pub fn inspect_running_root() -> Result<SelectedTargetProbe, String> {
    let root = SystemRoot::from_user_input("/").map_err(|error| error.to_string())?;
    let fs = RealFilesystem;
    let fstab_text = fs
        .rooted_read_to_string(root.canonical_path(), Path::new("etc/fstab"))
        .map_err(|error| format!("cannot read running-system fstab: {error}"))?;
    let (fstab, diagnostics) = parse_all_with_diagnostics(&fstab_text);
    let mut warning_strings = Vec::new();
    let inspection = inspect_target(&fs, &root, &mut warning_strings);
    let mut warnings = diagnostics
        .into_iter()
        .map(|diagnostic| {
            Warning::new(
                "FSTAB_PARSE_ERROR",
                format!(
                    "running-system fstab line {} is invalid ({:?}): {}",
                    diagnostic.line, diagnostic.kind, diagnostic.text
                ),
            )
        })
        .collect::<Vec<_>>();
    warnings.extend(
        warning_strings
            .into_iter()
            .map(|message| Warning::new("TARGET_INSPECTION_WARNING", message)),
    );
    Ok(SelectedTargetProbe {
        fstab,
        inspection,
        cleanup: crate::model::CleanupReport {
            all_clean: true,
            ..Default::default()
        },
        warnings,
    })
}

pub fn auto_select_cli_root(devices: &[BlockDevice]) -> Option<&BlockDevice> {
    let (selected, cleanup) = select_cli_root_with_cleanup(devices, None);
    cleanup
        .iter()
        .all(|report| report.all_clean)
        .then_some(selected)
        .flatten()
}

fn auto_select_cli_root_from_candidates<'a>(
    devices: &'a [BlockDevice],
    roots: &[catos_target::model::RootCandidate],
) -> Option<&'a BlockDevice> {
    let candidates: Vec<&str> = roots
        .iter()
        .filter(|root| {
            supported_mount_repair_root(root.filesystem.as_deref())
                && (root.filesystem.as_deref() != Some("btrfs")
                    || root.subvolume.as_deref() == Some("/@"))
                && root.confidence == RootCandidateConfidence::High
                && root.is_catos.status == DetectionStatus::Detected
                && root
                    .evidence
                    .iter()
                    .any(|evidence| evidence.code == "FSTAB_ROOT_MATCH")
        })
        .map(|root| root.source.as_str())
        .collect();
    match candidates.as_slice() {
        [source] => devices.iter().find(|device| {
            device.dev_path.as_deref() == Some(Path::new(source))
                && !device.mounted_before_session
                && !device.removable
                && device.class != DeviceClass::Disk
                && device.partition_role != PartitionRole::WholeDisk
        }),
        _ => None,
    }
}

pub fn supported_mount_repair_root(fstype: Option<&str>) -> bool {
    matches!(
        fstype,
        Some("btrfs" | "ext2" | "ext3" | "ext4" | "xfs" | "f2fs")
    )
}

pub fn same_block_device(discovered: &Path, requested: &Path) -> bool {
    if discovered == requested {
        return true;
    }
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match (std::fs::metadata(discovered), std::fs::metadata(requested)) {
        (Ok(left), Ok(right)) => {
            left.file_type().is_block_device()
                && right.file_type().is_block_device()
                && left.rdev() == right.rdev()
        }
        _ => false,
    }
}

pub fn target_rooted_path(target: &MountTargetIdentity, path: &str) -> String {
    let suffix = path.trim_start_matches('/');
    match target.root_subvol.as_deref() {
        Some(subvolume) => format!("{}/{}", subvolume.trim_end_matches('/'), suffix),
        None => format!("/{suffix}"),
    }
}

// `observe_target_inputs` intentionally lives in the repair orchestration
// layer: it enumerates btrfs subvolumes via the snapshot engine, which
// the `mount` capability is forbidden from depending on (stage-4 will
// route that call through `catos_target::execute::confined`).
