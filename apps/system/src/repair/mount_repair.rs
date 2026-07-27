//! `catos-repair mount` orchestrator: turn fstab + btrfs facts +
//! target identity into an immutable [`MountRepairPlan`] and (when
//! authorised) into a [`MountRepairReport`].
//!
//! ## What this module owns
//!
//! * Pure diagnosis: [`diagnose`] builds the same list of
//!   [`MountProblem`]s that Doctor's future mount check will produce.
//! * Plan construction: [`build_plan`] combines the diagnosis with
//!   [`crate::repair::subvol_decision`] and an [`crate::repair::fstab_edit`]
//!   plan to produce an immutable [`MountRepairPlan`] bound to a
//!   [`TargetIdentity`] and an [`FstabDigest`].
//! * Identity drift detection: [`detect_drift`] compares the plan's
//!   bound identity/digest to a freshly-observed snapshot and
//!   returns the matching `MountRepairOutcome`.
//! * In-memory apply: [`apply_in_memory`] runs the plan's fstab
//!   edits against the verbatim original text and verifies the new
//!   text parses. This is what the higher layer runs *before*
//!   writing to disk, so we never write a fstab we cannot re-parse.
//!
//! ## What this module does NOT own
//!
//! * It does not touch disk. The privileged layer (separate) does
//!   the atomic-replace dance and the private-namespace verification
//!   mount.
//! * It does not invoke any external tool.
//! * It does not mount or unmount anything.
//! * It does not acquire locks; the caller is responsible for
//!   taking the per-FSID lock (compatible with the recovery lock)
//!   before calling the privileged apply layer.
//!
//! ## Diagnosis ⇄ repair agreement
//!
//! Doctor's future `mount::diagnose(...)` MUST call [`diagnose`] so
//! the two surfaces cannot disagree. The spec is explicit:
//!
//! > 不要出现：Doctor 认为 fstab 正常；catos-repair mount 又认为
//! > 同一条目错误；或者反过来。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::shared::model::evidence::Evidence;
use crate::shared::model::fstab::FstabSource;
use crate::shared::model::inspection::Warning;
use crate::shared::model::mount_repair::{
    default_mount_options, AppliedAction, BootMountLayout, FstabDigest, FstabTransaction,
    MountProblem, MountRepairCleanup, MountRepairOutcome, MountRepairPlan, MountRepairReport,
    MountVerification, PlannedDirectory, PlannedFstabEdit, PlannedSubvolume, TargetIdentity,
};
use crate::shared::model::recovery::{CleanupSummary, RecoveryError, RecoveryErrorKind};
use crate::shared::model::runtime::DetectionStatus;
use crate::shared::model::storage::{
    BlockDevice, DeviceClass, EspCandidate, PartitionRole, RootCandidateConfidence,
};
use crate::shared::mount::namespace;
use crate::shared::mount::plan::{build_plan as build_mount_plan, PlanInputs};
use crate::shared::mount::probe::{inspect_selected_root, probe_unmounted_candidates, SelectedTargetProbe};
use crate::shared::mount::session::Session;
use crate::shared::mount::syscall::{self, ms_flags};
use crate::shared::parse::fstab::{parse_all_with_diagnostics, FstabEntry, FstabEntryKind};
use crate::shared::probe::candidate::device_matches_fstab_source;
use crate::shared::probe::discover_devices;
use crate::shared::probe::fs_probe::{FilesystemProbe, RealFilesystem};
use crate::shared::snapshot_engine::confined;
use crate::shared::snapshot_engine::external as btrfs;
use crate::shared::snapshot_engine::lock::DeviceLock;
use crate::repair::fstab_edit::apply_edits;
use crate::repair::path_safety::{validate_directory_creation, PathObservation};
use crate::repair::subvol_decision::{
    decide_all, history_from_entries, CatosConfirmation, SubvolDecision, SubvolFacts,
};
use crate::shared::system_root::SystemRoot;

/// Inputs to [`diagnose`] / [`build_plan`]. Built by the caller
/// from the parsed fstab, the btrfs probe, and the device discovery
/// layer. Pure data so tests can construct it directly.
#[derive(Debug, Clone, Default)]
pub struct MountRepairInputs {
    /// Verbatim original fstab text.
    pub fstab_text: String,
    /// Target identity observed at plan time.
    pub target: TargetIdentity,
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

/// Detect one of the six supported `/boot` and ESP layouts from the target's
/// own fstab plus already-discovered devices. `selected_esp` is either an
/// explicitly validated ESP or the unique ESP selected from probe evidence;
/// this function never guesses among candidates.
pub fn detect_boot_mount_layout(
    fstab: &[FstabEntry],
    devices: &[BlockDevice],
    root_device: &Path,
    selected_esp: Option<&Path>,
) -> Result<BootMountLayout, String> {
    let entries_at = |target: &str| -> Vec<&FstabEntry> {
        fstab
            .iter()
            .filter(|entry| entry.target == target)
            .collect()
    };
    for target in ["/boot", "/boot/efi", "/efi"] {
        if entries_at(target).len() > 1 {
            return Err(format!("multiple fstab entries target {target}"));
        }
    }

    let boot_entry = entries_at("/boot").into_iter().next();
    let boot_efi_entry = entries_at("/boot/efi").into_iter().next();
    let efi_entry = entries_at("/efi").into_iter().next();

    let fat_entry = |entry: &FstabEntry| is_fat_fstype(&entry.fstype);
    let nested_esp_entries: Vec<(&str, &FstabEntry)> =
        [("/boot/efi", boot_efi_entry), ("/efi", efi_entry)]
            .into_iter()
            .filter_map(|(target, entry)| {
                entry
                    .filter(|entry| fat_entry(entry))
                    .map(|entry| (target, entry))
            })
            .collect();
    if nested_esp_entries.len() > 1 {
        return Err("both /boot/efi and /efi are configured as ESP mounts".into());
    }

    let resolve = |entry: &FstabEntry| -> Result<&BlockDevice, String> {
        let matches: Vec<&BlockDevice> = devices
            .iter()
            .filter(|device| device_matches_fstab_source(device, &entry.source))
            .collect();
        match matches.as_slice() {
            [device] => Ok(*device),
            [] => Err(format!(
                "fstab source for {} does not resolve to a discovered device",
                entry.target
            )),
            _ => Err(format!(
                "fstab source for {} resolves to multiple devices",
                entry.target
            )),
        }
    };

    let selected_esp_device = match selected_esp {
        Some(path) => Some(
            devices
                .iter()
                .find(|device| {
                    device
                        .dev_path
                        .as_deref()
                        .is_some_and(|candidate| same_block_device(candidate, path))
                })
                .ok_or_else(|| "selected ESP is not a discovered block device".to_string())?,
        ),
        None => None,
    };
    if let Some(device) = selected_esp_device {
        if !is_fat_device(device) {
            return Err("selected ESP is not a FAT filesystem".into());
        }
    }

    let nested_esp = match nested_esp_entries.as_slice() {
        [] => None,
        [(mount_point, entry)] => {
            let resolved = match resolve(entry) {
                Ok(device) => device,
                Err(_) => selected_esp_device.ok_or_else(|| {
                    format!("{mount_point} source is stale and no unique ESP was selected")
                })?,
            };
            if !is_fat_device(resolved) {
                return Err(format!(
                    "{mount_point} does not resolve to a FAT filesystem"
                ));
            }
            if let Some(selected) = selected_esp_device {
                if !same_device_records(resolved, selected) {
                    return Err(format!(
                        "{mount_point} resolves to a different device than the selected ESP"
                    ));
                }
            }
            Some((*mount_point, resolved))
        }
        _ => unreachable!(),
    };

    if let Some(entry) = boot_entry {
        let boot_device = if is_fat_fstype(&entry.fstype) {
            match resolve(entry) {
                Ok(device) => device,
                Err(_) => selected_esp_device.ok_or_else(|| {
                    "direct /boot ESP source is stale and no unique ESP was selected".to_string()
                })?,
            }
        } else {
            resolve(entry)?
        };
        if is_fat_fstype(&entry.fstype) {
            if nested_esp.is_some() {
                return Err(
                    "direct /boot ESP conflicts with an additional nested ESP entry".into(),
                );
            }
            if !is_fat_device(boot_device) {
                return Err("direct /boot ESP does not resolve to a FAT filesystem".into());
            }
            if let Some(selected) = selected_esp_device {
                if !same_device_records(boot_device, selected) {
                    return Err("direct /boot entry does not match the selected ESP".into());
                }
            }
            let esp_device = boot_device
                .dev_path
                .clone()
                .ok_or_else(|| "direct /boot ESP has no stable device path".to_string())?;
            return Ok(BootMountLayout::EspAtBoot { esp_device });
        }

        if entry.fstype == "btrfs"
            && boot_device
                .dev_path
                .as_deref()
                .is_some_and(|path| same_block_device(path, root_device))
        {
            let subvolume = entry
                .options
                .iter()
                .find_map(|option| option.strip_prefix("subvol=").map(str::to_string))
                .ok_or_else(|| "separate Btrfs /boot entry has no subvol= selector".to_string())?;
            if subvolume == "/@" {
                return Err("/boot cannot reuse the root subvolume /@".into());
            }
            return Ok(BootMountLayout::BootBtrfsSubvolume {
                subvolume,
                esp_device: nested_esp
                    .and_then(|(_, device)| device.dev_path.clone())
                    .or_else(|| selected_esp_device.and_then(|device| device.dev_path.clone())),
                esp_mount_point: nested_esp.map(|(mount_point, _)| mount_point.to_string()),
            });
        }

        let Some((esp_mount_point, esp_device)) = nested_esp else {
            return Err(
                "a separate ordinary /boot filesystem requires a separate ESP entry".into(),
            );
        };
        let boot_path = boot_device
            .dev_path
            .clone()
            .ok_or_else(|| "separate /boot filesystem has no stable device path".to_string())?;
        let esp_path = esp_device
            .dev_path
            .clone()
            .ok_or_else(|| "ESP has no stable device path".to_string())?;
        return Ok(BootMountLayout::SeparateBootAndEsp {
            boot_device: boot_path,
            esp_device: esp_path,
            esp_mount_point: esp_mount_point.to_string(),
        });
    }

    match nested_esp {
        Some(("/boot/efi", device)) => Ok(BootMountLayout::EspAtBootEfi {
            esp_device: device
                .dev_path
                .clone()
                .ok_or_else(|| "ESP has no stable device path".to_string())?,
        }),
        Some(("/efi", device)) => Ok(BootMountLayout::EspAtEfi {
            esp_device: device
                .dev_path
                .clone()
                .ok_or_else(|| "ESP has no stable device path".to_string())?,
        }),
        Some((mount_point, _)) => Err(format!("unsupported ESP mount point {mount_point}")),
        None if selected_esp_device.is_some() => {
            Err("an ESP was selected but target fstab does not establish its mount point".into())
        }
        None => Ok(BootMountLayout::BootInsideRoot),
    }
}

fn is_fat_fstype(fstype: &str) -> bool {
    matches!(fstype, "vfat" | "fat" | "fat32" | "fat16" | "fat12")
}

fn is_fat_device(device: &BlockDevice) -> bool {
    device.filesystem.as_deref().is_some_and(is_fat_fstype)
}

fn same_device_records(left: &BlockDevice, right: &BlockDevice) -> bool {
    match (left.dev_path.as_deref(), right.dev_path.as_deref()) {
        (Some(left), Some(right)) => same_block_device(left, right),
        _ => left.major_minor.is_some() && left.major_minor == right.major_minor,
    }
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

/// Read-only diagnosis. Reused verbatim by Doctor's future mount
/// check.
///
/// Order of operations:
///   1. Parse fstab, capturing unparseable-line problems.
///   2. Check root entry exists and resolves to the target device.
///   3. For every CatOS standard mount point, check the matching
///      entry exists and points at the matching subvol.
///   4. Check ESP entry when an ESP is identified.
///   5. Surface duplicate mount-point entries.
///   6. Surface missing subvolumes / missing mount points from the
///      btrfs probe.
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
        for spec in crate::shared::model::mount_repair::CATOS_STANDARD_SUBVOLS {
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
        // mount point. We do NOT diagnose "missing /home" on a random
        // non-Catos target whose fstab never mentioned /home.
        let history = history_from_entries(&entries);
        for spec in crate::shared::model::mount_repair::CATOS_STANDARD_SUBVOLS {
            // `/` is the target root itself; if we are running diagnosis
            // on it, it exists. We never create `/` via mkdir, so do not
            // flag it as missing.
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

fn diagnose_esp(
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

/// Build the immutable repair plan from inputs.
///
/// The plan binds to:
/// * the target identity (so apply can detect device drift);
/// * the fstab digest (so apply can detect fstab drift);
/// * the diagnosis (so the user can audit what we intended to fix).
pub fn build_plan(inputs: &MountRepairInputs) -> MountRepairPlan {
    let problems = diagnose(inputs);
    let fstab_digest = digest_of(&inputs.fstab_text);
    let (entries, _diagnostics) = parse_all_with_diagnostics(&inputs.fstab_text);
    let fstab_edits = build_fstab_edits(inputs, &problems);
    let subvolumes = build_subvol_plan(&entries, inputs);
    let directories = build_directory_plan(inputs);
    let unresolved_conflicts = collect_conflicts(&problems);
    let risks = collect_risks(&problems, &subvolumes);

    MountRepairPlan {
        target: inputs.target.clone(),
        fstab_digest,
        problems,
        fstab_edits,
        subvolumes,
        directories,
        unresolved_conflicts,
        risks,
    }
}

pub(super) fn digest_of(text: &str) -> FstabDigest {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in hash {
        hex.push_str(&format!("{byte:02x}"));
    }
    FstabDigest {
        sha256: hex,
        byte_len: text.len() as u64,
    }
}

fn build_fstab_edits(
    inputs: &MountRepairInputs,
    problems: &[MountProblem],
) -> Vec<PlannedFstabEdit> {
    let mut edits = Vec::new();
    let entries_with_lines = parse_with_lines(&inputs.fstab_text);
    let entries: Vec<&FstabEntry> = entries_with_lines.iter().map(|(e, _)| e).collect();

    // Root UUID / subvol fixes. Only a root problem can rewrite `/`.
    for (entry, line) in &entries_with_lines {
        if entry.target != "/" {
            continue;
        }
        let line = *line;
        // Wrong UUID: replace source.
        if let Some(expected) = inputs.target.root_uuid.as_ref() {
            if let FstabSource::Uuid(actual) = &entry.source {
                if actual != expected {
                    edits.push(PlannedFstabEdit::ReplaceSource {
                        line,
                        new_source: format!("UUID={expected}"),
                        reason: format!(
                            "root UUID {actual} does not match discovered device ({expected})"
                        ),
                    });
                }
            }
        }
        // Wrong subvol on btrfs root.
        if entry.fstype == "btrfs"
            && problems
                .iter()
                .any(|p| matches!(p, MountProblem::RootWrongSubvol { .. }))
        {
            let source = inputs
                .target
                .root_uuid
                .as_ref()
                .map(|uuid| format!("UUID={uuid}"));
            edits.push(PlannedFstabEdit::ReplaceEntry {
                line,
                new_line: entry_with_subvol(entry, "/@", source.as_deref()),
                reason: "root subvol must be /@ per CatOS standard layout".into(),
            });
        }
    }

    // Correct existing non-root standard entries in place. Retain their
    // source, non-subvolume options, dump and pass fields.
    for (entry, line) in &entries_with_lines {
        let Some(expected) =
            crate::shared::model::mount_repair::standard_subvol_for_mount_point(&entry.target)
        else {
            continue;
        };
        if entry.target == "/" || entry.fstype != "btrfs" {
            continue;
        }
        let wrong_standard_subvol = problems.iter().any(|problem| matches!(problem,
            MountProblem::StandardWrongSubvol { mount_point, .. } if mount_point == &entry.target
        ));
        let wrong_snapshots_subvol = entry.target == "/.snapshots"
            && problems
                .iter()
                .any(|problem| matches!(problem, MountProblem::SnapshotsWrongSubvol { .. }));
        if wrong_standard_subvol || wrong_snapshots_subvol {
            edits.push(PlannedFstabEdit::ReplaceEntry {
                line: *line,
                new_line: entry_with_subvol(entry, expected, None),
                reason: format!("{} must use subvol={expected}", entry.target),
            });
        }
    }

    // Missing standard entries: append.
    for spec in crate::shared::model::mount_repair::CATOS_STANDARD_SUBVOLS {
        if spec.mount_point == "/" {
            continue;
        }
        let already = entries.iter().any(|e| e.target == spec.mount_point);
        let problem_present = problems.iter().any(|p| match p {
            MountProblem::MissingStandardEntry { mount_point, .. } => {
                mount_point == spec.mount_point
            }
            _ => false,
        });
        if !already && problem_present {
            let root_source = inputs
                .target
                .root_uuid
                .as_ref()
                .map(|uuid| format!("UUID={uuid}"))
                .or_else(|| {
                    entries
                        .iter()
                        .find(|e| e.target == "/")
                        .map(|e| source_column_string(&e.source))
                });
            let Some(root_source) = root_source else {
                continue;
            };
            let opts = default_mount_options("btrfs").unwrap_or("defaults");
            edits.push(PlannedFstabEdit::AppendEntry {
                new_line: format!(
                    "{root_source}  {mp}  btrfs  {opts},subvol={subvol}  0 0",
                    mp = spec.mount_point,
                    subvol = spec.subvol,
                ),
                reason: format!(
                    "missing CatOS standard entry for {mp} → {subvol}",
                    mp = spec.mount_point,
                    subvol = spec.subvol,
                ),
            });
        }
    }

    // ESP source fix. Only the mount point identified by the detected
    // topology is an ESP; a separate ordinary `/boot` entry must never be
    // rewritten to the ESP UUID.
    if let (Some(esp_uuid), Some(esp_mount_point)) = (
        inputs.target.esp_uuid.as_ref(),
        inputs
            .target
            .boot_layout
            .as_ref()
            .and_then(BootMountLayout::esp_mount_point),
    ) {
        for (entry, line) in &entries_with_lines {
            if entry.target != esp_mount_point || !is_fat_fstype(&entry.fstype) {
                continue;
            }
            let already_correct =
                matches!(&entry.source, FstabSource::Uuid(actual) if actual == esp_uuid);
            if already_correct {
                continue;
            }
            edits.push(PlannedFstabEdit::ReplaceSource {
                line: *line,
                new_source: format!("UUID={esp_uuid}"),
                reason: format!("ESP source does not match discovered device ({esp_uuid})"),
            });
        }
    }

    dedupe_edits(edits)
}

fn entry_with_subvol(entry: &FstabEntry, subvol: &str, source_override: Option<&str>) -> String {
    let source = source_override
        .map(str::to_owned)
        .unwrap_or_else(|| source_column_string(&entry.source));
    let mut options: Vec<String> = entry
        .options
        .iter()
        .filter(|option| !option.starts_with("subvol=") && !option.starts_with("subvolid="))
        .cloned()
        .collect();
    options.push(format!("subvol={subvol}"));
    format!(
        "{}  {}  {}  {}  {} {}",
        source,
        entry.target,
        entry.fstype,
        options.join(","),
        entry.dump,
        entry.pass,
    )
}

fn source_column_string(source: &FstabSource) -> String {
    match source {
        FstabSource::Uuid(v) => format!("UUID={v}"),
        FstabSource::PartUuid(v) => format!("PARTUUID={v}"),
        FstabSource::Label(v) => format!("LABEL={v}"),
        FstabSource::PartLabel(v) => format!("PARTLABEL={v}"),
        FstabSource::Path(v) => v.clone(),
        FstabSource::Pseudo(v) => v.clone(),
    }
}

/// Parse the verbatim fstab text and return each entry paired
/// with its 1-based file line number. The phase-2 parser drops
/// comments and blanks, so a parsed entry's Vec index does NOT
/// equal its file line — building a plan against Vec indices would
/// silently target the wrong physical line.
fn parse_with_lines(fstab_text: &str) -> Vec<(FstabEntry, usize)> {
    let mut out = Vec::new();
    for (idx, line) in fstab_text.lines().enumerate() {
        if let Ok(Some(entry)) = crate::shared::parse::fstab::parse_line(line) {
            out.push((entry, idx + 1));
        }
    }
    out
}

fn dedupe_edits(mut edits: Vec<PlannedFstabEdit>) -> Vec<PlannedFstabEdit> {
    // Two ReplaceSource on the same line: drop the weaker one.
    // (E.g. root UUID + subvol fix both target line 1; the
    // ReplaceEntry supersedes the ReplaceSource.)
    let mut seen_full_replace: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for e in &edits {
        if let PlannedFstabEdit::ReplaceEntry { line, .. } = e {
            seen_full_replace.insert(*line);
        }
    }
    edits.retain(|e| match e {
        PlannedFstabEdit::ReplaceSource { line, .. } => !seen_full_replace.contains(line),
        _ => true,
    });
    edits
}

fn build_subvol_plan(entries: &[FstabEntry], inputs: &MountRepairInputs) -> Vec<PlannedSubvolume> {
    if inputs.target.root_fstype != "btrfs" {
        return Vec::new();
    }
    let history = history_from_entries(entries);
    let decisions = decide_all(&history, &inputs.subvol_facts, inputs.catos_confirmation);
    decisions
        .into_iter()
        .filter_map(|d| match d {
            SubvolDecision::Create { .. } | SubvolDecision::CreateWithDataConflict { .. } => {
                d.into_planned()
            }
            _ => None,
        })
        .collect()
}

fn build_directory_plan(inputs: &MountRepairInputs) -> Vec<PlannedDirectory> {
    let mut out = Vec::new();
    if inputs.target.root_fstype == "btrfs" {
        for spec in crate::shared::model::mount_repair::CATOS_STANDARD_SUBVOLS {
            if spec.mount_point == "/" {
                continue;
            }
            let obs = inputs
                .mount_point_observations
                .get(spec.mount_point)
                .copied()
                .unwrap_or_else(MountPointObservation::missing);
            if !obs.exists && !obs.is_symlink && !obs.is_other_object {
                out.push(PlannedDirectory {
                    mount_point: spec.mount_point.to_string(),
                    reason: format!(
                        "standard CatOS mount point {} does not exist; creating",
                        spec.mount_point
                    ),
                });
            }
        }
    }
    // ESP mount points.
    for mp in ["/boot/efi", "/efi", "/boot"] {
        let obs = inputs
            .mount_point_observations
            .get(mp)
            .copied()
            .unwrap_or_else(MountPointObservation::missing);
        if !obs.exists && !obs.is_symlink && !obs.is_other_object {
            // Only include if the fstab actually references this
            // mount point — we do not invent ESP dirs from nothing.
            let (entries, _) = parse_all_with_diagnostics(&inputs.fstab_text);
            if entries.iter().any(|e| e.target == mp) {
                out.push(PlannedDirectory {
                    mount_point: mp.to_string(),
                    reason: format!("ESP mount point {mp} referenced by fstab does not exist"),
                });
            }
        }
    }
    out
}

fn collect_conflicts(problems: &[MountProblem]) -> Vec<String> {
    let mut out = Vec::new();
    for p in problems {
        match p {
            MountProblem::UnparseableLine { .. }
            | MountProblem::MissingRootEntry
            | MountProblem::RootSourceUnresolvable
            | MountProblem::DuplicateMountPoint { .. }
            | MountProblem::AmbiguousEsp { .. } => {
                out.push(format!("unresolved: {} ({})", p.code(), problem_summary(p)))
            }
            MountProblem::UnsafeMountPoint {
                mount_point,
                reason,
            } => out.push(format!("unsafe path {mount_point}: {reason}")),
            _ => {}
        }
    }
    out
}

fn collect_risks(problems: &[MountProblem], subvolumes: &[PlannedSubvolume]) -> Vec<String> {
    let mut out = Vec::new();
    if problems
        .iter()
        .any(|p| matches!(p, MountProblem::SnapshotsWrongSubvol { .. }))
    {
        out.push(
            "@snapshots subvol is wrong; snapper configuration may need Doctor attention".into(),
        );
    }
    if subvolumes.iter().any(|s| s.subvol == "/@snapshots") {
        out.push("recreating @snapshots does not run snapper create-config; check Doctor".into());
    }
    out
}

fn problem_summary(p: &MountProblem) -> String {
    match p {
        MountProblem::UnparseableLine { line, reason } => format!("line {line}: {reason}"),
        MountProblem::MissingRootEntry => "no entry for /".into(),
        MountProblem::RootSourceUnresolvable => "root source unresolvable".into(),
        MountProblem::RootUuidMismatch { expected, actual } => {
            format!("expected {expected}, got {actual}")
        }
        MountProblem::RootWrongSubvol { actual } => format!("actual subvol: {actual}"),
        MountProblem::StandardWrongSubvol {
            mount_point,
            expected,
            actual,
        } => format!("{mount_point}: expected {expected}, got {actual}"),
        MountProblem::MissingStandardEntry {
            mount_point,
            subvol,
        } => {
            format!("{mount_point} → {subvol} missing")
        }
        MountProblem::SnapshotsWrongSubvol { actual } => {
            format!("@snapshots actual: {actual}")
        }
        MountProblem::EspUuidMismatch { expected, actual } => {
            format!("expected {expected}, got {actual}")
        }
        MountProblem::EspMountPointMismatch { expected, actual } => {
            format!("expected {expected}, got {actual}")
        }
        MountProblem::DuplicateMountPoint { mount_point } => {
            format!("multiple entries for {mount_point}")
        }
        MountProblem::SwapEntryMistyped => "swap entry mistyped".into(),
        MountProblem::MissingSubvolume { subvol } => format!("{subvol} missing"),
        MountProblem::MissingMountPoint { mount_point } => format!("{mount_point} missing"),
        MountProblem::UnsafeMountPoint {
            mount_point,
            reason,
        } => {
            format!("{mount_point}: {reason}")
        }
        MountProblem::AmbiguousEsp { candidates } => {
            format!("multiple ESP candidates: {}", candidates.join(", "))
        }
        MountProblem::StaleSource { source } => format!("source {source} no longer exists"),
    }
}

/// Drift between the plan's bound identity/digest and a fresh
/// observation. Returns `None` if no drift; otherwise the
/// `MountRepairOutcome` the apply layer should report.
pub fn detect_drift(
    plan: &MountRepairPlan,
    new_target: &TargetIdentity,
    new_fstab_digest: &FstabDigest,
) -> Option<MountRepairOutcome> {
    if plan.target != *new_target {
        return Some(MountRepairOutcome::DeviceChanged);
    }
    if plan.fstab_digest != *new_fstab_digest {
        return Some(MountRepairOutcome::FstabChanged);
    }
    None
}

/// Apply the plan's fstab edits to the original text and verify the
/// result re-parses cleanly. Returns the new text on success.
///
/// This is the **in-memory** apply; the privileged layer writes the
/// returned text to disk atomically. We deliberately do not write
/// anything from here.
pub fn apply_in_memory(
    original: &str,
    plan: &MountRepairPlan,
) -> Result<String, MountRepairOutcome> {
    let new_text = apply_edits(original, &plan.fstab_edits)
        .map_err(|_| MountRepairOutcome::ConflictingFstab)?;
    // Verify the new text re-parses with no NEW unparseable lines.
    let (_, new_diagnostics) = parse_all_with_diagnostics(&new_text);
    if !new_diagnostics.is_empty() {
        return Err(MountRepairOutcome::ConflictingFstab);
    }
    Ok(new_text)
}

/// Top-level entry point used by the CLI. Performs diagnosis + plan +
/// in-memory apply. Does NOT touch disk. The CLI calls this and then
/// either renders the report (no apply) or hands the plan to the
/// privileged layer (apply).
pub fn run_mount_repair_diagnosis(
    inputs: MountRepairInputs,
    authorised: bool,
) -> MountRepairReport {
    let plan = build_plan(&inputs);
    let evidence = vec![Evidence::new(
        "DIAGNOSIS",
        "repair::mount",
        format!("diagnosed {} problem(s)", plan.problems.len()),
    )];
    let warnings: Vec<Warning> = plan
        .risks
        .iter()
        .map(|r| Warning::new("MOUNT_REPAIR_RISK", r.clone()))
        .collect();

    if plan.problems.is_empty() {
        return MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan),
            fstab_transaction: None,
            actions: Vec::new(),
            verification: None,
            cleanup: MountRepairCleanup::default(),
            final_outcome: MountRepairOutcome::Clean,
            requires_human_action: false,
            fully_complete: true,
            evidence,
            warnings,
        };
    }

    if !authorised {
        // Diagnosis-only mode (Doctor path): report problems without
        // attempting any change.
        let problem_count = plan.problems.len();
        return MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan),
            fstab_transaction: None,
            actions: Vec::new(),
            verification: None,
            cleanup: MountRepairCleanup::default(),
            final_outcome: MountRepairOutcome::Clean,
            requires_human_action: problem_count > 0,
            fully_complete: false,
            evidence,
            warnings,
        };
    }

    // Authorised apply (in-memory). The privileged layer is
    // responsible for the disk transaction.
    let original = inputs.fstab_text.clone();
    let plan_for_apply = plan.clone();
    let actions = build_action_audit(&plan_for_apply);
    match apply_in_memory(&original, &plan_for_apply) {
        Ok(_new_text) => {
            let data_conflict = plan_for_apply.subvolumes.iter().any(|s| {
                inputs
                    .mount_point_observations
                    .get(&s.mount_point)
                    .is_some_and(|obs| obs.entry_count.unwrap_or(0) > 0)
            });
            let outcome = if data_conflict {
                MountRepairOutcome::PartiallyRepaired
            } else {
                MountRepairOutcome::Repaired
            };
            MountRepairReport {
                target: Some(inputs.target.clone()),
                plan: Some(plan_for_apply.clone()),
                fstab_transaction: Some(FstabTransaction {
                    original_path: PathBuf::from("/etc/fstab"),
                    backup_path: None,
                    temp_path: None,
                    atomic_replace_succeeded: false,
                    parent_fsynced: false,
                    rollback_attempted: false,
                    rollback_succeeded: false,
                }),
                actions,
                verification: Some(MountVerification::default()),
                cleanup: MountRepairCleanup::default(),
                final_outcome: outcome,
                requires_human_action: data_conflict,
                fully_complete: !data_conflict,
                evidence,
                warnings,
            }
        }
        Err(outcome) => MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan_for_apply),
            fstab_transaction: None,
            actions,
            verification: None,
            cleanup: MountRepairCleanup::default(),
            final_outcome: outcome,
            requires_human_action: true,
            fully_complete: false,
            evidence,
            warnings,
        },
    }
}

fn build_action_audit(plan: &MountRepairPlan) -> Vec<AppliedAction> {
    let mut out = Vec::new();
    for edit in &plan.fstab_edits {
        out.push(AppliedAction::FstabEdited { edit: edit.clone() });
    }
    for sub in &plan.subvolumes {
        out.push(AppliedAction::SubvolumeCreated {
            subvol: sub.subvol.clone(),
        });
    }
    for dir in &plan.directories {
        out.push(AppliedAction::DirectoryCreated {
            mount_point: dir.mount_point.clone(),
        });
    }
    out
}
pub fn run_mount_repair_via_cli(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
    authorised: bool,
) -> MountRepairReport {
    let fs = RealFilesystem;
    let (devices, mut warnings) = discover_devices(&fs);
    let Some(root) = select_cli_root(&devices, root_device) else {
        return MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "root device must identify exactly one verified CatOS root",
        );
    };
    let requested_subvol = match (root.filesystem.as_deref(), root_subvolume) {
        (Some("btrfs"), Some(value)) => value,
        (Some("btrfs"), None) => "/@",
        (_, Some(_)) => {
            return MountRepairReport::refused(
                MountRepairOutcome::UnsupportedLayout,
                "--root-subvolume is valid only for Btrfs roots",
            );
        }
        (_, None) => "",
    };
    if root.filesystem.as_deref() == Some("btrfs") && requested_subvol != "/@" {
        return MountRepairReport::refused(
            MountRepairOutcome::UnsupportedLayout,
            "mount repair supports the CatOS standard Btrfs root subvolume /@",
        );
    }
    let Some(device) = root.dev_path.as_deref() else {
        return MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "selected root has no stable device path",
        );
    };

    let running_root = is_running_root_device(root);
    // Establish target-local facts before acquiring a write lock. The running
    // system is inspected through `/`; an offline target is mounted read-only.
    // Both paths feed the same fstab/layout logic.
    let selected_probe_result = if running_root {
        inspect_running_root().map_err(|message| crate::shared::model::mount::MountError {
            kind: crate::shared::model::mount::MountErrorKind::MountFailed,
            message,
            device_or_path: Some("/".into()),
            errno: None,
            completed_steps: Vec::new(),
            cleanup_complete: true,
            residual_mounts: Vec::new(),
        })
    } else {
        inspect_selected_root(
            root,
            (root.filesystem.as_deref() == Some("btrfs")).then_some(requested_subvol),
        )
    };
    let selected_probe = match selected_probe_result {
        Ok(probe) => probe,
        Err(error) => {
            return MountRepairReport::refused(
                MountRepairOutcome::UnsupportedLayout,
                &format!(
                    "cannot inspect selected target read-only: {}",
                    error.message
                ),
            );
        }
    };
    warnings.extend(selected_probe.warnings.clone());
    if selected_probe.inspection.is_catos_target.status != DetectionStatus::Detected {
        let mut report = MountRepairReport::refused(
            MountRepairOutcome::NotCatos,
            "selected target is not identified as CatOS",
        );
        report.warnings = warnings;
        return report;
    }

    let mut topology_probe = probe_unmounted_candidates(&devices, &selected_probe.fstab);
    warnings.append(&mut topology_probe.warnings);
    let esp = match select_mount_repair_esp(
        &devices,
        &selected_probe.fstab,
        &topology_probe.esps,
        esp_device,
    ) {
        Ok(esp) => esp,
        Err(reason) => {
            let mut report =
                MountRepairReport::refused(MountRepairOutcome::AmbiguousTarget, &reason);
            report.warnings = warnings;
            return report;
        }
    };
    let boot_layout = match detect_boot_mount_layout(
        &selected_probe.fstab,
        &devices,
        device,
        esp.and_then(|device| device.dev_path.as_deref()),
    ) {
        Ok(layout) => layout,
        Err(reason) => {
            let mut report =
                MountRepairReport::refused(MountRepairOutcome::UnsupportedLayout, &reason);
            report.warnings = warnings;
            return report;
        }
    };

    let target = TargetIdentity {
        root_device: device.to_path_buf(),
        root_fstype: root.filesystem.clone().unwrap_or_default(),
        root_subvol: (root.filesystem.as_deref() == Some("btrfs"))
            .then(|| requested_subvol.to_string()),
        root_uuid: root.uuid.clone(),
        esp_device: esp.and_then(|device| device.dev_path.clone()),
        esp_uuid: esp.and_then(|device| device.uuid.clone()),
        boot_layout: Some(boot_layout),
    };
    let lock = match DeviceLock::try_acquire(device) {
        Ok(lock) => lock,
        Err(error) => {
            return MountRepairReport::refused(MountRepairOutcome::DeviceChanged, &error.message)
        }
    };
    let mut session = match MountRepairRwSession::mount(
        device,
        root.filesystem.as_deref().unwrap_or_default(),
        running_root,
    ) {
        Ok(session) => session,
        Err(error) => {
            return MountRepairReport::refused(
                MountRepairOutcome::UnsupportedLayout,
                &error.message,
            );
        }
    };
    let top = session.storage_root().to_path_buf();
    let root_path = session.target_root();
    let inputs = match observe_target_inputs(&fs, &top, &root_path, target) {
        Ok(inputs) => inputs,
        Err(reason) => {
            let cleanup = session.cleanup();
            let mut report = MountRepairReport::refused(MountRepairOutcome::NotCatos, &reason);
            report.cleanup = cleanup_into_mount_repair(cleanup);
            report.warnings = warnings;
            drop(lock);
            return report;
        }
    };
    let mut report = execute_mount_repair(&inputs, &top, authorised, &devices);
    let cleanup = session.cleanup();
    report.cleanup = cleanup_into_mount_repair(cleanup);
    if !report.cleanup.all_clean {
        report.final_outcome = MountRepairOutcome::CleanupIncomplete;
        report.requires_human_action = true;
        report.fully_complete = false;
    }
    report.warnings.extend(warnings);
    drop(lock);
    report
}


mod apply;
mod boot_target;
mod rollback;
mod select;
mod session;
mod verify;
#[cfg(test)]
mod tests;

pub(crate) use boot_target::{open_boot_repair_target_session, BootRepairTargetSession};
use apply::execute_mount_repair;
#[cfg(test)]
use boot_target::boot_runtime_bind_flags;
use rollback::{
    ensure_nested_esp_mountpoint, failure_after_created_resources, mountpoint_matches_device,
    rollback_created_resources, rollback_nested_esp_mountpoint,
};
use select::{
    auto_select_cli_root, auto_select_running_root, inspect_running_root, is_running_root_device,
    observe_target_inputs, same_block_device, select_cli_root, select_mount_repair_esp,
    supported_mount_repair_root, target_rooted_path,
};
use session::MountRepairRwSession;
use verify::{
    cleanup_into_mount_repair, cleanup_plain_verification_mounts, validate_existing_mount_target,
    verify_fresh_written_target, verify_plain_written_target, verify_written_target,
};
