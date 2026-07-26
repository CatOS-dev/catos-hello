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

use crate::model::evidence::Evidence;
use crate::model::fstab::FstabSource;
use crate::model::inspection::Warning;
use crate::model::mount_repair::{
    default_mount_options, AppliedAction, BootMountLayout, FstabDigest, FstabTransaction,
    MountProblem, MountRepairCleanup, MountRepairOutcome, MountRepairPlan, MountRepairReport,
    MountVerification, PlannedDirectory, PlannedFstabEdit, PlannedSubvolume, TargetIdentity,
};
use crate::model::recovery::{CleanupSummary, RecoveryError, RecoveryErrorKind};
use crate::model::runtime::DetectionStatus;
use crate::model::storage::{
    BlockDevice, DeviceClass, EspCandidate, PartitionRole, RootCandidateConfidence,
};
use crate::mount::namespace;
use crate::mount::plan::{build_plan as build_mount_plan, PlanInputs};
use crate::mount::probe::{inspect_selected_root, probe_unmounted_candidates, SelectedTargetProbe};
use crate::mount::session::Session;
use crate::mount::syscall::{self, ms_flags};
use crate::parse::fstab::{parse_all_with_diagnostics, FstabEntry, FstabEntryKind};
use crate::probe::candidate::device_matches_fstab_source;
use crate::probe::discover_devices;
use crate::probe::fs_probe::{FilesystemProbe, RealFilesystem};
use crate::recovery::confined;
use crate::recovery::external as btrfs;
use crate::recovery::lock::DeviceLock;
use crate::repair::fstab_edit::apply_edits;
use crate::repair::path_safety::{validate_directory_creation, PathObservation};
use crate::repair::subvol_decision::{
    decide_all, history_from_entries, CatosConfirmation, SubvolDecision, SubvolFacts,
};
use crate::system_root::SystemRoot;

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
        for spec in crate::model::mount_repair::CATOS_STANDARD_SUBVOLS {
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
        for spec in crate::model::mount_repair::CATOS_STANDARD_SUBVOLS {
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

fn digest_of(text: &str) -> FstabDigest {
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
            crate::model::mount_repair::standard_subvol_for_mount_point(&entry.target)
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
    for spec in crate::model::mount_repair::CATOS_STANDARD_SUBVOLS {
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
        if let Ok(Some(entry)) = crate::parse::fstab::parse_line(line) {
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
        for spec in crate::model::mount_repair::CATOS_STANDARD_SUBVOLS {
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

/// Production CLI entry point for an explicitly selected, unmounted CatOS
/// Btrfs target. It mounts the Btrfs top level in a private session, gathers
/// target-local facts, and records actions only after they have succeeded.
enum MountRepairRwSession {
    Btrfs(crate::phase3::RecoveryRwSession),
    Plain(PlainRwSession),
    Running(RunningRootSession),
}

impl MountRepairRwSession {
    fn mount(device: &Path, fstype: &str, running_root: bool) -> Result<Self, RecoveryError> {
        if fstype == "btrfs" {
            crate::phase3::RecoveryRwSession::mount(device).map(Self::Btrfs)
        } else if running_root {
            RunningRootSession::enter().map(Self::Running)
        } else {
            PlainRwSession::mount(device, fstype).map(Self::Plain)
        }
    }

    fn storage_root(&self) -> &Path {
        match self {
            MountRepairRwSession::Btrfs(session) => session.top_level_mount(),
            MountRepairRwSession::Plain(session) => &session.mount_root,
            MountRepairRwSession::Running(session) => &session.root,
        }
    }

    fn target_root(&self) -> PathBuf {
        match self {
            MountRepairRwSession::Btrfs(session) => session.top_level_mount().join("@"),
            MountRepairRwSession::Plain(session) => session.mount_root.clone(),
            MountRepairRwSession::Running(session) => session.root.clone(),
        }
    }

    fn cleanup(&mut self) -> CleanupSummary {
        match self {
            MountRepairRwSession::Btrfs(session) => session.cleanup(),
            MountRepairRwSession::Plain(session) => session.cleanup(),
            MountRepairRwSession::Running(session) => session.cleanup(),
        }
    }
}

/// A writable target mount held exclusively for boot repair.  Unlike
/// `run_mount_repair_via_cli`, constructing this session never plans or
/// applies fstab/subvolume changes: it only mounts the already-confirmed
/// target layout and keeps the device lock until explicit cleanup.
pub(crate) struct BootRepairTargetSession {
    target: TargetIdentity,
    devices: Vec<BlockDevice>,
    root_session: MountRepairRwSession,
    auxiliary_mounts: Vec<PathBuf>,
    _lock: DeviceLock,
}

impl BootRepairTargetSession {
    pub(crate) fn target(&self) -> &TargetIdentity {
        &self.target
    }

    pub(crate) fn target_root(&self) -> PathBuf {
        self.root_session.target_root()
    }

    pub(crate) fn devices(&self) -> &[BlockDevice] {
        &self.devices
    }

    pub(crate) fn cleanup(&mut self) -> CleanupSummary {
        let mut cleanup = CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        };
        for mount_point in self.auxiliary_mounts.drain(..).rev() {
            match syscall::umount2(&mount_point, 0) {
                Ok(()) => cleanup.unmounted.push(mount_point.display().to_string()),
                Err(error) => {
                    let detach = syscall::umount2(
                        &mount_point,
                        crate::mount::syscall::mnt_flags::MNT_DETACH,
                    );
                    cleanup.all_clean = false;
                    cleanup.residual.push(match detach {
                        Ok(()) => format!(
                            "{}: umount2 failed ({error}); detached lazily",
                            mount_point.display()
                        ),
                        Err(detach_error) => format!(
                            "{}: umount2 failed ({error}); lazy detach failed ({detach_error})",
                            mount_point.display()
                        ),
                    });
                }
            }
        }
        let root_cleanup = self.root_session.cleanup();
        cleanup.unmounted.extend(root_cleanup.unmounted);
        cleanup.residual.extend(root_cleanup.residual);
        cleanup.all_clean &= root_cleanup.all_clean;
        cleanup
    }
}

/// Discover and mount the exact target required by boot repair without ever
/// entering mount repair's write/apply flow.  The returned session owns the
/// shared device lock and every mount it creates.
pub(crate) fn open_boot_repair_target_session(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
) -> Result<BootRepairTargetSession, String> {
    let fs = RealFilesystem;
    let (devices, _) = discover_devices(&fs);
    let root = select_cli_root(&devices, root_device)
        .ok_or_else(|| "root device must identify exactly one verified CatOS root".to_string())?;
    let requested_subvol = match (root.filesystem.as_deref(), root_subvolume) {
        (Some("btrfs"), Some(value)) => value,
        (Some("btrfs"), None) => "/@",
        (_, Some(_)) => return Err("--root-subvolume is valid only for Btrfs roots".into()),
        (_, None) => "",
    };
    if root.filesystem.as_deref() == Some("btrfs") && requested_subvol != "/@" {
        return Err("boot repair supports the CatOS standard Btrfs root subvolume /@".into());
    }
    let root_device_path = root
        .dev_path
        .as_deref()
        .ok_or_else(|| "selected root has no stable device path".to_string())?;
    let running_root = is_running_root_device(root);
    let selected_probe = if running_root {
        inspect_running_root()
    } else {
        inspect_selected_root(
            root,
            (root.filesystem.as_deref() == Some("btrfs")).then_some(requested_subvol),
        )
        .map_err(|error| error.message)
    }
    .map_err(|error| format!("cannot inspect selected target read-only: {error}"))?;
    if selected_probe.inspection.is_catos_target.status != DetectionStatus::Detected {
        return Err("selected target is not identified as CatOS".into());
    }
    let topology_probe = probe_unmounted_candidates(&devices, &selected_probe.fstab);
    let esp = select_mount_repair_esp(
        &devices,
        &selected_probe.fstab,
        &topology_probe.esps,
        esp_device,
    )?;
    let boot_layout = detect_boot_mount_layout(
        &selected_probe.fstab,
        &devices,
        root_device_path,
        esp.and_then(|device| device.dev_path.as_deref()),
    )?;
    let target = TargetIdentity {
        root_device: root_device_path.to_path_buf(),
        root_fstype: root.filesystem.clone().unwrap_or_default(),
        root_subvol: (root.filesystem.as_deref() == Some("btrfs"))
            .then(|| requested_subvol.to_string()),
        root_uuid: root.uuid.clone(),
        esp_device: esp.and_then(|device| device.dev_path.clone()),
        esp_uuid: esp.and_then(|device| device.uuid.clone()),
        boot_layout: Some(boot_layout),
    };
    let lock = DeviceLock::try_acquire(root_device_path).map_err(|error| error.message)?;
    let root_session = MountRepairRwSession::mount(
        root_device_path,
        root.filesystem.as_deref().unwrap_or_default(),
        running_root,
    )
    .map_err(|error| error.message.to_string())?;
    let mut session = BootRepairTargetSession {
        target,
        devices,
        root_session,
        auxiliary_mounts: Vec::new(),
        _lock: lock,
    };
    if let Err(error) = session
        .mount_runtime_filesystems()
        .and_then(|_| session.mount_boot_layout())
    {
        let cleanup = session.cleanup();
        return Err(format!(
            "cannot mount target boot layout: {error}; cleanup residuals: {:?}",
            cleanup.residual
        ));
    }
    Ok(session)
}

fn boot_runtime_bind_flags(source: &str) -> u64 {
    // /dev/fd resolves through /proc/self/fd and mkinitcpio expects the usual
    // recursive /dev and /proc views. /sys and /run, however, contain many
    // unrelated host submounts; copying those recursively makes one cleanup
    // entry insufficient. Efivars is mounted explicitly below when present.
    match source {
        "/dev" | "/proc" => ms_flags::MS_BIND | ms_flags::MS_REC,
        _ => ms_flags::MS_BIND,
    }
}

impl BootRepairTargetSession {
    fn mount_runtime_filesystems(&mut self) -> Result<(), String> {
        for source in ["/dev", "/proc", "/sys", "/run"] {
            if !Path::new(source).is_dir() {
                return Err(format!(
                    "required host runtime mount {source} is unavailable"
                ));
            }
            self.bind_host_path(source, source)?;
        }
        let efivars = Path::new("/sys/firmware/efi/efivars");
        if efivars.is_dir() {
            self.bind_host_path("/sys/firmware/efi/efivars", "/sys/firmware/efi/efivars")?;
        }
        Ok(())
    }

    fn mount_boot_layout(&mut self) -> Result<(), String> {
        let Some(layout) = self.target.boot_layout.clone() else {
            return Err("target boot layout was not detected".into());
        };
        match layout {
            BootMountLayout::BootInsideRoot => Ok(()),
            BootMountLayout::EspAtBootEfi { esp_device } => {
                self.mount_device_at(&esp_device, "/boot/efi", None)
            }
            BootMountLayout::EspAtEfi { esp_device } => {
                self.mount_device_at(&esp_device, "/efi", None)
            }
            BootMountLayout::EspAtBoot { esp_device } => {
                self.mount_device_at(&esp_device, "/boot", None)
            }
            BootMountLayout::SeparateBootAndEsp {
                boot_device,
                esp_device,
                esp_mount_point,
            } => {
                self.mount_device_at(&boot_device, "/boot", None)?;
                self.mount_device_at(&esp_device, &esp_mount_point, None)
            }
            BootMountLayout::BootBtrfsSubvolume {
                subvolume,
                esp_device,
                esp_mount_point,
            } => {
                self.mount_device_at(
                    &self.target.root_device.clone(),
                    "/boot",
                    Some(format!("subvol={subvolume}")),
                )?;
                match (esp_device, esp_mount_point) {
                    (Some(device), Some(mount_point)) => {
                        self.mount_device_at(&device, &mount_point, None)
                    }
                    (None, None) => Ok(()),
                    _ => Err("Btrfs /boot layout has incomplete ESP metadata".into()),
                }
            }
        }
    }

    fn mount_device_at(
        &mut self,
        device: &Path,
        target_relative: &str,
        options: Option<String>,
    ) -> Result<(), String> {
        let filesystem = self
            .devices
            .iter()
            .find(|candidate| {
                candidate
                    .dev_path
                    .as_deref()
                    .is_some_and(|path| same_block_device(path, device))
            })
            .and_then(|candidate| candidate.filesystem.as_deref())
            .ok_or_else(|| format!("{} has no detected filesystem", device.display()))?;
        let mount_point = self
            .target_root()
            .join(target_relative.trim_start_matches('/'));
        match std::fs::symlink_metadata(&mount_point) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", mount_point.display()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!("{} is not a directory", mount_point.display()));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", mount_point.display())),
        }
        let source = device
            .to_str()
            .ok_or_else(|| format!("{} is not valid UTF-8", device.display()))?;
        syscall::mount(
            Some(source),
            &mount_point,
            Some(filesystem),
            ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
            options.as_deref(),
        )
        .map_err(|error| {
            format!(
                "mount {} at {}: {error}",
                device.display(),
                mount_point.display()
            )
        })?;
        self.auxiliary_mounts.push(mount_point);
        Ok(())
    }

    fn bind_host_path(&mut self, source: &str, target_relative: &str) -> Result<(), String> {
        let mount_point = self
            .target_root()
            .join(target_relative.trim_start_matches('/'));
        match std::fs::symlink_metadata(&mount_point) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", mount_point.display()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!("{} is not a directory", mount_point.display()));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", mount_point.display())),
        }
        syscall::mount(
            Some(source),
            &mount_point,
            None,
            boot_runtime_bind_flags(source),
            None,
        )
        .map_err(|error| format!("bind mount {source} at {}: {error}", mount_point.display()))?;
        self.auxiliary_mounts.push(mount_point);
        Ok(())
    }
}

struct RunningRootSession {
    root: PathBuf,
}

impl RunningRootSession {
    fn enter() -> Result<Self, RecoveryError> {
        namespace::establish_private_namespace().map_err(|error| {
            RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
                format!("cannot establish private namespace for running-root repair: {error}"),
            )
        })?;
        Ok(Self {
            root: PathBuf::from("/"),
        })
    }

    fn cleanup(&mut self) -> CleanupSummary {
        CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        }
    }
}

struct PlainRwSession {
    session_dir: PathBuf,
    mount_root: PathBuf,
    mounted: bool,
}

impl PlainRwSession {
    fn mount(device: &Path, fstype: &str) -> Result<Self, RecoveryError> {
        namespace::establish_private_namespace().map_err(|error| {
            RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
                format!("cannot establish private mount namespace: {error}"),
            )
        })?;
        let session_dir = crate::mount::secure_dir::create_session_dir(
            Path::new(crate::mount::secure_dir::SESSION_ROOT_PARENT),
            "mount-repair-rw",
        )?;
        let mount_root = session_dir.join("root");
        std::fs::create_dir(&mount_root).map_err(|error| {
            RecoveryError::new(
                RecoveryErrorKind::SessionDirectoryNotSecure,
                format!("cannot create plain-root mountpoint: {error}"),
            )
        })?;
        let source = device.to_str().ok_or_else(|| {
            RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
                "plain root device path is not UTF-8",
            )
        })?;
        if let Err(error) = syscall::mount(
            Some(source),
            &mount_root,
            Some(fstype),
            ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
            None,
        ) {
            let _ = crate::mount::secure_dir::remove_session_dir(
                Path::new(crate::mount::secure_dir::SESSION_ROOT_PARENT),
                &session_dir,
            );
            return Err(RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
                format!("cannot mount plain target root read-write: {error}"),
            ));
        }
        Ok(Self {
            session_dir,
            mount_root,
            mounted: true,
        })
    }

    fn cleanup(&mut self) -> CleanupSummary {
        let mut summary = CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        };
        if self.mounted {
            match syscall::umount2(&self.mount_root, 0) {
                Ok(()) => {
                    summary
                        .unmounted
                        .push(self.mount_root.display().to_string());
                    self.mounted = false;
                }
                Err(error) => {
                    let _ = syscall::umount2(
                        &self.mount_root,
                        crate::mount::syscall::mnt_flags::MNT_DETACH,
                    );
                    summary
                        .residual
                        .push(format!("{}: {error}", self.mount_root.display()));
                    summary.all_clean = false;
                }
            }
        }
        if !self.mounted {
            if let Err(error) = crate::mount::secure_dir::remove_session_dir(
                Path::new(crate::mount::secure_dir::SESSION_ROOT_PARENT),
                &self.session_dir,
            ) {
                summary.residual.push(error.message.to_string());
                summary.all_clean = false;
            }
        }
        summary
    }
}

impl Drop for PlainRwSession {
    fn drop(&mut self) {
        if self.mounted {
            let _ = self.cleanup();
        }
    }
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
        inspect_running_root().map_err(|message| crate::model::mount::MountError {
            kind: crate::model::mount::MountErrorKind::MountFailed,
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

fn select_mount_repair_esp<'a>(
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
    // Do not invent a mount point merely because a disk happens to contain
    // an unrelated ESP.
    Ok(None)
}

fn select_cli_root<'a>(
    devices: &'a [BlockDevice],
    root_device: Option<&str>,
) -> Option<&'a BlockDevice> {
    match root_device {
        Some(requested) => devices.iter().find(|device| {
            device
                .dev_path
                .as_ref()
                .is_some_and(|path| same_block_device(path, Path::new(requested)))
                && supported_mount_repair_root(device.filesystem.as_deref())
                && (!device.mounted_before_session || is_running_root_device(device))
        }),
        None => auto_select_running_root(devices).or_else(|| auto_select_cli_root(devices)),
    }
}

fn is_running_root_device(device: &BlockDevice) -> bool {
    device.mount_point.as_deref() == Some(Path::new("/"))
        || device
            .mounts
            .iter()
            .any(|mount| mount.mount_point == Path::new("/"))
}

fn auto_select_running_root(devices: &[BlockDevice]) -> Option<&BlockDevice> {
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

fn inspect_running_root() -> Result<SelectedTargetProbe, String> {
    let root = SystemRoot::from_user_input("/").map_err(|error| error.to_string())?;
    let fs = RealFilesystem;
    let fstab_text = fs
        .rooted_read_to_string(root.canonical_path(), Path::new("etc/fstab"))
        .map_err(|error| format!("cannot read running-system fstab: {error}"))?;
    let (fstab, diagnostics) = parse_all_with_diagnostics(&fstab_text);
    let mut warning_strings = Vec::new();
    let inspection = crate::probe::inspect_target(&fs, &root, &mut warning_strings);
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
        cleanup: crate::model::mount::CleanupReport {
            all_clean: true,
            ..Default::default()
        },
        warnings,
    })
}

fn auto_select_cli_root(devices: &[BlockDevice]) -> Option<&BlockDevice> {
    let probes = probe_unmounted_candidates(devices, &[]);
    let candidates: Vec<&str> = probes
        .roots
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

fn supported_mount_repair_root(fstype: Option<&str>) -> bool {
    matches!(
        fstype,
        Some("btrfs" | "ext2" | "ext3" | "ext4" | "xfs" | "f2fs")
    )
}

fn same_block_device(discovered: &Path, requested: &Path) -> bool {
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

fn observe_target_inputs(
    fs: &RealFilesystem,
    top: &Path,
    root: &Path,
    target: TargetIdentity,
) -> Result<MountRepairInputs, String> {
    let fstab_text = fs
        .rooted_read_to_string(root, Path::new("etc/fstab"))
        .map_err(|error| format!("cannot safely read target /etc/fstab: {error}"))?;
    let os_release = fs
        .rooted_read_to_string(root, Path::new("etc/os-release"))
        .map_err(|error| format!("cannot safely read target os-release: {error}"))?;
    let catos_confirmation = if os_release.lines().any(|line| {
        let Some(value) = line.trim().strip_prefix("ID=") else {
            return false;
        };
        value.trim_matches('"') == "catos"
    }) {
        CatosConfirmation::Confirmed
    } else {
        CatosConfirmation::NotConfirmed
    };
    if catos_confirmation != CatosConfirmation::Confirmed {
        return Err("selected target is not identified as CatOS".into());
    }
    let listed = if target.root_fstype == "btrfs" {
        btrfs::list_subvolumes(top).map_err(|error| {
            format!(
                "cannot enumerate target Btrfs subvolumes: {}",
                error.message
            )
        })?
    } else {
        Vec::new()
    };
    let mut subvol_facts = SubvolFacts::default();
    let mut mount_point_observations = HashMap::new();
    if target.root_fstype == "btrfs" {
        for spec in crate::model::mount_repair::CATOS_STANDARD_SUBVOLS {
            let exists_as_subvol = listed.iter().any(|item| item.path == spec.subvol);
            let top_path = top.join(spec.subvol.trim_start_matches('/'));
            let (exists_as_directory, exists_as_other) = match std::fs::symlink_metadata(&top_path)
            {
                Ok(metadata) if metadata.file_type().is_symlink() => (false, true),
                Ok(metadata) if metadata.is_dir() => (true, false),
                Ok(_) => (false, true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, false),
                Err(_) => (false, true),
            };
            subvol_facts
                .observations
                .push(crate::repair::subvol_decision::SubvolObservation {
                    subvol: spec.subvol.to_string(),
                    exists_as_subvol,
                    exists_as_directory,
                    exists_as_other,
                    mount_point_entry_count: None,
                });
            if spec.mount_point == "/" {
                continue;
            }
            let relative = Path::new(spec.mount_point.trim_start_matches('/'));
            let observation = match fs.rooted_metadata(root, relative) {
                Ok(metadata) => MountPointObservation {
                    exists: true,
                    is_symlink: metadata.is_symlink,
                    is_directory: metadata.is_dir,
                    is_other_object: !metadata.is_dir,
                    entry_count: if metadata.is_dir {
                        fs.read_dir_names(&root.join(relative))
                            .ok()
                            .map(|entries| entries.len())
                    } else {
                        None
                    },
                },
                Err(crate::error::FsError::NotFound) => MountPointObservation::missing(),
                Err(error) => {
                    return Err(format!(
                        "cannot safely inspect target mount point {}: {error}",
                        spec.mount_point
                    ));
                }
            };
            mount_point_observations.insert(spec.mount_point.to_string(), observation);
        }
    }
    for mount_point in ["/boot", "/boot/efi", "/efi"] {
        let relative = Path::new(mount_point.trim_start_matches('/'));
        let observation = match fs.rooted_metadata(root, relative) {
            Ok(metadata) => MountPointObservation {
                exists: true,
                is_symlink: metadata.is_symlink,
                is_directory: metadata.is_dir,
                is_other_object: !metadata.is_dir,
                entry_count: if metadata.is_dir {
                    fs.read_dir_names(&root.join(relative))
                        .ok()
                        .map(|entries| entries.len())
                } else {
                    None
                },
            },
            Err(crate::error::FsError::NotFound) => MountPointObservation::missing(),
            Err(error) => {
                return Err(format!(
                    "cannot safely inspect target mount point {mount_point}: {error}"
                ));
            }
        };
        mount_point_observations.insert(mount_point.to_string(), observation);
    }

    Ok(MountRepairInputs {
        fstab_text,
        target,
        catos_confirmation,
        subvol_facts,
        mount_point_observations,
    })
}

fn target_rooted_path(target: &TargetIdentity, path: &str) -> String {
    let suffix = path.trim_start_matches('/');
    match target.root_subvol.as_deref() {
        Some(subvolume) => format!("{}/{}", subvolume.trim_end_matches('/'), suffix),
        None => format!("/{suffix}"),
    }
}

fn execute_mount_repair(
    inputs: &MountRepairInputs,
    top: &Path,
    authorised: bool,
    devices: &[BlockDevice],
) -> MountRepairReport {
    let plan = build_plan(inputs);
    if !authorised {
        return MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan),
            final_outcome: MountRepairOutcome::PartiallyRepaired,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new(
                "AUTHORIZATION_REQUIRED",
                "repair::mount",
                "mount repair requires explicit CLI authorization",
            )],
            ..Default::default()
        };
    }
    if !plan.unresolved_conflicts.is_empty() {
        return MountRepairReport::refused(
            MountRepairOutcome::ConflictingFstab,
            &plan.unresolved_conflicts.join("; "),
        );
    }
    if plan.fstab_edits.is_empty() && plan.subvolumes.is_empty() && plan.directories.is_empty() {
        let mut report = MountRepairReport::clean(inputs.target.clone());
        report.plan = Some(plan);
        return report;
    }
    let rewritten = match apply_in_memory(&inputs.fstab_text, &plan) {
        Ok(text) => text,
        Err(outcome) => {
            return MountRepairReport::refused(outcome, "fstab edits could not be applied safely");
        }
    };
    let current =
        match confined::read_rooted_file(top, &target_rooted_path(&inputs.target, "/etc/fstab"))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
        {
            Some(text) => text,
            None => {
                return MountRepairReport::refused(
                    MountRepairOutcome::FstabChanged,
                    "cannot safely re-read target fstab",
                );
            }
        };
    if digest_of(&current) != plan.fstab_digest {
        return MountRepairReport::refused(
            MountRepairOutcome::FstabChanged,
            "target fstab changed after planning",
        );
    }

    let mut actions = Vec::new();
    let mut created_subvolumes = Vec::new();
    let mut created_directories = Vec::new();
    let mut nested_esp_directory_created = false;

    for subvolume in &plan.subvolumes {
        if let Err(error) = confined::create_btrfs_subvolume(top, &subvolume.subvol) {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                actions,
                &created_subvolumes,
                &created_directories,
                nested_esp_directory_created,
                MountRepairOutcome::SubvolumeConflict,
                "SUBVOLUME_CREATE_FAILED",
                format!("cannot create {}: {}", subvolume.subvol, error.message),
                None,
                None,
            );
        }
        created_subvolumes.push(subvolume.subvol.clone());
        actions.push(AppliedAction::SubvolumeCreated {
            subvol: subvolume.subvol.clone(),
        });
    }

    for directory in &plan.directories {
        let path = Path::new(&directory.mount_point);
        let observation = inputs
            .mount_point_observations
            .get(&directory.mount_point)
            .copied()
            .unwrap_or_default();
        let policy_observation = PathObservation {
            is_symlink: observation.is_symlink,
            is_directory: observation.is_directory,
            is_regular_file: observation.is_other_object,
            is_other: false,
        };
        if let Err(error) = validate_directory_creation(path, &policy_observation) {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                actions,
                &created_subvolumes,
                &created_directories,
                nested_esp_directory_created,
                MountRepairOutcome::UnsafePath,
                "UNSAFE_MOUNTPOINT",
                format!("{}: {error:?}", directory.mount_point),
                None,
                None,
            );
        }
        let target_path = target_rooted_path(&inputs.target, &directory.mount_point);
        if let Err(error) = confined::create_rooted_directory(top, &target_path) {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                actions,
                &created_subvolumes,
                &created_directories,
                nested_esp_directory_created,
                MountRepairOutcome::UnsafePath,
                "MOUNTPOINT_CREATE_FAILED",
                format!("{}: {}", directory.mount_point, error.message),
                None,
                None,
            );
        }
        created_directories.push(directory.mount_point.clone());
        actions.push(AppliedAction::DirectoryCreated {
            mount_point: directory.mount_point.clone(),
        });
    }

    match ensure_nested_esp_mountpoint(top, &inputs.target, devices) {
        Ok(Some(mount_point)) => {
            nested_esp_directory_created = true;
            actions.push(AppliedAction::DirectoryCreated { mount_point });
        }
        Ok(None) => {}
        Err(reason) => {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                actions,
                &created_subvolumes,
                &created_directories,
                nested_esp_directory_created,
                MountRepairOutcome::UnsafePath,
                "NESTED_ESP_MOUNTPOINT_FAILED",
                reason,
                None,
                None,
            );
        }
    }

    let backup_path = target_rooted_path(&inputs.target, "/etc/fstab.catos-repair.backup");
    if let Err(error) =
        confined::atomic_write_rooted(top, &backup_path, inputs.fstab_text.as_bytes(), 0o600)
    {
        return failure_after_created_resources(
            inputs,
            plan.clone(),
            top,
            devices,
            actions,
            &created_subvolumes,
            &created_directories,
            nested_esp_directory_created,
            MountRepairOutcome::RollbackFailed,
            "FSTAB_BACKUP_FAILED",
            error.message.to_string(),
            None,
            None,
        );
    }

    let fstab_path = target_rooted_path(&inputs.target, "/etc/fstab");
    if let Err(error) = confined::atomic_write_rooted(top, &fstab_path, rewritten.as_bytes(), 0o644)
    {
        let rollback_succeeded =
            confined::atomic_write_rooted(top, &fstab_path, inputs.fstab_text.as_bytes(), 0o644)
                .is_ok();
        let transaction = FstabTransaction {
            original_path: PathBuf::from("/etc/fstab"),
            backup_path: Some(PathBuf::from("/etc/fstab.catos-repair.backup")),
            temp_path: None,
            atomic_replace_succeeded: false,
            parent_fsynced: false,
            rollback_attempted: true,
            rollback_succeeded,
        };
        return failure_after_created_resources(
            inputs,
            plan.clone(),
            top,
            devices,
            actions,
            &created_subvolumes,
            &created_directories,
            nested_esp_directory_created,
            if rollback_succeeded {
                MountRepairOutcome::VerificationFailed
            } else {
                MountRepairOutcome::RollbackFailed
            },
            "FSTAB_WRITE_FAILED",
            error.message.to_string(),
            Some(transaction),
            None,
        );
    }
    actions.extend(
        plan.fstab_edits
            .iter()
            .cloned()
            .map(|edit| AppliedAction::FstabEdited { edit }),
    );

    let verification = verify_written_target(devices, &inputs.target, &rewritten, top);
    if !verification.mounted {
        let rollback_succeeded =
            confined::atomic_write_rooted(top, &fstab_path, inputs.fstab_text.as_bytes(), 0o644)
                .is_ok();
        let transaction = FstabTransaction {
            original_path: PathBuf::from("/etc/fstab"),
            backup_path: Some(PathBuf::from("/etc/fstab.catos-repair.backup")),
            temp_path: None,
            atomic_replace_succeeded: true,
            parent_fsynced: true,
            rollback_attempted: true,
            rollback_succeeded,
        };
        return failure_after_created_resources(
            inputs,
            plan.clone(),
            top,
            devices,
            actions,
            &created_subvolumes,
            &created_directories,
            nested_esp_directory_created,
            if rollback_succeeded {
                MountRepairOutcome::VerificationFailed
            } else {
                MountRepairOutcome::RollbackFailed
            },
            "VERIFICATION_ROLLBACK",
            "verification failed; original fstab restoration was attempted".into(),
            Some(transaction),
            Some(verification),
        );
    }

    let data_conflict = plan.subvolumes.iter().any(|subvolume| {
        inputs
            .mount_point_observations
            .get(&subvolume.mount_point)
            .and_then(|observation| observation.entry_count)
            .is_some_and(|count| count > 0)
    });
    MountRepairReport {
        target: Some(inputs.target.clone()),
        plan: Some(plan),
        fstab_transaction: Some(FstabTransaction {
            original_path: PathBuf::from("/etc/fstab"),
            backup_path: Some(PathBuf::from("/etc/fstab.catos-repair.backup")),
            temp_path: None,
            atomic_replace_succeeded: true,
            parent_fsynced: true,
            rollback_attempted: false,
            rollback_succeeded: false,
        }),
        actions,
        verification: Some(verification),
        cleanup: MountRepairCleanup::default(),
        final_outcome: if data_conflict {
            MountRepairOutcome::DataConflict
        } else {
            MountRepairOutcome::Repaired
        },
        requires_human_action: data_conflict,
        fully_complete: !data_conflict,
        evidence: vec![Evidence::new(
            "FSTAB_WRITTEN",
            "repair::mount",
            "target fstab replaced atomically after target-local validation",
        )],
        warnings: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn failure_after_created_resources(
    inputs: &MountRepairInputs,
    plan: MountRepairPlan,
    top: &Path,
    devices: &[BlockDevice],
    mut actions: Vec<AppliedAction>,
    created_subvolumes: &[String],
    created_directories: &[String],
    nested_esp_directory_created: bool,
    requested_outcome: MountRepairOutcome,
    evidence_code: &str,
    message: String,
    fstab_transaction: Option<FstabTransaction>,
    verification: Option<MountVerification>,
) -> MountRepairReport {
    let residuals = rollback_created_resources(
        top,
        &inputs.target,
        devices,
        created_subvolumes,
        created_directories,
        nested_esp_directory_created,
        &mut actions,
    );
    let final_outcome = if residuals.is_empty() {
        requested_outcome
    } else {
        MountRepairOutcome::RollbackFailed
    };
    let mut evidence = vec![Evidence::new(evidence_code, "repair::mount", message)];
    for residual in &residuals {
        evidence.push(Evidence::new(
            "ROLLBACK_RESIDUAL",
            "repair::mount",
            residual.clone(),
        ));
    }
    MountRepairReport {
        target: Some(inputs.target.clone()),
        plan: Some(plan),
        fstab_transaction,
        actions,
        verification,
        cleanup: MountRepairCleanup::default(),
        final_outcome,
        requires_human_action: true,
        fully_complete: false,
        evidence,
        warnings: Vec::new(),
    }
}

fn rollback_created_resources(
    top: &Path,
    target: &TargetIdentity,
    devices: &[BlockDevice],
    created_subvolumes: &[String],
    created_directories: &[String],
    nested_esp_directory_created: bool,
    actions: &mut Vec<AppliedAction>,
) -> Vec<String> {
    let mut residuals = Vec::new();
    if nested_esp_directory_created {
        match rollback_nested_esp_mountpoint(top, target, devices) {
            Ok(()) => actions.push(AppliedAction::DirectoryRolledBack {
                mount_point: "/boot/efi".into(),
            }),
            Err(reason) => {
                actions.push(AppliedAction::RollbackResidual {
                    resource: "/boot/efi".into(),
                    reason: reason.clone(),
                });
                residuals.push(format!("/boot/efi: {reason}"));
            }
        }
    }
    for mount_point in created_directories.iter().rev() {
        let rooted = target_rooted_path(target, mount_point);
        match confined::remove_empty_rooted_directory(top, &rooted) {
            Ok(()) => actions.push(AppliedAction::DirectoryRolledBack {
                mount_point: mount_point.clone(),
            }),
            Err(error) => {
                let reason = error.message.to_string();
                actions.push(AppliedAction::RollbackResidual {
                    resource: mount_point.clone(),
                    reason: reason.clone(),
                });
                residuals.push(format!("{mount_point}: {reason}"));
            }
        }
    }
    for subvolume in created_subvolumes.iter().rev() {
        match confined::delete_empty_btrfs_subvolume(top, subvolume) {
            Ok(()) => actions.push(AppliedAction::SubvolumeRolledBack {
                subvol: subvolume.clone(),
            }),
            Err(error) => {
                let reason = error.message.to_string();
                actions.push(AppliedAction::RollbackResidual {
                    resource: subvolume.clone(),
                    reason: reason.clone(),
                });
                residuals.push(format!("{subvolume}: {reason}"));
            }
        }
    }
    residuals
}

fn rollback_nested_esp_mountpoint(
    top: &Path,
    target: &TargetIdentity,
    devices: &[BlockDevice],
) -> Result<(), String> {
    let Some(layout) = target.boot_layout.as_ref() else {
        return Ok(());
    };
    match layout {
        BootMountLayout::SeparateBootAndEsp {
            boot_device,
            esp_mount_point,
            ..
        } if esp_mount_point == "/boot/efi" => {
            let boot = devices
                .iter()
                .find(|device| {
                    device
                        .dev_path
                        .as_deref()
                        .is_some_and(|path| same_block_device(path, boot_device))
                })
                .ok_or_else(|| "separate /boot device disappeared during rollback".to_string())?;
            let _lock =
                DeviceLock::try_acquire(boot_device).map_err(|error| error.message.to_string())?;
            if mountpoint_matches_device(Path::new("/boot"), boot) {
                return confined::remove_empty_rooted_directory(Path::new("/boot"), "/efi")
                    .map_err(|error| error.message.to_string());
            }
            let fstype = boot
                .filesystem
                .as_deref()
                .ok_or_else(|| "separate /boot filesystem type is unknown".to_string())?;
            let source = boot_device
                .to_str()
                .ok_or_else(|| "separate /boot device path is not UTF-8".to_string())?;
            let session_dir = crate::mount::secure_dir::create_session_dir(
                Path::new(crate::mount::secure_dir::SESSION_ROOT_PARENT),
                "mount-repair-boot-rollback",
            )
            .map_err(|error| error.message.to_string())?;
            let mount_point = session_dir.join("boot");
            std::fs::create_dir(&mount_point)
                .map_err(|error| format!("cannot create rollback /boot mountpoint: {error}"))?;
            syscall::mount(
                Some(source),
                &mount_point,
                Some(fstype),
                ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
                None,
            )
            .map_err(|error| format!("cannot mount separate /boot for rollback: {error}"))?;
            let remove_result = confined::remove_empty_rooted_directory(&mount_point, "/efi")
                .map_err(|error| error.message.to_string());
            let unmount_result = syscall::umount2(&mount_point, 0)
                .map_err(|error| format!("cannot unmount rollback /boot: {error}"));
            let session_remove = crate::mount::secure_dir::remove_session_dir(
                Path::new(crate::mount::secure_dir::SESSION_ROOT_PARENT),
                &session_dir,
            )
            .map_err(|error| error.message.to_string());
            remove_result?;
            unmount_result?;
            session_remove
        }
        BootMountLayout::BootBtrfsSubvolume {
            subvolume,
            esp_mount_point: Some(esp_mount_point),
            ..
        } if esp_mount_point == "/boot/efi" => {
            let rooted = format!("{}/efi", subvolume.trim_end_matches('/'));
            confined::remove_empty_rooted_directory(top, &rooted)
                .map_err(|error| error.message.to_string())
        }
        _ => Ok(()),
    }
}

fn mountpoint_matches_device(mount_point: &Path, device: &BlockDevice) -> bool {
    let Some(expected_major_minor) = device.major_minor.as_deref() else {
        return false;
    };
    std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|body| {
            crate::parse::mountinfo::parse_all(&body)
                .into_iter()
                .find(|mount| mount.mount_point == mount_point)
        })
        .is_some_and(|mount| mount.major_minor == expected_major_minor)
}

fn ensure_nested_esp_mountpoint(
    top: &Path,
    target: &TargetIdentity,
    devices: &[BlockDevice],
) -> Result<Option<String>, String> {
    let Some(layout) = target.boot_layout.as_ref() else {
        return Ok(None);
    };
    match layout {
        BootMountLayout::SeparateBootAndEsp {
            boot_device,
            esp_mount_point,
            ..
        } if esp_mount_point == "/boot/efi" => {
            let boot = devices
                .iter()
                .find(|device| {
                    device
                        .dev_path
                        .as_deref()
                        .is_some_and(|path| same_block_device(path, boot_device))
                })
                .ok_or_else(|| "separate /boot device disappeared before repair".to_string())?;
            let fstype = boot
                .filesystem
                .as_deref()
                .ok_or_else(|| "separate /boot filesystem type is unknown".to_string())?;
            let source = boot_device
                .to_str()
                .ok_or_else(|| "separate /boot device path is not UTF-8".to_string())?;
            let _lock =
                DeviceLock::try_acquire(boot_device).map_err(|error| error.message.to_string())?;
            if mountpoint_matches_device(Path::new("/boot"), boot) {
                let fs = RealFilesystem;
                let existed = match fs.rooted_metadata(Path::new("/boot"), Path::new("efi")) {
                    Ok(metadata) if metadata.is_dir && !metadata.is_symlink => true,
                    Ok(_) => {
                        return Err(
                            "mounted separate /boot contains a non-directory efi entry".into()
                        );
                    }
                    Err(crate::error::FsError::NotFound) => false,
                    Err(error) => {
                        return Err(format!("cannot inspect mounted /boot/efi: {error}"));
                    }
                };
                if !existed {
                    confined::create_rooted_directory(Path::new("/boot"), "/efi")
                        .map_err(|error| error.message.to_string())?;
                }
                return Ok((!existed).then(|| "/boot/efi".to_string()));
            }
            let session_dir = crate::mount::secure_dir::create_session_dir(
                Path::new(crate::mount::secure_dir::SESSION_ROOT_PARENT),
                "mount-repair-boot-parent",
            )
            .map_err(|error| error.message.to_string())?;
            let mount_point = session_dir.join("boot");
            std::fs::create_dir(&mount_point)
                .map_err(|error| format!("cannot create temporary /boot mountpoint: {error}"))?;
            if let Err(error) = syscall::mount(
                Some(source),
                &mount_point,
                Some(fstype),
                ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
                None,
            ) {
                let _ = crate::mount::secure_dir::remove_session_dir(
                    Path::new(crate::mount::secure_dir::SESSION_ROOT_PARENT),
                    &session_dir,
                );
                return Err(format!("cannot mount separate /boot read-write: {error}"));
            }
            let fs = RealFilesystem;
            let existed = match fs.rooted_metadata(&mount_point, Path::new("efi")) {
                Ok(metadata) if metadata.is_dir && !metadata.is_symlink => true,
                Ok(_) => {
                    let _ = syscall::umount2(&mount_point, 0);
                    return Err("separate /boot contains a non-directory efi entry".into());
                }
                Err(crate::error::FsError::NotFound) => false,
                Err(error) => {
                    let _ = syscall::umount2(&mount_point, 0);
                    return Err(format!("cannot inspect separate /boot/efi: {error}"));
                }
            };
            let create_result = if existed {
                Ok(())
            } else {
                confined::create_rooted_directory(&mount_point, "/efi")
                    .map_err(|error| error.message.to_string())
            };
            let unmount_result = syscall::umount2(&mount_point, 0)
                .map_err(|error| format!("cannot unmount temporary separate /boot: {error}"));
            let remove_result = crate::mount::secure_dir::remove_session_dir(
                Path::new(crate::mount::secure_dir::SESSION_ROOT_PARENT),
                &session_dir,
            )
            .map_err(|error| error.message.to_string());
            create_result?;
            unmount_result?;
            remove_result?;
            Ok((!existed).then(|| "/boot/efi".to_string()))
        }
        BootMountLayout::BootBtrfsSubvolume {
            subvolume,
            esp_mount_point: Some(esp_mount_point),
            ..
        } if esp_mount_point == "/boot/efi" => {
            let rooted = format!("{}/efi", subvolume.trim_end_matches('/'));
            let physical = top.join(rooted.trim_start_matches('/'));
            let existed = match std::fs::symlink_metadata(&physical) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
                Ok(_) => {
                    return Err("Btrfs boot subvolume contains a non-directory efi entry".into())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(format!("cannot inspect Btrfs boot subvolume: {error}")),
            };
            if !existed {
                confined::create_rooted_directory(top, &rooted)
                    .map_err(|error| error.message.to_string())?;
            }
            Ok((!existed).then(|| "/boot/efi".to_string()))
        }
        _ => Ok(None),
    }
}

fn verify_written_target(
    devices: &[BlockDevice],
    target: &TargetIdentity,
    expected_fstab: &str,
    existing_storage_root: &Path,
) -> MountVerification {
    if target.root_subvol.is_none() {
        return verify_plain_written_target(devices, target, expected_fstab, existing_storage_root);
    }
    verify_fresh_written_target(devices, target, expected_fstab)
}

fn verify_fresh_written_target(
    devices: &[BlockDevice],
    target: &TargetIdentity,
    expected_fstab: &str,
) -> MountVerification {
    let (entries, diagnostics) = parse_all_with_diagnostics(expected_fstab);
    if !diagnostics.is_empty() {
        return MountVerification {
            mounted: false,
            observed_root_fstype: None,
            mounted_targets: Vec::new(),
            failure_message: Some("rewritten fstab did not parse cleanly".into()),
        };
    }
    let session_name = match crate::mount::secure_dir::fresh_session_name("mount-repair-verify") {
        Ok(name) => name,
        Err(error) => {
            return MountVerification {
                mounted: false,
                observed_root_fstype: None,
                mounted_targets: Vec::new(),
                failure_message: Some(error.message.to_string()),
            };
        }
    };
    let session_root = Path::new(crate::mount::session::SESSION_ROOT_PARENT).join(&session_name);
    let plan = match build_mount_plan(PlanInputs {
        session_root,
        devices,
        fstab: &entries,
        include_boot: true,
        include_local: true,
    }) {
        Ok(plan) => plan,
        Err(error) => {
            return MountVerification {
                mounted: false,
                observed_root_fstype: None,
                mounted_targets: Vec::new(),
                failure_message: Some(error.message),
            };
        }
    };
    let mut session = Session::new(session_name, &plan);
    let snapshot = match session.run(&plan) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return MountVerification {
                mounted: false,
                observed_root_fstype: None,
                mounted_targets: Vec::new(),
                failure_message: Some(error.message),
            };
        }
    };
    let root_fstab_matches = RealFilesystem
        .rooted_read_to_string(&snapshot.target_root, Path::new("etc/fstab"))
        .map(|actual| actual == expected_fstab)
        .unwrap_or(false);
    let mounted_targets = snapshot
        .mounts
        .iter()
        .map(|mount| {
            mount
                .target
                .strip_prefix(&snapshot.target_root)
                .ok()
                .filter(|relative| !relative.as_os_str().is_empty())
                .map(|relative| format!("/{}", relative.display()))
                .unwrap_or_else(|| "/".into())
        })
        .collect::<Vec<_>>();
    let observed_root_fstype = snapshot
        .mounts
        .iter()
        .find(|mount| mount.target == snapshot.target_root)
        .map(|mount| mount.fstype.clone());
    let root_type_matches = observed_root_fstype.as_deref() == Some(target.root_fstype.as_str());
    let cleanup = session.cleanup();
    let mounted = root_fstab_matches && root_type_matches && cleanup.all_clean;
    let failure_message = if !root_fstab_matches {
        Some("verification mount did not expose the written fstab".into())
    } else if !root_type_matches {
        Some(format!(
            "verification root fstype mismatch: expected {}, observed {:?}",
            target.root_fstype, observed_root_fstype
        ))
    } else if !cleanup.all_clean {
        Some("verification mount cleanup was incomplete".into())
    } else {
        None
    };
    MountVerification {
        mounted,
        observed_root_fstype,
        mounted_targets,
        failure_message,
    }
}

fn verify_plain_written_target(
    devices: &[BlockDevice],
    target: &TargetIdentity,
    expected_fstab: &str,
    existing_root: &Path,
) -> MountVerification {
    let (entries, diagnostics) = parse_all_with_diagnostics(expected_fstab);
    if !diagnostics.is_empty() {
        return MountVerification {
            mounted: false,
            observed_root_fstype: None,
            mounted_targets: Vec::new(),
            failure_message: Some("rewritten fstab did not parse cleanly".into()),
        };
    }

    let plan_root = existing_root
        .parent()
        .unwrap_or(existing_root)
        .join("plain-verification-plan");
    let plan = match build_mount_plan(PlanInputs {
        session_root: plan_root,
        devices,
        fstab: &entries,
        include_boot: true,
        include_local: true,
    }) {
        Ok(plan) => plan,
        Err(error) => {
            return MountVerification {
                mounted: false,
                observed_root_fstype: None,
                mounted_targets: Vec::new(),
                failure_message: Some(error.message),
            };
        }
    };

    let observed_root_fstype = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|body| {
            crate::parse::mountinfo::parse_all(&body)
                .into_iter()
                .find(|mount| mount.mount_point == existing_root)
                .map(|mount| mount.fstype)
        });
    if observed_root_fstype.as_deref() != Some(target.root_fstype.as_str()) {
        return MountVerification {
            mounted: false,
            observed_root_fstype: observed_root_fstype.clone(),
            mounted_targets: vec!["/".into()],
            failure_message: Some(format!(
                "verification root fstype mismatch: expected {}, observed {:?}",
                target.root_fstype, observed_root_fstype
            )),
        };
    }

    let mut mounted_resources: Vec<(PathBuf, String)> = Vec::new();
    let mut mounted_targets = vec!["/".to_string()];
    let mut steps: Vec<_> = plan.steps.iter().collect();
    steps.sort_by_key(|step| step.order);
    for step in steps {
        if step.target == plan.target_root {
            continue;
        }
        let relative = match step.target.strip_prefix(&plan.target_root) {
            Ok(relative) => relative,
            Err(_) => {
                cleanup_plain_verification_mounts(&mut mounted_resources);
                return MountVerification {
                    mounted: false,
                    observed_root_fstype,
                    mounted_targets,
                    failure_message: Some("verification plan target escaped its root".into()),
                };
            }
        };
        let actual_target = existing_root.join(relative);
        if let Err(error) = validate_existing_mount_target(existing_root, &actual_target) {
            cleanup_plain_verification_mounts(&mut mounted_resources);
            return MountVerification {
                mounted: false,
                observed_root_fstype,
                mounted_targets,
                failure_message: Some(error),
            };
        }
        let logical = if relative.as_os_str().is_empty() {
            "/".to_string()
        } else {
            format!("/{}", relative.display())
        };
        let pre_existing = std::fs::read_to_string("/proc/self/mountinfo")
            .ok()
            .and_then(|body| {
                crate::parse::mountinfo::parse_all(&body)
                    .into_iter()
                    .find(|mount| mount.mount_point == actual_target)
            });
        if let Some(observed) = pre_existing {
            let source_matches =
                if observed.source.starts_with("/dev/") && step.source.starts_with("/dev/") {
                    same_block_device(Path::new(&observed.source), Path::new(&step.source))
                } else {
                    observed.source == step.source
                };
            if observed.fstype != step.fstype || !source_matches {
                cleanup_plain_verification_mounts(&mut mounted_resources);
                return MountVerification {
                    mounted: false,
                    observed_root_fstype,
                    mounted_targets,
                    failure_message: Some(format!(
                        "pre-existing verification mount {logical} does not match fstab: source={} fstype={}",
                        observed.source, observed.fstype
                    )),
                };
            }
            mounted_targets.push(logical);
            continue;
        }
        let options = step.options_string();
        if let Err(error) = syscall::mount(
            Some(&step.source),
            &actual_target,
            Some(&step.fstype),
            ms_flags::MS_RDONLY,
            Some(&options),
        ) {
            cleanup_plain_verification_mounts(&mut mounted_resources);
            return MountVerification {
                mounted: false,
                observed_root_fstype,
                mounted_targets,
                failure_message: Some(format!(
                    "verification mount {} failed: {error}",
                    actual_target.display()
                )),
            };
        }
        mounted_targets.push(logical.clone());
        mounted_resources.push((actual_target, logical));
    }

    let fstab_matches = RealFilesystem
        .rooted_read_to_string(existing_root, Path::new("etc/fstab"))
        .map(|actual| actual == expected_fstab)
        .unwrap_or(false);
    let cleanup_error = cleanup_plain_verification_mounts(&mut mounted_resources);
    let mounted = fstab_matches && cleanup_error.is_none();
    let failure_message = if !fstab_matches {
        Some("verification root did not expose the written fstab".into())
    } else {
        cleanup_error
    };
    MountVerification {
        mounted,
        observed_root_fstype,
        mounted_targets,
        failure_message,
    }
}

fn validate_existing_mount_target(root: &Path, target: &Path) -> Result<(), String> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| "verification target is outside the mounted root".to_string())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err("verification target contains an unsafe path component".into());
        };
        current.push(part);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "verification mountpoint {} cannot be inspected: {error}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "verification mountpoint {} is not a real directory",
                current.display()
            ));
        }
    }
    Ok(())
}

fn cleanup_plain_verification_mounts(mounted: &mut Vec<(PathBuf, String)>) -> Option<String> {
    let mut residual = Vec::new();
    while let Some((target, logical)) = mounted.pop() {
        if let Err(error) = syscall::umount2(&target, 0) {
            let detach = syscall::umount2(&target, crate::mount::syscall::mnt_flags::MNT_DETACH);
            residual.push(match detach {
                Ok(()) => format!(
                    "verification mount {logical} required lazy detach after {error}"
                ),
                Err(detach_error) => format!(
                    "verification mount {logical} could not be unmounted: {error}; detach: {detach_error}"
                ),
            });
        }
    }
    (!residual.is_empty()).then(|| residual.join("; "))
}

fn cleanup_into_mount_repair(
    cleanup: crate::model::recovery::CleanupSummary,
) -> MountRepairCleanup {
    MountRepairCleanup {
        unmounted: cleanup.unmounted,
        residual: cleanup.residual,
        all_clean: cleanup.all_clean,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repair::subvol_decision::SubvolObservation;

    fn target_root_uuid(uuid: &str) -> TargetIdentity {
        TargetIdentity {
            root_device: PathBuf::from("/dev/sda2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some(uuid.into()),
            esp_device: None,
            esp_uuid: None,
            boot_layout: None,
        }
    }

    fn observation_present(subvol: &str) -> SubvolObservation {
        SubvolObservation {
            subvol: subvol.to_string(),
            exists_as_subvol: true,
            exists_as_directory: false,
            exists_as_other: false,
            mount_point_entry_count: Some(0),
        }
    }

    fn observation_missing(subvol: &str) -> SubvolObservation {
        SubvolObservation {
            subvol: subvol.to_string(),
            exists_as_subvol: false,
            exists_as_directory: false,
            exists_as_other: false,
            mount_point_entry_count: None,
        }
    }

    fn all_standard_present() -> Vec<SubvolObservation> {
        crate::model::mount_repair::CATOS_STANDARD_SUBVOLS
            .iter()
            .map(|s| observation_present(s.subvol))
            .collect()
    }

    fn selection_device(path: &str, mount_point: Option<&str>) -> BlockDevice {
        BlockDevice {
            name: Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("device")
                .to_string(),
            dev_path: Some(PathBuf::from(path)),
            major_minor: Some("8:2".into()),
            parent: "sda".into(),
            class: DeviceClass::Partition,
            disk_kind: crate::model::storage::DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: Some(2),
            size_sectors: Some(1_000_000),
            read_only: false,
            removable: false,
            filesystem: Some("ext4".into()),
            uuid: Some("root-uuid".into()),
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: mount_point.map(PathBuf::from),
            mounts: mount_point
                .map(|point| {
                    vec![crate::model::storage::MountObservation {
                        mount_point: PathBuf::from(point),
                        root: PathBuf::from("/"),
                        fstype: "ext4".into(),
                        read_only: false,
                    }]
                })
                .unwrap_or_default(),
            mounted_before_session: mount_point.is_some(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn boot_runtime_bind_recurses_only_for_dev_and_proc() {
        for source in ["/dev", "/proc"] {
            assert_ne!(boot_runtime_bind_flags(source) & ms_flags::MS_REC, 0);
        }
        for source in ["/sys", "/run"] {
            assert_eq!(boot_runtime_bind_flags(source), ms_flags::MS_BIND);
        }
    }

    #[test]
    fn explicit_running_root_is_selectable_but_other_mounted_device_is_not() {
        let running = selection_device("/dev/sda2", Some("/"));
        let data = selection_device("/dev/sdb1", Some("/data"));
        assert!(is_running_root_device(&running));
        assert!(!is_running_root_device(&data));
        assert!(select_cli_root(&[running], Some("/dev/sda2")).is_some());
        assert!(select_cli_root(&[data], Some("/dev/sdb1")).is_none());
    }

    // ---- Spec § 十一 → fstab 修复 ----

    #[test]
    fn clean_fstab_diagnoses_no_problems() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n\
                     UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: all_standard_present(),
            },
            mount_point_observations: HashMap::new(),
        };
        let problems = diagnose(&inputs);
        // /@ and /@home present; other standard subvols are missing
        // but they are not CatOS-confirmed and have no fstab history,
        // so they do NOT surface as problems.
        let root_problems: Vec<_> = problems
            .iter()
            .filter(|p| matches!(p, MountProblem::RootWrongSubvol { .. }))
            .collect();
        assert!(root_problems.is_empty());
    }

    #[test]
    fn directory_plan_never_contains_the_target_root() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root / btrfs defaults,subvol=/@ 0 0\n".into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: all_standard_present(),
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        assert!(plan
            .directories
            .iter()
            .all(|directory| directory.mount_point != "/"));
    }

    #[test]
    fn wrong_root_uuid_surfaces_problem() {
        let fstab = "UUID=wrong  /  btrfs  defaults,subvol=/@  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("correct"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let problems = diagnose(&inputs);
        assert!(problems
            .iter()
            .any(|p| matches!(p, MountProblem::RootUuidMismatch { .. })));
    }

    #[test]
    fn wrong_root_subvol_surfaces_problem_and_plan_fixes_it() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@wrong  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        assert!(plan
            .problems
            .iter()
            .any(|p| matches!(p, MountProblem::RootWrongSubvol { .. })));
        // The plan must include a full entry replace for the root.
        assert!(plan
            .fstab_edits
            .iter()
            .any(|e| matches!(e, PlannedFstabEdit::ReplaceEntry { line: 1, .. })));
    }

    #[test]
    fn missing_standard_entry_on_confirmed_catos_surfaces_and_appends() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@"), observation_missing("/@home")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        assert!(plan
            .problems
            .iter()
            .any(|p| matches!(p, MountProblem::MissingStandardEntry { mount_point, .. } if mount_point == "/home")));
        assert!(plan.fstab_edits.iter().any(|e| matches!(
            e,
            PlannedFstabEdit::AppendEntry { new_line, .. } if new_line.contains("/home")
        )));
    }

    #[test]
    fn duplicate_mount_point_surfaces_and_no_append() {
        let fstab = "UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n\
                     UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@home")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        assert!(plan
            .problems
            .iter()
            .any(|p| matches!(p, MountProblem::DuplicateMountPoint { mount_point } if mount_point == "/home")));
        // We must NOT append a third entry.
        assert!(!plan
            .fstab_edits
            .iter()
            .any(|e| matches!(e, PlannedFstabEdit::AppendEntry { .. })));
    }

    #[test]
    fn swap_entries_are_never_modified() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n\
                     UUID=swap  none  swap  defaults  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        // No edit targets the swap line.
        assert!(!plan.fstab_edits.iter().any(|e| matches!(
            e,
            PlannedFstabEdit::ReplaceSource { line: 2, .. }
                | PlannedFstabEdit::ReplaceEntry { line: 2, .. }
                | PlannedFstabEdit::DropDuplicate { line: 2, .. }
        )));
    }

    // ---- Spec § 十一 → 事务 / 回滚 at model level ----

    #[test]
    fn detect_drift_flags_device_change() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n".into(),
            target: target_root_uuid("root"),
            ..Default::default()
        };
        let plan = build_plan(&inputs);
        let mut new_target = inputs.target.clone();
        new_target.root_uuid = Some("different".into());
        let drift = detect_drift(&plan, &new_target, &plan.fstab_digest);
        assert_eq!(drift, Some(MountRepairOutcome::DeviceChanged));
    }

    #[test]
    fn detect_drift_flags_fstab_change() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n".into(),
            target: target_root_uuid("root"),
            ..Default::default()
        };
        let plan = build_plan(&inputs);
        let new_digest = digest_of("UUID=changed  /  btrfs  defaults  0 0\n");
        let drift = detect_drift(&plan, &inputs.target, &new_digest);
        assert_eq!(drift, Some(MountRepairOutcome::FstabChanged));
    }

    #[test]
    fn detect_drift_returns_none_when_no_change() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n".into(),
            target: target_root_uuid("root"),
            ..Default::default()
        };
        let plan = build_plan(&inputs);
        let drift = detect_drift(&plan, &inputs.target, &plan.fstab_digest);
        assert!(drift.is_none());
    }

    #[test]
    fn apply_in_memory_preserves_comments_and_fixes_root_subvol() {
        let fstab = "# header\n\
                     UUID=root  /  btrfs  defaults,subvol=/@wrong  0 0\n\
                     \n\
                     # home\n\
                     UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@"), observation_present("/@home")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        let new_text = apply_in_memory(&inputs.fstab_text, &plan).unwrap();
        // Comments preserved.
        assert!(new_text.contains("# header"));
        assert!(new_text.contains("# home"));
        // Blank line preserved.
        assert!(new_text.contains("\n\n"));
        // Root subvol fixed.
        assert!(new_text.contains("subvol=/@  0 0"));
        assert!(!new_text.contains("@wrong"));
        // /home untouched.
        assert!(new_text.contains("UUID=root  /home  btrfs  defaults,subvol=/@home  0 0"));
    }

    #[test]
    fn root_entry_fix_retains_the_discovered_uuid_when_subvol_is_also_wrong() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=old  /  btrfs  defaults,compress=zstd:3,subvol=/wrong  0 1\n".into(),
            target: target_root_uuid("new"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };

        let rewritten = apply_in_memory(&inputs.fstab_text, &build_plan(&inputs)).unwrap();

        assert!(rewritten.contains("UUID=new  /  btrfs  defaults,compress=zstd:3,subvol=/@  0 1"));
        assert!(!rewritten.contains("UUID=old"));
    }

    #[test]
    fn snapshots_wrong_subvol_rewrites_the_snapshots_entry() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n\
                         UUID=root  /.snapshots  btrfs  defaults,subvol=/@wrong  0 0\n"
                .into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![
                    observation_present("/@"),
                    observation_present("/@snapshots"),
                ],
            },
            mount_point_observations: HashMap::new(),
        };

        let plan = build_plan(&inputs);
        assert!(plan
            .problems
            .iter()
            .any(|problem| matches!(problem, MountProblem::SnapshotsWrongSubvol { .. })));

        let rewritten = apply_in_memory(&inputs.fstab_text, &plan).unwrap();
        assert!(rewritten.contains("/.snapshots  btrfs  defaults,subvol=/@snapshots  0 0"));
        assert!(!rewritten.contains("subvol=/@wrong"));
    }

    #[test]
    fn run_diagnosis_marks_clean_when_no_problems() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let report = run_mount_repair_diagnosis(inputs, true);
        assert_eq!(report.final_outcome, MountRepairOutcome::Clean);
        assert!(report.fully_complete);
    }

    #[test]
    fn run_diagnosis_marks_data_conflict_as_partial() {
        // Spec § 五 / § 十一: when mount-point has data, the result
        // MUST NOT be reported as fully repaired.
        let fstab = "UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@"), observation_missing("/@home")],
            },
            mount_point_observations: {
                let mut m = HashMap::new();
                m.insert(
                    "/home".to_string(),
                    MountPointObservation {
                        exists: true,
                        is_directory: true,
                        entry_count: Some(5),
                        ..Default::default()
                    },
                );
                m
            },
        };
        let report = run_mount_repair_diagnosis(inputs, true);
        assert_eq!(report.final_outcome, MountRepairOutcome::PartiallyRepaired);
        assert!(!report.fully_complete);
        assert!(report.requires_human_action);
    }

    #[test]
    fn unauthorised_run_does_not_attempt_apply() {
        let fstab = "UUID=wrong  /  btrfs  defaults,subvol=/@wrong  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("correct"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let report = run_mount_repair_diagnosis(inputs, false);
        // Diagnosis-only path: outcome is Clean (we didn't change
        // anything) but requires_human_action reflects that problems
        // exist.
        assert_eq!(report.final_outcome, MountRepairOutcome::Clean);
        assert!(report.requires_human_action);
        assert!(!report.fully_complete);
        assert!(report.actions.is_empty());
    }
}
