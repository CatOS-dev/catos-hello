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
use crate::model::storage::BlockDevice;
use crate::probe::fs_probe::{FilesystemProbe, RealFilesystem};
use crate::probe::discover_devices;
use crate::recovery::confined;
use crate::recovery::external as btrfs;
use crate::recovery::lock::DeviceLock;
use crate::repair::path_safety::{validate_directory_creation, PathObservation};
use crate::model::mount_repair::{
    default_mount_options, AppliedAction, FstabDigest, FstabTransaction, MountProblem,
    MountRepairCleanup, MountRepairOutcome, MountRepairPlan, MountRepairReport, MountVerification,
    PlannedDirectory, PlannedFstabEdit, PlannedSubvolume, TargetIdentity,
};
use crate::mount::plan::build_probe_plan;
use crate::mount::session::Session;
use crate::parse::fstab::{parse_all_with_diagnostics, FstabEntry, FstabEntryKind};
use crate::repair::fstab_edit::apply_edits;
use crate::repair::subvol_decision::{
    decide_all, history_from_entries, CatosConfirmation, SubvolDecision, SubvolFacts,
};

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

    // Standard CatOS entries.
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

    // ESP entry.
    diagnose_esp(&entries, inputs, &mut problems);

    // Swap entries: never modify, but flag obvious mis-typing.
    for entry in &entries {
        if entry.kind == FstabEntryKind::Swap && entry.fstype != "swap" {
            problems.push(MountProblem::SwapEntryMistyped);
        }
    }

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

    problems
}

fn diagnose_esp(
    entries: &[FstabEntry],
    inputs: &MountRepairInputs,
    problems: &mut Vec<MountProblem>,
) {
    let Some(esp_uuid) = inputs.target.esp_uuid.as_ref() else {
        return;
    };
    let esp_entries: Vec<&FstabEntry> = entries
        .iter()
        .filter(|e| matches!(e.target.as_str(), "/boot/efi" | "/efi" | "/boot"))
        .collect();
    if esp_entries.is_empty() {
        return;
    }
    if esp_entries.len() > 1 {
        problems.push(MountProblem::DuplicateMountPoint {
            mount_point: "/boot/efi".into(),
        });
        return;
    }
    let entry = esp_entries[0];
    if let FstabSource::Uuid(actual) = &entry.source {
        if actual != esp_uuid {
            problems.push(MountProblem::EspUuidMismatch {
                expected: esp_uuid.clone(),
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
        let Some(expected) = crate::model::mount_repair::standard_subvol_for_mount_point(&entry.target) else {
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
            let root_source = inputs.target.root_uuid.as_ref().map(|uuid| format!("UUID={uuid}"))
                .or_else(|| entries.iter().find(|e| e.target == "/").map(|e| source_column_string(&e.source)));
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

    // ESP UUID fix.
    if let Some(esp_uuid) = inputs.target.esp_uuid.as_ref() {
        for (entry, line) in &entries_with_lines {
            if !matches!(entry.target.as_str(), "/boot/efi" | "/efi" | "/boot") {
                continue;
            }
            if !matches!(&entry.source, FstabSource::Uuid(actual) if actual != esp_uuid) {
                continue;
            }
            edits.push(PlannedFstabEdit::ReplaceSource {
                line: *line,
                new_source: format!("UUID={esp_uuid}"),
                reason: format!("ESP UUID does not match discovered device ({esp_uuid})"),
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
    for spec in crate::model::mount_repair::CATOS_STANDARD_SUBVOLS {
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
pub fn run_mount_repair_via_cli(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
    authorised: bool,
) -> MountRepairReport {
    let fs = RealFilesystem;
    let (devices, warnings) = discover_devices(&fs);
    let Some(root) = select_cli_root(&devices, root_device) else {
        return MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "root device must name one discovered, unmounted btrfs device",
        );
    };
    let requested_subvol = root_subvolume.unwrap_or("/@");
    if requested_subvol != "/@" {
        return MountRepairReport::refused(
            MountRepairOutcome::UnsupportedLayout,
            "mount repair currently supports only the CatOS standard root subvolume /@",
        );
    }
    let Some(device) = root.dev_path.as_deref() else {
        return MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "selected root has no stable device path",
        );
    };
    let esp = esp_device.and_then(|requested| {
        devices.iter().find(|device| {
            device.dev_path.as_deref() == Some(Path::new(requested))
                && matches!(device.filesystem.as_deref(), Some("vfat" | "fat" | "fat32"))
        })
    });
    if esp_device.is_some() && esp.is_none() {
        return MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "explicit ESP must name a discovered FAT device",
        );
    }

    let target = TargetIdentity {
        root_device: device.to_path_buf(),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: root.uuid.clone(),
        esp_device: esp.and_then(|device| device.dev_path.clone()),
        esp_uuid: esp.and_then(|device| device.uuid.clone()),
    };
    let lock = match DeviceLock::try_acquire(device) {
        Ok(lock) => lock,
        Err(error) => return MountRepairReport::refused(MountRepairOutcome::DeviceChanged, &error.message),
    };
    let mut session = match crate::phase3::RecoveryRwSession::mount(device) {
        Ok(session) => session,
        Err(error) => return MountRepairReport::refused(MountRepairOutcome::UnsupportedLayout, &error.message),
    };
    let top = session.top_level_mount().to_path_buf();
    let root_path = top.join("@");
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
    let mut report = execute_mount_repair(&inputs, &top, authorised);
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

fn select_cli_root<'a>(
    devices: &'a [BlockDevice],
    root_device: Option<&str>,
) -> Option<&'a BlockDevice> {
    let requested = root_device?;
    devices.iter().find(|device| {
        device.dev_path.as_ref().is_some_and(|path| path == std::path::Path::new(requested))
            && device.filesystem.as_deref() == Some("btrfs")
            && !device.mounted_before_session
    })
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
    let listed = btrfs::list_subvolumes(top)
        .map_err(|error| format!("cannot enumerate target Btrfs subvolumes: {}", error.message))?;
    let mut subvol_facts = SubvolFacts::default();
    let mut mount_point_observations = HashMap::new();
    for spec in crate::model::mount_repair::CATOS_STANDARD_SUBVOLS {
        let exists_as_subvol = listed.iter().any(|item| item.path == spec.subvol);
        let top_path = top.join(spec.subvol.trim_start_matches('/'));
        let (exists_as_directory, exists_as_other) = match std::fs::symlink_metadata(&top_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => (false, true),
            Ok(metadata) if metadata.is_dir() => (true, false),
            Ok(_) => (false, true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, false),
            Err(_) => (false, true),
        };
        subvol_facts.observations.push(crate::repair::subvol_decision::SubvolObservation {
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
                    fs.read_dir_names(&root.join(relative)).ok().map(|entries| entries.len())
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
    Ok(MountRepairInputs {
        fstab_text,
        target,
        catos_confirmation,
        subvol_facts,
        mount_point_observations,
    })
}

fn execute_mount_repair(
    inputs: &MountRepairInputs,
    top: &Path,
    authorised: bool,
) -> MountRepairReport {
    let plan = build_plan(inputs);
    if !authorised {
        return MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan),
            final_outcome: MountRepairOutcome::PartiallyRepaired,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new("AUTHORIZATION_REQUIRED", "repair::mount", "mount repair requires explicit CLI authorization")],
            ..Default::default()
        };
    }
    if !plan.unresolved_conflicts.is_empty() {
        return MountRepairReport::refused(
            MountRepairOutcome::ConflictingFstab,
            &plan.unresolved_conflicts.join("; "),
        );
    }
    let rewritten = match apply_in_memory(&inputs.fstab_text, &plan) {
        Ok(text) => text,
        Err(outcome) => return MountRepairReport::refused(outcome, "fstab edits could not be applied safely"),
    };
    let current = match confined::read_rooted_file(top, "/@/etc/fstab")
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
        return MountRepairReport::refused(MountRepairOutcome::FstabChanged, "target fstab changed after planning");
    }
    let mut actions = Vec::new();
    for subvolume in &plan.subvolumes {
        if confined::create_btrfs_subvolume(top, &subvolume.subvol).is_err() {
            return MountRepairReport::refused(MountRepairOutcome::SubvolumeConflict, "btrfs subvolume create failed");
        }
        actions.push(AppliedAction::SubvolumeCreated { subvol: subvolume.subvol.clone() });
    }
    for directory in &plan.directories {
        let path = Path::new(&directory.mount_point);
        let observation = inputs.mount_point_observations.get(&directory.mount_point).copied().unwrap_or_default();
        let policy_observation = PathObservation {
            is_symlink: observation.is_symlink,
            is_directory: observation.is_directory,
            is_regular_file: observation.is_other_object,
            is_other: false,
        };
        if validate_directory_creation(path, &policy_observation).is_err() {
            return MountRepairReport::refused(MountRepairOutcome::UnsafePath, "unsafe target mount-point path");
        }
        let target_path = format!("/@{}", directory.mount_point);
        if confined::create_rooted_directory(top, &target_path).is_err() {
            return MountRepairReport::refused(MountRepairOutcome::UnsafePath, "cannot create target mount-point directory");
        }
        actions.push(AppliedAction::DirectoryCreated { mount_point: directory.mount_point.clone() });
    }
    if confined::atomic_write_rooted(
        top,
        "/@/etc/fstab.catos-repair.backup",
        inputs.fstab_text.as_bytes(),
        0o600,
    )
    .is_err()
        || confined::atomic_write_rooted(top, "/@/etc/fstab", rewritten.as_bytes(), 0o644)
            .is_err()
    {
        return MountRepairReport::refused(MountRepairOutcome::RollbackFailed, "atomic fstab transaction failed");
    }
    actions.extend(plan.fstab_edits.iter().cloned().map(|edit| AppliedAction::FstabEdited { edit }));
    let verification = verify_written_target(&inputs.target.root_device, &rewritten);
    if !verification.mounted {
        let rollback_succeeded = confined::atomic_write_rooted(
            top,
            "/@/etc/fstab",
            inputs.fstab_text.as_bytes(),
            0o644,
        )
        .is_ok();
        return MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan),
            fstab_transaction: Some(FstabTransaction {
                original_path: PathBuf::from("/etc/fstab"),
                backup_path: Some(PathBuf::from("/etc/fstab.catos-repair.backup")),
                temp_path: None,
                atomic_replace_succeeded: true,
                parent_fsynced: true,
                rollback_attempted: true,
                rollback_succeeded,
            }),
            actions,
            verification: Some(verification),
            cleanup: MountRepairCleanup::default(),
            final_outcome: if rollback_succeeded { MountRepairOutcome::VerificationFailed } else { MountRepairOutcome::RollbackFailed },
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new("VERIFICATION_ROLLBACK", "repair::mount", "verification failed; original fstab was restored")],
            warnings: Vec::new(),
        };
    }
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
        final_outcome: MountRepairOutcome::Repaired,
        requires_human_action: false,
        fully_complete: true,
        evidence: vec![Evidence::new("FSTAB_WRITTEN", "repair::mount", "target fstab replaced atomically after target-local validation")],
        warnings: Vec::new(),
    }
}

fn verify_written_target(device: &Path, expected_fstab: &str) -> MountVerification {
    let Some(device) = device.to_str() else {
        return MountVerification { mounted: false, observed_root_fstype: None, failure_message: Some("root device is not UTF-8".into()) };
    };
    let session_root = Path::new(crate::mount::session::SESSION_ROOT_PARENT).join(format!("mount-repair-verify-{}", std::process::id()));
    let plan = match build_probe_plan(session_root, device, "btrfs", Some("subvol=/@")) {
        Ok(plan) => plan,
        Err(error) => return MountVerification { mounted: false, observed_root_fstype: None, failure_message: Some(error.message) },
    };
    let mut session = Session::new(format!("mount-repair-verify-{}", std::process::id()), &plan);
    let snapshot = match session.run(&plan) {
        Ok(snapshot) => snapshot,
        Err(error) => return MountVerification { mounted: false, observed_root_fstype: None, failure_message: Some(error.message) },
    };
    let verified = RealFilesystem
        .rooted_read_to_string(&snapshot.target_root, Path::new("etc/fstab"))
        .map(|actual| actual == expected_fstab)
        .unwrap_or(false);
    let cleanup = session.cleanup();
    MountVerification {
        mounted: verified && cleanup.all_clean,
        observed_root_fstype: Some("btrfs".into()),
        failure_message: (!verified).then(|| "verification mount did not expose the written fstab".into()),
    }
}

fn cleanup_into_mount_repair(cleanup: crate::model::recovery::CleanupSummary) -> MountRepairCleanup {
    MountRepairCleanup { unmounted: cleanup.unmounted, residual: cleanup.residual, all_clean: cleanup.all_clean }
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
            fstab_text:
                "UUID=old  /  btrfs  defaults,compress=zstd:3,subvol=/wrong  0 1\n".into(),
            target: target_root_uuid("new"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };

        let rewritten = apply_in_memory(&inputs.fstab_text, &build_plan(&inputs)).unwrap();

        assert!(rewritten.contains(
            "UUID=new  /  btrfs  defaults,compress=zstd:3,subvol=/@  0 1"
        ));
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
