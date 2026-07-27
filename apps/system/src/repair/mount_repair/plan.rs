//! Plan construction: combine diagnosis with subvol decisions and
//! fstab edit plan to produce an immutable MountRepairPlan.
use std::collections::HashMap;
use crate::shared::model::evidence::Evidence;
use crate::shared::model::fstab::FstabSource;
use crate::shared::model::mount_repair::{
    BootMountLayout, FstabDigest, FstabTransaction, MountProblem, MountRepairPlan,
    PlannedDirectory, PlannedFstabEdit, PlannedSubvolume, default_mount_options,
};
use crate::target::model::BlockDevice;
use crate::shared::parse::fstab::{parse_all_with_diagnostics, FstabEntry, FstabEntryKind};
use crate::repair::fstab_edit::apply_edits;
use crate::repair::path_safety::{validate_directory_creation, PathObservation};
use crate::repair::subvol_decision::{decide_all, history_from_entries, SubvolDecision};
use super::{diagnose, is_fat_fstype, MountPointObservation, MountRepairInputs};

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

