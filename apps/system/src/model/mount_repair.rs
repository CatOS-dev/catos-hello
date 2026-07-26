//! Mount-configuration repair data model. Pure data + serde, no I/O.
//!
//! This is the structured result of `catos-repair mount`. It is NOT a
//! `RecoveryPlan`, NOT a phase-2 read-only `MountPlan`, and NOT an
//! `FsRepairReport`. It is its own first-class result so:
//!
//! * Doctor's future mount diagnosis can reuse the read-only
//!   [`MountRepairPlan::diagnose`] shape without inheriting "apply"
//!   semantics.
//! * Human and JSON output render the SAME [`MountRepairReport`], so
//!   they cannot diverge on the final outcome or audit trail.
//!
//! ## Design rules
//!
//! * Every individual edit/subvolume/directory action is recorded.
//! * `final_outcome` is the single source of truth for "did it work?".
//! * `cleanup` reports verbatim what was unmounted and what residual
//!   mounts (if any) remained. A session that fails cleanup MUST NOT
//!   report a clean outcome.
//! * The plan binds to disk facts (root identity, fstab digest) at
//!   build time. Any drift detected before apply MUST abort the plan.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::evidence::Evidence;
use crate::model::inspection::Warning;

// ---------------------------------------------------------------------------
// CatOS standard btrfs layout (single source of truth)
// ---------------------------------------------------------------------------

/// One row of the CatOS Calamares standard btrfs subvolume layout.
/// Mounted at `mount_point` via subvolume `subvol` (relative to the
/// btrfs top level, e.g. `/@home`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatosSubvolSpec {
    pub mount_point: &'static str,
    pub subvol: &'static str,
}

/// The canonical CatOS standard btrfs subvolume layout. Used by the
/// fstab editor, the subvolume-rebuild decision, and the mount-point
/// directory creator. Mirrors the CatOS Calamares config; do NOT
/// improvise an alternate layout.
pub const CATOS_STANDARD_SUBVOLS: &[CatosSubvolSpec] = &[
    CatosSubvolSpec {
        mount_point: "/",
        subvol: "/@",
    },
    CatosSubvolSpec {
        mount_point: "/home",
        subvol: "/@home",
    },
    CatosSubvolSpec {
        mount_point: "/root",
        subvol: "/@root",
    },
    CatosSubvolSpec {
        mount_point: "/srv",
        subvol: "/@srv",
    },
    CatosSubvolSpec {
        mount_point: "/var/cache",
        subvol: "/@cache",
    },
    CatosSubvolSpec {
        mount_point: "/var/tmp",
        subvol: "/@tmp",
    },
    CatosSubvolSpec {
        mount_point: "/var/log",
        subvol: "/@log",
    },
    CatosSubvolSpec {
        mount_point: "/.snapshots",
        subvol: "/@snapshots",
    },
];

/// Look up the standard subvolume path for a given mount point.
pub fn standard_subvol_for_mount_point(mount_point: &str) -> Option<&'static str> {
    CATOS_STANDARD_SUBVOLS
        .iter()
        .find(|row| row.mount_point == mount_point)
        .map(|row| row.subvol)
}

/// Look up the standard mount point for a given subvolume path.
pub fn standard_mount_point_for_subvol(subvol: &str) -> Option<&'static str> {
    CATOS_STANDARD_SUBVOLS
        .iter()
        .find(|row| row.subvol == subvol)
        .map(|row| row.mount_point)
}

/// Default CatOS mount options per filesystem type. Mirrors the
/// Calamares config; do NOT improvise alternate option strings.
pub fn default_mount_options(fstype: &str) -> Option<&'static str> {
    match fstype {
        "btrfs" => Some("defaults,noatime,compress=zstd,commit=120"),
        "ext4" => Some("defaults,noatime,commit=60"),
        "xfs" => Some("defaults,lazytime,noatime,attr2,inode64,logbsize=256k,noquota"),
        "f2fs" => Some("defaults,compress_algorithm=lz4,compress_chksum,gc_merge,lazytime"),
        "vfat" | "fat" | "exfat" => Some("defaults,umask=0077"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Final outcome taxonomy
// ---------------------------------------------------------------------------

/// Single source of truth for "what happened" during a mount repair.
/// Each variant maps to a stable snake_case string in JSON. Adding
/// variants is backward-compatible; renaming is NOT.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MountRepairOutcome {
    /// fstab and standard layout already correct; no change needed.
    Clean,
    /// Plan applied successfully; fstab rewritten atomically; missing
    /// subvolumes and mount points created; verification mount
    /// succeeded; cleanup complete.
    Repaired,
    /// Some but not all planned actions completed. The user must
    /// inspect.
    PartiallyRepaired,
    /// Refused: target could not be uniquely identified.
    AmbiguousTarget,
    /// Refused: target is not a CatOS system (no reliable os-release
    /// evidence).
    NotCatos,
    /// Refused or skipped: a mount-point path was unsafe (symlink
    /// escape, magic link, non-directory object, hostile target root).
    UnsafePath,
    /// Refused: fstab had conflicting entries for the same mount
    /// point and the editor refuses to guess.
    ConflictingFstab,
    /// Aborted: target identity changed between plan and apply.
    DeviceChanged,
    /// Aborted: fstab changed between plan and apply.
    FstabChanged,
    /// Refused or partially done: a needed subvolume could not be
    /// created because the mount-point path already holds another
    /// filesystem object.
    SubvolumeConflict,
    /// Partially done: a mount-point directory had pre-existing data
    /// that we are NOT authorised to migrate. Subvolume created,
    /// fstab fixed, but data was left in place and reported.
    DataConflict,
    /// Plan applied but verification mount failed. fstab may be in a
    /// worse state; user must inspect.
    VerificationFailed,
    /// Verification failed AND rollback to the original fstab also
    /// failed. The user is in a degraded state.
    RollbackFailed,
    /// Cleanup of session-created mounts did not complete. fstab may
    /// be correct but the namespace is dirty.
    CleanupIncomplete,
    /// Target layout is one we deliberately do not support in this
    /// stage (e.g. multiple ESPs, separate /boot subvolume).
    UnsupportedLayout,
    /// Catch-all for an internal error that prevented us from
    /// producing a meaningful result.
    #[default]
    Unknown,
}

impl MountRepairOutcome {
    /// Stable snake_case code, identical to the serde form.
    pub fn code(self) -> &'static str {
        match self {
            MountRepairOutcome::Clean => "clean",
            MountRepairOutcome::Repaired => "repaired",
            MountRepairOutcome::PartiallyRepaired => "partially_repaired",
            MountRepairOutcome::AmbiguousTarget => "ambiguous_target",
            MountRepairOutcome::NotCatos => "not_catos",
            MountRepairOutcome::UnsafePath => "unsafe_path",
            MountRepairOutcome::ConflictingFstab => "conflicting_fstab",
            MountRepairOutcome::DeviceChanged => "device_changed",
            MountRepairOutcome::FstabChanged => "fstab_changed",
            MountRepairOutcome::SubvolumeConflict => "subvolume_conflict",
            MountRepairOutcome::DataConflict => "data_conflict",
            MountRepairOutcome::VerificationFailed => "verification_failed",
            MountRepairOutcome::RollbackFailed => "rollback_failed",
            MountRepairOutcome::CleanupIncomplete => "cleanup_incomplete",
            MountRepairOutcome::UnsupportedLayout => "unsupported_layout",
            MountRepairOutcome::Unknown => "unknown",
        }
    }

    /// `true` iff the outcome represents a successful end state.
    pub fn is_success(self) -> bool {
        matches!(
            self,
            MountRepairOutcome::Clean
                | MountRepairOutcome::Repaired
                | MountRepairOutcome::PartiallyRepaired
        )
    }

    /// `true` iff the outcome means we deliberately refused to act.
    pub fn is_refusal(self) -> bool {
        matches!(
            self,
            MountRepairOutcome::AmbiguousTarget
                | MountRepairOutcome::NotCatos
                | MountRepairOutcome::UnsafePath
                | MountRepairOutcome::ConflictingFstab
                | MountRepairOutcome::SubvolumeConflict
                | MountRepairOutcome::UnsupportedLayout
        )
    }
}

// ---------------------------------------------------------------------------
// Diagnosis problem taxonomy (read-only; shared with Doctor)
// ---------------------------------------------------------------------------

/// One diagnosed fstab/layout problem. Shared between the read-only
/// diagnosis surface and the repair orchestrator so Doctor and
/// `catos-repair mount` cannot disagree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MountProblem {
    /// fstab could not be parsed (e.g. malformed line).
    UnparseableLine { line: usize, reason: String },
    /// No entry for `/` was found.
    MissingRootEntry,
    /// Root entry's source could not be resolved to a unique device.
    RootSourceUnresolvable,
    /// Root entry's UUID does not match the discovered root device.
    RootUuidMismatch { expected: String, actual: String },
    /// Root btrfs entry does not point at subvol=/@.
    RootWrongSubvol { actual: String },
    /// A non-root standard btrfs entry points at the wrong subvolume.
    StandardWrongSubvol {
        mount_point: String,
        expected: String,
        actual: String,
    },
    /// A standard CatOS subvolume entry is missing from fstab.
    MissingStandardEntry { mount_point: String, subvol: String },
    /// `/.snapshots` does not point at `/@snapshots`.
    SnapshotsWrongSubvol { actual: String },
    /// ESP entry's UUID does not match the discovered ESP.
    EspUuidMismatch { expected: String, actual: String },
    /// ESP entry's mount point disagrees with what the target
    /// actually uses.
    EspMountPointMismatch { expected: String, actual: String },
    /// Multiple entries resolve to the same mount point.
    DuplicateMountPoint { mount_point: String },
    /// A swap entry was misclassified (defensive; we never modify
    /// swap entries).
    SwapEntryMistyped,
    /// A standard subvolume referenced by fstab does not exist on
    /// disk.
    MissingSubvolume { subvol: String },
    /// A standard mount-point directory does not exist.
    MissingMountPoint { mount_point: String },
    /// A mount-point path is unsafe (symlink, magic link, non-dir).
    UnsafeMountPoint { mount_point: String, reason: String },
    /// Multiple ESP candidates were discovered; we cannot pick one
    /// safely.
    AmbiguousEsp { candidates: Vec<String> },
    /// fstab source is on a device that no longer exists.
    StaleSource { source: String },
}

impl MountProblem {
    pub fn code(&self) -> &'static str {
        match self {
            MountProblem::UnparseableLine { .. } => "unparseable_line",
            MountProblem::MissingRootEntry => "missing_root_entry",
            MountProblem::RootSourceUnresolvable => "root_source_unresolvable",
            MountProblem::RootUuidMismatch { .. } => "root_uuid_mismatch",
            MountProblem::RootWrongSubvol { .. } => "root_wrong_subvol",
            MountProblem::StandardWrongSubvol { .. } => "standard_wrong_subvol",
            MountProblem::MissingStandardEntry { .. } => "missing_standard_entry",
            MountProblem::SnapshotsWrongSubvol { .. } => "snapshots_wrong_subvol",
            MountProblem::EspUuidMismatch { .. } => "esp_uuid_mismatch",
            MountProblem::EspMountPointMismatch { .. } => "esp_mount_point_mismatch",
            MountProblem::DuplicateMountPoint { .. } => "duplicate_mount_point",
            MountProblem::SwapEntryMistyped => "swap_entry_mistyped",
            MountProblem::MissingSubvolume { .. } => "missing_subvolume",
            MountProblem::MissingMountPoint { .. } => "missing_mount_point",
            MountProblem::UnsafeMountPoint { .. } => "unsafe_mount_point",
            MountProblem::AmbiguousEsp { .. } => "ambiguous_esp",
            MountProblem::StaleSource { .. } => "stale_source",
        }
    }
}

// ---------------------------------------------------------------------------
// Edit operations (immutable plan building blocks)
// ---------------------------------------------------------------------------

/// One fstab edit the plan intends to apply. The editor applies these
/// against the verbatim original text so comments, blank lines, and
/// unknown entries are preserved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannedFstabEdit {
    /// Replace the source column of the entry at `line` (1-based)
    /// with `new_source`. Used to fix a wrong UUID without rewriting
    /// the whole line.
    ReplaceSource {
        line: usize,
        new_source: String,
        reason: String,
    },
    /// Replace the entire entry at `line` (1-based) with `new_line`.
    /// Used when source + options both need fixing.
    ReplaceEntry {
        line: usize,
        new_line: String,
        reason: String,
    },
    /// Append `new_line` at the end of the file. Used to add a
    /// missing standard CatOS entry. A trailing newline is added if
    /// the file does not already end with one.
    AppendEntry { new_line: String, reason: String },
    /// Drop the entry at `line` (1-based) because it is a verbatim
    /// duplicate of another entry resolving to the same mount point.
    /// Used only when the spec's "conflicting duplicate" rule allows
    /// it; otherwise the plan refuses with `ConflictingFstab`.
    DropDuplicate { line: usize, reason: String },
}

/// One subvolume the plan intends to (re)create. The orchestrator
/// refuses to create a subvolume unless every precondition holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedSubvolume {
    pub subvol: String,
    pub mount_point: String,
    pub reason: String,
}

/// One mount-point directory the plan intends to create.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedDirectory {
    pub mount_point: String,
    pub reason: String,
}

/// Per-action outcome recorded in the final report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppliedAction {
    FstabEdited {
        edit: PlannedFstabEdit,
    },
    FstabEditSkipped {
        edit: PlannedFstabEdit,
        reason: String,
    },
    SubvolumeCreated {
        subvol: String,
    },
    SubvolumeSkipped {
        subvol: String,
        reason: String,
    },
    DirectoryCreated {
        mount_point: String,
    },
    DirectorySkipped {
        mount_point: String,
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Target identity (bound to disk facts at plan time)
// ---------------------------------------------------------------------------

/// Snapshot of the target root identity at plan time. Any drift
/// detected at apply time MUST abort the plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TargetIdentity {
    /// Resolved block-device path for the root filesystem (e.g.
    /// `/dev/nvme0n1p2`).
    pub root_device: PathBuf,
    /// Filesystem type of the root filesystem (`btrfs`, `ext4`, ...).
    pub root_fstype: String,
    /// Root subvolume path for btrfs roots (e.g. `/@`). `None` for
    /// non-btrfs roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_subvol: Option<String>,
    /// UUID of the root filesystem, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_uuid: Option<String>,
    /// Resolved block-device path for the ESP, when one was uniquely
    /// identified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_device: Option<PathBuf>,
    /// UUID of the ESP filesystem, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_uuid: Option<String>,
}

/// Digest of the original fstab content as observed at plan time.
/// Used to detect "fstab changed between plan and apply".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FstabDigest {
    /// SHA-256 hex of the verbatim original bytes.
    pub sha256: String,
    /// Byte length of the original.
    pub byte_len: u64,
}

// ---------------------------------------------------------------------------
// Immutable RepairPlan
// ---------------------------------------------------------------------------

/// The immutable repair plan. Built once from observed disk facts;
/// any drift at apply time aborts the plan. Carried in the final
/// report so the user can audit "what did we intend to do?".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MountRepairPlan {
    /// Target identity snapshot at plan time.
    #[serde(default)]
    pub target: TargetIdentity,
    /// Digest of the original fstab at plan time.
    #[serde(default)]
    pub fstab_digest: FstabDigest,
    /// Read-only diagnosis. Doctor's future mount check reuses this
    /// surface so the two tools cannot disagree.
    #[serde(default)]
    pub problems: Vec<MountProblem>,
    /// fstab edits the plan intends to apply.
    #[serde(default)]
    pub fstab_edits: Vec<PlannedFstabEdit>,
    /// Subvolumes the plan intends to (re)create.
    #[serde(default)]
    pub subvolumes: Vec<PlannedSubvolume>,
    /// Mount-point directories the plan intends to create.
    #[serde(default)]
    pub directories: Vec<PlannedDirectory>,
    /// Conflicts the plan will NOT attempt to resolve automatically.
    /// Each carries a human-readable reason.
    #[serde(default)]
    pub unresolved_conflicts: Vec<String>,
    /// Warnings about risks the user should be aware of.
    #[serde(default)]
    pub risks: Vec<String>,
}

// ---------------------------------------------------------------------------
// Final report
// ---------------------------------------------------------------------------

/// fstab transaction audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FstabTransaction {
    /// Path of the original fstab inside the target root.
    pub original_path: PathBuf,
    /// Path of the backup written before the atomic replace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<PathBuf>,
    /// Path of the temp file used for the atomic replace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_path: Option<PathBuf>,
    /// `true` iff the atomic rename succeeded.
    pub atomic_replace_succeeded: bool,
    /// `true` iff the parent directory was fsynced after the rename.
    pub parent_fsynced: bool,
    /// `true` iff rollback to the backup was attempted.
    #[serde(default)]
    pub rollback_attempted: bool,
    /// `true` iff rollback succeeded. `false` means the user is in a
    /// degraded state.
    #[serde(default)]
    pub rollback_succeeded: bool,
}

/// Verification mount outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MountVerification {
    /// `true` iff the new fstab mounted cleanly in a private
    /// namespace.
    pub mounted: bool,
    /// fstype the kernel reported for the root mount, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_root_fstype: Option<String>,
    /// Failure message, when the verification mount failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

/// Cleanup summary. Mirrors the repair-fs shape so consumers can
/// reuse rendering logic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountRepairCleanup {
    #[serde(default)]
    pub unmounted: Vec<String>,
    #[serde(default)]
    pub residual: Vec<String>,
    pub all_clean: bool,
}

impl Default for MountRepairCleanup {
    fn default() -> Self {
        Self {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        }
    }
}

/// Final result of `catos-repair mount`. This struct is the contract:
/// human and JSON output both render it directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MountRepairReport {
    /// Target identity snapshot at plan time. `None` only when we
    /// refused before identifying a target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetIdentity>,
    /// The plan we built. Always populated when we got past target
    /// selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<MountRepairPlan>,
    /// fstab transaction audit. Populated when we attempted any
    /// fstab write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fstab_transaction: Option<FstabTransaction>,
    /// Per-action outcomes.
    #[serde(default)]
    pub actions: Vec<AppliedAction>,
    /// Verification mount outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<MountVerification>,
    /// Cleanup of mounts WE created.
    #[serde(default)]
    pub cleanup: MountRepairCleanup,
    /// Single source of truth for the final outcome.
    pub final_outcome: MountRepairOutcome,
    /// `true` iff the user must take manual action before relying on
    /// the result.
    pub requires_human_action: bool,
    /// `true` iff the repair is fully complete (no remaining manual
    /// steps).
    pub fully_complete: bool,
    /// Evidence trail.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Non-fatal warnings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

impl MountRepairReport {
    /// Convenience constructor for a refusal report.
    pub fn refused(outcome: MountRepairOutcome, reason: &str) -> Self {
        debug_assert!(
            outcome.is_refusal() || matches!(outcome, MountRepairOutcome::Unknown),
            "refused() called with non-refusal outcome {outcome:?}"
        );
        Self {
            final_outcome: outcome,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new(
                "REFUSED",
                "repair::mount",
                reason.to_string(),
            )],
            ..Default::default()
        }
    }

    /// Convenience constructor for a clean report (no work needed).
    pub fn clean(target: TargetIdentity) -> Self {
        Self {
            target: Some(target),
            final_outcome: MountRepairOutcome::Clean,
            requires_human_action: false,
            fully_complete: true,
            evidence: vec![Evidence::new(
                "CLEAN",
                "repair::mount",
                "fstab and standard layout already correct".to_string(),
            )],
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_code_matches_serde_form() {
        for outcome in [
            MountRepairOutcome::Clean,
            MountRepairOutcome::Repaired,
            MountRepairOutcome::PartiallyRepaired,
            MountRepairOutcome::AmbiguousTarget,
            MountRepairOutcome::NotCatos,
            MountRepairOutcome::UnsafePath,
            MountRepairOutcome::ConflictingFstab,
            MountRepairOutcome::DeviceChanged,
            MountRepairOutcome::FstabChanged,
            MountRepairOutcome::SubvolumeConflict,
            MountRepairOutcome::DataConflict,
            MountRepairOutcome::VerificationFailed,
            MountRepairOutcome::RollbackFailed,
            MountRepairOutcome::CleanupIncomplete,
            MountRepairOutcome::UnsupportedLayout,
            MountRepairOutcome::Unknown,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let trimmed = json.trim_matches('"');
            assert_eq!(outcome.code(), trimmed, "serde/code drift for {outcome:?}");
        }
    }

    #[test]
    fn standard_subvol_table_covers_required_mount_points() {
        // Spec § 二: the standard layout MUST include these eight.
        let required = [
            "/",
            "/home",
            "/root",
            "/srv",
            "/var/cache",
            "/var/tmp",
            "/var/log",
            "/.snapshots",
        ];
        for mp in required {
            let sub = standard_subvol_for_mount_point(mp);
            assert!(sub.is_some(), "missing standard subvol for {mp}");
        }
        assert_eq!(standard_subvol_for_mount_point("/home"), Some("/@home"));
        assert_eq!(
            standard_subvol_for_mount_point("/.snapshots"),
            Some("/@snapshots")
        );
        assert_eq!(standard_mount_point_for_subvol("/@log"), Some("/var/log"));
    }

    #[test]
    fn default_options_cover_required_fstypes() {
        assert!(default_mount_options("btrfs").is_some());
        assert!(default_mount_options("ext4").is_some());
        assert!(default_mount_options("xfs").is_some());
        assert!(default_mount_options("f2fs").is_some());
        assert!(default_mount_options("vfat").is_some());
        assert!(default_mount_options("nilfs2").is_none());
    }

    #[test]
    fn refused_report_marks_requires_human_action() {
        let r = MountRepairReport::refused(
            MountRepairOutcome::AmbiguousTarget,
            "multiple root candidates",
        );
        assert!(r.requires_human_action);
        assert!(!r.fully_complete);
        assert!(r.cleanup.all_clean);
    }

    #[test]
    fn clean_report_marks_fully_complete() {
        let target = TargetIdentity {
            root_device: PathBuf::from("/dev/sda2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("abc".into()),
            esp_device: None,
            esp_uuid: None,
        };
        let r = MountRepairReport::clean(target.clone());
        assert_eq!(r.final_outcome, MountRepairOutcome::Clean);
        assert!(r.fully_complete);
        assert!(!r.requires_human_action);
        assert_eq!(r.target.as_ref().unwrap(), &target);
    }
}
