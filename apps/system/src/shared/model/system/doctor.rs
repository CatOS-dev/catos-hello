//! Doctor aggregated-diagnosis data model. Pure data + serde. No I/O.
//!
//! ## Layering
//!
//! `model::doctor` is consumed by `output::doctor` (renderers) and
//! produced by `doctor::run` (orchestrator). It deliberately mirrors
//! the shape of the existing phase-specific models
//! (`FsRepairReport`, `MountRepairReport`, `BootRepairReport`,
//! `RecoveryStatusReport`) so a single Doctor view can stitch them
//! together without inventing a parallel taxonomy.
//!
//! ## Exit-code semantics (Scheme B)
//!
//! `overall_status` and the process exit code are independent:
//!
//! * Exit `0`  — Doctor completed the diagnosis and produced a report,
//!   regardless of whether the target is healthy.
//! * Exit `!= 0` — Doctor itself could not complete the diagnosis
//!   (broken invariant, serialisation failure, mount-namespace
//!   failure for a required offline probe, ...). Surfaced via
//!   [`DoctorReport::doctor_failed`].
//!
//! "The target is unhealthy" is NEVER an exit-code signal; it is
//! expressed via [`DoctorOverallStatus::Unhealthy`] (or stronger) and
//! the issue list.

use serde::{Deserialize, Serialize};

use crate::shared::model::evidence::Evidence;

/// Schema version for the Doctor report. Bumped only on a
/// backward-incompatible change to the top-level shape.
pub const DOCTOR_SCHEMA_VERSION: u32 = 1;

/// Overall health of the diagnosed target. Independent of the exit
/// code (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorOverallStatus {
    /// No known faults; every applicable check passed.
    Healthy,
    /// Non-blocking problem or an optional check unavailable. The
    /// system still boots / runs.
    Degraded,
    /// A problem requiring repair was found (fstab / fs / boot /
    /// recovery state). The system may still be running.
    Unhealthy,
    /// A severe consistency problem in the current root or boot
    /// path. Requires prioritised human action.
    Critical,
    /// Target identity could not be established or the evidence was
    /// insufficient to assign a health grade.
    Unknown,
}

impl DoctorOverallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DoctorOverallStatus::Healthy => "healthy",
            DoctorOverallStatus::Degraded => "degraded",
            DoctorOverallStatus::Unhealthy => "unhealthy",
            DoctorOverallStatus::Critical => "critical",
            DoctorOverallStatus::Unknown => "unknown",
        }
    }

    /// Conservative lattice reduction. Used by the aggregator when
    /// combining per-section statuses into one overall status.
    pub fn combine(self, other: DoctorOverallStatus) -> DoctorOverallStatus {
        use DoctorOverallStatus::*;
        // Unknown is absorptive only when paired with another Unknown;
        // otherwise the more specific status wins so a single
        // ambiguous section does not erase a known-healthy picture.
        match (self, other) {
            (Critical, _) | (_, Critical) => Critical,
            (Unhealthy, _) | (_, Unhealthy) => Unhealthy,
            (Degraded, _) | (_, Degraded) => Degraded,
            (Healthy, other) | (other, Healthy) => other,
            (Unknown, Unknown) => Unknown,
        }
    }
}

/// Status of a single diagnostic section. Distinct from
/// [`DoctorOverallStatus`] because a section may legitimately be
/// `skipped` (e.g. Secure Boot on a BIOS target) without affecting
/// the overall grade beyond a `degraded` ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorSectionStatus {
    /// Section ran and found no problem.
    Healthy,
    /// Section ran and found a non-blocking issue.
    Degraded,
    /// Section ran and found a problem requiring repair.
    Unhealthy,
    /// Section ran and found a critical problem.
    Critical,
    /// Section could not run because a required tool was missing
    /// or the runtime environment does not allow it (e.g. offline
    /// fsck on a currently-mounted root).
    Skipped,
    /// Section was intentionally not evaluated because it does not
    /// apply to the selected target (e.g. Secure Boot on BIOS).
    NotApplicable,
    /// Target identity was not established strongly enough to run
    /// the section.
    Unknown,
}

impl DoctorSectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DoctorSectionStatus::Healthy => "healthy",
            DoctorSectionStatus::Degraded => "degraded",
            DoctorSectionStatus::Unhealthy => "unhealthy",
            DoctorSectionStatus::Critical => "critical",
            DoctorSectionStatus::Skipped => "skipped",
            DoctorSectionStatus::NotApplicable => "not_applicable",
            DoctorSectionStatus::Unknown => "unknown",
        }
    }

    /// Map a section status to its contribution to the overall
    /// status. `Skipped`/`NotApplicable` do not affect the overall
    /// status directly; their downstream effect surfaces as
    /// `DoctorLimitation` entries which the aggregator may turn into
    /// a `Degraded` overall when the target is otherwise healthy.
    pub fn to_overall_contribution(self) -> Option<DoctorOverallStatus> {
        match self {
            DoctorSectionStatus::Healthy => Some(DoctorOverallStatus::Healthy),
            DoctorSectionStatus::Degraded => Some(DoctorOverallStatus::Degraded),
            DoctorSectionStatus::Unhealthy => Some(DoctorOverallStatus::Unhealthy),
            DoctorSectionStatus::Critical => Some(DoctorOverallStatus::Critical),
            DoctorSectionStatus::Unknown => Some(DoctorOverallStatus::Unknown),
            DoctorSectionStatus::Skipped | DoctorSectionStatus::NotApplicable => None,
        }
    }
}

/// Severity grade of a single [`DoctorIssue`]. Distinct from
/// [`DoctorSectionStatus`] because a degraded section may carry
/// `info`-level context that is not itself a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorSeverity {
    /// Informational context (e.g. a successful check that the
    /// operator may still want to see).
    Info,
    /// A non-blocking concern (e.g. an optional tool missing, a
    /// residual backup left after a successful recovery).
    Warning,
    /// A problem that should be repaired but does not prevent
    /// booting / running.
    Error,
    /// A severe problem requiring prioritised human action.
    Critical,
}

impl DoctorSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            DoctorSeverity::Info => "info",
            DoctorSeverity::Warning => "warning",
            DoctorSeverity::Error => "error",
            DoctorSeverity::Critical => "critical",
        }
    }
}

/// Stable section identifiers. Adding a new section is a
/// backward-compatible change; reordering an existing identifier's
/// meaning is NOT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorSectionId {
    Environment,
    Storage,
    Filesystem,
    Mount,
    Boot,
    SecureBoot,
    Recovery,
}

impl DoctorSectionId {
    pub fn as_str(self) -> &'static str {
        match self {
            DoctorSectionId::Environment => "environment",
            DoctorSectionId::Storage => "storage",
            DoctorSectionId::Filesystem => "filesystem",
            DoctorSectionId::Mount => "mount",
            DoctorSectionId::Boot => "boot",
            DoctorSectionId::SecureBoot => "secure_boot",
            DoctorSectionId::Recovery => "recovery",
        }
    }

    /// Display heading used by the human renderer.
    pub fn heading(self) -> &'static str {
        match self {
            DoctorSectionId::Environment => "Environment",
            DoctorSectionId::Storage => "Storage",
            DoctorSectionId::Filesystem => "Filesystem",
            DoctorSectionId::Mount => "Mount layout",
            DoctorSectionId::Boot => "Boot",
            DoctorSectionId::SecureBoot => "Secure Boot",
            DoctorSectionId::Recovery => "Recovery",
        }
    }

    /// All section ids in the canonical render order.
    pub fn all() -> &'static [DoctorSectionId] {
        &[
            DoctorSectionId::Environment,
            DoctorSectionId::Storage,
            DoctorSectionId::Filesystem,
            DoctorSectionId::Mount,
            DoctorSectionId::Boot,
            DoctorSectionId::SecureBoot,
            DoctorSectionId::Recovery,
        ]
    }
}

/// One diagnosed issue. The `code` field is the stable contract; the
/// `message` is human-readable and may change between releases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorIssue {
    /// Stable snake_case code (e.g. `FS_CORRUPTION_DETECTED`,
    /// `FSTAB_ROOT_SOURCE_MISMATCH`). Consumers MUST key on this;
    /// the message is for humans.
    pub code: String,
    pub severity: DoctorSeverity,
    /// Section this issue belongs to.
    pub section: DoctorSectionId,
    /// Short human-readable explanation. Never the only signal.
    pub message: String,
    /// Concrete observation the issue was derived from
    /// (command output snippet, conflicting field values, ...).
    /// Optional because some issues are derived purely from
    /// absence-of-evidence (e.g. `TARGET_NOT_FOUND`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Machine-friendly suggested next step, when one exists. The
    /// aggregator never executes these; it only emits them. See
    /// [`DoctorRecommendation`] for the shape used in the top-level
    /// `recommendations` list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_code: Option<String>,
}

impl DoctorIssue {
    pub fn new(
        code: impl Into<String>,
        severity: DoctorSeverity,
        section: DoctorSectionId,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity,
            section,
            message: message.into(),
            evidence: Vec::new(),
            recommendation_code: None,
        }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_recommendation(mut self, code: impl Into<String>) -> Self {
        self.recommendation_code = Some(code.into());
        self
    }
}

/// A limitation encountered while running a section. Limitations are
/// NOT faults: they explain why a section is `skipped` or
/// `degraded` without implying the target is broken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorLimitation {
    pub section: DoctorSectionId,
    /// Stable snake_case code (e.g. `FS_OFFLINE_CHECK_REQUIRED`,
    /// `TOOL_MISSING`, `SECTION_TARGET_UNKNOWN`).
    pub code: String,
    pub message: String,
}

impl DoctorLimitation {
    pub fn new(
        section: DoctorSectionId,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            section,
            code: code.into(),
            message: message.into(),
        }
    }
}

/// A recommended next step. The aggregator never executes these; the
/// human renderer surfaces them so the operator knows what to do.
///
/// `command` is a stable, parseable token (e.g.
/// `catos-repair mount`) — never an arbitrary shell pipeline. When
/// the situation is too ambiguous for a single command,
/// `recommend_live_environment` is emitted instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorRecommendation {
    /// Stable snake_case code (e.g. `RUN_CATOS_REPAIR_MOUNT`,
    /// `RUN_CATOS_RECOVERY_RESUME`, `BOOT_LIVE_ENVIRONMENT`).
    pub code: String,
    /// Human-readable explanation of why this is recommended.
    pub message: String,
    /// Optional machine-friendly command, when one is safe to
    /// suggest. Absent when the situation requires operator
    /// judgement (ambiguous target, conflicting providers, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Issue codes this recommendation addresses. Empty when the
    /// recommendation is generic (e.g. `BOOT_LIVE_ENVIRONMENT`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

impl DoctorRecommendation {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            command: None,
            addresses: Vec::new(),
        }
    }

    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    pub fn addressing(mut self, issue_code: impl Into<String>) -> Self {
        self.addresses.push(issue_code.into());
        self
    }
}

/// Result of one diagnostic section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorSection {
    pub id: DoctorSectionId,
    pub status: DoctorSectionStatus,
    /// Issues localised to this section. The aggregator also
    /// surfaces them in the top-level `issues` list (deduplicated);
    /// the section-local copy exists so a consumer can render one
    /// section without re-filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<DoctorIssue>,
    /// Evidence the section derived its status from, beyond the
    /// per-issue evidence. Used for positive findings (e.g. "fsck
    /// reported clean", "provider detected: grub").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl DoctorSection {
    pub fn new(id: DoctorSectionId, status: DoctorSectionStatus) -> Self {
        Self {
            id,
            status,
            issues: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

/// Summary of the cleanup Doctor performed for its own private mount
/// namespace. Doctor is read-only on the target; the only resources
/// it may clean up are mounts it created itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorCleanup {
    /// Mounts Doctor created and successfully removed before exit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleaned: Vec<String>,
    /// Mounts Doctor created but could not remove. Residual mounts
    /// imply Doctor itself failed (exit != 0); they are surfaced
    /// explicitly so the operator can clean them up.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residual: Vec<String>,
    /// `true` iff `residual` is empty.
    pub all_clean: bool,
}

impl DoctorCleanup {
    pub fn clean() -> Self {
        Self {
            cleaned: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        }
    }
}

/// Identity of the selected diagnosis target. Mirrors the relevant
/// subset of [`crate::mount::model::TargetIdentity`] so Doctor
/// output is self-contained without dragging in the full plan-bound
/// shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorTarget {
    /// `running_root` when `/` itself is the diagnosed CatOS system;
    /// `offline` when a different block device was selected; `none`
    /// when no unique target could be identified.
    pub kind: DoctorTargetKind,
    /// Stable target root device path (e.g. `/dev/nvme0n1p2`).
    /// Absent when `kind == None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_device: Option<String>,
    /// Filesystem type of the root device, when identified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_fstype: Option<String>,
    /// Btrfs subvolume path mounted at `/`, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_subvolume: Option<String>,
    /// Stable ESP device path, when an ESP was identified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_device: Option<String>,
    /// Detected CatOS-flavour boot/ESP layout label, when
    /// applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_layout: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorTargetKind {
    /// `/` was uniquely confirmed to be a CatOS system and was
    /// diagnosed in place.
    RunningRoot,
    /// A different block device was selected as the diagnosis
    /// target.
    Offline,
    /// No unique CatOS target could be identified.
    #[default]
    None,
}

impl DoctorTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DoctorTargetKind::RunningRoot => "running_root",
            DoctorTargetKind::Offline => "offline",
            DoctorTargetKind::None => "none",
        }
    }
}

/// Environment summary reused from phase 1. Doctor does not
/// re-derive environment facts; it cites them so consumers see one
/// coherent picture.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorEnvironment {
    /// `running_system`, `chroot`, `live_environment`, `initramfs`,
    /// or `unknown` — same vocabulary as phase 1.
    pub primary_mode: String,
    /// Whether `/` itself looks like the running CatOS root.
    pub running_root_is_catos: bool,
}

/// Top-level Doctor report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Always `1` for now; bumped only on a backward-incompatible
    /// top-level shape change.
    pub schema_version: u32,
    /// `catos-doctor`.
    pub program: String,
    /// Program version (`CARGO_PKG_VERSION`).
    pub program_version: String,
    pub environment: DoctorEnvironment,
    pub target: DoctorTarget,
    pub overall_status: DoctorOverallStatus,
    /// `true` iff every applicable section produced a definitive
    /// result. `false` when at least one section was `skipped`,
    /// `unknown`, or carried a `limitation`.
    pub complete: bool,
    /// Ordered by [`DoctorSectionId::all`]. Sections that did not
    /// apply are emitted with `status = not_applicable`.
    pub sections: Vec<DoctorSection>,
    /// Aggregated, deduplicated issue list ordered by severity
    /// (critical first) and then by section.
    pub issues: Vec<DoctorIssue>,
    /// Limitations encountered while running the sections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<DoctorLimitation>,
    /// Recommended next steps. The aggregator never executes them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommendations: Vec<DoctorRecommendation>,
    /// Cross-section warnings (probe anomalies, de-duplication
    /// notes, ...). Section-local warnings live inside each
    /// [`DoctorSection`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Cleanup summary for Doctor's own private mount namespace.
    pub cleanup: DoctorCleanup,
    /// Cross-section evidence trail. Per-section evidence lives
    /// inside each [`DoctorSection`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl Default for DoctorReport {
    fn default() -> Self {
        Self {
            schema_version: DOCTOR_SCHEMA_VERSION,
            program: "catos-doctor".to_string(),
            program_version: crate::PROGRAM_VERSION.to_string(),
            environment: DoctorEnvironment::default(),
            target: DoctorTarget::default(),
            overall_status: DoctorOverallStatus::Unknown,
            complete: false,
            sections: Vec::new(),
            issues: Vec::new(),
            limitations: Vec::new(),
            recommendations: Vec::new(),
            warnings: Vec::new(),
            cleanup: DoctorCleanup::clean(),
            evidence: Vec::new(),
        }
    }
}

impl DoctorReport {
    /// Helper for unit tests and stub renderers: a minimal report
    /// that ran nothing useful. Production code should never produce
    /// this shape.
    #[doc(hidden)]
    pub fn empty_stub() -> Self {
        let mut report = Self::default();
        for id in DoctorSectionId::all() {
            report
                .sections
                .push(DoctorSection::new(*id, DoctorSectionStatus::Unknown));
        }
        report
    }
}

/// Stable issue code constants. Centralised so the orchestrator,
/// tests, and documentation reference the same literal.
pub mod issue_code {
    // Target selection
    pub const TARGET_NOT_FOUND: &str = "TARGET_NOT_FOUND";
    pub const TARGET_AMBIGUOUS: &str = "TARGET_AMBIGUOUS";
    pub const TARGET_NOT_CATOS: &str = "TARGET_NOT_CATOS";

    // Filesystem
    pub const FS_OFFLINE_CHECK_REQUIRED: &str = "FS_OFFLINE_CHECK_REQUIRED";
    pub const FS_CORRUPTION_DETECTED: &str = "FS_CORRUPTION_DETECTED";
    pub const FS_TOOL_MISSING: &str = "FS_TOOL_MISSING";
    pub const FS_MULTI_DEVICE: &str = "FS_MULTI_DEVICE";
    pub const FS_CHECK_FAILED: &str = "FS_CHECK_FAILED";

    // Mount / fstab
    pub const FSTAB_ROOT_SOURCE_MISMATCH: &str = "FSTAB_ROOT_SOURCE_MISMATCH";
    pub const FSTAB_ROOT_SUBVOLUME_WRONG: &str = "FSTAB_ROOT_SUBVOLUME_WRONG";
    pub const STANDARD_SUBVOLUME_MISSING: &str = "STANDARD_SUBVOLUME_MISSING";
    pub const ESP_AMBIGUOUS: &str = "ESP_AMBIGUOUS";
    pub const ESP_UUID_MISMATCH: &str = "ESP_UUID_MISMATCH";
    pub const FSTAB_UNPARSEABLE: &str = "FSTAB_UNPARSEABLE";

    // Boot
    pub const BOOT_PROVIDER_AMBIGUOUS: &str = "BOOT_PROVIDER_AMBIGUOUS";
    pub const BOOT_PROVIDER_CONFLICT: &str = "BOOT_PROVIDER_CONFLICT";
    pub const BOOT_VERIFICATION_FAILED: &str = "BOOT_VERIFICATION_FAILED";
    pub const BOOT_PLATFORM_UNSUPPORTED: &str = "BOOT_PLATFORM_UNSUPPORTED";
    pub const BOOT_ASSET_MISSING: &str = "BOOT_ASSET_MISSING";

    // Secure Boot
    pub const SECURE_BOOT_STATE_INCOMPLETE: &str = "SECURE_BOOT_STATE_INCOMPLETE";
    pub const SECURE_BOOT_POLICY_MISMATCH: &str = "SECURE_BOOT_POLICY_MISMATCH";

    // Recovery
    pub const RECOVERY_TRANSACTION_INTERRUPTED: &str = "RECOVERY_TRANSACTION_INTERRUPTED";
    pub const RECOVERY_RECORD_DRIFT: &str = "RECOVERY_RECORD_DRIFT";
    pub const RECOVERY_CLEANUP_RESIDUAL: &str = "RECOVERY_CLEANUP_RESIDUAL";
    pub const RECOVERY_BACKUP_PRESENT: &str = "RECOVERY_BACKUP_PRESENT";

    // Doctor-internal
    pub const DOCTOR_INTERNAL_ERROR: &str = "DOCTOR_INTERNAL_ERROR";
    pub const DOCTOR_SECTION_FAILED: &str = "DOCTOR_SECTION_FAILED";
}

/// Stable recommendation code constants.
pub mod recommendation_code {
    pub const RUN_CATOS_REPAIR_FS: &str = "RUN_CATOS_REPAIR_FS";
    pub const RUN_CATOS_REPAIR_MOUNT: &str = "RUN_CATOS_REPAIR_MOUNT";
    pub const RUN_CATOS_REPAIR_BOOT: &str = "RUN_CATOS_REPAIR_BOOT";
    pub const RUN_CATOS_RECOVERY_RESUME: &str = "RUN_CATOS_RECOVERY_RESUME";
    pub const RUN_CATOS_RECOVERY_REVERT: &str = "RUN_CATOS_RECOVERY_REVERT";
    pub const BOOT_LIVE_ENVIRONMENT: &str = "BOOT_LIVE_ENVIRONMENT";
    pub const MANUAL_REVIEW: &str = "MANUAL_REVIEW";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_status_combine_critical_dominates() {
        use DoctorOverallStatus::*;
        assert_eq!(Healthy.combine(Critical), Critical);
        assert_eq!(Critical.combine(Healthy), Critical);
        assert_eq!(Unhealthy.combine(Critical), Critical);
        assert_eq!(Degraded.combine(Critical), Critical);
    }

    #[test]
    fn overall_status_combine_unhealthy_beats_degraded() {
        use DoctorOverallStatus::*;
        assert_eq!(Degraded.combine(Unhealthy), Unhealthy);
        assert_eq!(Unhealthy.combine(Degraded), Unhealthy);
    }

    #[test]
    fn overall_status_combine_unknown_vs_specific() {
        // The more specific status wins so a single ambiguous
        // section does not erase a known-healthy picture.
        use DoctorOverallStatus::*;
        assert_eq!(Healthy.combine(Unknown), Unknown);
        assert_eq!(Unknown.combine(Healthy), Unknown);
        assert_eq!(Unhealthy.combine(Unknown), Unhealthy);
    }

    #[test]
    fn overall_status_combine_unknown_unknown_stays_unknown() {
        use DoctorOverallStatus::*;
        assert_eq!(Unknown.combine(Unknown), Unknown);
    }

    #[test]
    fn section_status_to_overall_contribution_drops_skipped() {
        use DoctorSectionStatus::*;
        assert_eq!(
            Skipped.to_overall_contribution(),
            None,
            "skipped sections must not affect the overall status directly"
        );
        assert_eq!(
            NotApplicable.to_overall_contribution(),
            None,
            "not_applicable sections must not affect the overall status directly"
        );
        assert_eq!(
            Healthy.to_overall_contribution(),
            Some(DoctorOverallStatus::Healthy)
        );
    }

    #[test]
    fn severity_ordering_is_info_warning_error_critical() {
        use DoctorSeverity::*;
        assert!(Info < Warning);
        assert!(Warning < Error);
        assert!(Error < Critical);
    }

    #[test]
    fn section_id_all_returns_canonical_order() {
        let all = DoctorSectionId::all();
        assert_eq!(all.len(), 7);
        assert_eq!(all[0], DoctorSectionId::Environment);
        assert_eq!(all[6], DoctorSectionId::Recovery);
        // Order must be stable so the human renderer can rely on it.
        for window in all.windows(2) {
            assert!(
                window[0].as_str() != window[1].as_str(),
                "duplicate section id in canonical order"
            );
        }
    }
}
