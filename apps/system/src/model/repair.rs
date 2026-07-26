//! Filesystem repair data model. Pure data + serde, no I/O.
//!
//! This is the structured result of `catos-repair fs`. It is NOT a
//! `RecoveryPlan` and NOT a `MountPlan`: it is its own first-class
//! result, designed so Doctor can later reuse the read-only check
//! parts without dragging in any "apply" semantics.
//!
//! Design rules:
//!
//! * Every attempt is recorded individually (`attempts`). A "did we
//!   try the dangerous fallback?" question must be answerable from
//!   the model alone, with no I/O.
//! * `final_outcome` is the single source of truth for "did it
//!   work?". Human and JSON output render it identically.
//! * Exit statuses are recorded raw (the tool's actual exit code),
//!   plus a structured `exit_interpretation` so consumers do not have
//!   to re-implement e2fsck's bitmask table.
//! * `cleanup` reports verbatim what was unmounted and what residual
//!   mounts (if any) remained. A session that fails cleanup MUST NOT
//!   report `final_outcome = *` clean.
//! * `requires_human_action` is independent of `final_outcome` so
//!   consumers can flag "we repaired it, but you should still look"
//!   (e.g. after XFS `-L`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::evidence::Evidence;
use crate::model::inspection::Warning;

// ---------------------------------------------------------------------------
// Final outcome taxonomy
// ---------------------------------------------------------------------------

/// The single source of truth for "what happened". Each variant maps
/// to a stable snake_case string in JSON (the public contract).
///
/// Adding variants is backward-compatible. Renaming is NOT.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FsRepairOutcome {
    /// Filesystem checked clean; no repair was needed.
    Clean,
    /// Repair attempted and verification succeeded. Filesystem is
    /// usable.
    Repaired,
    /// Repair attempted and verification succeeded, BUT a high-risk
    /// fallback was used (e.g. `xfs_repair -L`, `btrfs check --repair`).
    /// Data loss is possible. The user should inspect before trusting.
    RepairedWithRisk,
    /// Repair attempted; verification failed OR the tool reported
    /// uncorrected errors. The filesystem may still be mountable but
    /// is not trustworthy.
    Unrepaired,
    /// Filesystem type is not in our routing table. We refused
    /// rather than guess. Distinct from `ToolMissing` so downstream
    /// tooling can tell the operator "we don't know how" vs "install
    /// this package".
    Unsupported,
    /// The chosen tool is not installed. The report identifies which
    /// tool by name.
    ToolMissing,
    /// Refused because the target was already mounted when we
    /// inspected it and we did not mount it ourselves. Repairing a
    /// mounted filesystem is unsafe; the spec forbids it.
    RefusedMounted,
    /// Refused because the target IS the currently running root.
    /// Repairing / while running on / corrupts the live system.
    RefusedRunningRoot,
    /// Refused because multiple equally-plausible candidates were
    /// discovered and the user did not specify one. We never guess.
    AmbiguousTarget,
    /// Repair ran but the post-repair read-only verification mount
    /// failed. The filesystem may be in a worse state than before;
    /// the user must inspect manually.
    VerificationFailed,
    /// Catch-all for an internal error that prevented us from
    /// producing a meaningful repair result. Should never appear in
    /// normal operation; included so the model is total.
    #[default]
    Unknown,
}

impl FsRepairOutcome {
    /// Stable snake_case code, identical to the serde form. Used by
    /// human output so JSON and human text always agree.
    pub fn code(self) -> &'static str {
        match self {
            FsRepairOutcome::Clean => "clean",
            FsRepairOutcome::Repaired => "repaired",
            FsRepairOutcome::RepairedWithRisk => "repaired_with_risk",
            FsRepairOutcome::Unrepaired => "unrepaired",
            FsRepairOutcome::Unsupported => "unsupported",
            FsRepairOutcome::ToolMissing => "tool_missing",
            FsRepairOutcome::RefusedMounted => "refused_mounted",
            FsRepairOutcome::RefusedRunningRoot => "refused_running_root",
            FsRepairOutcome::AmbiguousTarget => "ambiguous_target",
            FsRepairOutcome::VerificationFailed => "verification_failed",
            FsRepairOutcome::Unknown => "unknown",
        }
    }

    /// `true` iff the outcome represents a successful repair end
    /// state. Used by the orchestrator to set exit codes and by
    /// callers to decide whether to escalate.
    pub fn is_success(self) -> bool {
        matches!(
            self,
            FsRepairOutcome::Clean | FsRepairOutcome::Repaired | FsRepairOutcome::RepairedWithRisk
        )
    }

    /// `true` iff the outcome means we deliberately refused to act.
    pub fn is_refusal(self) -> bool {
        matches!(
            self,
            FsRepairOutcome::RefusedMounted
                | FsRepairOutcome::RefusedRunningRoot
                | FsRepairOutcome::AmbiguousTarget
        )
    }
}

// ---------------------------------------------------------------------------
// Tool routing
// ---------------------------------------------------------------------------

/// Which filesystem-specific official tool we routed to. Each
/// variant pins the exact binary name we look for in
/// `/usr/{bin,sbin},/bin,/sbin`. Adding a variant is backward-
/// compatible.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepairTool {
    E2fsck,
    FsckFat,
    FsckF2fs,
    XfsRepair,
    BtrfsCheck,
}

impl RepairTool {
    /// The exact binary name we resolve through trusted directories.
    /// Distinct from the JSON enum form because the binary name is a
    /// filesystem lookup, not a public contract.
    pub fn binary_name(self) -> &'static str {
        match self {
            RepairTool::E2fsck => "e2fsck",
            RepairTool::FsckFat => "fsck.fat",
            RepairTool::FsckF2fs => "fsck.f2fs",
            RepairTool::XfsRepair => "xfs_repair",
            RepairTool::BtrfsCheck => "btrfs",
        }
    }

    /// Stable snake_case code; the JSON contract.
    pub fn code(self) -> &'static str {
        match self {
            RepairTool::E2fsck => "e2fsck",
            RepairTool::FsckFat => "fsck_fat",
            RepairTool::FsckF2fs => "fsck_f2fs",
            RepairTool::XfsRepair => "xfs_repair",
            RepairTool::BtrfsCheck => "btrfs_check",
        }
    }
}

/// What kind of attempt this was. A single repair flow may produce
/// several attempts (e.g. btrfs: readonly check, then --repair, then
/// readonly check again). Each attempt records its own outcome so
/// the audit trail is complete.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttemptKind {
    /// Read-only filesystem check (no writes). e.g. `btrfs check
    /// --readonly`, or the pre-repair `e2fsck -n` style invocation.
    ReadonlyCheck,
    /// Normal non-interactive auto-repair. e.g. `e2fsck -y`, plain
    /// `xfs_repair DEVICE`, `btrfs check --repair`.
    Repair,
    /// High-risk fallback, only used when normal repair fails. The
    /// two authorized cases are `xfs_repair -L DEVICE` and
    /// `btrfs check --repair DEVICE` (the latter is always labeled
    /// high-risk because the btrfs-progs authors themselves warn
    /// against running it without operator review).
    HighRiskFallback,
    /// Post-repair read-only verification check.
    VerificationCheck,
}

impl AttemptKind {
    pub fn is_high_risk(self) -> bool {
        matches!(self, AttemptKind::HighRiskFallback)
    }

    pub fn code(self) -> &'static str {
        match self {
            AttemptKind::ReadonlyCheck => "readonly_check",
            AttemptKind::Repair => "repair",
            AttemptKind::HighRiskFallback => "high_risk_fallback",
            AttemptKind::VerificationCheck => "verification_check",
        }
    }
}

// ---------------------------------------------------------------------------
// Attempts
// ---------------------------------------------------------------------------

/// Structured interpretation of an exit code. `raw_code` is the
/// literal value; the rest is the human/JSON-friendly decoding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitInterpretation {
    /// Raw exit code as the OS reported it. `-1` if the process was
    /// killed by a signal and no code was produced.
    pub raw_code: i32,
    /// True iff the tool completed without detecting any error.
    pub clean: bool,
    /// True iff the tool reports it corrected one or more errors.
    pub errors_corrected: bool,
    /// True iff the tool requests a reboot (e2fsck bit 1).
    pub reboot_required: bool,
    /// True iff the tool exited early without finishing (e2fsck bit
    /// 1 + the "exit" semantics). Distinct from `errors_uncorrected`
    /// because "exited" can mean "operator interrupt" in some
    /// tools.
    pub exited_early: bool,
    /// True iff the tool detected errors it could not fix.
    pub errors_uncorrected: bool,
    /// True iff the runner killed the process for exceeding the
    /// timeout.
    pub timed_out: bool,
    /// True iff the binary could not be found in trusted
    /// directories. Distinct from a non-zero exit.
    pub binary_missing: bool,
    /// Free-text label the runner fills in (e.g. "e2fsck-bitmask-0")
    /// for fast grep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl ExitInterpretation {
    /// The "nothing happened" interpretation used when we never ran
    /// the tool (binary missing or refused).
    pub fn not_run() -> Self {
        Self {
            raw_code: -1,
            clean: false,
            errors_corrected: false,
            reboot_required: false,
            exited_early: false,
            errors_uncorrected: false,
            timed_out: false,
            binary_missing: false,
            label: Some("not_run".into()),
        }
    }
}

/// One repair attempt — one process invocation, one set of captured
/// outputs. A `catos-repair fs` flow may produce many attempts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepairAttempt {
    /// What role this attempt played in the overall flow.
    pub kind: AttemptKind,
    /// Tool that ran.
    pub tool: RepairTool,
    /// argv passed to the tool, NOT including argv[0]. Recorded so
    /// the audit trail is complete and downstream tooling can verify
    /// "we did not pass shell strings".
    pub argv: Vec<String>,
    /// Whether this attempt was a high-risk fallback. Mirrors
    /// `kind.is_high_risk()` but is a top-level field so JSON
    /// consumers can filter without dereferencing the enum.
    pub high_risk: bool,
    /// Structured exit interpretation.
    pub exit: ExitInterpretation,
    /// Captured stdout, truncated to the runner's safety limit. May
    /// be empty.
    #[serde(default)]
    pub stdout: String,
    /// Captured stderr, truncated to the runner's safety limit. May
    /// be empty.
    #[serde(default)]
    pub stderr: String,
    /// Whether stdout was truncated by the runner.
    pub stdout_truncated: bool,
    /// Whether stderr was truncated by the runner.
    pub stderr_truncated: bool,
    /// Free-text rationale for why this attempt was made. Surfaced
    /// verbatim in human output.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Result of the read-only verification mount performed after a
/// successful repair. We mount the target once read-only, confirm
/// the mount succeeds and the filesystem is structurally usable,
/// then unmount before returning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VerificationMount {
    /// True iff the verification mount succeeded.
    pub mounted: bool,
    /// Filesystem type the kernel reported for the mount, when
    /// available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_fstype: Option<String>,
    /// Error message if the mount failed. Empty on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

/// Cleanup summary specific to repair. Reuses the phase-2
/// `CleanupReport` shape but lives in this model so consumers do
/// not need to import `model::mount`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RepairCleanup {
    /// Mounts this `catos-repair` invocation created and successfully
    /// unmounted.
    #[serde(default)]
    pub unmounted: Vec<String>,
    /// Mounts this `catos-repair` invocation created but could NOT
    /// unmount. Each entry carries a reason.
    #[serde(default)]
    pub residual: Vec<String>,
    /// Whether the final state is clean.
    pub all_clean: bool,
}

// ---------------------------------------------------------------------------
// Top-level report
// ---------------------------------------------------------------------------

/// The result of `catos-repair fs`. This struct is the contract:
/// human and JSON output both render it directly. Doctor's future
/// "check only" mode will reuse the inner `attempts` /
/// `VerificationMount` shape without the repair apply steps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FsRepairReport {
    /// The block device we targeted. `None` when we refused before
    /// identifying one (ambiguous, refused before scan, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device: Option<PathBuf>,
    /// Filesystem type we identified on the target. `None` when the
    /// type is unknown or the target was refused before we probed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_type: Option<String>,
    /// Whether the target was already mounted when we inspected it.
    /// Repair is refused in that case.
    pub was_mounted_before_session: bool,
    /// Tool we routed to. `None` when we refused to route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_tool: Option<RepairTool>,
    /// Every attempt, in execution order. May be empty for refusals.
    #[serde(default)]
    pub attempts: Vec<RepairAttempt>,
    /// Read-only verification mount after repair. Absent when no
    /// repair was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_mount: Option<VerificationMount>,
    /// Cleanup of mounts WE created. Never absent when a mount was
    /// attempted; always present in the model for shape stability.
    #[serde(default)]
    pub cleanup: RepairCleanup,
    /// Single source of truth for the final outcome.
    pub final_outcome: FsRepairOutcome,
    /// Whether the user must take manual action before relying on
    /// the result. Independent of `final_outcome` so a
    /// `RepairedWithRisk` outcome still flags manual review.
    pub requires_human_action: bool,
    /// Evidence trail (probes, decisions, refusals).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Non-fatal warnings collected during the flow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

impl FsRepairReport {
    /// Convenience: did any attempt use a high-risk fallback?
    pub fn used_high_risk_fallback(&self) -> bool {
        self.attempts.iter().any(|attempt| attempt.high_risk)
    }

    /// Convenience: did any attempt record that the chosen binary
    /// was missing?
    pub fn tool_was_missing(&self) -> bool {
        self.attempts
            .iter()
            .any(|attempt| attempt.exit.binary_missing)
    }

    /// Construct a refused report with no attempts and no target.
    pub fn refused(outcome: FsRepairOutcome, reason: &str) -> Self {
        debug_assert!(
            outcome.is_refusal(),
            "refused() called with non-refusal outcome {outcome:?}"
        );
        Self {
            target_device: None,
            filesystem_type: None,
            was_mounted_before_session: false,
            selected_tool: None,
            attempts: Vec::new(),
            verification_mount: None,
            cleanup: RepairCleanup::default(),
            final_outcome: outcome,
            requires_human_action: true,
            evidence: vec![Evidence::new(
                "REFUSED",
                "repair::orchestrator",
                reason.to_string(),
            )],
            warnings: Vec::new(),
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
        // Lock the public JSON contract: serde rename and `code()`
        // must agree character-for-character. A drift here silently
        // breaks downstream tooling that filters on outcome.
        for outcome in [
            FsRepairOutcome::Clean,
            FsRepairOutcome::Repaired,
            FsRepairOutcome::RepairedWithRisk,
            FsRepairOutcome::Unrepaired,
            FsRepairOutcome::Unsupported,
            FsRepairOutcome::ToolMissing,
            FsRepairOutcome::RefusedMounted,
            FsRepairOutcome::RefusedRunningRoot,
            FsRepairOutcome::AmbiguousTarget,
            FsRepairOutcome::VerificationFailed,
            FsRepairOutcome::Unknown,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let trimmed = json.trim_matches('"');
            assert_eq!(outcome.code(), trimmed, "serde/code drift for {outcome:?}");
        }
    }

    #[test]
    fn outcome_success_classification_is_stable() {
        // Only clean / repaired / repaired_with_risk count as success.
        // RepairedWithRisk is still success: the repair achieved a
        // usable state, the risk is reported separately.
        assert!(FsRepairOutcome::Clean.is_success());
        assert!(FsRepairOutcome::Repaired.is_success());
        assert!(FsRepairOutcome::RepairedWithRisk.is_success());
        assert!(!FsRepairOutcome::Unrepaired.is_success());
        assert!(!FsRepairOutcome::Unsupported.is_success());
        assert!(!FsRepairOutcome::ToolMissing.is_success());
        assert!(!FsRepairOutcome::RefusedMounted.is_success());
        assert!(!FsRepairOutcome::RefusedRunningRoot.is_success());
        assert!(!FsRepairOutcome::AmbiguousTarget.is_success());
        assert!(!FsRepairOutcome::VerificationFailed.is_success());
        assert!(!FsRepairOutcome::Unknown.is_success());
    }

    #[test]
    fn outcome_refusal_classification_is_stable() {
        // Refusals MUST be distinguishable from "tried and failed".
        // Without this, a downstream consumer might retry an unsafe
        // operation that we deliberately declined.
        assert!(FsRepairOutcome::RefusedMounted.is_refusal());
        assert!(FsRepairOutcome::RefusedRunningRoot.is_refusal());
        assert!(FsRepairOutcome::AmbiguousTarget.is_refusal());
        assert!(!FsRepairOutcome::Unrepaired.is_refusal());
        assert!(!FsRepairOutcome::Unsupported.is_refusal());
    }

    #[test]
    fn tool_binary_name_is_distinct_from_code() {
        // The binary name is what we look up on disk; the code is
        // what JSON consumers match on. They differ for `btrfs`
        // (binary) vs `btrfs_check` (code) because the `btrfs`
        // binary owns many subcommands and the code must identify
        // the specific check/repair surface.
        for tool in [
            RepairTool::E2fsck,
            RepairTool::FsckFat,
            RepairTool::FsckF2fs,
            RepairTool::XfsRepair,
            RepairTool::BtrfsCheck,
        ] {
            assert!(!tool.binary_name().is_empty());
            assert!(!tool.code().is_empty());
        }
        assert_eq!(RepairTool::BtrfsCheck.binary_name(), "btrfs");
        assert_eq!(RepairTool::BtrfsCheck.code(), "btrfs_check");
    }

    #[test]
    fn attempt_kind_high_risk_classification_is_stable() {
        // The two high-risk fallbacks the spec authorises are
        // xfs_repair -L and btrfs check --repair. The orchestrator
        // MUST mark those attempts HighRiskFallback so the report's
        // `repaired_with_risk` outcome can be derived from the
        // audit trail alone.
        assert!(AttemptKind::HighRiskFallback.is_high_risk());
        assert!(!AttemptKind::Repair.is_high_risk());
        assert!(!AttemptKind::ReadonlyCheck.is_high_risk());
        assert!(!AttemptKind::VerificationCheck.is_high_risk());
    }

    #[test]
    fn report_used_high_risk_fallback_inspects_attempts() {
        // A report with a high-risk attempt must report it via the
        // helper. Guards against a regression where we add a fallback
        // but forget to mark it.
        let mut report = FsRepairReport {
            final_outcome: FsRepairOutcome::RepairedWithRisk,
            ..Default::default()
        };
        assert!(!report.used_high_risk_fallback());
        report.attempts.push(RepairAttempt {
            kind: AttemptKind::HighRiskFallback,
            tool: RepairTool::XfsRepair,
            argv: vec!["-L".into(), "/dev/sda1".into()],
            high_risk: true,
            exit: ExitInterpretation::not_run(),
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            rationale: "log zeroing fallback".into(),
        });
        assert!(report.used_high_risk_fallback());
    }

    #[test]
    fn refused_report_marks_requires_human_action() {
        // Every refusal implies the operator must do something. The
        // inverse is not true: RepairedWithRisk also requires review.
        let report = FsRepairReport::refused(
            FsRepairOutcome::RefusedRunningRoot,
            "target is the running root",
        );
        assert!(report.requires_human_action);
        assert!(report.attempts.is_empty());
    }

    #[test]
    fn default_outcome_is_unknown_never_a_clean_silently() {
        // FsRepairOutcome::default() must be Unknown. A report that
        // forgot to set its outcome must NOT silently look clean.
        assert_eq!(FsRepairOutcome::default(), FsRepairOutcome::Unknown);
        assert!(!FsRepairOutcome::Unknown.is_success());
    }
}
