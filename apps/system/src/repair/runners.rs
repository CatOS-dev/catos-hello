//! Per-filesystem repair flows.
//!
//! Each function takes a `&dyn CommandRunner`, the target device
//! path, and returns a list of [`RepairAttempt`]s plus a
//! repair-level outcome. The orchestrator turns these into a final
//! `FsRepairOutcome` after verification.
//!
//! ## Verified flag sources
//!
//! Flags below were verified against current upstream documentation
//! (e2fsck(8), fsck.fat(8), fsck.f2fs(8), xfs_repair(8),
//! btrfs-check(8)). Do NOT change them from memory; check the
//! citations in each function's doc comment.
//!
//! ## Why each flow returns attempts AND an outcome
//!
//! The orchestrator needs both: the attempts go into the report
//! verbatim (audit trail), and the outcome decides whether to
//! proceed to verification. A flow that returned only "the report"
//! would force the orchestrator to re-derive "did it work?" from
//! the same data — duplication that drifts.

use crate::model::repair::{AttemptKind, ExitInterpretation, RepairAttempt, RepairTool};
use crate::repair::runner::{CommandRunner, RepairInvocation, RepairRunnerError, ToolResult};
use std::time::Duration;

/// Repair-level outcome returned by each per-fstype flow. This is
/// NOT the final `FsRepairOutcome`: the orchestrator still has to
/// run the verification mount and combine the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowOutcome {
    /// Filesystem checked clean; no repair was needed.
    Clean,
    /// Repair ran and the tool reported success (or
    /// "errors-corrected, no errors left"). Verification may still
    /// fail downstream.
    Repaired,
    /// High-risk fallback was used and reported success. Caller
    /// upgrades to `RepairedWithRisk`.
    RepairedViaHighRiskFallback,
    /// The tool is missing. No further attempts make sense for this
    /// fstype.
    ToolMissing,
    /// The tool ran but reported errors it could not fix. Caller
    /// surfaces `Unrepaired`.
    Unrepaired,
    /// The tool timed out. Treated as Unrepaired for outcome
    /// purposes, but recorded distinctly so the report shows it.
    TimedOut,
}

/// Result of running a per-fstype flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowResult {
    pub attempts: Vec<RepairAttempt>,
    pub outcome: FlowOutcome,
}

/// Whether the orchestrator knows how to route this filesystem type.
/// Anything else short-circuits to `FsRepairOutcome::Unsupported`.
pub fn supports_filesystem(fstype: &str) -> Option<RepairTool> {
    match fstype {
        "ext2" | "ext3" | "ext4" => Some(RepairTool::E2fsck),
        "vfat" | "fat" | "fat32" | "fat16" | "fat12" | "msdos" => Some(RepairTool::FsckFat),
        "f2fs" => Some(RepairTool::FsckF2fs),
        "xfs" => Some(RepairTool::XfsRepair),
        "btrfs" => Some(RepairTool::BtrfsCheck),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// e2fsck (ext2/ext3/ext4)
// ---------------------------------------------------------------------------

/// Run e2fsck on the target.
///
/// ## Flags (verified against e2fsck(8), e2fsprogs current)
///
/// * `-y` — assume "yes" to all prompts. This is the canonical
///   non-interactive auto-repair flag. (`-p` is "preen", which only
///   fixes safe problems; we want full auto-repair.)
/// * `-C 0` — progress reporter on file descriptor 0 (none). Disables
///   the default progress bar that would otherwise try to write to
///   the controlling terminal we do not have.
///
/// ## Exit code bitmask (verified)
///
/// ```text
///   0 = no errors
///   1 = system errors corrected, file system is clean
///   2 = system errors corrected, system should be rebooted
///   4 = file system errors left uncorrected
///   8 = operational error
///  16 = usage or syntax error
///  32 = e2fsck canceled by user request
/// 128 = shared library error
/// ```
///
/// Combinations are bitmask ORed, so `3` means "errors corrected AND
/// reboot recommended". We MUST interpret bit-by-bit; the spec is
/// explicit: "工具返回'已修复、建议重启'等标准非零状态时，不能
/// 一律误判成执行器崩溃".
pub fn e2fsck_flow<R: CommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<FlowResult, crate::repair::runner::RepairRunnerError> {
    let invocation = RepairInvocation::new(
        RepairTool::E2fsck.binary_name(),
        vec!["-y".into(), "-C".into(), "0".into(), device.into()],
    );
    let result = runner.invoke(&invocation)?;
    let outcome_decision = decide_e2fsck_outcome(&result);
    let interpretation = decode_e2fsck_exit(&result);
    let attempt = RepairAttempt {
        kind: AttemptKind::Repair,
        tool: RepairTool::E2fsck,
        argv: invocation.argv,
        high_risk: false,
        exit: interpretation,
        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        rationale: "e2fsck non-interactive auto-repair (-y -C 0)".into(),
    };

    Ok(FlowResult {
        attempts: vec![attempt],
        outcome: outcome_decision,
    })
}

/// Decide the e2fsck flow outcome from the tool result, without
/// holding any borrows into the attempt. Pure function.
fn decide_e2fsck_outcome(result: &ToolResult) -> FlowOutcome {
    if result.binary_missing {
        return FlowOutcome::ToolMissing;
    }
    if result.timed_out {
        return FlowOutcome::TimedOut;
    }
    let code = result.exit_code;
    if code == 0 {
        return FlowOutcome::Clean;
    }
    if (code & 0x04) != 0 || (code & 0x10) != 0 || (code & 0x08) != 0 || (code & 0x80) != 0 {
        // Bit 2 (uncorrected), bit 5 (usage error), bit 7 (shared
        // lib error), or bit 3 (operational). Any of these means
        // the tool did NOT successfully repair.
        return FlowOutcome::Unrepaired;
    }
    // Exit codes 1, 2, 3 (1|2) mean "errors corrected" or
    // "errors corrected + reboot recommended". That is success.
    FlowOutcome::Repaired
}

/// Decode an e2fsck exit code into the structured interpretation.
/// Pure function; exported so tests can pin the bitmask table.
pub fn decode_e2fsck_exit(result: &ToolResult) -> ExitInterpretation {
    let code = result.exit_code;
    let mut interp = result.base_interpretation();
    if result.binary_missing || result.timed_out {
        interp.label = Some(format!(
            "e2fsck-binary-{}-code-{}",
            result.binary_missing as u8, code
        ));
        return interp;
    }
    interp.clean = code == 0;
    interp.errors_corrected = (code & 0x01) != 0;
    interp.reboot_required = (code & 0x02) != 0;
    interp.exited_early = (code & 0x20) != 0;
    interp.errors_uncorrected = (code & 0x04) != 0;
    interp.label = Some(format!("e2fsck-code-{code}"));
    interp
}

// ---------------------------------------------------------------------------
// fsck.fat (vfat/fat/msdos/fat12/16/32)
// ---------------------------------------------------------------------------

/// Run fsck.fat on the target.
///
/// ## Flags (verified against fsck.fat(8), dosfstools current)
///
/// * `-a` — automatic repair (avar = "auto"). Same as `-p` per the
///   man page; we use `-a` because it is unambiguous in output.
///
/// ## Exit codes (verified)
///
/// ```text
///   0 = no recoverable errors
///   1 = recoverable errors found (and corrected under -a)
///   2 = usage error, no filesystem access
/// ```
pub fn fat_flow<R: CommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<FlowResult, crate::repair::runner::RepairRunnerError> {
    let invocation = RepairInvocation::new(
        RepairTool::FsckFat.binary_name(),
        vec!["-a".into(), device.into()],
    );
    let result = runner.invoke(&invocation)?;
    let interpretation = decode_fat_exit(&result);
    let attempt = RepairAttempt {
        kind: AttemptKind::Repair,
        tool: RepairTool::FsckFat,
        argv: invocation.argv,
        high_risk: false,
        exit: interpretation,
        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        rationale: "fsck.fat non-interactive auto-repair (-a)".into(),
    };

    let outcome = if result.binary_missing {
        FlowOutcome::ToolMissing
    } else if result.timed_out {
        FlowOutcome::TimedOut
    } else if result.exit_code == 0 {
        FlowOutcome::Clean
    } else if result.exit_code == 1 {
        FlowOutcome::Repaired
    } else {
        // 2 = usage error; anything else is unexpected. Treat as
        // unrepaired rather than guessing.
        FlowOutcome::Unrepaired
    };

    Ok(FlowResult {
        attempts: vec![attempt],
        outcome,
    })
}

pub fn decode_fat_exit(result: &ToolResult) -> ExitInterpretation {
    let code = result.exit_code;
    let mut interp = result.base_interpretation();
    if result.binary_missing || result.timed_out {
        interp.label = Some("fsck.fat-not-run".into());
        return interp;
    }
    interp.clean = code == 0;
    interp.errors_corrected = code == 1;
    // fsck.fat does not document a "reboot" bit; default false.
    // Usage error (2) and higher are surfaced via errors_uncorrected
    // because they mean the tool did not produce a clean state.
    interp.errors_uncorrected = code >= 2;
    interp.exited_early = false;
    interp.label = Some(format!("fsck.fat-code-{code}"));
    interp
}

// ---------------------------------------------------------------------------
// fsck.f2fs
// ---------------------------------------------------------------------------

/// Run fsck.f2fs on the target.
///
/// ## Flags (verified against current upstream f2fs-tools)
///
/// * `-a` — fix kernel-reported corruption only. Conservative
///   auto-repair; matches e2fsck preen semantics. NOT the same as
///   `-f`, which force-fixes the entire partition (the brute-force
///   mode).
///
/// We deliberately do NOT use `-f` or its alias `-y`: those run the
/// brute-force fix on the entire partition. The spec authorizes
/// high-risk fallbacks only for xfs and btrfs; f2fs's brute-force
/// mode is NOT authorized here.
///
/// ## Exit codes (verified against f2fs-tools `fsck/main.c`)
///
/// Same bitmask as e2fsck:
/// ```text
///   0 = success
///   1 = corrected
///   2 = reboot
///   4 = uncorrected
///   8 = operational
///  16 = usage/syntax
///  32 = canceled
/// 128 = shared lib error
/// ```
pub fn f2fs_flow<R: CommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<FlowResult, crate::repair::runner::RepairRunnerError> {
    let invocation = RepairInvocation::new(
        RepairTool::FsckF2fs.binary_name(),
        vec!["-a".into(), device.into()],
    );
    let result = runner.invoke(&invocation)?;
    let interpretation = decode_f2fs_exit(&result);
    let attempt = RepairAttempt {
        kind: AttemptKind::Repair,
        tool: RepairTool::FsckF2fs,
        argv: invocation.argv,
        high_risk: false,
        exit: interpretation,
        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        rationale: "fsck.f2fs non-interactive auto-repair (-a; conservative)".into(),
    };

    let outcome = if result.binary_missing {
        FlowOutcome::ToolMissing
    } else if result.timed_out {
        FlowOutcome::TimedOut
    } else if result.exit_code == 0 {
        FlowOutcome::Clean
    } else if (result.exit_code & 0x04) != 0
        || (result.exit_code & 0x10) != 0
        || (result.exit_code & 0x08) != 0
        || (result.exit_code & 0x80) != 0
    {
        // Uncorrected, usage, operational, or shared lib error.
        FlowOutcome::Unrepaired
    } else {
        // 1 = corrected, 2 = reboot, 3 = both. All success.
        FlowOutcome::Repaired
    };

    Ok(FlowResult {
        attempts: vec![attempt],
        outcome,
    })
}

pub fn decode_f2fs_exit(result: &ToolResult) -> ExitInterpretation {
    // f2fs reuses the e2fsck bitmask table. We share the decoder
    // rather than duplicating the bit assignments.
    let mut interp = decode_e2fsck_exit(result);
    if let Some(label) = interp.label.as_mut() {
        *label = label.replacen("e2fsck-", "fsck.f2fs-", 1);
    }
    interp
}

// ---------------------------------------------------------------------------
// xfs_repair
// ---------------------------------------------------------------------------

/// Run xfs_repair on the target.
///
/// ## Sequence (verified against xfs_repair(8), xfsprogs current)
///
/// 1. `xfs_repair DEVICE` — the canonical repair invocation. No
///    flags needed; the tool defaults to modify-mode when invoked
///    without `-n`.
/// 2. If (1) fails because the log is dirty (exit code 2), run
///    `xfs_repair -L DEVICE` as the **authorized last-resort
///    fallback**. The man page warns verbatim: "Forces xfs_repair
///    to zero the log even if it is dirty ... can cause the loss of
///    user files and/or data."
///
/// ## Exit codes (verified)
///
/// Normal repair (modify mode):
/// ```text
///   0 = success
///   1 = runtime error
///   2 = log is dirty (use -L as last resort)
/// ```
///
/// The `-e` flag would change "repaired something" to exit 4; we do
/// NOT pass `-e` so the canonical mapping above applies.
pub fn xfs_flow<R: CommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<FlowResult, crate::repair::runner::RepairRunnerError> {
    let normal_invocation =
        RepairInvocation::new(RepairTool::XfsRepair.binary_name(), vec![device.into()]);
    let normal_result = runner.invoke(&normal_invocation)?;
    let normal_interp = decode_xfs_exit(&normal_result, false);
    let normal_attempt = RepairAttempt {
        kind: AttemptKind::Repair,
        tool: RepairTool::XfsRepair,
        argv: normal_invocation.argv.clone(),
        high_risk: false,
        exit: normal_interp,
        stdout: String::from_utf8_lossy(&normal_result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&normal_result.stderr).into_owned(),
        stdout_truncated: normal_result.stdout_truncated,
        stderr_truncated: normal_result.stderr_truncated,
        rationale: "xfs_repair canonical modify-mode invocation".into(),
    };

    let outcome = if normal_result.binary_missing {
        FlowOutcome::ToolMissing
    } else if normal_result.timed_out {
        FlowOutcome::TimedOut
    } else if normal_result.exit_code == 0 {
        FlowOutcome::Clean
    } else if normal_result.exit_code == 2 {
        // Dirty log: fall back to -L as the spec authorizes. Mark
        // the attempt HighRiskFallback.
        let fallback_invocation = RepairInvocation::new(
            RepairTool::XfsRepair.binary_name(),
            vec!["-L".into(), device.into()],
        );
        let fallback_result = runner.invoke(&fallback_invocation)?;
        let fallback_interp = decode_xfs_exit(&fallback_result, true);
        let fallback_attempt = RepairAttempt {
            kind: AttemptKind::HighRiskFallback,
            tool: RepairTool::XfsRepair,
            argv: fallback_invocation.argv.clone(),
            high_risk: true,
            exit: fallback_interp,
            stdout: String::from_utf8_lossy(&fallback_result.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&fallback_result.stderr).into_owned(),
            stdout_truncated: fallback_result.stdout_truncated,
            stderr_truncated: fallback_result.stderr_truncated,
            rationale: "xfs_repair -L authorized last-resort fallback (zeroes the log; may cause data loss)".into(),
        };

        let combined_outcome = if fallback_result.exit_code == 0 {
            FlowOutcome::RepairedViaHighRiskFallback
        } else {
            FlowOutcome::Unrepaired
        };
        let mut attempts = vec![normal_attempt];
        attempts.push(fallback_attempt);
        return Ok(FlowResult {
            attempts,
            outcome: combined_outcome,
        });
    } else {
        // 1 = runtime error; anything else unexpected. Treat as
        // unrepaired rather than guessing.
        FlowOutcome::Unrepaired
    };

    Ok(FlowResult {
        attempts: vec![normal_attempt],
        outcome,
    })
}

pub fn decode_xfs_exit(result: &ToolResult, high_risk: bool) -> ExitInterpretation {
    let code = result.exit_code;
    let mut interp = result.base_interpretation();
    if result.binary_missing || result.timed_out {
        interp.label = Some("xfs_repair-not-run".into());
        return interp;
    }
    interp.clean = code == 0;
    // xfs_repair's exit codes are not a bitmask; 0 is success and
    // any non-zero is a failure of some kind. We mark
    // errors_corrected=false unconditionally because the tool does
    // not signal "fixed but dirty" — it either succeeded (0) or did
    // not (1+). Verification mount is what tells us the real state.
    interp.errors_corrected = false;
    interp.reboot_required = false;
    interp.exited_early = false;
    interp.errors_uncorrected = code != 0;
    interp.label = Some(format!(
        "xfs_repair-{}-code-{code}",
        if high_risk { "L" } else { "normal" }
    ));
    interp
}

// ---------------------------------------------------------------------------
// btrfs check
// ---------------------------------------------------------------------------

/// Topology reported by `btrfs filesystem show DEVICE`. A repair flow
/// supports only a single-device filesystem; unknown topology is refused
/// just as conservatively as a known multi-device filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsTopology {
    SingleDevice,
    MultiDevice,
    Unknown,
}

pub fn btrfs_topology<R: CommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<BtrfsTopology, RepairRunnerError> {
    let invocation = RepairInvocation::new(
        RepairTool::BtrfsCheck.binary_name(),
        vec!["filesystem".into(), "show".into(), device.into()],
    )
    .with_timeout(Duration::from_secs(30));
    let result = runner.invoke(&invocation)?;
    if result.binary_missing || result.timed_out || result.exit_code != 0 {
        return Ok(BtrfsTopology::Unknown);
    }
    let output = String::from_utf8_lossy(&result.stdout);
    let count = output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Total devices ")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse::<u32>().ok())
    });
    Ok(match count {
        Some(1) => BtrfsTopology::SingleDevice,
        Some(_) => BtrfsTopology::MultiDevice,
        None => BtrfsTopology::Unknown,
    })
}

/// Run the btrfs check sequence on the target.
///
/// ## Sequence (verified against btrfs-check(8), btrfs-progs current)
///
/// 1. `btrfs check --readonly DEVICE` — read-only check. The man
///    page says `btrfs check` is read-only by default; we add
///    `--readonly` explicitly so the audit trail is unambiguous.
/// 2. If (1) reports errors, run `btrfs check --repair DEVICE` as
///    the **authorized last-resort fallback**. The man page warns
///    verbatim: "Do not use --repair unless you are advised to do
///    so by a developer or an experienced user...".
/// 3. After repair, run `btrfs check --readonly DEVICE` again to
///    confirm the filesystem is now clean.
///
/// The orchestrator then runs the standard read-only verification
/// mount, which is the final structural check.
///
/// ## Exit codes (verified)
///
/// btrfs-progs documents only:
/// ```text
///   0 = success
///   non-zero = failure
/// ```
///
/// We do not interpret specific non-zero values for btrfs because
/// the upstream documentation is silent on them.
///
/// ## Multi-device btrfs
///
/// This flow operates on ONE device. The orchestrator detects
/// multi-device btrfs by inspecting the discovered device set: if
/// `btrfs filesystem show` reports more than one device for this
/// FSID, the orchestrator refuses with `Unsupported` and surfaces
/// "manual intervention required". The spec explicitly says:
/// "本阶段不实现多设备 Btrfs 恢复编排".
pub fn btrfs_flow<R: CommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<FlowResult, crate::repair::runner::RepairRunnerError> {
    // Step 1: read-only check.
    let check_invocation = RepairInvocation::new(
        RepairTool::BtrfsCheck.binary_name(),
        vec!["check".into(), "--readonly".into(), device.into()],
    );
    let check_result = runner.invoke(&check_invocation)?;
    let check_interp = decode_btrfs_exit(&check_result);
    let check_attempt = RepairAttempt {
        kind: AttemptKind::ReadonlyCheck,
        tool: RepairTool::BtrfsCheck,
        argv: check_invocation.argv.clone(),
        high_risk: false,
        exit: check_interp,
        stdout: String::from_utf8_lossy(&check_result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&check_result.stderr).into_owned(),
        stdout_truncated: check_result.stdout_truncated,
        stderr_truncated: check_result.stderr_truncated,
        rationale: "btrfs check --readonly (read-only structural check)".into(),
    };

    if check_result.binary_missing {
        return Ok(FlowResult {
            attempts: vec![check_attempt],
            outcome: FlowOutcome::ToolMissing,
        });
    }
    if check_result.timed_out {
        return Ok(FlowResult {
            attempts: vec![check_attempt],
            outcome: FlowOutcome::TimedOut,
        });
    }
    if check_result.exit_code == 0 {
        // Clean: no repair needed.
        return Ok(FlowResult {
            attempts: vec![check_attempt],
            outcome: FlowOutcome::Clean,
        });
    }

    // Step 2: check failed -> run --repair as authorized fallback.
    let repair_invocation = RepairInvocation::new(
        RepairTool::BtrfsCheck.binary_name(),
        vec!["check".into(), "--repair".into(), device.into()],
    );
    let repair_result = runner.invoke(&repair_invocation)?;
    let repair_interp = decode_btrfs_exit(&repair_result);
    let repair_attempt = RepairAttempt {
        kind: AttemptKind::HighRiskFallback,
        tool: RepairTool::BtrfsCheck,
        argv: repair_invocation.argv.clone(),
        high_risk: true,
        exit: repair_interp,
        stdout: String::from_utf8_lossy(&repair_result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&repair_result.stderr).into_owned(),
        stdout_truncated: repair_result.stdout_truncated,
        stderr_truncated: repair_result.stderr_truncated,
        rationale: "btrfs check --repair authorized last-resort fallback (btrfs-progs authors warn against running without developer advice)".into(),
    };

    if repair_result.exit_code != 0 {
        // Repair failed; we still try the second read-only check
        // below so the report shows the final state, but the outcome
        // is Unrepaired.
    }

    // Step 3: re-run read-only check to confirm post-repair state.
    let recheck_invocation = RepairInvocation::new(
        RepairTool::BtrfsCheck.binary_name(),
        vec!["check".into(), "--readonly".into(), device.into()],
    );
    let recheck_result = runner.invoke(&recheck_invocation)?;
    let recheck_interp = decode_btrfs_exit(&recheck_result);
    let recheck_attempt = RepairAttempt {
        kind: AttemptKind::VerificationCheck,
        tool: RepairTool::BtrfsCheck,
        argv: recheck_invocation.argv.clone(),
        high_risk: false,
        exit: recheck_interp,
        stdout: String::from_utf8_lossy(&recheck_result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&recheck_result.stderr).into_owned(),
        stdout_truncated: recheck_result.stdout_truncated,
        stderr_truncated: recheck_result.stderr_truncated,
        rationale: "btrfs check --readonly (post-repair recheck)".into(),
    };

    let outcome = if repair_result.exit_code == 0 && recheck_result.exit_code == 0 {
        FlowOutcome::RepairedViaHighRiskFallback
    } else {
        FlowOutcome::Unrepaired
    };

    Ok(FlowResult {
        attempts: vec![check_attempt, repair_attempt, recheck_attempt],
        outcome,
    })
}

pub fn decode_btrfs_exit(result: &ToolResult) -> ExitInterpretation {
    let code = result.exit_code;
    let mut interp = result.base_interpretation();
    if result.binary_missing || result.timed_out {
        interp.label = Some("btrfs-not-run".into());
        return interp;
    }
    interp.clean = code == 0;
    // btrfs-progs documents only 0=success, non-zero=failure. We do
    // not invent interpretations for specific non-zero codes.
    interp.errors_corrected = false;
    interp.reboot_required = false;
    interp.exited_early = false;
    interp.errors_uncorrected = code != 0;
    interp.label = Some(format!("btrfs-check-code-{code}"));
    interp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repair::runner::{RecordedRunner, ToolResult};

    #[test]
    fn supports_filesystem_returns_tool_for_known_fstypes() {
        assert_eq!(supports_filesystem("ext4"), Some(RepairTool::E2fsck));
        assert_eq!(supports_filesystem("ext2"), Some(RepairTool::E2fsck));
        assert_eq!(supports_filesystem("vfat"), Some(RepairTool::FsckFat));
        assert_eq!(supports_filesystem("fat32"), Some(RepairTool::FsckFat));
        assert_eq!(supports_filesystem("f2fs"), Some(RepairTool::FsckF2fs));
        assert_eq!(supports_filesystem("xfs"), Some(RepairTool::XfsRepair));
        assert_eq!(supports_filesystem("btrfs"), Some(RepairTool::BtrfsCheck));
        assert_eq!(supports_filesystem("ntfs3"), None);
        assert_eq!(supports_filesystem("zfs"), None);
        assert_eq!(supports_filesystem(""), None);
    }

    // ---------------- e2fsck ----------------

    #[test]
    fn e2fsck_clean_exit_is_clean() {
        let runner = RecordedRunner::new().queue_raw(0, b"clean".to_vec(), b"".to_vec());
        let flow = e2fsck_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Clean);
        assert_eq!(flow.attempts.len(), 1);
        assert!(flow.attempts[0].exit.clean);
    }

    #[test]
    fn e2fsck_exit_1_is_repaired() {
        let runner = RecordedRunner::new().queue_raw(1, b"corrected".to_vec(), b"".to_vec());
        let flow = e2fsck_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Repaired);
        assert!(flow.attempts[0].exit.errors_corrected);
    }

    #[test]
    fn e2fsck_exit_2_is_repaired_with_reboot() {
        // Exit 2 by itself means "reboot recommended" but bit 0
        // (errors_corrected) is NOT set. This is still a successful
        // outcome: no errors were left uncorrected. The spec is
        // explicit: do not misread standard non-zero "fixed, reboot"
        // states as executor crashes.
        let runner = RecordedRunner::new().queue_raw(2, b"".to_vec(), b"".to_vec());
        let flow = e2fsck_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Repaired);
        assert!(flow.attempts[0].exit.reboot_required);
        assert!(!flow.attempts[0].exit.errors_corrected);
        assert!(!flow.attempts[0].exit.errors_uncorrected);
    }

    #[test]
    fn e2fsck_exit_3_combines_corrected_and_reboot() {
        // Bit 0 | bit 1 = 3.
        let runner = RecordedRunner::new().queue_raw(3, b"".to_vec(), b"".to_vec());
        let flow = e2fsck_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Repaired);
        assert!(flow.attempts[0].exit.errors_corrected);
        assert!(flow.attempts[0].exit.reboot_required);
    }

    #[test]
    fn e2fsck_exit_4_is_unrepaired() {
        // Bit 2 = errors left uncorrected.
        let runner = RecordedRunner::new().queue_raw(4, b"".to_vec(), b"".to_vec());
        let flow = e2fsck_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Unrepaired);
        assert!(flow.attempts[0].exit.errors_uncorrected);
    }

    #[test]
    fn e2fsck_missing_binary_is_tool_missing() {
        let runner = RecordedRunner::new().queue(ToolResult::binary_missing());
        let flow = e2fsck_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::ToolMissing);
        assert!(flow.attempts[0].exit.binary_missing);
    }

    #[test]
    fn e2fsck_argv_is_independent_no_shell() {
        // The argv MUST be passed as separate elements; no shell.
        // Verifiable from the recorded runner.
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let _ = e2fsck_flow(&runner, "/dev/sda1").unwrap();
        let invocations = runner.invocations();
        assert_eq!(invocations[0].binary, "e2fsck");
        assert_eq!(
            invocations[0].argv,
            vec!["-y", "-C", "0", "/dev/sda1"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn e2fsck_truncation_is_recorded() {
        // The runner may truncate stdout/stderr to the safety limit.
        // The attempt MUST record the truncation flag.
        let runner = RecordedRunner::new().queue(ToolResult {
            binary_missing: false,
            timed_out: false,
            exit_code: 0,
            stdout: b"clean".to_vec(),
            stderr: b"".to_vec(),
            stdout_truncated: true,
            stderr_truncated: false,
        });
        let flow = e2fsck_flow(&runner, "/dev/sda1").unwrap();
        assert!(flow.attempts[0].stdout_truncated);
        assert!(!flow.attempts[0].stderr_truncated);
    }

    // ---------------- fsck.fat ----------------

    #[test]
    fn fat_clean_exit_is_clean() {
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let flow = fat_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Clean);
    }

    #[test]
    fn fat_exit_1_is_repaired() {
        let runner = RecordedRunner::new().queue_raw(1, b"".to_vec(), b"".to_vec());
        let flow = fat_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Repaired);
        assert!(flow.attempts[0].exit.errors_corrected);
    }

    #[test]
    fn fat_exit_2_is_unrepaired_usage_error() {
        let runner = RecordedRunner::new().queue_raw(2, b"".to_vec(), b"usage".to_vec());
        let flow = fat_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Unrepaired);
    }

    #[test]
    fn fat_uses_a_flag_not_r() {
        // -a is auto-repair; -r is interactive (default). We must
        // use -a for non-interactive mode.
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let _ = fat_flow(&runner, "/dev/sda1").unwrap();
        assert!(runner.any_invocation_with_flag("-a"));
        assert!(!runner.any_invocation_with_flag("-r"));
    }

    // ---------------- fsck.f2fs ----------------

    #[test]
    fn f2fs_clean_exit_is_clean() {
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let flow = f2fs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Clean);
    }

    #[test]
    fn f2fs_exit_1_is_repaired() {
        let runner = RecordedRunner::new().queue_raw(1, b"".to_vec(), b"".to_vec());
        let flow = f2fs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Repaired);
    }

    #[test]
    fn f2fs_uses_a_not_f_or_y() {
        // -a = auto-fix kernel-reported; -f = brute force; -y is an
        // alias for -f. We use the conservative -a.
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let _ = f2fs_flow(&runner, "/dev/sda1").unwrap();
        assert!(runner.any_invocation_with_flag("-a"));
        assert!(!runner.any_invocation_with_flag("-f"));
        assert!(!runner.any_invocation_with_flag("-y"));
    }

    // ---------------- xfs ----------------

    #[test]
    fn xfs_clean_does_not_use_l() {
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let flow = xfs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Clean);
        assert!(!runner.any_invocation_with_flag("-L"));
        assert_eq!(flow.attempts.len(), 1);
        assert!(!flow.attempts[0].high_risk);
    }

    #[test]
    fn xfs_dirty_log_triggers_l_fallback_marked_high_risk() {
        // Exit 2 = dirty log. We MUST escalate to -L, and the -L
        // attempt MUST be marked HighRiskFallback.
        let runner = RecordedRunner::new()
            .queue_raw(2, b"".to_vec(), b"dirty log".to_vec())
            .queue_raw(0, b"".to_vec(), b"".to_vec());
        let flow = xfs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::RepairedViaHighRiskFallback);
        assert_eq!(flow.attempts.len(), 2);
        assert!(!flow.attempts[0].high_risk);
        assert!(flow.attempts[1].high_risk);
        assert_eq!(flow.attempts[1].kind, AttemptKind::HighRiskFallback);
        assert!(flow.attempts[1].rationale.contains("last-resort"));
    }

    #[test]
    fn xfs_runtime_error_does_not_escalate_to_l() {
        // Exit 1 = runtime error, NOT a dirty log. We MUST NOT
        // escalate to -L for non-dirty-log failures.
        let runner = RecordedRunner::new().queue_raw(1, b"".to_vec(), b"oops".to_vec());
        let flow = xfs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Unrepaired);
        assert!(!runner.any_invocation_with_flag("-L"));
        assert_eq!(flow.attempts.len(), 1);
    }

    #[test]
    fn xfs_l_failure_is_unrepaired() {
        let runner = RecordedRunner::new()
            .queue_raw(2, b"".to_vec(), b"dirty log".to_vec())
            .queue_raw(1, b"".to_vec(), b"still bad".to_vec());
        let flow = xfs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Unrepaired);
        assert_eq!(flow.attempts.len(), 2);
        assert!(flow.attempts[1].high_risk);
    }

    #[test]
    fn xfs_argv_does_not_use_shell() {
        // The argv MUST be ["DEVICE"], not ["DEVICE -L"] or any
        // shell-concatenated form.
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let _ = xfs_flow(&runner, "/dev/sda1").unwrap();
        let invocations = runner.invocations();
        assert_eq!(invocations[0].binary, "xfs_repair");
        assert_eq!(invocations[0].argv, vec!["/dev/sda1".to_string()]);
    }

    // ---------------- btrfs ----------------

    #[test]
    fn btrfs_clean_check_does_not_run_repair() {
        // The spec is explicit: only run --repair if the read-only
        // check finds errors. A clean check MUST NOT escalate.
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let flow = btrfs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Clean);
        assert!(!runner.any_invocation_with_flag("--repair"));
        assert_eq!(flow.attempts.len(), 1);
        assert_eq!(flow.attempts[0].kind, AttemptKind::ReadonlyCheck);
    }

    #[test]
    fn btrfs_failed_check_runs_repair_then_rechecks() {
        // Spec: read-only check finds errors -> run --repair -> re-
        // run read-only check.
        let runner = RecordedRunner::new()
            .queue_raw(1, b"errors found".to_vec(), b"".to_vec())
            .queue_raw(0, b"repaired".to_vec(), b"".to_vec())
            .queue_raw(0, b"clean".to_vec(), b"".to_vec());
        let flow = btrfs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::RepairedViaHighRiskFallback);
        assert_eq!(flow.attempts.len(), 3);
        assert_eq!(flow.attempts[0].kind, AttemptKind::ReadonlyCheck);
        assert_eq!(flow.attempts[1].kind, AttemptKind::HighRiskFallback);
        assert!(flow.attempts[1].high_risk);
        assert_eq!(flow.attempts[2].kind, AttemptKind::VerificationCheck);
    }

    #[test]
    fn btrfs_repair_failure_is_unrepaired_even_if_recheck_succeeds() {
        // The spec requires: "repair 后再次运行只读检查". We do that
        // always. If repair failed, the outcome is Unrepaired
        // regardless of what the recheck says — because if repair
        // failed, the recheck running clean would be suspicious.
        let runner = RecordedRunner::new()
            .queue_raw(1, b"errors".to_vec(), b"".to_vec())
            .queue_raw(1, b"repair failed".to_vec(), b"".to_vec())
            .queue_raw(0, b"clean".to_vec(), b"".to_vec());
        let flow = btrfs_flow(&runner, "/dev/sda1").unwrap();
        assert_eq!(flow.outcome, FlowOutcome::Unrepaired);
    }

    #[test]
    fn btrfs_uses_btrfs_check_subcommand_via_btrfs_binary() {
        // The binary name is `btrfs`; the subcommand is `check`. The
        // argv is ["check", "--readonly", DEVICE] (or with --repair).
        let runner = RecordedRunner::new().queue_raw(0, b"".to_vec(), b"".to_vec());
        let _ = btrfs_flow(&runner, "/dev/sda1").unwrap();
        let invocations = runner.invocations();
        assert_eq!(invocations[0].binary, "btrfs");
        assert_eq!(
            invocations[0].argv,
            vec!["check", "--readonly", "/dev/sda1"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn btrfs_topology_refuses_multiple_members() {
        let runner = RecordedRunner::new().queue(ToolResult {
            stdout: b"Label: none  uuid: test\n\tTotal devices 2 FS bytes used 1\n".to_vec(),
            ..ToolResult::success_empty()
        });
        assert_eq!(
            btrfs_topology(&runner, "/dev/sda1").unwrap(),
            BtrfsTopology::MultiDevice
        );
        assert_eq!(
            runner.invocations()[0].argv,
            vec!["filesystem", "show", "/dev/sda1"]
        );
    }

    // ---------------- common ----------------

    #[test]
    fn missing_tool_short_circuits_to_tool_missing_outcome() {
        // For all flows, a binary-missing result MUST produce
        // FlowOutcome::ToolMissing so the orchestrator can surface
        // FsRepairOutcome::ToolMissing. No flow should attempt to
        // retry or fall back when the tool is missing.
        let runner = RecordedRunner::new().queue(ToolResult::binary_missing());
        assert_eq!(
            e2fsck_flow(&runner, "/dev/sda1").unwrap().outcome,
            FlowOutcome::ToolMissing
        );
        let runner = RecordedRunner::new().queue(ToolResult::binary_missing());
        assert_eq!(
            fat_flow(&runner, "/dev/sda1").unwrap().outcome,
            FlowOutcome::ToolMissing
        );
        let runner = RecordedRunner::new().queue(ToolResult::binary_missing());
        assert_eq!(
            f2fs_flow(&runner, "/dev/sda1").unwrap().outcome,
            FlowOutcome::ToolMissing
        );
        let runner = RecordedRunner::new().queue(ToolResult::binary_missing());
        assert_eq!(
            xfs_flow(&runner, "/dev/sda1").unwrap().outcome,
            FlowOutcome::ToolMissing
        );
        let runner = RecordedRunner::new().queue(ToolResult::binary_missing());
        assert_eq!(
            btrfs_flow(&runner, "/dev/sda1").unwrap().outcome,
            FlowOutcome::ToolMissing
        );
    }
}
