use crate::command::{FsCommandInvocation, FsCommandRunner, FsRunnerError};
use crate::diagnose::btrfs::{decode_btrfs_exit, reports_metadata_checksum_failure};
use crate::execute::{FlowOutcome, FlowResult};
use crate::model::{AttemptKind, RepairAttempt, RepairTool};
use crate::plan::btrfs::BtrfsRepairPlan;

pub(super) fn execute<R: FsCommandRunner + ?Sized>(
    runner: &R,
    plan: &BtrfsRepairPlan,
) -> Result<FlowResult, FsRunnerError> {
    let device = plan.device.as_str();
    debug_assert!(matches!(
        plan.topology,
        crate::diagnose::BtrfsTopology::SingleDevice
    ));
    // Step 1: read-only check.
    let check_invocation = FsCommandInvocation::new(
        RepairTool::BtrfsCheck.binary_name(),
        vec!["check".into(), "--readonly".into(), device.into()],
    );
    let check_result = runner.invoke(&check_invocation)?;
    let check_detected_corruption = reports_metadata_checksum_failure(&check_result);
    let mut check_interp = decode_btrfs_exit(&check_result);
    if check_detected_corruption {
        check_interp.clean = false;
        check_interp.errors_uncorrected = true;
        check_interp.label = Some("btrfs-metadata-checksum-failure".into());
    }
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
    if check_result.exit_code == 0 && !check_detected_corruption {
        // Clean: no repair needed. btrfs-progs may still return zero after
        // recovering a bad DUP metadata mirror; the explicit checksum
        // diagnostic above is therefore part of the corruption verdict.
        return Ok(FlowResult {
            attempts: vec![check_attempt],
            outcome: FlowOutcome::Clean,
        });
    }

    if !plan.allow_repair_fallback {
        return Ok(FlowResult {
            attempts: vec![check_attempt],
            outcome: FlowOutcome::Unrepaired,
        });
    }

    // Step 2: check failed -> run --repair as authorized fallback.
    let repair_invocation = FsCommandInvocation::new(
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

    if !plan.verify_after_repair {
        let outcome = if repair_result.exit_code == 0 {
            FlowOutcome::RepairedViaHighRiskFallback
        } else {
            FlowOutcome::Unrepaired
        };
        return Ok(FlowResult {
            attempts: vec![check_attempt, repair_attempt],
            outcome,
        });
    }

    // Step 3: re-run read-only check to confirm post-repair state.
    let recheck_invocation = FsCommandInvocation::new(
        RepairTool::BtrfsCheck.binary_name(),
        vec!["check".into(), "--readonly".into(), device.into()],
    );
    let recheck_result = runner.invoke(&recheck_invocation)?;
    let recheck_detected_corruption = reports_metadata_checksum_failure(&recheck_result);
    let mut recheck_interp = decode_btrfs_exit(&recheck_result);
    if recheck_detected_corruption {
        recheck_interp.clean = false;
        recheck_interp.errors_uncorrected = true;
        recheck_interp.label = Some("btrfs-metadata-checksum-failure".into());
    }
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

    let outcome = if repair_result.exit_code == 0
        && recheck_result.exit_code == 0
        && !recheck_detected_corruption
    {
        FlowOutcome::RepairedViaHighRiskFallback
    } else {
        FlowOutcome::Unrepaired
    };

    Ok(FlowResult {
        attempts: vec![check_attempt, repair_attempt, recheck_attempt],
        outcome,
    })
}
