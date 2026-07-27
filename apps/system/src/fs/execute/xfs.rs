use crate::fs::command::{FsCommandInvocation, FsCommandRunner, FsRunnerError};
use crate::fs::diagnose::xfs::decode_xfs_exit;
use crate::fs::execute::{FlowOutcome, FlowResult};
use crate::fs::model::{AttemptKind, RepairAttempt, RepairTool};
use crate::fs::plan::xfs::XfsRepairPlan;

pub(super) fn execute<R: FsCommandRunner + ?Sized>(
    runner: &R,
    plan: &XfsRepairPlan,
) -> Result<FlowResult, FsRunnerError> {
    let device = plan.device.as_str();
    let normal_invocation =
        FsCommandInvocation::new(RepairTool::XfsRepair.binary_name(), vec![device.into()]);
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
        // Modify-mode xfs_repair does not distinguish "nothing to do"
        // from "repairs were made" in its normal exit status. Never
        // claim clean without a preceding -n check.
        FlowOutcome::Repaired
    } else if normal_result.exit_code == 2 && plan.allow_log_zero_fallback {
        // Dirty log: fall back to -L as the spec authorizes. Mark
        // the attempt HighRiskFallback.
        let fallback_invocation = FsCommandInvocation::new(
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
