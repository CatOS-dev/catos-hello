use crate::fs::command::{FsCommandInvocation, FsCommandRunner, FsRunnerError, ToolResult};
use crate::fs::diagnose::ext::decode_e2fsck_exit;
use crate::fs::execute::{FlowOutcome, FlowResult};
use crate::fs::model::{AttemptKind, RepairAttempt, RepairTool};
use crate::fs::plan::ext::ExtRepairPlan;

pub(super) fn execute<R: FsCommandRunner + ?Sized>(
    runner: &R,
    plan: &ExtRepairPlan,
) -> Result<FlowResult, FsRunnerError> {
    let device = plan.device.as_str();
    let invocation = FsCommandInvocation::new(
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
