use crate::command::{FsCommandInvocation, FsCommandRunner, FsRunnerError};
use crate::diagnose::fat::decode_fat_exit;
use crate::execute::{FlowOutcome, FlowResult};
use crate::model::{AttemptKind, RepairAttempt, RepairTool};
use crate::plan::fat::FatRepairPlan;

pub(super) fn execute<R: FsCommandRunner + ?Sized>(
    runner: &R,
    plan: &FatRepairPlan,
) -> Result<FlowResult, FsRunnerError> {
    let device = plan.device.as_str();
    let invocation = FsCommandInvocation::new(
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
