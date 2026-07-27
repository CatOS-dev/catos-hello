use crate::command::{FsCommandInvocation, FsCommandRunner, FsRunnerError};
use crate::diagnose::f2fs::decode_f2fs_exit;
use crate::execute::{FlowOutcome, FlowResult};
use crate::model::{AttemptKind, RepairAttempt, RepairTool};
use crate::plan::f2fs::F2fsRepairPlan;

pub(super) fn execute<R: FsCommandRunner + ?Sized>(
    runner: &R,
    plan: &F2fsRepairPlan,
) -> Result<FlowResult, FsRunnerError> {
    let device = plan.device.as_str();
    let invocation = FsCommandInvocation::new(
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
