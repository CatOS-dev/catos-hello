use crate::fs::command::{FsCommandInvocation, FsCommandRunner, ToolResult};
use crate::fs::diagnose::{ReadonlyOutcome, ReadonlyResult};
use crate::fs::model::{ExitInterpretation, RepairTool};

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

/// `xfs_repair -n DEVICE` — read-only check. Verified against
/// xfs_repair(8): `-n` is the documented "no-op mode" which only
/// prints what would be done.
pub fn check<R: FsCommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<ReadonlyResult, crate::fs::command::FsRunnerError> {
    let invocation = FsCommandInvocation::new(
        RepairTool::XfsRepair.binary_name(),
        vec!["-n".into(), device.into()],
    );
    let result = runner.invoke(&invocation)?;
    let interp = decode_xfs_exit(&result, false);
    let outcome = if result.binary_missing {
        ReadonlyOutcome::ToolMissing
    } else if result.timed_out {
        ReadonlyOutcome::TimedOut
    } else if result.exit_code == 0 {
        ReadonlyOutcome::Clean
    } else {
        // xfs_repair -n is purely diagnostic; any non-zero exit is
        // detected corruption.
        ReadonlyOutcome::CorruptionDetected
    };
    Ok(ReadonlyResult {
        outcome,
        argv: invocation.argv,
        tool: RepairTool::XfsRepair.binary_name(),
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        label: interp.label,
    })
}
