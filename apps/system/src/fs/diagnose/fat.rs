use crate::fs::command::{FsCommandInvocation, FsCommandRunner, ToolResult};
use crate::fs::diagnose::{ReadonlyOutcome, ReadonlyResult};
use crate::fs::model::{ExitInterpretation, RepairTool};

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

/// `fsck.fat -n DEVICE` — read-only check. Verified against
/// fsck.fat(8): `-n` is the documented "perform no modifications"
/// mode. The tool performs a read-only pass and reports what it
/// would have done.
pub fn check<R: FsCommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<ReadonlyResult, crate::fs::command::FsRunnerError> {
    let invocation = FsCommandInvocation::new(
        RepairTool::FsckFat.binary_name(),
        vec!["-n".into(), device.into()],
    );
    let result = runner.invoke(&invocation)?;
    let interp = decode_fat_exit(&result);
    let outcome = if result.binary_missing {
        ReadonlyOutcome::ToolMissing
    } else if result.timed_out {
        ReadonlyOutcome::TimedOut
    } else if result.exit_code == 0 {
        ReadonlyOutcome::Clean
    } else if result.exit_code == 1 {
        // Exit 1 under `-n` means "recoverable errors found, not
        // applied". This is detected corruption from Doctor's
        // perspective.
        ReadonlyOutcome::CorruptionDetected
    } else {
        ReadonlyOutcome::Ambiguous
    };
    Ok(ReadonlyResult {
        outcome,
        argv: invocation.argv,
        tool: RepairTool::FsckFat.binary_name(),
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        label: interp.label,
    })
}
