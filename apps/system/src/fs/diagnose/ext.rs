use crate::fs::command::{FsCommandInvocation, FsCommandRunner, ToolResult};
use crate::fs::diagnose::{ReadonlyOutcome, ReadonlyResult};
use crate::fs::model::{ExitInterpretation, RepairTool};

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

/// `e2fsck -n DEVICE` — read-only check. Verified against e2fsck(8):
/// `-n` opens the filesystem read-only and assumes 'no' to every
/// repair prompt. The tool never writes.
pub fn check<R: FsCommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<ReadonlyResult, crate::fs::command::FsRunnerError> {
    let invocation = FsCommandInvocation::new(
        RepairTool::E2fsck.binary_name(),
        vec!["-n".into(), "-C".into(), "0".into(), device.into()],
    );
    let result = runner.invoke(&invocation)?;
    let interp = decode_e2fsck_exit(&result);
    let outcome = decide_e2fsck_readonly_outcome(&result);
    Ok(ReadonlyResult {
        outcome,
        argv: invocation.argv,
        tool: RepairTool::E2fsck.binary_name(),
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        label: interp.label,
    })
}

pub(crate) fn decide_e2fsck_readonly_outcome(result: &ToolResult) -> ReadonlyOutcome {
    if result.binary_missing {
        return ReadonlyOutcome::ToolMissing;
    }
    if result.timed_out {
        return ReadonlyOutcome::TimedOut;
    }
    let code = result.exit_code;
    if code == 0 {
        return ReadonlyOutcome::Clean;
    }
    if (code & 0x04) != 0 {
        // Bit 2 = errors left uncorrected. Under `-n` the tool did
        // not attempt to correct them, so their presence means
        // corruption was detected.
        return ReadonlyOutcome::CorruptionDetected;
    }
    if (code & 0x01) != 0 || (code & 0x02) != 0 {
        // Exit 1 / 2 under `-n`: the tool would have corrected
        // errors in write mode. Read-only it observed them, so this
        // is detected corruption.
        return ReadonlyOutcome::CorruptionDetected;
    }
    // Operational / usage / shared-lib errors: ambiguous.
    ReadonlyOutcome::Ambiguous
}
