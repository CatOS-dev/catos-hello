use crate::command::{FsCommandInvocation, FsCommandRunner, ToolResult};
use crate::diagnose::ext::{decide_e2fsck_readonly_outcome, decode_e2fsck_exit};
use crate::diagnose::ReadonlyResult;
use crate::model::{ExitInterpretation, RepairTool};

pub fn decode_f2fs_exit(result: &ToolResult) -> ExitInterpretation {
    // f2fs reuses the e2fsck bitmask table. We share the decoder
    // rather than duplicating the bit assignments.
    let mut interp = decode_e2fsck_exit(result);
    if let Some(label) = interp.label.as_mut() {
        *label = label.replacen("e2fsck-", "fsck.f2fs-", 1);
    }
    interp
}

/// `fsck.f2fs --dry-run DEVICE` — read-only check. Verified against
/// f2fs-tools: `--dry-run` performs a read-only verification pass.
/// We do NOT pass `-a`/`-f`/`-y`; none of those are read-only.
pub fn check<R: FsCommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<ReadonlyResult, crate::command::FsRunnerError> {
    let invocation = FsCommandInvocation::new(
        RepairTool::FsckF2fs.binary_name(),
        vec!["--dry-run".into(), device.into()],
    );
    let result = runner.invoke(&invocation)?;
    // f2fs reuses the e2fsck bitmask table for the read-only result
    // (a confirmed bug or correction surfaces as the same bits).
    let interp = decode_f2fs_exit(&result);
    let outcome = decide_e2fsck_readonly_outcome(&result);
    Ok(ReadonlyResult {
        outcome,
        argv: invocation.argv,
        tool: RepairTool::FsckF2fs.binary_name(),
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        label: interp.label,
    })
}
