use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::command::{FsCommandInvocation, FsCommandRunner, FsRunnerError, ToolResult};
use crate::diagnose::{ReadonlyOutcome, ReadonlyResult};
use crate::model::{ExitInterpretation, RepairTool};

/// Topology reported by `btrfs filesystem show DEVICE`. A repair flow
/// supports only a single-device filesystem; unknown topology is refused
/// just as conservatively as a known multi-device filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BtrfsTopology {
    SingleDevice,
    MultiDevice,
    Unknown,
}

pub fn topology<R: FsCommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<BtrfsTopology, FsRunnerError> {
    let invocation = FsCommandInvocation::new(
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

pub(crate) fn reports_metadata_checksum_failure(result: &ToolResult) -> bool {
    const DIAGNOSTIC: &[u8] = b"checksum verify failed";
    result
        .stdout
        .windows(DIAGNOSTIC.len())
        .any(|window| window == DIAGNOSTIC)
        || result
            .stderr
            .windows(DIAGNOSTIC.len())
            .any(|window| window == DIAGNOSTIC)
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

/// `btrfs check --readonly DEVICE` — read-only structural check.
/// Verified against btrfs-check(8): `--readonly` runs the check in
/// read-only mode and is the canonical non-mutating invocation.
///
/// This is the SAME first step `btrfs_flow` runs in repair mode; the
/// difference is Doctor stops here. It never escalates to `--repair`.
pub fn check<R: FsCommandRunner + ?Sized>(
    runner: &R,
    device: &str,
) -> Result<ReadonlyResult, crate::command::FsRunnerError> {
    let invocation = FsCommandInvocation::new(
        RepairTool::BtrfsCheck.binary_name(),
        vec!["check".into(), "--readonly".into(), device.into()],
    );
    let result = runner.invoke(&invocation)?;
    let checksum_failed = reports_metadata_checksum_failure(&result);
    let mut interp = decode_btrfs_exit(&result);
    if checksum_failed {
        interp.clean = false;
        interp.errors_uncorrected = true;
        interp.label = Some("btrfs-metadata-checksum-failure".into());
    }
    let outcome = if result.binary_missing {
        ReadonlyOutcome::ToolMissing
    } else if result.timed_out {
        ReadonlyOutcome::TimedOut
    } else if result.exit_code == 0 && !checksum_failed {
        ReadonlyOutcome::Clean
    } else if checksum_failed || result.exit_code != 0 {
        ReadonlyOutcome::CorruptionDetected
    } else {
        ReadonlyOutcome::Ambiguous
    };
    Ok(ReadonlyResult {
        outcome,
        argv: invocation.argv,
        tool: RepairTool::BtrfsCheck.binary_name(),
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        label: interp.label,
    })
}
