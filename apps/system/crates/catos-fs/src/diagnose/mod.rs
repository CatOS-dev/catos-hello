//! Read-only filesystem diagnosis. No function in this module may construct
//! a repair plan, acquire a write lock, or invoke a write-capable tool mode.

pub mod btrfs;
pub mod ext;
pub mod f2fs;
pub mod fat;
pub mod xfs;

use crate::command::{FsCommandRunner, FsRunnerError};
use crate::model::RepairTool;
use crate::plan::supports_filesystem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadonlyOutcome {
    /// Filesystem verified clean. No write occurred.
    Clean,
    /// Filesystem has detectable corruption. The Doctor caller
    /// surfaces `FS_CORRUPTION_DETECTED`.
    CorruptionDetected,
    /// The required fsck binary is not installed on the host.
    /// Corruption status is unknown.
    ToolMissing,
    /// The tool timed out. Corruption status is unknown.
    TimedOut,
    /// The tool ran but its result was ambiguous. Corruption status
    /// is unknown.
    Ambiguous,
}

/// Result of running a read-only check flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadonlyResult {
    pub outcome: ReadonlyOutcome,
    /// Recorded invocation, suitable for the Doctor evidence trail.
    pub argv: Vec<String>,
    /// Tool name, e.g. `e2fsck`, for the evidence trail.
    pub tool: &'static str,
    /// Captured stdout (truncated by the runner's safety limit).
    pub stdout: Vec<u8>,
    /// Captured stderr (truncated).
    pub stderr: Vec<u8>,
    /// Raw exit code; `-1` when the binary was missing or the call
    /// timed out.
    pub exit_code: i32,
    /// `true` when stdout/stderr were truncated by the runner's cap.
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    /// Stable label derived from the exit-code interpreter, when the
    /// tool ran at all.
    pub label: Option<String>,
}

impl ReadonlyResult {
    /// `true` iff the read-only check completed cleanly.
    pub fn is_clean(&self) -> bool {
        matches!(self.outcome, ReadonlyOutcome::Clean)
    }
}

pub fn check_only_for<R: FsCommandRunner + ?Sized>(
    fstype: &str,
    runner: &R,
    device: &str,
) -> Result<Option<ReadonlyResult>, FsRunnerError> {
    Ok(match supports_filesystem(fstype) {
        Some(RepairTool::E2fsck) => Some(ext::check(runner, device)?),
        Some(RepairTool::FsckFat) => Some(fat::check(runner, device)?),
        Some(RepairTool::FsckF2fs) => Some(f2fs::check(runner, device)?),
        Some(RepairTool::XfsRepair) => Some(xfs::check(runner, device)?),
        Some(RepairTool::BtrfsCheck) => Some(btrfs::check(runner, device)?),
        None => None,
    })
}

pub use btrfs::BtrfsTopology;

pub use btrfs::check as btrfs_check_only;
pub use ext::check as e2fsck_check_only;
pub use f2fs::check as f2fs_check_only;
pub use fat::check as fat_check_only;
pub use xfs::check as xfs_check_only;
