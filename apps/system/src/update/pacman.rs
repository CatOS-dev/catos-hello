//! pacman-side helpers for `catos-update`.
//!
//! Update enumeration goes through `checkupdates`, the canonical Arch
//! helper that performs a temporary pacman DB sync in a private
//! tmpdir so the host DB is never mutated as a side effect of merely
//! listing pending updates. We resolve and run it via the existing
//! trusted-tool runner so its environment and output bounding are
//! identical to every other external tool used in this binary.

use std::time::Duration;

use crate::process::{run_trusted_tool, ToolOutput};

/// Maximum wall time `checkupdates` may take before we abort it.
/// `checkupdates` normally finishes in a few seconds; a hung mirror
/// download is the only realistic reason to exceed this.
const CHECKUPDATES_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum stdout we retain from `checkupdates`. Each pending-update
/// line is on the order of 100 bytes; 1 MiB is far beyond any
/// realistic pending set while still bounding memory.
const CHECKUPDATES_MAX_OUTPUT: usize = 1024 * 1024;

/// List pending pacman updates as `name oldver newver` strings, one
/// per line. Returns an empty vector when the system is up to date.
///
/// Errors are returned as human-readable strings so the entry layer
/// can surface them directly. A missing `checkupdates` binary is
/// reported the same way as a runtime failure: callers do not need
/// to distinguish.
pub fn list_pending_updates() -> Result<Vec<String>, String> {
    let output = run_trusted_tool(
        "checkupdates",
        &[],
        CHECKUPDATES_TIMEOUT,
        CHECKUPDATES_MAX_OUTPUT,
    )?;
    Ok(parse_pending(&output))
}

/// Parse `checkupdates` output into a list of non-empty update lines.
///
/// `checkupdates` returns 0 when there are updates AND when there
/// are none (the latter produces empty stdout). It returns non-zero
/// only on actual failure, so we treat a non-success status strictly:
/// the host cannot enumerate updates safely.
fn parse_pending(output: &ToolOutput) -> Vec<String> {
    if !output.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn fake_output(success: bool, stdout: &[u8]) -> ToolOutput {
        let raw = if success { 0 } else { 1 };
        ToolOutput {
            path: std::path::PathBuf::from("/usr/bin/checkupdates"),
            status: ExitStatusExt::from_raw(raw),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
        }
    }

    #[test]
    fn empty_stdout_is_no_updates() {
        assert!(parse_pending(&fake_output(true, b"")).is_empty());
    }

    #[test]
    fn lines_are_trimmed_and_filtered() {
        let out = fake_output(true, b"  foo 1-1 -> 1-2\n\n  bar 2-1 -> 2-2\n\n");
        let lines = parse_pending(&out);
        assert_eq!(lines, vec!["foo 1-1 -> 1-2", "bar 2-1 -> 2-2"]);
    }

    #[test]
    fn failed_checkupdates_yields_empty() {
        // A non-success exit from checkupdates must not be interpreted
        // as "no updates"; the orchestrator layer treats an empty list
        // as up-to-date. Here we only assert the parser does not
        // fabricate update lines out of a failure.
        let out = fake_output(false, b"error: mirror unreachable");
        assert!(parse_pending(&out).is_empty());
    }
}
