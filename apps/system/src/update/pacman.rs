//! pacman-side helpers for `catos-update`.
//!
//! Update enumeration goes through `checkupdates`, the canonical Arch
//! helper that performs a temporary pacman DB sync in a private
//! tmpdir so the host DB is never mutated as a side effect of merely
//! listing pending updates. We resolve and run it via the existing
//! trusted-tool runner so its environment and output bounding are
//! identical to every other external tool used in this binary.

use std::time::Duration;

use catos_process::{run_trusted_tool, ToolOutput};

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
    parse_pending(&output)
}

/// Parse `checkupdates` output into a list of non-empty update lines.
///
/// `checkupdates` returns 0 when updates are available, 2 when the system is
/// already current, and another non-zero status on failure. Timeouts and
/// truncated output are also failures because an incomplete package list must
/// never be presented as authoritative.
fn parse_pending(output: &ToolOutput) -> Result<Vec<String>, String> {
    if output.timed_out {
        return Err("checkupdates timed out before update enumeration completed".into());
    }
    if output.stdout_truncated || output.stderr_truncated {
        return Err("checkupdates output exceeded the safety limit and was truncated".into());
    }
    match output.status.code() {
        Some(2) => return Ok(Vec::new()),
        Some(0) => {}
        Some(code) => {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(if detail.is_empty() {
                format!("checkupdates exited with status {code}")
            } else {
                format!("checkupdates exited with status {code}: {detail}")
            });
        }
        None => return Err("checkupdates was terminated by a signal".into()),
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let updates = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if updates.is_empty() {
        return Err("checkupdates exited successfully but returned no update entries".into());
    }
    Ok(updates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn fake_output(code: i32, stdout: &[u8], stderr: &[u8]) -> ToolOutput {
        ToolOutput {
            path: std::path::PathBuf::from("/usr/bin/checkupdates"),
            status: ExitStatusExt::from_raw(code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
        }
    }

    #[test]
    fn successful_empty_output_is_rejected_as_inconsistent() {
        let error = parse_pending(&fake_output(0, b"", b""))
            .expect_err("exit 0 must contain at least one update entry");
        assert!(error.contains("no update entries"), "{error}");
    }

    #[test]
    fn lines_are_trimmed_and_filtered() {
        let out = fake_output(0, b"  foo 1-1 -> 1-2\n\n  bar 2-1 -> 2-2\n\n", b"");
        let lines = parse_pending(&out).expect("successful update listing");
        assert_eq!(lines, vec!["foo 1-1 -> 1-2", "bar 2-1 -> 2-2"]);
    }

    #[test]
    fn exit_two_means_no_updates() {
        assert!(parse_pending(&fake_output(2, b"", b""))
            .expect("checkupdates exit 2 is the documented no-update result")
            .is_empty());
    }

    #[test]
    fn failed_checkupdates_is_not_reported_as_up_to_date() {
        let error = parse_pending(&fake_output(1, b"", b"error: mirror unreachable\n"))
            .expect_err("checkupdates failure must remain an error");
        assert!(error.contains("mirror unreachable"), "{error}");
    }

    #[test]
    fn timed_out_or_truncated_results_are_rejected() {
        let mut timed_out = fake_output(0, b"foo 1-1 -> 1-2\n", b"");
        timed_out.timed_out = true;
        assert!(parse_pending(&timed_out).is_err());

        let mut truncated = fake_output(0, b"foo 1-1 -> 1-2\n", b"");
        truncated.stdout_truncated = true;
        assert!(parse_pending(&truncated).is_err());
    }
}
