//! Command runner trait for repair tools.
//!
//! This is the **only** interface the orchestrator uses to spawn
//! repair binaries. The default implementation (`TrustedRunner`)
//! goes through [`crate::shared::process::run_trusted_tool`] with the
//! existing fixed-path, minimal-env, bounded-output, deadline-bound
//! contract. Tests inject a fake runner (`RecordedRunner`) so
//! behaviour tests do NOT need root, loop devices, or even the tools
//! installed.
//!
//! ## Why a trait
//!
//! The behaviour contract for `catos-repair fs` is large: tool
//! routing, exit-code interpretation, high-risk-fallback labelling,
//! output truncation, "tool missing" detection. Most of those are
//! pure functions of (argv, exit code, captured bytes). Validating
//! them against the real `e2fsck` binary requires a corrupted ext4
//! image and root to mount/repair — fine for an opt-in smoke test,
//! useless for unit testing.
//!
//! The trait lets us drive the entire flow against a fake that
//! records every argv and replays a canned exit/stdout/stderr. That
//! is how we test "did we route ext4 to e2fsck with `-y` and not
//! `-p`?" without root, and how we test "did the high-risk XFS
//! fallback get marked?" without deliberately corrupting an XFS.
//!
//! ## Hard rule: this module never shells out
//!
//! The trait's `invoke` takes a binary name, a slice of argv, and a
//! timeout. There is no `&str` raw shell form, no `sh -c`, no
//! environment mutation surface. The real implementation enforces
//! the trusted-path lookup from `process.rs`.

use std::cell::RefCell;
use std::time::Duration;

use crate::model::repair::ExitInterpretation;

/// One captured invocation. The orchestrator builds
/// [`RepairInvocation`]s to describe what it wants to run; the runner
/// produces a [`ToolResult`] describing what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairInvocation {
    /// Binary name (no path). Resolved against trusted directories
    /// by the runner.
    pub binary: String,
    /// argv[1..]. Recorded verbatim in the report.
    pub argv: Vec<String>,
    /// Optional deadline. Write-capable filesystem repair defaults to
    /// no deadline: killing a tool while it updates metadata can make
    /// an already damaged filesystem worse.
    pub timeout: Option<Duration>,
}

impl RepairInvocation {
    pub fn new(binary: &str, argv: Vec<String>) -> Self {
        Self {
            binary: binary.to_string(),
            argv,
            timeout: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// Outcome of a single tool invocation, in the shape the orchestrator
/// needs to build an [`ExitInterpretation`]. Pure data; the
/// orchestrator's per-tool interpreters (e.g. `e2fsck_decode_exit`)
/// map this to the final structured fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    /// True iff the runner could not find the binary in trusted
    /// directories. Distinct from a non-zero exit so the orchestrator
    /// can report `FsRepairOutcome::ToolMissing` precisely.
    pub binary_missing: bool,
    /// True iff the runner killed the process for exceeding the
    /// timeout.
    pub timed_out: bool,
    /// Raw exit code, when available. `-1` if the process was killed
    /// by a signal or never started (binary_missing).
    pub exit_code: i32,
    /// Captured stdout, already truncated to the runner's safety
    /// limit.
    pub stdout: Vec<u8>,
    /// Captured stderr, already truncated.
    pub stderr: Vec<u8>,
    /// Whether stdout was truncated by the runner.
    pub stdout_truncated: bool,
    /// Whether stderr was truncated.
    pub stderr_truncated: bool,
}

impl ToolResult {
    /// A canned "binary missing" result for tests.
    pub fn binary_missing() -> Self {
        Self {
            binary_missing: true,
            timed_out: false,
            exit_code: -1,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    /// A canned "tool exited 0 with no output" result for tests.
    pub fn success_empty() -> Self {
        Self {
            binary_missing: false,
            timed_out: false,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    /// A canned "tool timed out" result for tests.
    pub fn timed_out() -> Self {
        Self {
            binary_missing: false,
            timed_out: true,
            exit_code: -1,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    /// Build the structured interpretation that is NOT tool-specific:
    /// the `binary_missing` and `timed_out` flags go straight through,
    /// and we record the raw code. Tool-specific decoders (e.g.
    /// `e2fsck_decode_exit`) fill in the rest.
    pub fn base_interpretation(&self) -> ExitInterpretation {
        ExitInterpretation {
            raw_code: self.exit_code,
            clean: false,
            errors_corrected: false,
            reboot_required: false,
            exited_early: false,
            errors_uncorrected: false,
            timed_out: self.timed_out,
            binary_missing: self.binary_missing,
            label: None,
        }
    }
}

/// Error returned by [`CommandRunner::invoke`] for genuine runner
/// failures (spawn error, I/O error reading pipes). Binary-missing
/// and non-zero exits are NOT errors here — they are `Ok(ToolResult)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRunnerError {
    pub message: String,
}

impl std::fmt::Display for RepairRunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "repair runner error: {}", self.message)
    }
}

impl std::error::Error for RepairRunnerError {}

/// The injection point. Real implementation spawns the tool through
/// the trusted-path runner; tests record the invocation and return a
/// canned result.
pub trait CommandRunner: std::fmt::Debug {
    /// Run one tool. Return the captured outcome, or a runner-level
    /// error (not a tool non-zero exit). Implementations MUST:
    ///
    /// * Resolve `invocation.binary` only from the fixed trusted
    ///   directories (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`).
    /// * Pass `invocation.argv` as separate argv elements; no shell.
    /// * Clear the environment and set only `LC_ALL=C`, `LANG=C`,
    ///   `PATH=/usr/bin:/usr/sbin:/bin:/sbin`.
    /// * Enforce `invocation.timeout` when one was explicitly set.
    /// * Cap captured stdout/stderr at the runner's safety limit
    ///   (default 64 KiB) and flag truncation.
    fn invoke(&self, invocation: &RepairInvocation) -> Result<ToolResult, RepairRunnerError>;
}

// ---------------------------------------------------------------------------
// TrustedRunner: real implementation
// ---------------------------------------------------------------------------

/// Default runner: delegates to [`crate::shared::process::run_trusted_tool`],
/// reusing the same trusted-path / minimal-env / bounded-output /
/// deadline guarantees as blkid and btrfs-progs invocations.
#[derive(Debug, Clone, Copy)]
pub struct TrustedRunner {
    /// Maximum bytes of stdout/stderr to retain. Defaults to 64 KiB
    /// per stream. The rest is truncated and flagged so the report
    /// surfaces "we cut this off".
    pub max_output_bytes: usize,
}

impl TrustedRunner {
    pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;

    pub fn new() -> Self {
        Self {
            max_output_bytes: Self::DEFAULT_MAX_OUTPUT,
        }
    }

    pub fn with_max_output(max_output_bytes: usize) -> Self {
        Self { max_output_bytes }
    }
}

impl Default for TrustedRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for TrustedRunner {
    fn invoke(&self, invocation: &RepairInvocation) -> Result<ToolResult, RepairRunnerError> {
        // Reject any binary name that looks like a path. The trusted
        // runner resolves only by basename in fixed directories.
        if invocation.binary.is_empty() || invocation.binary.contains('/') {
            return Err(RepairRunnerError {
                message: format!(
                    "repair runner refuses path-like binary name {:?}; expected a bare tool name resolved from trusted dirs",
                    invocation.binary
                ),
            });
        }

        // Binary missing is a structured outcome, not a runner error.
        if crate::shared::process::trusted_tool_path(&invocation.binary).is_none() {
            return Ok(ToolResult::binary_missing());
        }

        let argv_refs: Vec<&str> = invocation.argv.iter().map(String::as_str).collect();

        // The trusted runner returns a structured error string for
        // spawn/pipe failures. Re-map into our error type so the
        // orchestrator sees one error type.
        let output = crate::shared::process::run_trusted_tool_with_optional_timeout(
            invocation.binary.as_str(),
            &argv_refs,
            invocation.timeout,
            self.max_output_bytes,
        )
        .map_err(|message| RepairRunnerError {
            message: format!("failed to invoke {}: {message}", invocation.binary),
        })?;

        Ok(ToolResult {
            binary_missing: false,
            timed_out: output.timed_out,
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
        })
    }
}

// ---------------------------------------------------------------------------
// RecordedRunner: fake runner for tests
// ---------------------------------------------------------------------------

/// A recording fake runner. The orchestrator talks to it through the
/// [`CommandRunner`] trait; tests inspect what was invoked and
/// control what comes back.
///
/// The runner stores invocations in order and replays a queued result
/// per invocation. If a test does not queue enough results, the runner
/// returns a synthetic "exited 0" result so the test fails loudly on
/// the assertion rather than silently on an index panic.
///
/// Interior mutability (`RefCell`) is used because the orchestrator
/// takes `&R: CommandRunner`. The cell pattern keeps the trait
/// signature honest (no `&mut self`) without unsafe code. The runner
/// is `!Sync` by virtue of `RefCell`, which matches the single-
/// threaded test execution model.
#[derive(Debug, Default, Clone)]
pub struct RecordedRunner {
    invocations: RefCell<Vec<RecordedInvocation>>,
    queued_results: RefCell<Vec<ToolResult>>,
}

/// One recorded invocation, for inspection by tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedInvocation {
    pub binary: String,
    pub argv: Vec<String>,
}

impl RecordedRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue the next result. Multiple calls queue in order; the
    /// runner pops one per `invoke`. Builder-style: returns `self`
    /// so tests can chain.
    pub fn queue(self, result: ToolResult) -> Self {
        self.queued_results.borrow_mut().push(result);
        self
    }

    /// Convenience: queue a result with explicit exit/stdout/stderr.
    pub fn queue_raw(
        self,
        exit_code: i32,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
    ) -> Self {
        self.queue(ToolResult {
            binary_missing: false,
            timed_out: false,
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
            stdout_truncated: false,
            stderr_truncated: false,
        })
    }

    /// Convenience: queue a binary-missing result.
    pub fn queue_missing(self) -> Self {
        self.queue(ToolResult::binary_missing())
    }

    /// All invocations the orchestrator made, in order. Clones the
    /// recorded vector so the borrow is released.
    pub fn invocations(&self) -> Vec<RecordedInvocation> {
        self.invocations.borrow().clone()
    }

    /// How many times the runner was invoked.
    pub fn invocation_count(&self) -> usize {
        self.invocations.borrow().len()
    }

    /// True iff some invocation matched the predicate.
    pub fn any_invocation<F: Fn(&RecordedInvocation) -> bool>(&self, predicate: F) -> bool {
        self.invocations.borrow().iter().any(predicate)
    }

    /// True iff some invocation used the given binary.
    pub fn invoked_binary(&self, name: &str) -> bool {
        self.any_invocation(|inv| inv.binary == name)
    }

    /// True iff some invocation's argv contains the given flag.
    pub fn any_invocation_with_flag(&self, flag: &str) -> bool {
        self.any_invocation(|inv| inv.argv.iter().any(|arg| arg == flag))
    }

    /// True iff some invocation's argv contains a flag matching the
    /// given predicate.
    pub fn any_invocation_with_argv<F: Fn(&str) -> bool>(&self, predicate: F) -> bool {
        self.any_invocation(|inv| inv.argv.iter().any(|arg| predicate(arg)))
    }
}

impl CommandRunner for RecordedRunner {
    fn invoke(&self, invocation: &RepairInvocation) -> Result<ToolResult, RepairRunnerError> {
        self.invocations.borrow_mut().push(RecordedInvocation {
            binary: invocation.binary.clone(),
            argv: invocation.argv.clone(),
        });
        let mut queue = self.queued_results.borrow_mut();
        Ok(if queue.is_empty() {
            // Default to a clean success. Tests that forget to queue
            // enough results fail on their own assertions, not here.
            ToolResult::success_empty()
        } else {
            queue.remove(0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_runner_records_invocations_in_order() {
        let runner = RecordedRunner::new()
            .queue_raw(0, b"ok".to_vec(), b"".to_vec())
            .queue_raw(1, b"".to_vec(), b"oops".to_vec());
        let inv_a = RepairInvocation::new("e2fsck", vec!["-y".into(), "/dev/sda1".into()]);
        let inv_b = RepairInvocation::new("xfs_repair", vec!["/dev/sda1".into()]);

        let a = runner.invoke(&inv_a).unwrap();
        let b = runner.invoke(&inv_b).unwrap();

        assert_eq!(a.exit_code, 0);
        assert_eq!(b.exit_code, 1);
        let recorded = runner.invocations();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].binary, "e2fsck");
        assert_eq!(
            recorded[0].argv,
            vec!["-y".to_string(), "/dev/sda1".to_string()]
        );
        assert_eq!(recorded[1].binary, "xfs_repair");
        assert!(runner.invoked_binary("e2fsck"));
        assert!(!runner.invoked_binary("fsck.fat"));
        assert!(runner.any_invocation_with_flag("-y"));
        assert!(!runner.any_invocation_with_flag("-L"));
    }

    #[test]
    fn recorded_runner_defaults_to_success_when_queue_empty() {
        // A test that forgot to queue enough results gets a clean
        // exit so it fails on its own assertion, not on a panic
        // here. This is the same pattern as Mockall's default
        // return values.
        let runner = RecordedRunner::new();
        let inv = RepairInvocation::new("e2fsck", vec!["/dev/sda1".into()]);
        let result = runner.invoke(&inv).unwrap();
        assert!(result.exit_code == 0);
        assert_eq!(runner.invocation_count(), 1);
    }

    #[test]
    fn recorded_runner_handles_missing_and_timeout_canned_results() {
        let runner = RecordedRunner::new()
            .queue(ToolResult::binary_missing())
            .queue(ToolResult::timed_out());

        let missing = runner
            .invoke(&RepairInvocation::new("fsck.f2fs", vec!["--poke".into()]))
            .unwrap();
        let timeout = runner
            .invoke(&RepairInvocation::new(
                "e2fsck",
                vec!["-y".into(), "/dev/sda1".into()],
            ))
            .unwrap();

        assert!(missing.binary_missing);
        assert!(!missing.timed_out);
        assert!(timeout.timed_out);
        assert!(!timeout.binary_missing);
    }

    #[test]
    fn trusted_runner_rejects_path_like_binary_name() {
        // Defends against a refactor that passes a user-controlled
        // path into the trusted runner. The trusted runner resolves
        // ONLY bare names from fixed directories; anything else is a
        // caller bug.
        let runner = TrustedRunner::new();
        let inv = RepairInvocation::new("/tmp/fake-tool", vec![]);
        let err = runner.invoke(&inv).unwrap_err();
        assert!(err.message.contains("path-like"));
    }
}
