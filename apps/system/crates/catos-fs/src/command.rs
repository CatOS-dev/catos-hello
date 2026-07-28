//! Filesystem command contract and recording test runner.
//!
//! This module is effect-neutral: it defines invocations, results, and the
//! runner trait. The production process-spawning implementation lives in
//! `fs::execute::runner`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Duration;

use crate::model::ExitInterpretation;

/// One captured invocation. The orchestrator builds
/// [`FsCommandInvocation`]s to describe what it wants to run; the runner
/// produces a [`ToolResult`] describing what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsCommandInvocation {
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

impl FsCommandInvocation {
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

/// Error returned by [`FsCommandRunner::invoke`] for genuine runner
/// failures (spawn error, I/O error reading pipes). Binary-missing
/// and non-zero exits are NOT errors here — they are `Ok(ToolResult)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRunnerError {
    pub message: String,
}

impl std::fmt::Display for FsRunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "filesystem runner error: {}", self.message)
    }
}

impl std::error::Error for FsRunnerError {}

/// The injection point. Real implementation spawns the tool through
/// the trusted-path runner; tests record the invocation and return a
/// canned result.
pub trait FsCommandRunner: std::fmt::Debug {
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
    fn invoke(&self, invocation: &FsCommandInvocation) -> Result<ToolResult, FsRunnerError>;
}

#[derive(Debug, Default, Clone)]
pub struct RecordedRunner {
    invocations: RefCell<Vec<RecordedInvocation>>,
    expected: RefCell<VecDeque<ExpectedInvocation>>,
}

/// One recorded invocation, for inspection by tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedInvocation {
    pub binary: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedInvocation {
    invocation: RecordedInvocation,
    result: ToolResult,
}

impl RecordedRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare one exact external call and the result it must return.
    /// Calls are consumed in FIFO order. An invocation that was not
    /// declared, or whose binary/argv differs, is a runner error.
    pub fn expect(
        self,
        binary: &str,
        argv: impl IntoIterator<Item = impl Into<String>>,
        result: ToolResult,
    ) -> Self {
        self.expected.borrow_mut().push_back(ExpectedInvocation {
            invocation: RecordedInvocation {
                binary: binary.to_string(),
                argv: argv.into_iter().map(Into::into).collect(),
            },
            result,
        });
        self
    }

    /// Convenience: declare one exact call with explicit
    /// exit/stdout/stderr.
    pub fn expect_raw(
        self,
        binary: &str,
        argv: impl IntoIterator<Item = impl Into<String>>,
        exit_code: i32,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
    ) -> Self {
        self.expect(
            binary,
            argv,
            ToolResult {
                binary_missing: false,
                timed_out: false,
                exit_code,
                stdout: stdout.into(),
                stderr: stderr.into(),
                stdout_truncated: false,
                stderr_truncated: false,
            },
        )
    }

    /// Convenience: declare one exact call whose trusted binary is
    /// unavailable.
    pub fn expect_missing(
        self,
        binary: &str,
        argv: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.expect(binary, argv, ToolResult::binary_missing())
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

    /// Assert that every declared external call was consumed. Tests
    /// must call this after exercising the flow so early returns cannot
    /// silently leave expected work unexecuted.
    pub fn assert_consumed(&self) {
        let expected = self.expected.borrow();
        assert!(
            expected.is_empty(),
            "unconsumed filesystem runner calls: {:?}",
            *expected
        );
    }
}

impl FsCommandRunner for RecordedRunner {
    fn invoke(&self, invocation: &FsCommandInvocation) -> Result<ToolResult, FsRunnerError> {
        let actual = RecordedInvocation {
            binary: invocation.binary.clone(),
            argv: invocation.argv.clone(),
        };
        self.invocations.borrow_mut().push(actual.clone());
        let expected = self
            .expected
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| FsRunnerError {
                message: format!(
                    "unconfigured external call: {} {}",
                    actual.binary,
                    actual.argv.join(" ")
                ),
            })?;
        if expected.invocation != actual {
            return Err(FsRunnerError {
                message: format!(
                    "external call mismatch: expected {} {:?}, observed {} {:?}",
                    expected.invocation.binary,
                    expected.invocation.argv,
                    actual.binary,
                    actual.argv
                ),
            });
        }
        Ok(expected.result)
    }
}

// Production implementation of the neutral command transport.
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

impl FsCommandRunner for TrustedRunner {
    fn invoke(&self, invocation: &FsCommandInvocation) -> Result<ToolResult, FsRunnerError> {
        // Reject any binary name that looks like a path. The trusted
        // runner resolves only by basename in fixed directories.
        if invocation.binary.is_empty() || invocation.binary.contains('/') {
            return Err(FsRunnerError {
                message: format!(
                    "repair runner refuses path-like binary name {:?}; expected a bare tool name resolved from trusted dirs",
                    invocation.binary
                ),
            });
        }

        // Binary missing is a structured outcome, not a runner error.
        if catos_process::trusted_tool_path(&invocation.binary).is_none() {
            return Ok(ToolResult::binary_missing());
        }

        let argv_refs: Vec<&str> = invocation.argv.iter().map(String::as_str).collect();

        // The trusted runner returns a structured error string for
        // spawn/pipe failures. Re-map into our error type so the
        // orchestrator sees one error type.
        let output = catos_process::run_trusted_tool_with_optional_timeout(
            invocation.binary.as_str(),
            &argv_refs,
            invocation.timeout,
            self.max_output_bytes,
        )
        .map_err(|message| FsRunnerError {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_runner_rejects_unconfigured_external_call() {
        let runner = RecordedRunner::new();
        let error = runner
            .invoke(&FsCommandInvocation::new("e2fsck", vec!["-n".into()]))
            .unwrap_err();
        assert!(error.message.contains("unconfigured external call"));
    }

    #[test]
    fn recorded_runner_rejects_binary_or_argv_mismatch() {
        let runner = RecordedRunner::new().expect_raw("e2fsck", ["-n", "/dev/vda1"], 0, b"", b"");
        let error = runner
            .invoke(&FsCommandInvocation::new(
                "e2fsck",
                vec!["-y".into(), "/dev/vda1".into()],
            ))
            .unwrap_err();
        assert!(error.message.contains("external call mismatch"));
    }

    #[test]
    #[should_panic(expected = "unconsumed filesystem runner calls")]
    fn recorded_runner_rejects_unconsumed_expectations() {
        let runner = RecordedRunner::new().expect_raw("e2fsck", ["-n", "/dev/vda1"], 0, b"", b"");
        runner.assert_consumed();
    }
}
