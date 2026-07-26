//! Minimal target command executor.
//!
//! This is the **only** surface the boot-repair orchestrator uses
//! to spawn target-side binaries (`grub-install`, `mkinitcpio`,
//! `bootctl`, `limine-install`, `catos-firmware-boot-update`,
//! `catos-secureboot`, `efibootmgr`, `snapper`, `systemctl`,
//! `kernel-install`). It replaces `libcalamares.utils.target_env_call`
//! with a much narrower contract:
//!
//! * **Fixed allow-list.** Only the binaries listed in
//!   [`ALLOWED_BINARIES`] may be invoked. Adding one is a code
//!   review event, not a runtime decision.
//! * **argv only.** Every argument is a separate string. There is no
//!   `sh -c` form, no shell expansion, no environment mutation
//!   surface. The trait's `invoke` takes a slice of `&str`.
//! * **No user-controlled commands.** The binary name is fixed by
//!   the orchestrator; the caller cannot inject a tool path.
//! * **Bounded output drain.** stdout and stderr are drained to EOF
//!   (so verbose tools are not killed by SIGPIPE) but capped at a
//!   safety limit per stream. Truncation is reported.
//! * **No mount cleanup.** The executor never unmounts anything.
//!   The orchestrator's mount session owns all cleanup.
//!
//! Tests inject a [`RecordedTargetRunner`] so behaviour tests do
//! NOT need root, loop devices, or the tools installed.

use std::cell::RefCell;
use std::time::Duration;

use crate::model::boot_repair::{TargetCommand, TargetCommandResult};

/// The fixed allow-list of binaries the boot-repair orchestrator may
/// spawn. Mirrors exactly the commands bootloadu invokes through
/// `target_env_call`. Adding an entry here is the only way to widen
/// the surface.
pub const ALLOWED_BINARIES: &[&str] = &[
    "mkinitcpio",
    "grub-install",
    "grub-mkconfig",
    "limine-install",
    "limine-update",
    "limine-list",
    "limine-btrfs",
    "bootctl",
    "kernel-install",
    "efibootmgr",
    "catos-firmware-boot-update",
    "catos-secureboot",
    "snapper",
    "systemctl",
];

/// One requested invocation. Built by the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRequest {
    pub binary: String,
    pub argv: Vec<String>,
    pub description: String,
}

impl TargetRequest {
    pub fn new(binary: &str, argv: Vec<String>, description: impl Into<String>) -> Self {
        Self {
            binary: binary.to_string(),
            argv,
            description: description.into(),
        }
    }
}

impl From<&TargetRequest> for TargetCommand {
    fn from(request: &TargetRequest) -> Self {
        TargetCommand {
            binary: request.binary.clone(),
            argv: request.argv.clone(),
            description: request.description.clone(),
        }
    }
}

/// Trait the orchestrator talks to. Real implementation spawns the
/// tool; tests record and replay.
pub trait TargetRunner: std::fmt::Debug {
    fn invoke(&self, request: &TargetRequest) -> TargetCommandResult;
}

/// Default real runner. Spawns the target binary directly (no
/// chroot, no shell) using the same trusted-path resolution as
/// [`crate::process::run_trusted_tool`].
///
/// The runner does NOT enter a chroot itself; the boot-repair
/// orchestrator runs the target system's binaries from the live
/// environment after bind-mounting the target root. This matches
/// the existing stage 1–3 confined-execution discipline and avoids
/// creating a general-purpose chroot API.
#[derive(Debug, Clone, Copy)]
pub struct TrustedTargetRunner {
    pub max_output_bytes: usize,
    pub timeout: Option<Duration>,
}

impl TrustedTargetRunner {
    pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;

    pub fn new() -> Self {
        Self {
            max_output_bytes: Self::DEFAULT_MAX_OUTPUT,
            timeout: None,
        }
    }
}

impl Default for TrustedTargetRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetRunner for TrustedTargetRunner {
    fn invoke(&self, request: &TargetRequest) -> TargetCommandResult {
        if !ALLOWED_BINARIES.contains(&request.binary.as_str()) {
            return TargetCommandResult {
                command: request.into(),
                binary_missing: true,
                timed_out: false,
                exit_code: -1,
                stdout: Vec::new(),
                stderr: format!(
                    "target executor refuses non-allow-list binary {:?}",
                    request.binary
                )
                .into_bytes(),
                stdout_truncated: false,
                stderr_truncated: false,
            };
        }
        let argv_refs: Vec<&str> = request.argv.iter().map(String::as_str).collect();
        match crate::process::run_trusted_tool_with_optional_timeout(
            &request.binary,
            &argv_refs,
            self.timeout,
            self.max_output_bytes,
        ) {
            Ok(output) => TargetCommandResult {
                command: request.into(),
                binary_missing: false,
                timed_out: output.timed_out,
                exit_code: output.status.code().unwrap_or(-1),
                stdout: output.stdout,
                stderr: output.stderr,
                stdout_truncated: output.stdout_truncated,
                stderr_truncated: output.stderr_truncated,
            },
            Err(message) => TargetCommandResult {
                command: request.into(),
                binary_missing: true,
                timed_out: false,
                exit_code: -1,
                stdout: Vec::new(),
                stderr: message.into_bytes(),
                stdout_truncated: false,
                stderr_truncated: false,
            },
        }
    }
}

/// Recording fake runner for tests. Records every invocation and
/// replays queued results in order. When the queue is empty, it
/// returns a synthetic "exit 0, no output" result so tests fail on
/// their own assertions rather than panicking inside `invoke`.
#[derive(Debug, Default, Clone)]
pub struct RecordedTargetRunner {
    invocations: RefCell<Vec<TargetRequest>>,
    queued: RefCell<Vec<TargetCommandResult>>,
}

impl RecordedTargetRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue the next result. Builder-style: returns `self` so tests
    /// can chain.
    pub fn queue(self, result: TargetCommandResult) -> Self {
        self.queued.borrow_mut().push(result);
        self
    }

    /// Queue a canned "exit code, stdout, stderr" result.
    pub fn queue_raw(
        self,
        exit_code: i32,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
    ) -> Self {
        self.queue(TargetCommandResult {
            command: TargetCommand {
                binary: String::new(),
                argv: Vec::new(),
                description: String::new(),
            },
            binary_missing: false,
            timed_out: false,
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
            stdout_truncated: false,
            stderr_truncated: false,
        })
    }

    pub fn queue_missing(self) -> Self {
        self.queue(TargetCommandResult {
            command: TargetCommand {
                binary: String::new(),
                argv: Vec::new(),
                description: String::new(),
            },
            binary_missing: true,
            timed_out: false,
            exit_code: -1,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        })
    }

    pub fn invocations(&self) -> Vec<TargetRequest> {
        self.invocations.borrow().clone()
    }

    pub fn invoked_binary(&self, name: &str) -> bool {
        self.invocations
            .borrow()
            .iter()
            .any(|inv| inv.binary == name)
    }
}

impl TargetRunner for RecordedTargetRunner {
    fn invoke(&self, request: &TargetRequest) -> TargetCommandResult {
        self.invocations.borrow_mut().push(request.clone());
        let mut queue = self.queued.borrow_mut();
        if queue.is_empty() {
            // Default to a clean success with empty output.
            TargetCommandResult {
                command: request.into(),
                binary_missing: false,
                timed_out: false,
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            }
        } else {
            let mut result = queue.remove(0);
            // Always stamp the recorded result with the request we
            // actually received, so test assertions on
            // `result.command.argv` match what the orchestrator sent.
            result.command = request.into();
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_runner_refuses_non_allowlisted_binary() {
        let runner = TrustedTargetRunner::new();
        let request = TargetRequest::new("rm", vec!["-rf".into(), "/".into()], "hostile");
        let result = runner.invoke(&request);
        assert!(result.binary_missing);
        assert!(String::from_utf8_lossy(&result.stderr).contains("non-allow-list"));
    }

    #[test]
    fn recorded_runner_records_invocations_in_order() {
        let runner = RecordedTargetRunner::new()
            .queue_raw(0, b"ok".to_vec(), b"".to_vec())
            .queue_raw(1, b"".to_vec(), b"oops".to_vec());
        let req_a = TargetRequest::new(
            "grub-install",
            vec!["--target=x86_64-efi".into()],
            "install GRUB UEFI",
        );
        let req_b = TargetRequest::new("mkinitcpio", vec!["-P".into()], "regenerate initramfs");
        let a = runner.invoke(&req_a);
        let b = runner.invoke(&req_b);
        assert_eq!(a.exit_code, 0);
        assert_eq!(b.exit_code, 1);
        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].binary, "grub-install");
        assert_eq!(invocations[0].argv, vec!["--target=x86_64-efi".to_string()]);
        assert_eq!(invocations[1].binary, "mkinitcpio");
        assert!(runner.invoked_binary("grub-install"));
        assert!(!runner.invoked_binary("bootctl"));
    }

    #[test]
    fn recorded_runner_defaults_to_success_when_queue_empty() {
        let runner = RecordedTargetRunner::new();
        let req = TargetRequest::new("bootctl", vec!["is-installed".into()], "verify");
        let result = runner.invoke(&req);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.command.binary, "bootctl");
    }

    #[test]
    fn allow_list_covers_only_documented_tools() {
        for tool in [
            "mkinitcpio",
            "grub-install",
            "grub-mkconfig",
            "limine-install",
            "bootctl",
            "kernel-install",
            "catos-firmware-boot-update",
            "catos-secureboot",
        ] {
            assert!(
                ALLOWED_BINARIES.contains(&tool),
                "{tool} must be allow-listed"
            );
        }
        for hostile in ["sh", "bash", "rm", "cp", "dd", "mkfs.ext4"] {
            assert!(
                !ALLOWED_BINARIES.contains(&hostile),
                "{hostile} must NOT be allow-listed"
            );
        }
    }
}
