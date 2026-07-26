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
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
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
    "sdboot-btrfs",
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

/// Default real runner. It invokes the host's fixed-path `chroot` helper
/// with a target binary that was resolved from the mounted target root.
/// The chroot is deliberately not exposed as a public command interface:
/// this type accepts only [`TargetRequest`] values whose binary is in the
/// fixed allow-list.
#[derive(Debug, Clone)]
pub struct TrustedTargetRunner {
    target_root: PathBuf,
    pub max_output_bytes: usize,
    pub timeout: Option<Duration>,
}

impl TrustedTargetRunner {
    pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;

    pub fn new() -> Self {
        Self::for_target(PathBuf::from("/"))
    }

    pub fn for_target(target_root: impl Into<PathBuf>) -> Self {
        Self {
            target_root: target_root.into(),
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
        let Some(target_binary) = target_binary_path(&self.target_root, &request.binary) else {
            return TargetCommandResult {
                command: request.into(),
                binary_missing: true,
                timed_out: false,
                exit_code: -1,
                stdout: Vec::new(),
                stderr: format!(
                    "target binary {:?} is not executable below {}",
                    request.binary,
                    self.target_root.display()
                )
                .into_bytes(),
                stdout_truncated: false,
                stderr_truncated: false,
            };
        };
        let mut command = Command::new(&target_binary);
        command
            .args(&request.argv)
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("PATH", "/usr/bin:/usr/sbin:/bin:/sbin");

        if self.target_root != Path::new("/") {
            let target_root = match CString::new(self.target_root.as_os_str().as_bytes()) {
                Ok(path) => path,
                Err(_) => {
                    return TargetCommandResult {
                        command: request.into(),
                        binary_missing: true,
                        timed_out: false,
                        exit_code: -1,
                        stdout: Vec::new(),
                        stderr: b"target root contains an embedded NUL byte".to_vec(),
                        stdout_truncated: false,
                        stderr_truncated: false,
                    };
                }
            };
            // SAFETY: the closure performs only async-signal-safe syscalls
            // before exec. It changes a freshly-forked child's mount namespace
            // and never mutates the parent namespace.
            unsafe {
                command.pre_exec(move || pivot_to_target_root(&target_root));
            }
        }

        match crate::shared::process::run_prepared_command_with_optional_timeout(
            command,
            PathBuf::from(&target_binary),
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

fn pivot_to_target_root(target_root: &CStr) -> std::io::Result<()> {
    const SLASH: &CStr = c"/";
    const DOT: &CStr = c".";

    syscall_result(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;
    syscall_result(unsafe {
        libc::mount(
            std::ptr::null(),
            SLASH.as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    })?;
    // A rescue initramfs uses the special rootfs mount, which cannot be the
    // old root of pivot_root. Stack a private bind mount at `/` first.
    syscall_result(unsafe {
        libc::mount(
            SLASH.as_ptr(),
            SLASH.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
            std::ptr::null(),
        )
    })?;
    // A Btrfs target root is a directory inside the top-level mount rather
    // than a mountpoint of its own. Bind it to itself inside the child.
    syscall_result(unsafe {
        libc::mount(
            target_root.as_ptr(),
            target_root.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
            std::ptr::null(),
        )
    })?;
    syscall_result(unsafe { libc::chdir(target_root.as_ptr()) })?;
    syscall_result(unsafe {
        libc::syscall(libc::SYS_pivot_root, DOT.as_ptr(), DOT.as_ptr()) as libc::c_int
    })?;
    syscall_result(unsafe { libc::umount2(DOT.as_ptr(), libc::MNT_DETACH) })?;
    syscall_result(unsafe { libc::chdir(SLASH.as_ptr()) })
}

fn syscall_result(result: libc::c_int) -> std::io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn target_binary_path(target_root: &Path, binary: &str) -> Option<String> {
    const TARGET_TOOL_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];
    if binary.is_empty() || binary.contains('/') {
        return None;
    }
    TARGET_TOOL_DIRS.iter().find_map(|directory| {
        let relative = directory.trim_start_matches('/');
        let candidate = target_root.join(relative).join(binary);
        std::fs::metadata(candidate)
            .ok()
            .filter(|metadata| {
                use std::os::unix::fs::PermissionsExt;

                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
            .map(|_| format!("{directory}/{binary}"))
    })
}

/// Recording fake runner for tests. Records every invocation and
/// replays queued results in order. An undeclared call is a failure:
/// provider tests must explicitly model every target command they expect.
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
            TargetCommandResult {
                command: request.into(),
                binary_missing: true,
                timed_out: false,
                exit_code: -1,
                stdout: Vec::new(),
                stderr: b"unexpected target command: no queued result".to_vec(),
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
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn target_fixture(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("catos-target-exec-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        root
    }

    #[test]
    fn trusted_runner_refuses_non_allowlisted_binary() {
        let runner = TrustedTargetRunner::new();
        let request = TargetRequest::new("rm", vec!["-rf".into(), "/".into()], "hostile");
        let result = runner.invoke(&request);
        assert!(result.binary_missing);
        assert!(String::from_utf8_lossy(&result.stderr).contains("non-allow-list"));
    }

    #[test]
    fn target_binary_path_includes_the_binary_name() {
        let root = target_fixture("binary-path");
        let tool = root.join("usr/bin/mkinitcpio");
        fs::write(&tool, b"#!/bin/sh\n").unwrap();
        let mut permissions = fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tool, permissions).unwrap();

        assert_eq!(
            target_binary_path(&root, "mkinitcpio"),
            Some("/usr/bin/mkinitcpio".to_string())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires CAP_SYS_CHROOT; exercised by the privileged QEMU harness"]
    fn trusted_runner_executes_the_target_binary_inside_target_root() {
        let root = target_fixture("chroot");
        fs::copy("/bin/busybox", root.join("usr/bin/busybox")).unwrap();
        let mut busybox_permissions = fs::metadata(root.join("usr/bin/busybox"))
            .unwrap()
            .permissions();
        busybox_permissions.set_mode(0o755);
        fs::set_permissions(root.join("usr/bin/busybox"), busybox_permissions).unwrap();
        let script = root.join("usr/bin/limine-list");
        fs::write(
            &script,
            "#!/usr/bin/busybox sh\nprintf 'target-root:%s\\n' \"$1\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();

        let runner = TrustedTargetRunner::for_target(&root);
        let request = TargetRequest::new("limine-list", vec!["fixture".into()], "verify target");
        let result = runner.invoke(&request);
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, b"target-root:fixture\n");
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
    fn recorded_runner_fails_when_queue_empty() {
        let runner = RecordedTargetRunner::new();
        let req = TargetRequest::new("bootctl", vec!["is-installed".into()], "verify");
        let result = runner.invoke(&req);
        assert_eq!(result.exit_code, -1);
        assert!(result.binary_missing);
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
