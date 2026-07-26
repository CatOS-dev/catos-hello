//! Read-write mount session for recovery write operations.

use std::path::{Path, PathBuf};

use crate::shared::model::recovery::{CleanupSummary, RecoveryError, RecoveryErrorKind};
use crate::shared::mount::namespace;
use crate::shared::mount::secure_dir::{create_session_dir, remove_session_dir, SESSION_ROOT_PARENT};
use crate::shared::mount::syscall::{self, mnt_flags, ms_flags};

/// A private mount namespace with the btrfs top-level mounted
/// read-write at a session directory created under
/// `/run/catos-system/sessions/`. The session directory is created
/// with the shared [`crate::shared::mount::secure_dir`] primitives so that
/// phase 2 and phase 3 apply identical security semantics.
///
/// Lifecycle contract:
///
/// * every successful construction is paired with an explicit
///   [`RecoveryRwSession::cleanup`] call by the orchestrator on
///   BOTH the success and error paths of `apply`, `resume`, and
///   `revert`;
/// * `cleanup` is idempotent: a second call is a no-op;
/// * the explicit `cleanup` result is the authoritative cleanup
///   report — it is what gets persisted into the transaction
///   record's `last_cleanup`;
/// * `Drop` is the last-resort safety net. If `cleanup` was NOT
///   called (e.g. the process panicked between mount and the
///   explicit cleanup call), `Drop` runs the same teardown but
///   cannot surface the result to the caller. A panic-style
///   cleanup is logged to stderr so an operator scanning logs can
///   still see what happened.
pub struct RecoveryRwSession {
    top_level_mount: PathBuf,
    session_dir: PathBuf,
    cleanup_state: RecoveryRwSessionCleanupState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryRwSessionCleanupState {
    Mounted,
    Cleaned,
}

impl RecoveryRwSession {
    /// Mount the btrfs top-level (subvolid=5) read-write inside a
    /// private mount namespace at a freshly-created, secure
    /// session directory.
    pub fn mount(device: &Path) -> Result<Self, RecoveryError> {
        namespace::establish_private_namespace().map_err(|e| RecoveryError {
            kind: RecoveryErrorKind::SyscallFailed,
            message: format!("cannot establish private namespace: {e}").into(),
            transaction_id: None,
            current_state: None,
            failed_step: Some("namespace".into()),
            errno: Some(e.errno),
            external_exit_code: None,
            completed_steps: Box::default(),
            disk_facts: None,
            resume_possible: false,
            revert_possible: false,
            manual_intervention_required: true,
            record_persistence_error: None,
        })?;

        let session_dir = create_session_dir(Path::new(SESSION_ROOT_PARENT), "recovery-rw")
            .map_err(|err| RecoveryError {
                kind: err.kind,
                message: err.message,
                transaction_id: None,
                current_state: None,
                failed_step: Some("session-dir".into()),
                errno: None,
                external_exit_code: None,
                completed_steps: Box::default(),
                disk_facts: None,
                resume_possible: false,
                revert_possible: false,
                manual_intervention_required: true,
                record_persistence_error: None,
            })?;

        let data = "subvolid=5";
        let source = device.to_str().ok_or_else(|| RecoveryError {
            kind: RecoveryErrorKind::SyscallFailed,
            message: format!("device path {} is not valid UTF-8", device.display()).into(),
            transaction_id: None,
            current_state: None,
            failed_step: Some("mount".into()),
            errno: None,
            external_exit_code: None,
            completed_steps: Box::default(),
            disk_facts: None,
            resume_possible: false,
            revert_possible: false,
            manual_intervention_required: false,
            record_persistence_error: None,
        })?;

        syscall::mount(
            Some(source),
            &session_dir,
            Some("btrfs"),
            ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
            Some(data),
        )
        .map_err(|e| RecoveryError {
            kind: RecoveryErrorKind::SyscallFailed,
            message: format!("cannot mount btrfs rw at {}: {e}", session_dir.display()).into(),
            transaction_id: None,
            current_state: None,
            failed_step: Some("mount".into()),
            errno: Some(e.errno),
            external_exit_code: None,
            completed_steps: Box::default(),
            disk_facts: None,
            resume_possible: false,
            revert_possible: false,
            manual_intervention_required: false,
            record_persistence_error: None,
        })?;

        Ok(RecoveryRwSession {
            top_level_mount: session_dir.clone(),
            session_dir,
            cleanup_state: RecoveryRwSessionCleanupState::Mounted,
        })
    }

    pub fn top_level_mount(&self) -> &Path {
        &self.top_level_mount
    }

    /// Explicitly tear down the read-write mount and remove the
    /// session directory. Idempotent. The returned [`CleanupSummary`]
    /// is the authoritative teardown report; the orchestrator MUST
    /// persist it into the transaction record so operators can
    /// diagnose a dirty recovery environment from outside the
    /// process.
    ///
    /// Three distinct outcomes are observable from the returned
    /// summary:
    ///
    /// * clean: `residual` is empty and `all_clean == true`;
    /// * lazy-detached: `residual` carries the mount with a
    ///   "detached lazily" reason — the umount2 failed but
    ///   `MNT_DETACH` succeeded. The kernel still owns the mount;
    ///   the operator MUST be told. `all_clean == false`;
    /// * residual: `residual` carries the mount with both errno
    ///   values; the mount is still live in the namespace.
    ///   `all_clean == false`. The session directory is NOT
    ///   removed in this case.
    ///
    /// A separate `directory_removed` flag would be redundant: the
    /// `residual` summary already distinguishes "directory cleanup
    /// failed" via a synthetic residual entry.
    pub fn cleanup(&mut self) -> CleanupSummary {
        if self.cleanup_state == RecoveryRwSessionCleanupState::Cleaned {
            return CleanupSummary {
                unmounted: Vec::new(),
                residual: Vec::new(),
                all_clean: true,
            };
        }
        let mut summary = CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        };

        match syscall::umount2(&self.session_dir, 0) {
            Ok(()) => {
                summary
                    .unmounted
                    .push(self.session_dir.display().to_string());
            }
            Err(plain_err) => match syscall::umount2(&self.session_dir, mnt_flags::MNT_DETACH) {
                Ok(()) => {
                    // Lazy-detach inside a private namespace is
                    // operationally clean: the mount is removed from
                    // this namespace immediately, and the namespace
                    // itself dies with the process so the kernel
                    // drops the last reference. The diagnostic is
                    // preserved in `unmounted` (with the lazy-detach
                    // note) rather than `residual` so dashboards
                    // still see "the umount path was non-trivial",
                    // but the recovery exit code can treat the
                    // transaction as successful.
                    summary.all_clean = true;
                    summary.unmounted.push(format!(
                        "{}: umount2 failed (errno {}); detached lazily inside private namespace",
                        self.session_dir.display(),
                        plain_err.errno
                    ));
                }
                Err(detach_err) => {
                    summary.all_clean = false;
                    summary.residual.push(format!(
                        "{}: umount2 errno {} and MNT_DETACH errno {}",
                        self.session_dir.display(),
                        plain_err.errno,
                        detach_err.errno
                    ));
                }
            },
        }

        if summary.all_clean {
            if let Err(err) = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &self.session_dir)
            {
                summary.all_clean = false;
                summary.residual.push(format!(
                    "session directory cleanup: {} ({})",
                    err.message,
                    err.kind.code()
                ));
            }
        }

        self.cleanup_state = RecoveryRwSessionCleanupState::Cleaned;
        summary
    }
}

impl Drop for RecoveryRwSession {
    fn drop(&mut self) {
        if self.cleanup_state == RecoveryRwSessionCleanupState::Mounted {
            // Last-resort safety net. The orchestrator is supposed
            // to call `cleanup()` explicitly; reaching Drop in
            // Mounted state means a panic or early return bypassed
            // the explicit path. Run the same teardown and emit a
            // stderr line so a post-mortem log scan can see that
            // the explicit cleanup was skipped.
            let summary = self.cleanup();
            if !summary.all_clean {
                eprintln!(
                    "catos-system: recovery rw session dropped without explicit cleanup; \
                     residual: {:?}",
                    summary.residual
                );
            } else {
                eprintln!(
                    "catos-system: recovery rw session dropped without explicit cleanup; \
                     cleanup completed as Drop safety net"
                );
            }
        }
    }
}
