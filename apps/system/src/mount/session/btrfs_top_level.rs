//! Btrfs top-level read-write mount session.
//!
//! A private mount namespace with the btrfs top-level (subvolid=5)
//! mounted read-write at a session directory created under
//! `/run/catos-system/sessions/`. The session directory is created
//! with the shared [`crate::mount::execute::secure_dir`] primitives so
//! the read-only and read-write paths apply identical security
//! semantics.
//!
//! Lifecycle contract:
//!
//! * every successful construction is paired with an explicit
//!   [`BtrfsTopLevelRwSession::cleanup`] call by the orchestrator on
//!   BOTH the success and error paths;
//! * `cleanup` is idempotent: a second call is a no-op;
//! * the explicit `cleanup` result is the authoritative teardown
//!   report;
//! * `Drop` is the last-resort safety net.

use std::path::{Path, PathBuf};

use crate::mount::execute::namespace;
use crate::mount::execute::secure_dir::{create_session_dir, remove_session_dir, SESSION_ROOT_PARENT};
use crate::mount::execute::syscall::{self, mnt_flags, ms_flags};
use crate::mount::model::{CleanupReport, MountedResource, ResidualMount};
use crate::mount::session::cleanup::{MountSessionError, MountSessionErrorKind};

pub struct BtrfsTopLevelRwSession {
    top_level_mount: PathBuf,
    session_dir: PathBuf,
    cleanup_state: BtrfsTopLevelRwSessionCleanupState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BtrfsTopLevelRwSessionCleanupState {
    Mounted,
    Cleaned,
}

impl BtrfsTopLevelRwSession {
    /// Mount the btrfs top-level (subvolid=5) read-write inside a
    /// private mount namespace at a freshly-created, secure session
    /// directory.
    pub fn mount(device: &Path) -> Result<Self, MountSessionError> {
        namespace::establish_private_namespace()
            .map_err(|e| MountSessionError {
                kind: MountSessionErrorKind::NamespaceUnavailable,
                message: format!("cannot establish private namespace: {e}"),
                errno: Some(e.errno),
            })?;

        let session_dir = create_session_dir(Path::new(SESSION_ROOT_PARENT), "recovery-rw")?;

        let data = "subvolid=5";
        let source = device.to_str().ok_or_else(|| MountSessionError {
            kind: MountSessionErrorKind::InvalidDevicePath,
            message: format!("device path {} is not valid UTF-8", device.display()),
            errno: None,
        })?;

        if let Err(e) = syscall::mount(
            Some(source),
            &session_dir,
            Some("btrfs"),
            ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
            Some(data),
        ) {
            // Best-effort cleanup of the session directory before
            // surfacing the mount failure; the directory is otherwise
            // leaked because we never reached the Mounted state.
            let _ = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &session_dir);
            return Err(MountSessionError {
                kind: MountSessionErrorKind::MountFailed,
                message: format!("cannot mount btrfs rw at {}: {e}", session_dir.display()),
                errno: Some(e.errno),
            });
        }

        Ok(BtrfsTopLevelRwSession {
            top_level_mount: session_dir.clone(),
            session_dir,
            cleanup_state: BtrfsTopLevelRwSessionCleanupState::Mounted,
        })
    }

    pub fn top_level_mount(&self) -> &Path {
        &self.top_level_mount
    }

    /// Explicitly tear down the read-write mount and remove the
    /// session directory. Idempotent. The returned [`CleanupReport`]
    /// is the authoritative teardown report.
    ///
    /// Observable outcomes:
    ///
    /// * clean: `residual` is empty and `all_clean == true`;
    /// * lazy-detached: a residual carries the mount with a
    ///   "detached lazily" reason — umount2 failed but `MNT_DETACH`
    ///   succeeded. The kernel still owns the mount; the operator
    ///   MUST be told. `all_clean == false`;
    /// * residual: a residual carries both errno values; the mount is
    ///   still live. `all_clean == false`. The session directory is
    ///   NOT removed in this case.
    pub fn cleanup(&mut self) -> CleanupReport {
        if self.cleanup_state == BtrfsTopLevelRwSessionCleanupState::Cleaned {
            return CleanupReport::default();
        }
        let mut report = CleanupReport::default();
        let label = self.session_dir.display().to_string();

        match syscall::umount2(&self.session_dir, 0) {
            Ok(()) => {
                report.unmounted.push(MountedResource {
                    order: 0,
                    source: label.clone(),
                    target: self.session_dir.clone(),
                    fstype: "btrfs".into(),
                    options: String::new(),
                });
            }
            Err(plain) => match syscall::umount2(&self.session_dir, mnt_flags::MNT_DETACH) {
                Ok(()) => {
                    // Lazy-detach inside a private namespace is
                    // operationally clean: the mount is removed from
                    // this namespace immediately. The diagnostic is
                    // preserved as a residual so the operator sees the
                    // umount path was non-trivial.
                    report.residual.push(ResidualMount {
                        resource: MountedResource {
                            order: 0,
                            source: label.clone(),
                            target: self.session_dir.clone(),
                            fstype: "btrfs".into(),
                            options: String::new(),
                        },
                        reason: format!(
                            "{}: umount2 failed (errno {}); detached lazily inside private namespace",
                            self.session_dir.display(),
                            plain.errno
                        ),
                        error_code: plain.classify().code().to_string(),
                    });
                }
                Err(detach_err) => {
                    report.all_clean = false;
                    report.residual.push(ResidualMount {
                        resource: MountedResource {
                            order: 0,
                            source: label.clone(),
                            target: self.session_dir.clone(),
                            fstype: "btrfs".into(),
                            options: String::new(),
                        },
                        reason: format!(
                            "{}: umount2 errno {} and MNT_DETACH errno {}",
                            self.session_dir.display(),
                            plain.errno,
                            detach_err.errno
                        ),
                        error_code: detach_err.classify().code().to_string(),
                    });
                }
            },
        }

        if report.all_clean {
            if let Err(err) = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &self.session_dir)
            {
                report.all_clean = false;
                report.residual.push(ResidualMount {
                    resource: MountedResource {
                        order: 0,
                        source: label,
                        target: self.session_dir.clone(),
                        fstype: String::new(),
                        options: String::new(),
                    },
                    reason: format!("session directory cleanup: {} ({})", err.message, err.kind.code()),
                    error_code: err.kind.code().to_string(),
                });
            }
        }

        self.cleanup_state = BtrfsTopLevelRwSessionCleanupState::Cleaned;
        report
    }
}

impl Drop for BtrfsTopLevelRwSession {
    fn drop(&mut self) {
        if self.cleanup_state == BtrfsTopLevelRwSessionCleanupState::Mounted {
            let summary = self.cleanup();
            if !summary.all_clean {
                eprintln!(
                    "catos-system: btrfs top-level rw session dropped without explicit cleanup; \
                     residual: {:?}",
                    summary.residual
                );
            } else {
                eprintln!(
                    "catos-system: btrfs top-level rw session dropped without explicit cleanup; \
                     cleanup completed as Drop safety net"
                );
            }
        }
    }
}
