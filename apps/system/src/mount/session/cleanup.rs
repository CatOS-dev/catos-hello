//! Mount-session cleanup data and the session-layer error taxonomy.
//!
//! Sessions (`ReadOnlyMountSession`, `BtrfsTopLevelRwSession`,
//! `TargetMountRwSession`) and the secure session-directory primitives
//! return [`MountSessionError`]. Application layers (recovery, repair)
//! convert it into their own error types at the boundary.
//!
//! The cleanup report data itself lives in [`crate::mount::model`]
//! (`CleanupReport`); this module owns the focused session error and
//! the shared unmount-with-detach helper used by the read-write
//! sessions.

use std::path::Path;

use crate::mount::execute::syscall::{self, mnt_flags, SyscallError};
use crate::mount::model::{CleanupReport, ResidualMount};

/// Failure of a mount-session operation: namespace establishment,
/// secure session-directory creation/removal, randomness, or the
/// underlying mount(2) call.
///
/// Kept focused and separate from [`crate::mount::model::MountError`]
/// (which describes a single mount/umount operation) because
/// session-directory and randomness failures do not fit the
/// mount-operation contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSessionError {
    pub kind: MountSessionErrorKind,
    pub message: String,
    pub errno: Option<i32>,
}

impl MountSessionError {
    pub fn new(kind: MountSessionErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            errno: None,
        }
    }

    pub fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl std::fmt::Display for MountSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.code(), self.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountSessionErrorKind {
    NamespaceUnavailable,
    SessionDirectoryNotSecure,
    SessionDirectoryConflict,
    SessionDirectoryCleanupFailed,
    RandomSourceFailed,
    MountFailed,
    InvalidDevicePath,
}

impl MountSessionErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            MountSessionErrorKind::NamespaceUnavailable => "namespace_unavailable",
            MountSessionErrorKind::SessionDirectoryNotSecure => "session_directory_not_secure",
            MountSessionErrorKind::SessionDirectoryConflict => "session_directory_conflict",
            MountSessionErrorKind::SessionDirectoryCleanupFailed => {
                "session_directory_cleanup_failed"
            }
            MountSessionErrorKind::RandomSourceFailed => "random_source_failed",
            MountSessionErrorKind::MountFailed => "mount_failed",
            MountSessionErrorKind::InvalidDevicePath => "invalid_device_path",
        }
    }
}

/// Unmount one target with a `MNT_DETACH` fallback, recording the
/// outcome into `report`. Used by the read-write sessions so their
/// cleanup loops share identical semantics: plain `umount2(0)` first,
/// `MNT_DETACH` on failure, NEVER `MNT_FORCE` (it can corrupt
/// in-flight metadata).
///
/// Returns the updated report and a boolean that is `true` when the
/// mount was cleanly unmounted (so the caller can decide whether to
/// remove the session directory).
pub fn unmount_with_detach(
    target: &Path,
    label: String,
    mut report: CleanupReport,
) -> (CleanupReport, bool) {
    match syscall::umount2(target, 0) {
        Ok(()) => {
            report.unmounted.push(crate::mount::model::MountedResource {
                order: 0,
                source: label.clone(),
                target: target.to_path_buf(),
                fstype: String::new(),
                options: String::new(),
            });
            (report, true)
        }
        Err(plain) => match syscall::umount2(target, mnt_flags::MNT_DETACH) {
            Ok(()) => {
                report.residual.push(ResidualMount {
                    resource: crate::mount::model::MountedResource {
                        order: 0,
                        source: label,
                        target: target.to_path_buf(),
                        fstype: String::new(),
                        options: String::new(),
                    },
                    reason: format!(
                        "{target}: umount2 failed (errno {}); detached lazily",
                        plain.errno,
                        target = target.display()
                    ),
                    error_code: plain.classify().code().to_string(),
                });
                (report, true)
            }
            Err(detach) => {
                report.all_clean = false;
                report.residual.push(ResidualMount {
                    resource: crate::mount::model::MountedResource {
                        order: 0,
                        source: label,
                        target: target.to_path_buf(),
                        fstype: String::new(),
                        options: String::new(),
                    },
                    reason: format!(
                        "{target}: umount2 errno {} and MNT_DETACH errno {}",
                        plain.errno,
                        detach.errno,
                        target = target.display()
                    ),
                    error_code: detach.classify().code().to_string(),
                });
                (report, false)
            }
        },
    }
}

/// Map a raw syscall failure from namespace establishment into the
/// session error taxonomy.
pub(crate) fn from_namespace_error(error: SyscallError) -> MountSessionError {
    MountSessionError {
        kind: MountSessionErrorKind::NamespaceUnavailable,
        message: format!("cannot establish private mount namespace: {error}"),
        errno: Some(error.errno),
    }
}
