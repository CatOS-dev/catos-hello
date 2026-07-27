//! Generic per-target-device write lock.
//!
//! Acquired by execution paths (repair, recovery) before mutating a
//! target device, so two writers cannot race on the same FSID. The lock
//! is an `flock(2)` on a `/run/catos-system/locks/<fsid>` file; the file
//! descriptor is held for the lifetime of the guard.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

const LOCK_DIR: &str = "/run/catos-system/locks";

/// Error returned by [`acquire`].
#[derive(Debug)]
pub enum LockError {
    /// Could not create/open the lock directory or lock file.
    Io(io::Error),
    /// `flock(2)` failed.
    Lock(io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Io(e) => write!(f, "lock file I/O failure: {e}"),
            LockError::Lock(e) => write!(f, "flock failed: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

/// RAII guard for a held exclusive `flock`. Dropping releases the lock.
pub struct WriteLock {
    _file: File,
}

impl WriteLock {
    /// Acquire an exclusive lock keyed on `fsid`. Blocks until the lock is
    /// obtained or an error occurs.
    pub fn acquire(fsid: &str) -> Result<Self, LockError> {
        let dir = PathBuf::from(LOCK_DIR);
        std::fs::create_dir_all(&dir).map_err(LockError::Io)?;
        let path = dir.join(fsid);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(LockError::Io)?;
        // SAFETY: flock(2) on a file descriptor we own.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc < 0 {
            return Err(LockError::Lock(io::Error::last_os_error()));
        }
        Ok(WriteLock { _file: file })
    }
}

/// Failure to acquire the shared non-blocking lock on a concrete target
/// device inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLockErrorKind {
    StatFailed,
    OpenFailed,
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLockError {
    pub kind: DeviceLockErrorKind,
    pub message: String,
}

impl std::fmt::Display for DeviceLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DeviceLockError {}

/// Non-blocking exclusive lock held on the target device inode. This is
/// shared by filesystem, mount, and snapshot execution paths.
#[derive(Debug)]
pub struct DeviceLock {
    _file: File,
}

impl DeviceLock {
    pub fn try_acquire(device: &std::path::Path) -> Result<Self, DeviceLockError> {
        let file = OpenOptions::new()
            .read(true)
            .open(device)
            .map_err(|error| DeviceLockError {
                kind: DeviceLockErrorKind::OpenFailed,
                message: format!(
                    "cannot open target device {} for shared write lock: {error}",
                    device.display()
                ),
            })?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(DeviceLockError {
                kind: DeviceLockErrorKind::Busy,
                message: format!(
                    "target device {} is locked by another writer: {}",
                    device.display(),
                    std::io::Error::last_os_error()
                ),
            });
        }
        Ok(Self { _file: file })
    }

    /// Synthetic tests use character devices such as `/dev/null`; only real
    /// block devices participate in the cross-capability write fence.
    pub fn try_acquire_if_block_device(
        device: &std::path::Path,
    ) -> Result<Option<Self>, DeviceLockError> {
        use std::os::unix::fs::FileTypeExt;
        let metadata = std::fs::metadata(device).map_err(|error| DeviceLockError {
            kind: DeviceLockErrorKind::StatFailed,
            message: format!(
                "cannot stat target device {} for shared write lock: {error}",
                device.display()
            ),
        })?;
        if !metadata.file_type().is_block_device() {
            return Ok(None);
        }
        Self::try_acquire(device).map(Some)
    }
}
