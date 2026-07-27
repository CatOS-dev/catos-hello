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
