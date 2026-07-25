//! Per-FSID exclusive transaction lock.
//!
//! Recovery transactions are mutually exclusive per btrfs filesystem:
//! at most one of `apply`, `resume`, `revert` may run against a given
//! FSID at a time. This module owns the lock primitive.
//!
//! ## Why non-blocking
//!
//! The lock is acquired with `flock(LOCK_EX | LOCK_NB)`. A blocking
//! acquire would let a wedged first process hang the second one
//! indefinitely; a non-blocking acquire returns `EAGAIN` immediately,
//! which the engine surfaces as a structured
//! [`RecoveryErrorKind::TransactionAlreadyActive`] error so the
//! operator can decide whether to wait, investigate, or kill the
//! holder.
//!
//! ## Why a lock FILE, not a lock on the state record
//!
//! The state record lives at
//! `/.catos-recovery/transactions/<id>/state.json`, which is per
//! transaction. Two different transactions against the same FSID
//! would not collide on that file. The lock file lives at
//! `/.catos-recovery/locks/<fsid>.lock`, which is per FSID, so two
//! transactions targeting the same btrfs collide correctly even if
//! they have different transaction ids.
//!
//! ## RAII
//!
//! [`TransactionLock`] owns the open file descriptor. Dropping the
//! guard closes the fd, which releases the flock. The engine stores
//! the guard for the lifetime of the transaction; no explicit release
//! is needed.
//!
//! ## Choice of primitive
//!
//! We use raw `libc::flock` via an `extern "C"` binding, consistent
//! with the rest of the engine (renameat2, fsync). The crate has a
//! strict "serde + serde_json only" dependency policy; pulling in
//! `fs2` / `fs4` solely for a one-line flock wrapper would violate
//! that for no functional gain.

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::model::recovery::{RecoveryError, RecoveryErrorKind};
use crate::recovery::confined;

/// `flock(LOCK_EX)` = 2. `LOCK_NB` = 4. Combined = 6.
const LOCK_EX_NB: std::os::raw::c_int = 2 | 4;

/// RAII guard for the per-FSID transaction lock. Dropping releases.
/// Manual `Debug` because `File` does not implement `Debug`.
#[derive(Debug)]
pub struct TransactionLock {
    _file: File,
}

impl TransactionLock {
    /// Try to acquire the exclusive, non-blocking lock on
    /// `lock_path`. Returns:
    /// * `Ok(TransactionLock)` — acquired; hold the guard to keep
    ///   the lock.
    /// * `Err(RecoveryError { kind: TransactionAlreadyActive })` —
    ///   another process holds the lock (EAGAIN / EWOULDBLOCK).
    /// * `Err(...)` — any other I/O or syscall failure.
    ///
    /// `fsid_for_error` is the raw FSID used purely for the error
    /// message; it is NOT used to compute the lock path (the caller
    /// has already done that).
    //
    // Local allow, justified: `try_acquire` is part of the public
    // API surface (`pub use lock::TransactionLock` in mod.rs). It is
    // consumed by:
    //   * `engine::acquire_lock_guard` (which boxes the error itself
    //     to keep its own result small),
    //   * `src/bin/recovery_lock_hold_helper.rs` (the test helper
    //     binary, which prints `err.kind.code()` and `err.message`
    //     directly to stdout),
    //   * `tests/test_recovery_lock.rs` (which calls `.unwrap_err()`
    //     and reads `err.kind`).
    // Boxing at THIS signature would force all three callers to
    // dereference before reading the structured fields, AND would
    // change the signature visible to any future external consumer
    // of the lock primitive. Cost-benefit: keep the allow.
    #[allow(clippy::result_large_err)]
    pub fn try_acquire(lock_path: &Path, fsid_for_error: &str) -> Result<Self, RecoveryError> {
        let file = match confined::open_lock_file(lock_path) {
            Ok(file) => file,
            Err(mut error) => {
                error.message = format!(
                    "cannot safely open transaction lock file {} for fsid {}: {}",
                    lock_path.display(),
                    fsid_for_error,
                    error.message
                )
                .into_boxed_str();
                return Err(error);
            }
        };

        let rc = libc_flock(file.as_raw_fd(), LOCK_EX_NB);
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            // EAGAIN (11) / EWOULDBLOCK (11 on Linux) — the lock is
            // held by another process. Surface as
            // TransactionAlreadyActive so the caller can present a
            // structured "another transaction is running" error
            // instead of a generic syscall failure.
            if errno == 11 || errno == ewouldblock_errno() {
                return Err(RecoveryError::new(
                    RecoveryErrorKind::TransactionAlreadyActive,
                    format!(
                        "another recovery transaction is already active for btrfs filesystem \
                         fsid {fsid_for_error}; lock file {} is held by another process \
                         (errno={errno})",
                        lock_path.display()
                    ),
                ));
            }
            return Err(RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
                format!(
                    "flock(LOCK_EX | LOCK_NB) on {} failed: errno={errno}",
                    lock_path.display()
                ),
            ));
        }
        Ok(TransactionLock { _file: file })
    }
}

/// Compute the canonical lock file path for a given (top_level, fsid).
/// Exposed so the engine and tests agree on the layout.
pub fn lock_file_path(top_level_mount: &Path, fsid: &str) -> PathBuf {
    top_level_mount
        .join(".catos-recovery")
        .join("locks")
        .join(format!("{}.lock", sanitize_fsid(fsid)))
}

/// Restrict the FSID to filesystem-safe characters so a hostile or
/// malformed FSID cannot escape the locks directory.
fn sanitize_fsid(fsid: &str) -> String {
    fsid.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------

extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

fn libc_flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int {
    // SAFETY: flock(2) is a kernel syscall with the documented
    // signature; the file descriptor is owned by the caller.
    unsafe { flock(fd, operation) }
}

/// On Linux EAGAIN and EWOULDBLOCK have the same value (11); keep
/// the constant explicit so a future port to a platform where they
/// diverge does not silently regress.
fn ewouldblock_errno() -> std::os::raw::c_int {
    11
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch_lock_path(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "catos-lock-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&root);
        root.join(".catos-recovery/locks/test.lock")
    }

    #[test]
    fn try_acquire_then_re_acquire_after_drop_succeeds() {
        let path = scratch_lock_path("drop");
        let g1 = TransactionLock::try_acquire(&path, "fsid-A").unwrap();
        drop(g1);
        // After the guard drops, the same path can be re-acquired.
        let _g2 = TransactionLock::try_acquire(&path, "fsid-A").unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn try_acquire_is_non_blocking_when_held_in_same_process() {
        // Two File handles to the SAME path inside one process still
        // share the same inode-level flock on Linux; the second
        // acquire MUST fail with TransactionAlreadyActive rather
        // than block.
        let path = scratch_lock_path("nonblock");
        let _g1 = TransactionLock::try_acquire(&path, "fsid-B").unwrap();
        let err = TransactionLock::try_acquire(&path, "fsid-B").unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::TransactionAlreadyActive);
        assert!(
            err.message.contains("fsid B")
                || err.message.contains("fsid_B")
                || err.message.contains("fsid"),
            "msg={}",
            err.message
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn lock_file_path_is_per_fsid_under_locks_dir() {
        let top = Path::new("/tmp/fake-top");
        let p = lock_file_path(top, "abc-123");
        assert!(p.starts_with("/tmp/fake-top/.catos-recovery/locks"));
        assert!(p.ends_with("abc-123.lock"));
    }

    #[test]
    fn sanitize_replaces_unsafe_chars() {
        assert_eq!(sanitize_fsid("abc/../../../etc"), "abc__________etc");
        assert_eq!(sanitize_fsid("0a1b-2c3d_4e5f"), "0a1b-2c3d_4e5f");
    }

    #[test]
    fn try_acquire_rejects_symlink_lock_file() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "catos-lock-symlink-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let outside = root.with_extension("outside");
        let lock_path = lock_file_path(&root, "fsid-symlink");
        std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        std::fs::write(&outside, b"sentinel").unwrap();
        symlink(&outside, &lock_path).unwrap();
        let error = TransactionLock::try_acquire(&lock_path, "fsid-symlink").unwrap_err();
        assert_eq!(error.kind, RecoveryErrorKind::UnsafeRecoveryPath);
        assert_eq!(std::fs::read(&outside).unwrap(), b"sentinel");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(outside);
    }
}
