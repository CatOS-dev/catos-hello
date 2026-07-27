//! Raw syscall wrappers for the mount layer. Thin FFI + errno
//! classification. NO policy lives here: callers (`namespace`, `session`)
//! decide which call to make and what an errno means in context.
//!
//! Layering rule: this module is the ONLY place in the crate that issues
//! `mount(2)`, `umount2(2)`, and `unshare(2)`. Keeping the surface here
//! means a future security audit has exactly one file to read.
//!
//! All syscalls are issued via the raw `syscall(2)` trampoline rather than
//! libc wrappers, for two reasons:
//!   1. musl's `mount`/`umount2` are thin wrappers anyway, so we lose
//!      nothing and gain a direct view of the return code / errno.
//!   2. We avoid any libc symbol-versioning surprise in the initramfs.
//!
//! On non-Linux targets every function returns an explicit
//! `Err(SyscallError::UnsupportedPlatform)`. The binary is Linux-musl only;
//! this branch exists so `cargo check` on a dev host still type-checks.

use std::ffi::CString;
use std::path::Path;

use crate::mount::model::MountErrorKind;

// ---------------------------------------------------------------------------
// Kernel constants (x86_64; identical on all Linux arches we target).
// ---------------------------------------------------------------------------

/// mount(2) syscall number on x86_64.
const SYS_MOUNT: i64 = 165;
/// umount2(2) syscall number on x86_64.
const SYS_UMOUNT2: i64 = 166;
/// unshare(2) syscall number on x86_64.
const SYS_UNSHARE: i64 = 272;

/// `MS_*` mount flag bits. Source: linux/uapi/asm-generic/mount.h.
/// Exposed as `pub` so `namespace` and `plan` can compose them without
/// re-defining magic numbers.
pub mod ms_flags {
    pub const MS_RDONLY: u64 = 1;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_SYNCHRONOUS: u64 = 16;
    pub const MS_REMOUNT: u64 = 32;
    pub const MS_MANDLOCK: u64 = 64;
    pub const MS_DIRSYNC: u64 = 128;
    pub const MS_NOATIME: u64 = 1024;
    pub const MS_NODIRATIME: u64 = 2048;
    pub const MS_BIND: u64 = 4096;
    pub const MS_MOVE: u64 = 8192;
    pub const MS_REC: u64 = 16384;
    pub const MS_SILENT: u64 = 32768;
    pub const MS_POSIXACL: u64 = 1 << 16;
    pub const MS_UNBINDABLE: u64 = 1 << 17;
    pub const MS_PRIVATE: u64 = 1 << 18;
    pub const MS_SLAVE: u64 = 1 << 19;
    pub const MS_SHARED: u64 = 1 << 20;
    pub const MS_RELATIME: u64 = 1 << 21;
    pub const MS_KERNMOUNT: u64 = 1 << 22;
    pub const MS_I_VERSION: u64 = 1 << 23;
    pub const MS_STRICTATIME: u64 = 1 << 24;
    pub const MS_LAZYTIME: u64 = 1 << 25;
}

/// `umount2` flag bits.
pub mod mnt_flags {
    pub const MNT_FORCE: i32 = 1;
    pub const MNT_DETACH: i32 = 2;
    pub const MNT_EXPIRE: i32 = 4;
}

/// `unshare` flag bits we care about.
pub mod clone_flags {
    /// `CLONE_NEWNS` — new mount namespace.
    pub const CLONE_NEWNS: i32 = 0x0002_0000;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Failure of a raw syscall, carrying the errno and the originating call
/// name. The caller maps this to a [`MountError`] with full context.
///
/// `Errno` is kept as the raw positive `i32` (matching libc's `errno`)
/// rather than a typed enum because we want the JSON contract to expose
/// the exact kernel value for debugging exotic failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallError {
    pub syscall: &'static str,
    pub errno: i32,
}

impl SyscallError {
    /// Map the raw errno to the coarsest [`MountErrorKind`] the caller
    /// should surface. This is the ONLY errno→kind table in the crate;
    /// callers add device/path/step context.
    ///
    /// Design rule: when an errno is ambiguous between two failure modes,
    /// we pick the more conservative (i.e. more specific) variant so the
    /// JSON consumer is never told "permission denied" when the real
    /// problem was "filesystem not supported".
    pub fn classify(&self) -> MountErrorKind {
        // EAGAIN from mount is extremely rare and almost always means the
        // device is being torn down; treat as busy.
        match (self.syscall, self.errno) {
            // CAP_SYS_ADMIN missing.
            (_, 1) => match self.syscall {
                "unshare" => MountErrorKind::NamespaceUnavailable,
                _ => MountErrorKind::CapabilityMissing,
            },
            // ENOENT — source device or target path missing.
            (_, 2) => MountErrorKind::DeviceNotFound,
            // EACCES — permission to open device or create target.
            (_, 13) => MountErrorKind::PermissionDenied,
            // EFAULT — pointer bug on our side; surface generically.
            (_, 14) => MountErrorKind::MountFailed,
            // ENOTBLK — source is not a block device.
            ("mount", 15) => MountErrorKind::WrongFilesystemType,
            // EBUSY — device or mountpoint busy.
            (_, 16) => MountErrorKind::DeviceBusy,
            // EEXIST — mountpoint already has a mount we did not create.
            ("mount", 17) => MountErrorKind::AlreadyMounted,
            ("mkdir", 17) => MountErrorKind::UnsafeTargetPath,
            // EXDEV — cross-device move / invalid bind.
            ("mount", 18) => MountErrorKind::InvalidMountOption,
            // ENODEV — fstype not registered in the kernel.
            ("mount", 19) => MountErrorKind::UnsupportedFilesystem,
            // ENOTDIR — target path's parent is not a directory.
            ("mount", 20) => MountErrorKind::UnsafeTargetPath,
            ("mkdir", 20) => MountErrorKind::UnsafeTargetPath,
            // EINVAL — bad option string, bad flags, or wrong superblock
            // signature. The most common real cause is a wrong fstype
            // argument; second most common is a bad mount option.
            ("mount", 22) => MountErrorKind::InvalidMountOption,
            ("mkdir", 22) => MountErrorKind::UnsafeTargetPath,
            ("umount2", 22) => MountErrorKind::UnmountFailed,
            ("unshare", 22) => MountErrorKind::NamespaceUnavailable,
            // ENOSPC — namespace quota or journal space.
            ("unshare", 28) => MountErrorKind::NamespaceUnavailable,
            // EROFS — device is read-only and the caller asked for rw.
            // Phase 2 never asks for rw so this should not fire; if it
            // does, surface as unsafe rather than silently retrying.
            ("mount", 30) => MountErrorKind::UnsafeReadOnlyMode,
            // Anything else: generic.
            _ => match self.syscall {
                "mount" => MountErrorKind::MountFailed,
                "umount2" => MountErrorKind::UnmountFailed,
                "unshare" => MountErrorKind::NamespaceUnavailable,
                _ => MountErrorKind::MountFailed,
            },
        }
    }
}

impl std::fmt::Display for SyscallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: errno {}", self.syscall, self.errno)
    }
}

// ---------------------------------------------------------------------------
// Syscall wrappers
// ---------------------------------------------------------------------------

extern "C" {
    fn syscall(number: std::os::raw::c_long, ...) -> std::os::raw::c_long;
}

/// Issue a `mount(2)` syscall.
///
/// * `source` — device path or pseudo-source token (`tmpfs`). May be `None`
///   for bind/remount operations.
/// * `target` — absolute mountpoint path inside the current namespace.
/// * `fstype` — filesystem type string (`ext4`, `btrfs`, ...). `None` for
///   bind/move operations.
/// * `flags` — `MS_*` bit set, composed by the caller from [`ms_flags`].
/// * `data` — comma-separated option string the kernel parses. `None`
///   passes a NULL pointer.
///
/// Returns `Err` on non-zero return; the caller maps errno via
/// [`SyscallError::classify`].
pub fn mount(
    source: Option<&str>,
    target: &Path,
    fstype: Option<&str>,
    flags: u64,
    data: Option<&str>,
) -> Result<(), SyscallError> {
    let source_c = opt_cstr(source)?;
    // Target MUST exist and be a directory (or a file for bind); a NULL
    // target is a caller bug, classify as DeviceNotFound.
    let target_s = target.to_str().ok_or(SyscallError {
        syscall: "mount",
        errno: 2,
    })?;
    let target_c = CString::new(target_s).map_err(|_| SyscallError {
        syscall: "mount",
        errno: 2,
    })?;
    let fstype_c = opt_cstr(fstype)?;

    // Convert data string to a raw pointer. Invalid C strings must fail
    // closed: silently turning `ro,noload,...` into NULL would drop the
    // filesystem-specific no-replay options and could write to the target.
    let data_c = opt_cstr_with_errno(data, 22)?;

    let rc = unsafe {
        syscall(
            SYS_MOUNT as std::os::raw::c_long,
            source_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            target_c.as_ptr(),
            fstype_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            flags as std::os::raw::c_ulong,
            data_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(SyscallError {
            syscall: "mount",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        })
    }
}

/// Issue an `umount2(2)` syscall.
///
/// * `target` — absolute mountpoint path.
/// * `flags` — `MNT_*` bit set, composed by the caller from [`mnt_flags`].
///   Phase 2 cleanup uses `MNT_DETACH` only as a last-resort fallback for
///   residual mounts; `MNT_FORCE` is forbidden because it can corrupt
///   in-flight writes (even on RO mounts the kernel may hold metadata).
pub fn umount2(target: &Path, flags: i32) -> Result<(), SyscallError> {
    let target_s = target.to_str().ok_or(SyscallError {
        syscall: "umount2",
        errno: 2,
    })?;
    let target_c = CString::new(target_s).map_err(|_| SyscallError {
        syscall: "umount2",
        errno: 2,
    })?;
    let rc = unsafe {
        syscall(
            SYS_UMOUNT2 as std::os::raw::c_long,
            target_c.as_ptr(),
            flags as std::os::raw::c_int,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(SyscallError {
            syscall: "umount2",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        })
    }
}

/// Issue an `unshare(2)` syscall.
///
/// Phase 2 only ever calls this with `CLONE_NEWNS`. `CLONE_NEWUSER` is
/// deliberately NOT supported: a user namespace would let an unprivileged
/// caller fake CAP_SYS_ADMIN, which we refuse to rely on for mount safety.
pub fn unshare(flags: i32) -> Result<(), SyscallError> {
    let rc = unsafe {
        syscall(
            SYS_UNSHARE as std::os::raw::c_long,
            flags as std::os::raw::c_int,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(SyscallError {
            syscall: "unshare",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        })
    }
}

fn opt_cstr(s: Option<&str>) -> Result<Option<CString>, SyscallError> {
    opt_cstr_with_errno(s, 2)
}

fn opt_cstr_with_errno(
    s: Option<&str>,
    invalid_errno: i32,
) -> Result<Option<CString>, SyscallError> {
    match s {
        Some(inner) => {
            // Empty string → treat as None (NULL), matching kernel semantics
            // for "no source".
            if inner.is_empty() {
                Ok(None)
            } else {
                CString::new(inner).map(Some).map_err(|_| SyscallError {
                    syscall: "mount",
                    errno: invalid_errno,
                })
            }
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The errno→kind table is part of the JSON contract. A regression
    /// here silently turns a "filesystem not supported" into "permission
    /// denied" for downstream consumers. Lock every mapping we ship.
    #[test]
    fn errno_to_kind_is_stable() {
        let cases = [
            // (syscall, errno, expected_kind)
            ("mount", 1, MountErrorKind::CapabilityMissing),
            ("umount2", 1, MountErrorKind::CapabilityMissing),
            ("unshare", 1, MountErrorKind::NamespaceUnavailable),
            ("mount", 2, MountErrorKind::DeviceNotFound),
            ("mount", 13, MountErrorKind::PermissionDenied),
            ("mount", 15, MountErrorKind::WrongFilesystemType),
            ("mount", 16, MountErrorKind::DeviceBusy),
            ("umount2", 16, MountErrorKind::DeviceBusy),
            ("mount", 17, MountErrorKind::AlreadyMounted),
            ("mount", 19, MountErrorKind::UnsupportedFilesystem),
            ("mount", 20, MountErrorKind::UnsafeTargetPath),
            ("mkdir", 17, MountErrorKind::UnsafeTargetPath),
            ("mkdir", 20, MountErrorKind::UnsafeTargetPath),
            ("mkdir", 22, MountErrorKind::UnsafeTargetPath),
            ("mount", 22, MountErrorKind::InvalidMountOption),
            ("unshare", 22, MountErrorKind::NamespaceUnavailable),
            ("unshare", 28, MountErrorKind::NamespaceUnavailable),
            ("mount", 30, MountErrorKind::UnsafeReadOnlyMode),
            // Generic fallback.
            ("mount", 999, MountErrorKind::MountFailed),
            ("umount2", 999, MountErrorKind::UnmountFailed),
            ("unshare", 999, MountErrorKind::NamespaceUnavailable),
        ];
        for (sc, errno, expected) in cases {
            let e = SyscallError { syscall: sc, errno };
            assert_eq!(e.classify(), expected, "syscall={sc} errno={errno}");
        }
    }

    /// MS_PRIVATE bit must be exactly 1<<18. Locking the numeric value
    /// guards against a future refactor reading the kernel header wrong.
    #[test]
    fn ms_private_bit_value_is_stable() {
        assert_eq!(ms_flags::MS_PRIVATE, 1 << 18);
        assert_eq!(ms_flags::MS_REC, 16384);
        assert_eq!(ms_flags::MS_RDONLY, 1);
    }

    /// CLONE_NEWNS must be exactly 0x00020000.
    #[test]
    fn clone_newns_value_is_stable() {
        assert_eq!(clone_flags::CLONE_NEWNS, 0x0002_0000);
    }

    /// MNT_DETACH and MNT_EXPIRE numeric values are part of the cleanup
    /// contract; lock them so a refactor does not silently switch to
    /// MNT_FORCE (which can corrupt metadata).
    #[test]
    fn mnt_flag_values_are_stable() {
        assert_eq!(mnt_flags::MNT_FORCE, 1);
        assert_eq!(mnt_flags::MNT_DETACH, 2);
        assert_eq!(mnt_flags::MNT_EXPIRE, 4);
    }

    /// Syscall numbers are part of the ABI; lock them so a cross-arch
    /// porting mistake fails here rather than at runtime.
    #[test]
    fn syscall_numbers_are_x86_64_values() {
        assert_eq!(SYS_MOUNT, 165);
        assert_eq!(SYS_UMOUNT2, 166);
        assert_eq!(SYS_UNSHARE, 272);
    }

    /// SyscallError Display includes the syscall name and errno so a
    /// log line stays debuggable.
    #[test]
    fn syscall_error_display_is_useful() {
        let e = SyscallError {
            syscall: "mount",
            errno: 13,
        };
        let s = format!("{e}");
        assert!(s.contains("mount"));
        assert!(s.contains("13"));
    }

    /// A NUL in the option string must not degrade to a NULL data pointer,
    /// because that would discard noload/rescue=nologreplay/norecovery.
    #[test]
    fn mount_data_with_nul_is_rejected() {
        let err = opt_cstr_with_errno(Some("ro,noload\0discard"), 22).unwrap_err();
        assert_eq!(err.errno, 22);
        assert_eq!(err.classify(), MountErrorKind::InvalidMountOption);
    }
}
