//! Btrfs snapshot operations that remain in `snapshot_engine` pending the
//! phase-4 migration of `snapshot::execute::btrfs`.
//!
//! Phase-1 target refactor: the generic rooted-filesystem confinement
//! primitives (read/write/list/remove/openat2/path-validation) moved to
//! [`catos_target::execute::confined`]. Only the four btrfs-specific
//! operations remain here:
//!   * [`create_btrfs_snapshot`]
//!   * [`create_btrfs_subvolume`]
//!   * [`delete_empty_btrfs_subvolume`]
//!   * [`exchange_rooted_paths`]
//!
//! They call into the migrated helpers via `catos_target::execute::confined`
//! and map [`FsError`] back to [`SnapshotError`] at the seam. This forms a
//! former cross-layer dependency; generic confined filesystem operations are
//! eliminated in phase 4 when `snapshot_engine` is deleted.

use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::model::{fs_to_snapshot, SnapshotError, SnapshotErrorKind};
use catos_target::execute::confined::{
    cstring_pub, entry_type_pub, fsync_fd_pub, list_rooted_directory_names_pub,
    open_rooted_directory_pub, open_rooted_parent_pub, unsafe_path_pub, PubRootedEntry,
};

const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;
const BTRFS_SUBVOL_NAME_MAX: usize = 4039;
const BTRFS_PATH_NAME_MAX: usize = 4087;
const BTRFS_IOC_SNAP_CREATE_V2: u64 = 0x5000_9417;
const BTRFS_IOC_SUBVOL_CREATE_V2: u64 = 0x5000_9418;
const BTRFS_IOC_SNAP_DESTROY: u64 = 0x5000_940f;
const RENAME_EXCHANGE: libc::c_uint = 1 << 1;

/// Layout of `struct btrfs_ioctl_vol_args_v2` from `linux/btrfs.h`.
#[repr(C)]
struct BtrfsIoctlVolArgsV2 {
    fd: i64,
    transid: u64,
    flags: u64,
    unused: [u64; 4],
    name: [u8; BTRFS_SUBVOL_NAME_MAX + 1],
}

#[repr(C)]
struct BtrfsIoctlVolArgs {
    fd: i64,
    name: [u8; BTRFS_PATH_NAME_MAX + 1],
}

/// Create a btrfs snapshot through pinned source and destination
/// directory file descriptors.
pub fn create_btrfs_snapshot(
    top_level: &Path,
    source_subvolume: &str,
    destination_subvolume: &str,
    read_only: bool,
) -> Result<(), SnapshotError> {
    let source =
        open_rooted_directory_pub(top_level, source_subvolume, false).map_err(fs_to_snapshot)?;
    let destination =
        open_rooted_parent_pub(top_level, destination_subvolume, true).map_err(fs_to_snapshot)?;

    match entry_type_pub(
        destination.parent.as_raw_fd(),
        &destination.name,
        &destination.display,
    )
    .map_err(fs_to_snapshot)?
    {
        None => {}
        Some(libc::S_IFLNK) => {
            return Err(
                unsafe_path_pub(&destination.display, "snapshot destination is a symlink").into(),
            );
        }
        Some(_) => {
            return Err(SnapshotError::new(
                SnapshotErrorKind::RootSwitchConflict,
                format!(
                    "snapshot destination {} already exists",
                    destination.display.display()
                ),
            ));
        }
    }

    let name = destination.name.as_bytes();
    if name.is_empty() || name.len() > BTRFS_SUBVOL_NAME_MAX || name.contains(&0) {
        return Err(unsafe_path_pub(
            &destination.display,
            "invalid btrfs snapshot destination name",
        )
        .into());
    }

    let mut arguments = BtrfsIoctlVolArgsV2 {
        fd: i64::from(source.as_raw_fd()),
        transid: 0,
        flags: if read_only { BTRFS_SUBVOL_RDONLY } else { 0 },
        unused: [0; 4],
        name: [0; BTRFS_SUBVOL_NAME_MAX + 1],
    };
    arguments.name[..name.len()].copy_from_slice(name);

    let result = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            destination.parent.as_raw_fd(),
            BTRFS_IOC_SNAP_CREATE_V2 as libc::c_ulong,
            &mut arguments,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        let mut recovery_error = SnapshotError::new(
            if error.raw_os_error() == Some(libc::EEXIST) {
                SnapshotErrorKind::RootSwitchConflict
            } else {
                SnapshotErrorKind::SyscallFailed
            },
            format!(
                "BTRFS_IOC_SNAP_CREATE_V2 {} -> {} failed: {error}",
                source_subvolume, destination_subvolume
            ),
        );
        recovery_error.errno = error.raw_os_error();
        return Err(recovery_error);
    }
    fsync_fd_pub(
        destination.parent.as_raw_fd(),
        &destination.display,
        "fsync snapshot destination parent",
    )
    .map_err(fs_to_snapshot)
}

/// Create an empty Btrfs subvolume below a pinned parent directory fd.
pub fn create_btrfs_subvolume(top_level: &Path, rooted_path: &str) -> Result<(), SnapshotError> {
    let destination =
        open_rooted_parent_pub(top_level, rooted_path, false).map_err(fs_to_snapshot)?;
    match entry_type_pub(
        destination.parent.as_raw_fd(),
        &destination.name,
        &destination.display,
    )
    .map_err(fs_to_snapshot)?
    {
        None => {}
        Some(libc::S_IFLNK) => {
            return Err(unsafe_path_pub(
                &destination.display,
                "subvolume destination is a symlink",
            )
            .into());
        }
        Some(_) => {
            return Err(SnapshotError::new(
                SnapshotErrorKind::RootSwitchConflict,
                format!(
                    "subvolume destination {} already exists",
                    destination.display.display()
                ),
            ));
        }
    }

    let name = destination.name.as_bytes();
    if name.is_empty() || name.len() > BTRFS_SUBVOL_NAME_MAX || name.contains(&0) {
        return Err(unsafe_path_pub(
            &destination.display,
            "invalid btrfs subvolume destination name",
        )
        .into());
    }
    let mut arguments = BtrfsIoctlVolArgsV2 {
        fd: 0,
        transid: 0,
        flags: 0,
        unused: [0; 4],
        name: [0; BTRFS_SUBVOL_NAME_MAX + 1],
    };
    arguments.name[..name.len()].copy_from_slice(name);
    let result = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            destination.parent.as_raw_fd(),
            BTRFS_IOC_SUBVOL_CREATE_V2 as libc::c_ulong,
            &mut arguments,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        let mut recovery_error = SnapshotError::new(
            if error.raw_os_error() == Some(libc::EEXIST) {
                SnapshotErrorKind::RootSwitchConflict
            } else {
                SnapshotErrorKind::SyscallFailed
            },
            format!(
                "BTRFS_IOC_SUBVOL_CREATE_V2 {} failed: {error}",
                destination.display.display()
            ),
        );
        recovery_error.errno = error.raw_os_error();
        return Err(recovery_error);
    }
    fsync_fd_pub(
        destination.parent.as_raw_fd(),
        &destination.display,
        "fsync subvolume destination parent",
    )
    .map_err(fs_to_snapshot)
}

/// Delete a Btrfs subvolume only after proving its directory is empty.
pub fn delete_empty_btrfs_subvolume(
    top_level: &Path,
    rooted_path: &str,
) -> Result<(), SnapshotError> {
    let names = list_rooted_directory_names_pub(top_level, rooted_path).map_err(fs_to_snapshot)?;
    if !names.is_empty() {
        return Err(SnapshotError::new(
            SnapshotErrorKind::RootSwitchConflict,
            format!("refusing to delete non-empty Btrfs subvolume {rooted_path}"),
        ));
    }
    let destination =
        open_rooted_parent_pub(top_level, rooted_path, false).map_err(fs_to_snapshot)?;
    require_directory_entry(&destination)?;
    let name = destination.name.as_bytes();
    if name.is_empty() || name.len() > BTRFS_PATH_NAME_MAX || name.contains(&0) {
        return Err(unsafe_path_pub(
            &destination.display,
            "invalid Btrfs subvolume rollback name",
        )
        .into());
    }
    let mut arguments = BtrfsIoctlVolArgs {
        fd: 0,
        name: [0; BTRFS_PATH_NAME_MAX + 1],
    };
    arguments.name[..name.len()].copy_from_slice(name);
    let result = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            destination.parent.as_raw_fd(),
            BTRFS_IOC_SNAP_DESTROY as libc::c_ulong,
            &mut arguments,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        let mut recovery_error = SnapshotError::new(
            SnapshotErrorKind::SyscallFailed,
            format!(
                "BTRFS_IOC_SNAP_DESTROY {} failed: {error}",
                destination.display.display()
            ),
        );
        recovery_error.errno = error.raw_os_error();
        return Err(recovery_error);
    }
    fsync_fd_pub(
        destination.parent.as_raw_fd(),
        &destination.display,
        "fsync Btrfs subvolume parent after rollback",
    )
    .map_err(fs_to_snapshot)
}

pub fn exchange_rooted_paths(
    top_level: &Path,
    left: &str,
    right: &str,
) -> Result<(), SnapshotError> {
    let left = open_rooted_parent_pub(top_level, left, false).map_err(fs_to_snapshot)?;
    let right = open_rooted_parent_pub(top_level, right, false).map_err(fs_to_snapshot)?;
    require_directory_entry(&left)?;
    require_directory_entry(&right)?;
    exchange_open_entries(&left, &right)
}

fn exchange_open_entries(
    left: &PubRootedEntry,
    right: &PubRootedEntry,
) -> Result<(), SnapshotError> {
    let left_name = cstring_pub(&left.name, &left.display).map_err(fs_to_snapshot)?;
    let right_name = cstring_pub(&right.name, &right.display).map_err(fs_to_snapshot)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            left.parent.as_raw_fd(),
            left_name.as_ptr(),
            right.parent.as_raw_fd(),
            right_name.as_ptr(),
            RENAME_EXCHANGE,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        let mut recovery_error = SnapshotError::new(
            SnapshotErrorKind::SyscallFailed,
            format!(
                "renameat2(RENAME_EXCHANGE) {} <-> {} failed: {error}",
                left.display.display(),
                right.display.display()
            ),
        );
        recovery_error.errno = error.raw_os_error();
        return Err(recovery_error);
    }
    fsync_fd_pub(
        left.parent.as_raw_fd(),
        &left.display,
        "fsync left exchange parent",
    )
    .map_err(fs_to_snapshot)?;
    if left.parent.as_raw_fd() != right.parent.as_raw_fd() {
        fsync_fd_pub(
            right.parent.as_raw_fd(),
            &right.display,
            "fsync right exchange parent",
        )
        .map_err(fs_to_snapshot)?;
    }
    Ok(())
}

fn require_directory_entry(entry: &PubRootedEntry) -> Result<(), SnapshotError> {
    match entry_type_pub(entry.parent.as_raw_fd(), &entry.name, &entry.display)
        .map_err(fs_to_snapshot)?
    {
        Some(libc::S_IFDIR) => Ok(()),
        Some(libc::S_IFLNK) => {
            Err(unsafe_path_pub(&entry.display, "root exchange entry is a symlink").into())
        }
        Some(_) => Err(SnapshotError::new(
            SnapshotErrorKind::RootSwitchConflict,
            format!(
                "root exchange entry {} is not a directory",
                entry.display.display()
            ),
        )),
        None => Err(SnapshotError::new(
            SnapshotErrorKind::RootSwitchConflict,
            format!("root exchange entry {} is missing", entry.display.display()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catos_target::execute::confined::{atomic_write_rooted, remove_empty_rooted_directory};
    use catos_target::FsError;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TX_ID: &str = "tx-00000000000000000000000000000001";

    fn scratch(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "catos-confined-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn snapshot_destination_parent_symlink_is_rejected() {
        let top = scratch("snapshot-link");
        let outside = scratch("snapshot-link-outside");
        std::fs::create_dir_all(top.join("@")).unwrap();
        std::fs::create_dir_all(top.join(".catos-recovery/staging")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, top.join(".catos-recovery/staging").join(TX_ID)).unwrap();
        let error = create_btrfs_snapshot(
            &top,
            "/@",
            &format!("/.catos-recovery/staging/{TX_ID}/new-root"),
            false,
        )
        .unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::UnsafeRecoveryPath);
        assert!(!outside.join("new-root").exists());
        let _ = std::fs::remove_dir_all(top);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn exchange_parent_symlink_is_rejected() {
        let top = scratch("exchange-link");
        let outside = scratch("exchange-link-outside");
        std::fs::create_dir_all(top.join("@")).unwrap();
        std::fs::create_dir_all(top.join(".catos-recovery/staging")).unwrap();
        std::fs::create_dir_all(outside.join("new-root")).unwrap();
        symlink(&outside, top.join(".catos-recovery/staging").join(TX_ID)).unwrap();
        let error = exchange_rooted_paths(
            &top,
            "/@",
            &format!("/.catos-recovery/staging/{TX_ID}/new-root"),
        )
        .unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::UnsafeRecoveryPath);
        assert!(top.join("@").is_dir());
        assert!(outside.join("new-root").is_dir());
        let _ = std::fs::remove_dir_all(top);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn empty_rooted_directory_is_removed_but_nonempty_is_preserved() {
        let top = scratch("empty-dir-rollback");
        std::fs::create_dir_all(top.join("empty")).unwrap();
        std::fs::create_dir_all(top.join("nonempty")).unwrap();
        std::fs::write(top.join("nonempty/data"), b"keep").unwrap();

        remove_empty_rooted_directory(&top, "/empty").unwrap();
        assert!(!top.join("empty").exists());
        let error = remove_empty_rooted_directory(&top, "/nonempty").unwrap_err();
        assert!(
            matches!(error, FsError::Io(_)),
            "non-empty rooted directory must surface as FsError::Io, got {error:?}"
        );
        assert_eq!(std::fs::read(top.join("nonempty/data")).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(top);
    }

    #[test]
    fn btrfs_subvolume_rollback_refuses_nonempty_before_ioctl() {
        let top = scratch("nonempty-subvol-rollback");
        std::fs::create_dir_all(top.join("candidate")).unwrap();
        std::fs::write(top.join("candidate/data"), b"keep").unwrap();

        let error = delete_empty_btrfs_subvolume(&top, "/candidate").unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::RootSwitchConflict);
        assert_eq!(std::fs::read(top.join("candidate/data")).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(top);
    }

    #[test]
    fn rooted_atomic_write_replaces_target_file_and_rejects_parent_symlink() {
        let top = scratch("rooted-write");
        let outside = scratch("rooted-write-outside");
        std::fs::create_dir_all(top.join("@/etc")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(top.join("@/etc/fstab"), "old\n").unwrap();

        atomic_write_rooted(&top, "/@/etc/fstab", b"new\n", 0o644).unwrap();
        assert_eq!(
            std::fs::read_to_string(top.join("@/etc/fstab")).unwrap(),
            "new\n"
        );

        std::fs::remove_file(top.join("@/etc/fstab")).unwrap();
        std::fs::remove_dir(top.join("@/etc")).unwrap();
        symlink(&outside, top.join("@/etc")).unwrap();
        let error = atomic_write_rooted(&top, "/@/etc/fstab", b"blocked\n", 0o644).unwrap_err();
        assert!(matches!(error, FsError::OutsideRoot(_)));
        assert!(!outside.join("fstab").exists());

        let _ = std::fs::remove_dir_all(top);
        let _ = std::fs::remove_dir_all(outside);
    }
}
