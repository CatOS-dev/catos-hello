//! Symlink-safe recovery storage rooted at the mounted btrfs top level.
//!
//! Every privileged phase-3 file operation is resolved from an already
//! opened top-level directory fd. Directory components are opened one at
//! a time with `openat2(2)` and
//! `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS`.
//! The resulting dirfds remain pinned for the operation, so replacing a
//! pathname after validation cannot redirect a write outside the target.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::shared::model::recovery::{RecoveryError, RecoveryErrorKind};

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const CONFINED_RESOLVE: u64 = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
const MAX_RECOVERY_FILE_BYTES: u64 = 16 * 1024 * 1024;
const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;
const BTRFS_SUBVOL_NAME_MAX: usize = 4039;
const BTRFS_PATH_NAME_MAX: usize = 4087;
const BTRFS_IOC_SNAP_CREATE_V2: u64 = 0x5000_9417;
const BTRFS_IOC_SUBVOL_CREATE_V2: u64 = 0x5000_9418;
const BTRFS_IOC_SNAP_DESTROY: u64 = 0x5000_940f;
const RENAME_EXCHANGE: libc::c_uint = 1 << 1;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Layout of `struct btrfs_ioctl_vol_args_v2` from
/// `linux/btrfs.h`. The kernel ABI is exactly one 4096-byte page.
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

struct RootedEntry {
    parent: OwnedFd,
    name: OsString,
    display: PathBuf,
}

/// A path below `<top-level>/.catos-recovery` split into a trusted
/// top-level pathname and untrusted relative components. The split is
/// purely lexical; no pathname is followed until the top-level fd is
/// open and all remaining components are resolved relative to it.
#[derive(Debug, Clone)]
pub struct ConfinedPath {
    top_level: PathBuf,
    relative: Vec<OsString>,
}

impl ConfinedPath {
    pub fn parse(path: &Path) -> Result<Self, RecoveryError> {
        let mut top_level = PathBuf::new();
        let mut relative = Vec::new();
        let mut found_recovery_root = false;

        for component in path.components() {
            match component {
                Component::RootDir => {
                    if found_recovery_root {
                        return Err(unsafe_path(path, "absolute component after recovery root"));
                    }
                    top_level.push(Path::new("/"));
                }
                Component::Normal(part) => {
                    if part == OsStr::new(".catos-recovery") {
                        if found_recovery_root {
                            return Err(unsafe_path(path, "multiple .catos-recovery components"));
                        }
                        found_recovery_root = true;
                        relative.push(part.to_os_string());
                    } else if found_recovery_root {
                        validate_component(part, path)?;
                        relative.push(part.to_os_string());
                    } else {
                        validate_component(part, path)?;
                        top_level.push(part);
                    }
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(unsafe_path(path, "dot, parent, or prefix component"));
                }
            }
        }

        if !found_recovery_root || relative.is_empty() {
            return Err(unsafe_path(
                path,
                "path is not below a .catos-recovery directory",
            ));
        }
        if top_level.as_os_str().is_empty() {
            top_level.push(Path::new("/"));
        }
        Ok(Self {
            top_level,
            relative,
        })
    }

    fn open_top_level(&self) -> Result<OwnedFd, RecoveryError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.top_level)
            .map_err(|error| {
                map_path_error(
                    &self.top_level,
                    "open btrfs top-level directory",
                    error,
                    false,
                )
            })?;
        Ok(file.into())
    }

    fn open_parent(&self, create: bool) -> Result<(OwnedFd, OsString), RecoveryError> {
        if self.relative.len() < 2 {
            return Err(unsafe_path(
                &self.display_path(),
                "recovery file path has no parent below .catos-recovery",
            ));
        }
        let mut dir = self.open_top_level()?;
        for component in &self.relative[..self.relative.len() - 1] {
            dir = open_directory_component(dir.as_raw_fd(), component, create, 0o700)
                .map_err(|error| annotate_component(error, &self.display_path(), component))?;
        }
        Ok((dir, self.relative.last().cloned().expect("checked length")))
    }

    fn open_directory(&self, create: bool) -> Result<OwnedFd, RecoveryError> {
        let mut dir = self.open_top_level()?;
        for component in &self.relative {
            dir = open_directory_component(dir.as_raw_fd(), component, create, 0o700)
                .map_err(|error| annotate_component(error, &self.display_path(), component))?;
        }
        Ok(dir)
    }

    fn display_path(&self) -> PathBuf {
        let mut path = self.top_level.clone();
        for component in &self.relative {
            path.push(component);
        }
        path
    }
}

pub fn is_confined_recovery_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(component, Component::Normal(part) if part == OsStr::new(".catos-recovery"))
    })
}

pub fn read_file(path: &Path) -> Result<Vec<u8>, RecoveryError> {
    let confined = ConfinedPath::parse(path)?;
    let (parent, name) = confined.open_parent(false)?;
    let fd = open_file_at(
        parent.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
        true,
    )?;
    require_regular_file(fd.as_raw_fd(), path)?;
    read_owned_fd(fd, path)
}

/// Read an operator-supplied plan file without following any symlink in
/// the path. This is read-only and is intentionally not restricted to
/// `.catos-recovery`, because `recovery plan --json > /tmp/plan.json`
/// is a supported workflow.
pub fn read_external_file(path: &Path) -> Result<Vec<u8>, RecoveryError> {
    let c_path = cstring(path.as_os_str(), path)?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    let fd = openat2_raw(libc::AT_FDCWD, &c_path, &how)
        .map_err(|error| map_path_error(path, "open external plan file", error, true))?;
    require_regular_file(fd.as_raw_fd(), path)?;
    read_owned_fd(fd, path)
}

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), RecoveryError> {
    let confined = ConfinedPath::parse(path)?;
    let (parent, name) = confined.open_parent(true)?;
    reject_existing_non_regular_or_symlink(parent.as_raw_fd(), &name, path)?;

    let (temp_name, temp_fd) = create_temp_file(parent.as_raw_fd(), &name, path, mode)?;
    let mut temp = File::from(temp_fd);
    let write_result = (|| {
        temp.write_all(bytes)
            .map_err(|error| io_error(path, "write recovery temp file", error))?;
        temp.flush()
            .map_err(|error| io_error(path, "flush recovery temp file", error))?;
        temp.sync_all()
            .map_err(|error| io_error(path, "fsync recovery temp file", error))?;
        Ok::<(), RecoveryError>(())
    })();
    drop(temp);
    if let Err(error) = write_result {
        let _ = unlinkat_name(parent.as_raw_fd(), &temp_name);
        return Err(error);
    }

    let temp_c = cstring(&temp_name, path)?;
    let final_c = cstring(&name, path)?;
    let rc = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            temp_c.as_ptr(),
            parent.as_raw_fd(),
            final_c.as_ptr(),
        )
    };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        let _ = unlinkat_name(parent.as_raw_fd(), &temp_name);
        return Err(map_path_error(
            path,
            "atomically rename recovery file",
            error,
            true,
        ));
    }
    fsync_fd(parent.as_raw_fd(), path, "fsync recovery parent directory")
}

/// Atomically replace a regular file below a mounted filesystem top level.
///
/// This is deliberately separate from [`atomic_write`]: recovery records are
/// confined to `.catos-recovery`, while mount repair needs to update the
/// target system's own files. The rooted path is still resolved entirely by
/// pinned dirfds, with no symlink followed in any component.
pub fn atomic_write_rooted(
    top_level: &Path,
    rooted_path: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), RecoveryError> {
    let entry = open_rooted_parent(top_level, rooted_path, false)?;
    reject_existing_non_regular_or_symlink(entry.parent.as_raw_fd(), &entry.name, &entry.display)?;

    let (temp_name, temp_fd) =
        create_temp_file(entry.parent.as_raw_fd(), &entry.name, &entry.display, mode)?;
    let mut temp = File::from(temp_fd);
    let write_result = (|| {
        temp.write_all(bytes)
            .map_err(|error| io_error(&entry.display, "write rooted temp file", error))?;
        temp.flush()
            .map_err(|error| io_error(&entry.display, "flush rooted temp file", error))?;
        temp.sync_all()
            .map_err(|error| io_error(&entry.display, "fsync rooted temp file", error))?;
        Ok::<(), RecoveryError>(())
    })();
    drop(temp);
    if let Err(error) = write_result {
        let _ = unlinkat_name(entry.parent.as_raw_fd(), &temp_name);
        return Err(error);
    }

    let temp_c = cstring(&temp_name, &entry.display)?;
    let final_c = cstring(&entry.name, &entry.display)?;
    let rc = unsafe {
        libc::renameat(
            entry.parent.as_raw_fd(),
            temp_c.as_ptr(),
            entry.parent.as_raw_fd(),
            final_c.as_ptr(),
        )
    };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        let _ = unlinkat_name(entry.parent.as_raw_fd(), &temp_name);
        return Err(map_path_error(
            &entry.display,
            "atomically rename rooted file",
            error,
            false,
        ));
    }
    fsync_fd(
        entry.parent.as_raw_fd(),
        &entry.display,
        "fsync rooted parent directory",
    )
}

/// Create a directory path below a mounted filesystem top level without
/// traversing a symlink. Existing components must be directories.
pub fn create_rooted_directory(top_level: &Path, rooted_path: &str) -> Result<(), RecoveryError> {
    open_rooted_directory(top_level, rooted_path, true).map(|_| ())
}

/// List one rooted directory without following symlinks in any component.
pub fn list_rooted_directory_names(
    top_level: &Path,
    rooted_path: &str,
) -> Result<Vec<OsString>, RecoveryError> {
    let directory = open_rooted_directory(top_level, rooted_path, false)?;
    list_open_directory_names(directory.as_raw_fd(), Path::new(rooted_path))
}

/// Remove an ordinary rooted directory only after proving it is empty.
pub fn remove_empty_rooted_directory(
    top_level: &Path,
    rooted_path: &str,
) -> Result<(), RecoveryError> {
    let entry = open_rooted_parent(top_level, rooted_path, false)?;
    match entry_type(entry.parent.as_raw_fd(), &entry.name, &entry.display)? {
        None => return Ok(()),
        Some(kind) if kind == libc::S_IFDIR => {}
        Some(libc::S_IFLNK) => {
            return Err(unsafe_path(
                &entry.display,
                "empty-directory rollback target is a symlink",
            ));
        }
        Some(_) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::RootSwitchConflict,
                format!(
                    "rollback target {} is not a directory",
                    entry.display.display()
                ),
            ));
        }
    }
    let names = list_rooted_directory_names(top_level, rooted_path)?;
    if !names.is_empty() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::RootSwitchConflict,
            format!(
                "refusing to remove non-empty rollback directory {}",
                entry.display.display()
            ),
        ));
    }
    unlinkat_dir_name(entry.parent.as_raw_fd(), &entry.name).map_err(|error| {
        map_path_error(&entry.display, "remove empty rooted directory", error, true)
    })?;
    fsync_fd(
        entry.parent.as_raw_fd(),
        &entry.display,
        "fsync rooted directory parent after rollback",
    )
}

pub fn remove_file(path: &Path) -> Result<(), RecoveryError> {
    let confined = ConfinedPath::parse(path)?;
    let (parent, name) = confined.open_parent(false)?;
    match entry_type(parent.as_raw_fd(), &name, path)? {
        None => return Ok(()),
        Some(kind) if kind == libc::S_IFLNK => {
            return Err(unsafe_path(
                path,
                "refusing to remove symlink as recovery record",
            ));
        }
        Some(kind) if kind != libc::S_IFREG => {
            return Err(unsafe_path(path, "recovery record is not a regular file"));
        }
        Some(_) => {}
    }
    unlinkat_name(parent.as_raw_fd(), &name)
        .map_err(|error| map_path_error(path, "remove recovery file", error, true))?;
    fsync_fd(parent.as_raw_fd(), path, "fsync recovery parent directory")
}

pub fn open_lock_file(path: &Path) -> Result<File, RecoveryError> {
    let confined = ConfinedPath::parse(path)?;
    let (parent, name) = confined.open_parent(true)?;
    reject_existing_non_regular_or_symlink(parent.as_raw_fd(), &name, path)?;
    let fd = open_file_at(
        parent.as_raw_fd(),
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
        false,
    )?;
    require_regular_file(fd.as_raw_fd(), path)?;
    Ok(File::from(fd))
}

pub fn list_directory_names(path: &Path) -> Result<Vec<OsString>, RecoveryError> {
    let confined = ConfinedPath::parse(path)?;
    let dir = match confined.open_directory(false) {
        Ok(dir) => dir,
        Err(error) if error_errno(&error) == Some(libc::ENOENT) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };

    let duplicate = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io_error(
            path,
            "duplicate recovery directory fd",
            std::io::Error::last_os_error(),
        ));
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(io_error(path, "open recovery directory stream", error));
    }

    let mut names = Vec::new();
    loop {
        errno_clear();
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let errno = errno_get();
            unsafe { libc::closedir(stream) };
            if errno != 0 {
                return Err(io_error(
                    path,
                    "read recovery directory",
                    std::io::Error::from_raw_os_error(errno),
                ));
            }
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(OsString::from_vec(bytes.to_vec()));
        }
    }
    Ok(names)
}

fn list_open_directory_names(
    directory_fd: RawFd,
    path: &Path,
) -> Result<Vec<OsString>, RecoveryError> {
    let duplicate = unsafe { libc::fcntl(directory_fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io_error(
            path,
            "duplicate rooted directory fd",
            std::io::Error::last_os_error(),
        ));
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(io_error(path, "open rooted directory stream", error));
    }
    let mut names = Vec::new();
    loop {
        errno_clear();
        let item = unsafe { libc::readdir(stream) };
        if item.is_null() {
            let errno = errno_get();
            unsafe { libc::closedir(stream) };
            if errno != 0 {
                return Err(io_error(
                    path,
                    "read rooted directory",
                    std::io::Error::from_raw_os_error(errno),
                ));
            }
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(OsString::from_vec(bytes.to_vec()));
        }
    }
    Ok(names)
}

/// Return the size of a regular file below `top_level` without reading its
/// contents. Every path component is resolved beneath the pinned root and
/// symlinks are rejected. Missing paths return `Ok(None)`.
pub fn rooted_regular_file_size(
    top_level: &Path,
    rooted_path: &str,
) -> Result<Option<u64>, RecoveryError> {
    let entry = open_rooted_parent(top_level, rooted_path, false)?;
    match entry_type(entry.parent.as_raw_fd(), &entry.name, &entry.display)? {
        None => Ok(None),
        Some(libc::S_IFLNK) => Err(unsafe_path(
            &entry.display,
            "rooted regular-file query encountered a symlink",
        )),
        Some(kind) if kind != libc::S_IFREG => Err(unsafe_path(
            &entry.display,
            "rooted regular-file query target is not a regular file",
        )),
        Some(_) => {
            let fd = open_file_at(
                entry.parent.as_raw_fd(),
                &entry.name,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
                false,
            )?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
            let rc = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
            if rc != 0 {
                return Err(io_error(
                    &entry.display,
                    "inspect rooted regular file",
                    std::io::Error::last_os_error(),
                ));
            }
            let stat = unsafe { stat.assume_init() };
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(unsafe_path(
                    &entry.display,
                    "opened rooted object is not a regular file",
                ));
            }
            Ok(Some(stat.st_size.max(0) as u64))
        }
    }
}

/// Read a regular file below a mounted filesystem top-level without
/// following symlinks in any component.
pub fn read_rooted_file(top_level: &Path, rooted_path: &str) -> Result<Vec<u8>, RecoveryError> {
    let entry = open_rooted_parent(top_level, rooted_path, false)?;
    let fd = open_file_at(
        entry.parent.as_raw_fd(),
        &entry.name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
        true,
    )?;
    require_regular_file(fd.as_raw_fd(), &entry.display)?;
    read_owned_fd(fd, &entry.display)
}

/// Remove one regular file below a mounted target root without following a
/// symlink in any component. Used only to roll back a file created by the
/// current boot-repair configuration transaction.
pub fn remove_rooted_file(top_level: &Path, rooted_path: &str) -> Result<(), RecoveryError> {
    let entry = open_rooted_parent(top_level, rooted_path, false)?;
    match entry_type(entry.parent.as_raw_fd(), &entry.name, &entry.display)? {
        None => return Ok(()),
        Some(libc::S_IFLNK) => {
            return Err(unsafe_path(
                &entry.display,
                "refusing to remove a symlink during configuration rollback",
            ));
        }
        Some(libc::S_IFREG) => {}
        Some(_) => {
            return Err(unsafe_path(
                &entry.display,
                "configuration rollback target is not a regular file",
            ));
        }
    }
    unlinkat_name(entry.parent.as_raw_fd(), &entry.name)
        .map_err(|error| map_path_error(&entry.display, "remove rooted file", error, false))?;
    fsync_fd(
        entry.parent.as_raw_fd(),
        &entry.display,
        "fsync rooted parent after configuration rollback",
    )
}

/// Create a btrfs snapshot through pinned source and destination
/// directory file descriptors. No pathname is resolved after the
/// destination parent has been opened, so replacing an intermediate
/// directory cannot redirect the snapshot outside `top_level`.
pub fn create_btrfs_snapshot(
    top_level: &Path,
    source_subvolume: &str,
    destination_subvolume: &str,
    read_only: bool,
) -> Result<(), RecoveryError> {
    let source = open_rooted_directory(top_level, source_subvolume, false)?;
    let destination = open_rooted_parent(top_level, destination_subvolume, true)?;

    match entry_type(
        destination.parent.as_raw_fd(),
        &destination.name,
        &destination.display,
    )? {
        None => {}
        Some(libc::S_IFLNK) => {
            return Err(unsafe_path(
                &destination.display,
                "snapshot destination is a symlink",
            ));
        }
        Some(_) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::RootSwitchConflict,
                format!(
                    "snapshot destination {} already exists",
                    destination.display.display()
                ),
            ));
        }
    }

    let name = destination.name.as_bytes();
    if name.is_empty() || name.len() > BTRFS_SUBVOL_NAME_MAX || name.contains(&0) {
        return Err(unsafe_path(
            &destination.display,
            "invalid btrfs snapshot destination name",
        ));
    }

    let mut arguments = BtrfsIoctlVolArgsV2 {
        fd: i64::from(source.as_raw_fd()),
        transid: 0,
        flags: if read_only { BTRFS_SUBVOL_RDONLY } else { 0 },
        unused: [0; 4],
        name: [0; BTRFS_SUBVOL_NAME_MAX + 1],
    };
    arguments.name[..name.len()].copy_from_slice(name);

    // libc exposes ioctl's request type differently on glibc and
    // musl. Issue the Linux syscall directly so the kernel ABI remains
    // one unsigned-long request value on every supported libc target.
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
        let mut recovery_error = RecoveryError::new(
            if error.raw_os_error() == Some(libc::EEXIST) {
                RecoveryErrorKind::RootSwitchConflict
            } else {
                RecoveryErrorKind::SyscallFailed
            },
            format!(
                "BTRFS_IOC_SNAP_CREATE_V2 {} -> {} failed: {error}",
                source_subvolume, destination_subvolume
            ),
        );
        recovery_error.errno = error.raw_os_error();
        return Err(recovery_error);
    }
    fsync_fd(
        destination.parent.as_raw_fd(),
        &destination.display,
        "fsync snapshot destination parent",
    )
}

/// Create an empty Btrfs subvolume below a pinned parent directory fd.
///
/// The kernel receives the destination parent fd and leaf name directly, so
/// a target-controlled symlink can never redirect this write outside the
/// mounted filesystem.
pub fn create_btrfs_subvolume(top_level: &Path, rooted_path: &str) -> Result<(), RecoveryError> {
    let destination = open_rooted_parent(top_level, rooted_path, false)?;
    match entry_type(
        destination.parent.as_raw_fd(),
        &destination.name,
        &destination.display,
    )? {
        None => {}
        Some(libc::S_IFLNK) => {
            return Err(unsafe_path(
                &destination.display,
                "subvolume destination is a symlink",
            ));
        }
        Some(_) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::RootSwitchConflict,
                format!(
                    "subvolume destination {} already exists",
                    destination.display.display()
                ),
            ));
        }
    }

    let name = destination.name.as_bytes();
    if name.is_empty() || name.len() > BTRFS_SUBVOL_NAME_MAX || name.contains(&0) {
        return Err(unsafe_path(
            &destination.display,
            "invalid btrfs subvolume destination name",
        ));
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
        let mut recovery_error = RecoveryError::new(
            if error.raw_os_error() == Some(libc::EEXIST) {
                RecoveryErrorKind::RootSwitchConflict
            } else {
                RecoveryErrorKind::SyscallFailed
            },
            format!(
                "BTRFS_IOC_SUBVOL_CREATE_V2 {} failed: {error}",
                destination.display.display()
            ),
        );
        recovery_error.errno = error.raw_os_error();
        return Err(recovery_error);
    }
    fsync_fd(
        destination.parent.as_raw_fd(),
        &destination.display,
        "fsync subvolume destination parent",
    )
}

/// Atomically exchange two entries below the same mounted btrfs
/// top-level using dirfd-relative `renameat2(RENAME_EXCHANGE)`.
/// Delete a Btrfs subvolume only after proving its directory is empty.
/// This is used solely to roll back subvolumes created by the current mount
/// repair transaction; it never deletes pre-existing or non-empty content.
pub fn delete_empty_btrfs_subvolume(
    top_level: &Path,
    rooted_path: &str,
) -> Result<(), RecoveryError> {
    let names = list_rooted_directory_names(top_level, rooted_path)?;
    if !names.is_empty() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::RootSwitchConflict,
            format!("refusing to delete non-empty Btrfs subvolume {rooted_path}"),
        ));
    }
    let destination = open_rooted_parent(top_level, rooted_path, false)?;
    require_directory_entry(&destination)?;
    let name = destination.name.as_bytes();
    if name.is_empty() || name.len() > BTRFS_PATH_NAME_MAX || name.contains(&0) {
        return Err(unsafe_path(
            &destination.display,
            "invalid Btrfs subvolume rollback name",
        ));
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
        let mut recovery_error = RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!(
                "BTRFS_IOC_SNAP_DESTROY {} failed: {error}",
                destination.display.display()
            ),
        );
        recovery_error.errno = error.raw_os_error();
        return Err(recovery_error);
    }
    fsync_fd(
        destination.parent.as_raw_fd(),
        &destination.display,
        "fsync Btrfs subvolume parent after rollback",
    )
}

pub fn exchange_rooted_paths(
    top_level: &Path,
    left: &str,
    right: &str,
) -> Result<(), RecoveryError> {
    let left = open_rooted_parent(top_level, left, false)?;
    let right = open_rooted_parent(top_level, right, false)?;
    require_directory_entry(&left)?;
    require_directory_entry(&right)?;
    exchange_open_entries(&left, &right)
}

fn exchange_open_entries(left: &RootedEntry, right: &RootedEntry) -> Result<(), RecoveryError> {
    let left_name = cstring(&left.name, &left.display)?;
    let right_name = cstring(&right.name, &right.display)?;
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
        let mut recovery_error = RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!(
                "renameat2(RENAME_EXCHANGE) {} <-> {} failed: {error}",
                left.display.display(),
                right.display.display()
            ),
        );
        recovery_error.errno = error.raw_os_error();
        return Err(recovery_error);
    }
    fsync_fd(
        left.parent.as_raw_fd(),
        &left.display,
        "fsync left exchange parent",
    )?;
    if left.parent.as_raw_fd() != right.parent.as_raw_fd() {
        fsync_fd(
            right.parent.as_raw_fd(),
            &right.display,
            "fsync right exchange parent",
        )?;
    }
    Ok(())
}

fn require_directory_entry(entry: &RootedEntry) -> Result<(), RecoveryError> {
    match entry_type(entry.parent.as_raw_fd(), &entry.name, &entry.display)? {
        Some(libc::S_IFDIR) => Ok(()),
        Some(libc::S_IFLNK) => Err(unsafe_path(
            &entry.display,
            "root exchange entry is a symlink",
        )),
        Some(_) => Err(RecoveryError::new(
            RecoveryErrorKind::RootSwitchConflict,
            format!(
                "root exchange entry {} is not a directory",
                entry.display.display()
            ),
        )),
        None => Err(RecoveryError::new(
            RecoveryErrorKind::RootSwitchConflict,
            format!("root exchange entry {} is missing", entry.display.display()),
        )),
    }
}

fn open_rooted_parent(
    top_level: &Path,
    rooted_path: &str,
    create_parent: bool,
) -> Result<RootedEntry, RecoveryError> {
    let components = rooted_components(rooted_path)?;
    let (name, parents) = components.split_last().ok_or_else(|| {
        unsafe_path(
            Path::new(rooted_path),
            "rooted operation requires a final entry name",
        )
    })?;
    let mut parent = open_top_level_directory(top_level)?;
    let mut display = top_level.to_path_buf();
    for component in parents {
        display.push(component);
        parent = open_directory_component(parent.as_raw_fd(), component, create_parent, 0o700)
            .map_err(|error| annotate_component(error, &display, component))?;
    }
    display.push(name);
    Ok(RootedEntry {
        parent,
        name: name.clone(),
        display,
    })
}

fn open_rooted_directory(
    top_level: &Path,
    rooted_path: &str,
    create: bool,
) -> Result<OwnedFd, RecoveryError> {
    let components = rooted_components(rooted_path)?;
    let mut directory = open_top_level_directory(top_level)?;
    let mut display = top_level.to_path_buf();
    for component in components {
        display.push(&component);
        directory = open_directory_component(directory.as_raw_fd(), &component, create, 0o700)
            .map_err(|error| annotate_component(error, &display, &component))?;
    }
    Ok(directory)
}

fn open_top_level_directory(top_level: &Path) -> Result<OwnedFd, RecoveryError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(top_level)
        .map_err(|error| {
            map_path_error(top_level, "open btrfs top-level directory", error, false)
        })?;
    Ok(file.into())
}

fn rooted_components(path: &str) -> Result<Vec<OsString>, RecoveryError> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(unsafe_path(path, "rooted path must be absolute"));
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                validate_component(part, path)?;
                components.push(part.to_os_string());
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(unsafe_path(path, "dot, parent, or prefix component"));
            }
        }
    }
    if components.is_empty() {
        return Err(unsafe_path(path, "top-level root itself is not an entry"));
    }
    Ok(components)
}

fn open_directory_component(
    parent: RawFd,
    name: &OsStr,
    create: bool,
    mode: u32,
) -> Result<OwnedFd, RecoveryError> {
    let c_name = cstring(name, Path::new(name))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: CONFINED_RESOLVE,
    };
    match openat2_raw(parent, &c_name, &how) {
        Ok(fd) => Ok(fd),
        Err(error) if create && error.raw_os_error() == Some(libc::ENOENT) => {
            let rc = unsafe { libc::mkdirat(parent, c_name.as_ptr(), mode as libc::mode_t) };
            if rc != 0 {
                let mkdir_error = std::io::Error::last_os_error();
                if mkdir_error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(map_path_error(
                        Path::new(name),
                        "create recovery directory",
                        mkdir_error,
                        true,
                    ));
                }
            }
            openat2_raw(parent, &c_name, &how).map_err(|error| {
                map_path_error(
                    Path::new(name),
                    "open newly-created recovery directory",
                    error,
                    true,
                )
            })
        }
        Err(error) => Err(map_path_error(
            Path::new(name),
            "open recovery directory component",
            error,
            true,
        )),
    }
}

fn open_file_at(
    parent: RawFd,
    name: &OsStr,
    flags: i32,
    mode: u32,
    not_found_is_transaction: bool,
) -> Result<OwnedFd, RecoveryError> {
    let c_name = cstring(name, Path::new(name))?;
    let how = OpenHow {
        flags: flags as u64,
        mode: mode as u64,
        resolve: CONFINED_RESOLVE,
    };
    openat2_raw(parent, &c_name, &how).map_err(|error| {
        map_path_error(
            Path::new(name),
            "open confined recovery file",
            error,
            not_found_is_transaction,
        )
    })
}

fn openat2_raw(dirfd: RawFd, path: &CString, how: &OpenHow) -> std::io::Result<OwnedFd> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) })
    }
}

fn create_temp_file(
    parent: RawFd,
    final_name: &OsStr,
    path: &Path,
    mode: u32,
) -> Result<(OsString, OwnedFd), RecoveryError> {
    for _ in 0..128 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut bytes = Vec::with_capacity(final_name.as_bytes().len() + 48);
        bytes.push(b'.');
        bytes.extend_from_slice(final_name.as_bytes());
        bytes.extend_from_slice(format!(".{}.{}.tmp", std::process::id(), sequence).as_bytes());
        let name = OsString::from_vec(bytes);
        match open_file_at(
            parent,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
            false,
        ) {
            Ok(fd) => {
                let rc = unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) };
                if rc != 0 {
                    let error = std::io::Error::last_os_error();
                    drop(fd);
                    let _ = unlinkat_name(parent, &name);
                    return Err(io_error(path, "chmod recovery temp file", error));
                }
                return Ok((name, fd));
            }
            Err(error) if error_errno(&error) == Some(libc::EEXIST) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(RecoveryError::new(
        RecoveryErrorKind::StateRecordCorrupt,
        format!("cannot allocate unique temp file for {}", path.display()),
    ))
}

fn reject_existing_non_regular_or_symlink(
    parent: RawFd,
    name: &OsStr,
    path: &Path,
) -> Result<(), RecoveryError> {
    match entry_type(parent, name, path)? {
        None | Some(libc::S_IFREG) => Ok(()),
        Some(libc::S_IFLNK) => Err(unsafe_path(path, "recovery file is a symlink")),
        Some(_) => Err(unsafe_path(path, "recovery file is not a regular file")),
    }
}

fn entry_type(
    parent: RawFd,
    name: &OsStr,
    path: &Path,
) -> Result<Option<libc::mode_t>, RecoveryError> {
    let c_name = cstring(name, path)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let rc = unsafe {
        libc::fstatat(
            parent,
            c_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(map_path_error(path, "inspect recovery file", error, true));
    }
    let stat = unsafe { stat.assume_init() };
    Ok(Some(stat.st_mode & libc::S_IFMT))
}

fn require_regular_file(fd: RawFd, path: &Path) -> Result<(), RecoveryError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(io_error(
            path,
            "inspect opened recovery file",
            std::io::Error::last_os_error(),
        ));
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(unsafe_path(
            path,
            "opened recovery object is not a regular file",
        ));
    }
    Ok(())
}

fn read_owned_fd(fd: OwnedFd, path: &Path) -> Result<Vec<u8>, RecoveryError> {
    let file = File::from(fd);
    let mut bytes = Vec::new();
    file.take(MAX_RECOVERY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, "read recovery file", error))?;
    if bytes.len() as u64 > MAX_RECOVERY_FILE_BYTES {
        return Err(RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            format!(
                "recovery file {} exceeds {} bytes",
                path.display(),
                MAX_RECOVERY_FILE_BYTES
            ),
        ));
    }
    Ok(bytes)
}

fn unlinkat_name(parent: RawFd, name: &OsStr) -> std::io::Result<()> {
    let c_name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let rc = unsafe { libc::unlinkat(parent, c_name.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unlinkat_dir_name(parent: RawFd, name: &OsStr) -> std::io::Result<()> {
    let c_name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let rc = unsafe { libc::unlinkat(parent, c_name.as_ptr(), libc::AT_REMOVEDIR) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn fsync_fd(fd: RawFd, path: &Path, operation: &str) -> Result<(), RecoveryError> {
    let rc = unsafe { libc::fsync(fd) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io_error(path, operation, std::io::Error::last_os_error()))
    }
}

fn cstring(value: &OsStr, path: &Path) -> Result<CString, RecoveryError> {
    CString::new(value.as_bytes()).map_err(|_| unsafe_path(path, "path component contains NUL"))
}

fn validate_component(component: &OsStr, path: &Path) -> Result<(), RecoveryError> {
    let bytes = component.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&0) {
        return Err(unsafe_path(path, "invalid recovery path component"));
    }
    Ok(())
}

fn annotate_component(mut error: RecoveryError, path: &Path, component: &OsStr) -> RecoveryError {
    error.message = format!(
        "{} while resolving component {:?} of {}",
        error.message,
        component,
        path.display()
    )
    .into_boxed_str();
    error
}

fn map_path_error(
    path: &Path,
    operation: &str,
    error: std::io::Error,
    not_found_is_transaction: bool,
) -> RecoveryError {
    let errno = error.raw_os_error();
    let kind = match errno {
        Some(libc::ELOOP | libc::EXDEV | libc::ENOTDIR) => RecoveryErrorKind::UnsafeRecoveryPath,
        Some(libc::ENOSYS) => RecoveryErrorKind::UnsafeRecoveryPath,
        Some(libc::ENOENT) if not_found_is_transaction => RecoveryErrorKind::TransactionNotFound,
        _ => RecoveryErrorKind::StateRecordCorrupt,
    };
    let mut recovery_error = RecoveryError::new(
        kind,
        format!("{operation} {} failed: {error}", path.display()),
    );
    recovery_error.errno = errno;
    recovery_error
}

fn io_error(path: &Path, operation: &str, error: std::io::Error) -> RecoveryError {
    let mut recovery_error = RecoveryError::new(
        RecoveryErrorKind::StateRecordCorrupt,
        format!("{operation} {} failed: {error}", path.display()),
    );
    recovery_error.errno = error.raw_os_error();
    recovery_error
}

fn unsafe_path(path: &Path, reason: &str) -> RecoveryError {
    RecoveryError::new(
        RecoveryErrorKind::UnsafeRecoveryPath,
        format!("unsafe recovery path {}: {reason}", path.display()),
    )
}

fn error_errno(error: &RecoveryError) -> Option<i32> {
    error.errno
}

#[cfg(target_env = "gnu")]
fn errno_clear() {
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(target_env = "gnu")]
fn errno_get() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_env = "musl")]
fn errno_clear() {
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(target_env = "musl")]
fn errno_get() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
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
        assert_eq!(error.kind, RecoveryErrorKind::UnsafeRecoveryPath);
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
        assert_eq!(error.kind, RecoveryErrorKind::UnsafeRecoveryPath);
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
        assert_eq!(error.kind, RecoveryErrorKind::RootSwitchConflict);
        assert_eq!(std::fs::read(top.join("nonempty/data")).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(top);
    }

    #[test]
    fn btrfs_subvolume_rollback_refuses_nonempty_before_ioctl() {
        let top = scratch("nonempty-subvol-rollback");
        std::fs::create_dir_all(top.join("candidate")).unwrap();
        std::fs::write(top.join("candidate/data"), b"keep").unwrap();

        let error = delete_empty_btrfs_subvolume(&top, "/candidate").unwrap_err();
        assert_eq!(error.kind, RecoveryErrorKind::RootSwitchConflict);
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
        assert_eq!(error.kind, RecoveryErrorKind::UnsafeRecoveryPath);
        assert!(!outside.join("fstab").exists());

        let _ = std::fs::remove_dir_all(top);
        let _ = std::fs::remove_dir_all(outside);
    }
}
