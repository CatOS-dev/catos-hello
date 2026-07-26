//! Filesystem probe abstraction. Real implementation reads via `std::fs`;
//! fixture implementation reads from an in-memory map so tests do not
//! depend on the host's `/proc`.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::shared::error::FsError;

/// Minimal stat-like info needed by probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaData {
    pub ino: u64,
    pub dev: u64,
    /// Full st_mode (permission bits + file type).
    pub mode: u32,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
}

impl MetaData {
    /// True if any executable bit is set.
    pub fn is_executable(&self) -> bool {
        self.mode & 0o111 != 0
    }
}

/// Filesystem abstraction used by every probe. Implementations:
/// - [`RealFilesystem`]: reads the running system via `std::fs`.
/// - [`FixtureFilesystem`]: in-memory map for tests.
pub trait FilesystemProbe {
    fn exists(&self, path: &Path) -> bool;
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FsError>;
    fn metadata(&self, path: &Path) -> Result<MetaData, FsError>;
    fn read_to_string(&self, path: &Path) -> Result<String, FsError>;
    fn read_link(&self, path: &Path) -> Result<PathBuf, FsError>;
    /// List immediate child names of a directory (not recursive, no `.`/`..`).
    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>, FsError>;

    fn rooted_metadata(&self, root: &Path, rel: &Path) -> Result<MetaData, FsError> {
        let resolved = resolve_beneath(self, root, rel)?;
        self.metadata(&resolved)
    }

    fn rooted_read_to_string(&self, root: &Path, rel: &Path) -> Result<String, FsError> {
        let resolved = resolve_beneath(self, root, rel)?;
        self.read_to_string(&resolved)
    }

    /// Convenience wrapper that returns false instead of an error.
    fn is_dir(&self, path: &Path) -> bool {
        matches!(self.metadata(path), Ok(m) if m.is_dir)
    }
    /// Convenience wrapper that returns false instead of an error.
    fn is_file(&self, path: &Path) -> bool {
        matches!(self.metadata(path), Ok(m) if m.is_file)
    }
}

/// Real filesystem. All methods are read-only.
pub struct RealFilesystem;

impl FilesystemProbe for RealFilesystem {
    fn exists(&self, path: &Path) -> bool {
        // symlink_metadata so a broken symlink still counts as "exists".
        std::fs::symlink_metadata(path).is_ok()
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FsError> {
        std::fs::canonicalize(path).map_err(|e| classify_io(path, &e))
    }

    fn metadata(&self, path: &Path) -> Result<MetaData, FsError> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).map_err(|e| classify_io(path, &e))?;
        Ok(MetaData {
            ino: meta.ino(),
            dev: meta.dev(),
            mode: meta.mode(),
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            is_symlink: meta.file_type().is_symlink(),
        })
    }

    fn read_to_string(&self, path: &Path) -> Result<String, FsError> {
        let bytes = std::fs::read(path).map_err(|e| classify_io(path, &e))?;
        String::from_utf8(bytes).map_err(|_| FsError::NotUtf8)
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf, FsError> {
        std::fs::read_link(path).map_err(|e| classify_io(path, &e))
    }

    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>, FsError> {
        let rd = std::fs::read_dir(path).map_err(|e| classify_io(path, &e))?;
        let mut names = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| FsError::Io(e.to_string()))?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    fn rooted_metadata(&self, root: &Path, rel: &Path) -> Result<MetaData, FsError> {
        use std::os::unix::fs::MetadataExt;

        let file = openat2_in_root(root, rel, O_PATH | O_CLOEXEC)?;
        let meta = file.metadata().map_err(|e| classify_io(rel, &e))?;
        Ok(MetaData {
            ino: meta.ino(),
            dev: meta.dev(),
            mode: meta.mode(),
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            is_symlink: meta.file_type().is_symlink(),
        })
    }

    fn rooted_read_to_string(&self, root: &Path, rel: &Path) -> Result<String, FsError> {
        let mut file = openat2_in_root(root, rel, O_CLOEXEC)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| classify_io(rel, &e))?;
        String::from_utf8(bytes).map_err(|_| FsError::NotUtf8)
    }
}

fn resolve_beneath(
    fs: &(impl FilesystemProbe + ?Sized),
    root: &Path,
    rel: &Path,
) -> Result<PathBuf, FsError> {
    let canonical_root = fs.canonicalize(root)?;
    let candidate = root.join(rel);
    let resolved = fs.canonicalize(&candidate)?;
    if resolved == canonical_root || resolved.starts_with(&canonical_root) {
        Ok(resolved)
    } else {
        Err(FsError::OutsideRoot(format!(
            "{} -> {}",
            candidate.display(),
            resolved.display()
        )))
    }
}

#[cfg(target_os = "linux")]
const SYS_OPENAT2: std::os::raw::c_long = 437;
const O_CLOEXEC: u64 = 0x80000;
const O_PATH: u64 = 0x200000;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn openat2_in_root(root: &Path, rel: &Path, flags: u64) -> Result<std::fs::File, FsError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let root_file = std::fs::File::open(root).map_err(|e| classify_io(root, &e))?;
    let rel_bytes = rel.strip_prefix("/").unwrap_or(rel).as_os_str().as_bytes();
    let rel_c = CString::new(rel_bytes)
        .map_err(|_| FsError::Io(format!("path contains NUL: {}", rel.display())))?;
    let how = OpenHow {
        flags,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };

    extern "C" {
        fn syscall(number: std::os::raw::c_long, ...) -> std::os::raw::c_long;
    }

    let fd = unsafe {
        syscall(
            SYS_OPENAT2,
            root_file.as_raw_fd(),
            rel_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(38) {
            return Err(FsError::Io(
                "openat2 is unavailable; refusing unconstrained target-root access".to_string(),
            ));
        }
        return Err(classify_io(rel, &error));
    }

    Ok(unsafe { std::fs::File::from_raw_fd(fd as i32) })
}

fn classify_io(path: &Path, e: &std::io::Error) -> FsError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => FsError::NotFound,
        ErrorKind::PermissionDenied => FsError::PermissionDenied,
        _ => FsError::Io(format!("{}: {}", path.display(), e)),
    }
}

/// In-memory filesystem for tests. Paths are stored absolute and canonical
/// (no `..` resolution is performed: tests are expected to use absolute
/// paths without `..`).
#[derive(Debug, Default, Clone)]
pub struct FixtureFilesystem {
    /// Regular file contents keyed by canonical path.
    files: HashMap<PathBuf, Vec<u8>>,
    /// Empty-marker directories (existence check; contents discovered via
    /// child paths).
    dirs: HashMap<PathBuf, FixtureDir>,
    /// Symbolic links.
    symlinks: HashMap<PathBuf, PathBuf>,
    /// Explicit metadata overrides keyed by path. Missing entries get
    /// synthesised defaults (so tests don't need to mock inode numbers).
    metas: HashMap<PathBuf, MetaData>,
}

#[derive(Debug, Default, Clone)]
struct FixtureDir {
    /// Whether to behave as if non-readable (causes PermissionDenied).
    unreadable: bool,
}

impl FixtureFilesystem {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a regular file with string contents.
    pub fn file(mut self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) -> Self {
        let p = path.into();
        self.files.insert(p.clone(), contents.into());
        self.metas.entry(p).or_insert(default_file_meta());
        self
    }

    /// Insert an empty directory.
    pub fn dir(mut self, path: impl Into<PathBuf>) -> Self {
        let p = path.into();
        self.dirs.insert(p, FixtureDir::default());
        self
    }

    /// Insert an unreadable directory (causes `PermissionDenied` on read_dir
    /// and read_to_string of its children).
    pub fn unreadable_dir(mut self, path: impl Into<PathBuf>) -> Self {
        let p = path.into();
        self.dirs.insert(p, FixtureDir { unreadable: true });
        self
    }

    /// Insert a symbolic link.
    pub fn symlink(mut self, src: impl Into<PathBuf>, dst: impl Into<PathBuf>) -> Self {
        self.symlinks.insert(src.into(), dst.into());
        self
    }

    /// Override metadata for a specific path.
    pub fn with_meta(mut self, path: impl Into<PathBuf>, meta: MetaData) -> Self {
        self.metas.insert(path.into(), meta);
        self
    }

    fn resolve(&self, path: &Path) -> Option<PathBuf> {
        use std::path::Component;

        if !path.is_absolute() {
            return None;
        }

        let mut current = PathBuf::from("/");
        let mut hops = 0;
        for component in path.components() {
            match component {
                Component::RootDir => current = PathBuf::from("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    current.pop();
                    if current.as_os_str().is_empty() {
                        current.push("/");
                    }
                }
                Component::Normal(part) => {
                    current.push(part);
                    while let Some(target) = self.symlinks.get(&current) {
                        hops += 1;
                        if hops > 16 {
                            return None;
                        }
                        current = if target.is_absolute() {
                            target.clone()
                        } else {
                            current.parent().unwrap_or(Path::new("/")).join(target)
                        };
                        current = lexical_normalise(&current);
                    }
                }
                Component::Prefix(_) => return None,
            }
        }
        Some(lexical_normalise(&current))
    }
}

fn lexical_normalise(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => out = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
                if out.as_os_str().is_empty() {
                    out.push("/");
                }
            }
            Component::Normal(part) => out.push(part),
            Component::Prefix(_) => {}
        }
    }
    out
}

fn default_file_meta() -> MetaData {
    MetaData {
        ino: 0,
        dev: 0,
        mode: 0o644,
        is_dir: false,
        is_file: true,
        is_symlink: false,
    }
}

impl FilesystemProbe for FixtureFilesystem {
    fn exists(&self, path: &Path) -> bool {
        if let Some(resolved) = self.resolve(path) {
            self.files.contains_key(&resolved)
                || self.dirs.contains_key(&resolved)
                || self.symlinks.contains_key(&resolved)
        } else {
            false
        }
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FsError> {
        let resolved = self.resolve(path).ok_or(FsError::NotFound)?;
        let mut cursor = resolved.parent();
        while let Some(parent) = cursor {
            if self.dirs.get(parent).is_some_and(|dir| dir.unreadable) {
                return Err(FsError::PermissionDenied);
            }
            cursor = parent.parent();
        }
        if self.files.contains_key(&resolved) || self.dirs.contains_key(&resolved) {
            Ok(resolved)
        } else {
            Err(FsError::NotFound)
        }
    }

    fn metadata(&self, path: &Path) -> Result<MetaData, FsError> {
        let resolved = self.resolve(path).ok_or(FsError::NotFound)?;
        // Refuse to stat anything under an unreadable directory, mirroring
        // real filesystem behaviour where lack of execute permission on a
        // directory blocks metadata lookup of its children.
        let mut cursor = resolved.parent();
        while let Some(parent) = cursor {
            if let Some(d) = self.dirs.get(parent) {
                if d.unreadable {
                    return Err(FsError::PermissionDenied);
                }
            }
            cursor = parent.parent();
        }
        if let Some(meta) = self.metas.get(&resolved) {
            return Ok(*meta);
        }
        if self.files.contains_key(&resolved) {
            return Ok(default_file_meta());
        }
        if self.dirs.contains_key(&resolved) {
            return Ok(MetaData {
                ino: 0,
                dev: 0,
                mode: 0o755,
                is_dir: true,
                is_file: false,
                is_symlink: false,
            });
        }
        if self.symlinks.contains_key(path) {
            return Ok(MetaData {
                ino: 0,
                dev: 0,
                mode: 0o777,
                is_dir: false,
                is_file: false,
                is_symlink: true,
            });
        }
        Err(FsError::NotFound)
    }

    fn read_to_string(&self, path: &Path) -> Result<String, FsError> {
        let resolved = self.resolve(path).ok_or(FsError::NotFound)?;
        // Refuse to read files under an unreadable directory.
        if let Some(parent) = resolved.parent() {
            if let Some(d) = self.dirs.get(parent) {
                if d.unreadable {
                    return Err(FsError::PermissionDenied);
                }
            }
        }
        let bytes = self.files.get(&resolved).ok_or(FsError::NotFound)?;
        String::from_utf8(bytes.clone()).map_err(|_| FsError::NotUtf8)
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf, FsError> {
        self.symlinks.get(path).cloned().ok_or(FsError::NotFound)
    }

    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>, FsError> {
        let resolved = self.resolve(path).ok_or(FsError::NotFound)?;
        if let Some(d) = self.dirs.get(&resolved) {
            if d.unreadable {
                return Err(FsError::PermissionDenied);
            }
        }
        let prefix = resolved.as_path();
        let mut names: Vec<String> = Vec::new();
        // Same logic for files / dirs / symlinks; write it out three times to
        // keep the closure monomorphic and the type checker happy.
        for k in self.files.keys() {
            if let Ok(rest) = k.strip_prefix(prefix) {
                if rest.components().count() == 1 {
                    names.push(rest.to_string_lossy().into_owned());
                }
            }
        }
        for k in self.dirs.keys() {
            if let Ok(rest) = k.strip_prefix(prefix) {
                if rest.components().count() == 1 {
                    names.push(rest.to_string_lossy().into_owned());
                }
            }
        }
        for k in self.symlinks.keys() {
            if let Ok(rest) = k.strip_prefix(prefix) {
                if rest.components().count() == 1 {
                    names.push(rest.to_string_lossy().into_owned());
                }
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}
