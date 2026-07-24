//! Filesystem probe abstraction. Real implementation reads via `std::fs`;
//! fixture implementation reads from an in-memory map so tests do not
//! depend on the host's `/proc`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::FsError;

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
    fn metadata(&self, path: &Path) -> Result<MetaData, FsError>;
    fn read_to_string(&self, path: &Path) -> Result<String, FsError>;
    fn read_link(&self, path: &Path) -> Result<PathBuf, FsError>;
    /// List immediate child names of a directory (not recursive, no `.`/`..`).
    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>, FsError>;

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
        // Resolve at most a few symlink hops to keep tests predictable.
        let mut current = path.to_path_buf();
        for _ in 0..8 {
            if let Some(target) = self.symlinks.get(&current) {
                current = target.clone();
                continue;
            }
            break;
        }
        Some(current)
    }
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

    fn metadata(&self, path: &Path) -> Result<MetaData, FsError> {
        let resolved = self.resolve(path).ok_or(FsError::NotFound)?;
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
