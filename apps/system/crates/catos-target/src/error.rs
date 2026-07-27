//! Target-owned filesystem and rooted-path errors.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    PermissionDenied,
    NotUtf8,
    OutsideRoot(String),
    Io(String),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::NotFound => write!(f, "not found"),
            FsError::PermissionDenied => write!(f, "permission denied"),
            FsError::NotUtf8 => write!(f, "content not utf-8"),
            FsError::OutsideRoot(path) => write!(f, "resolved path escapes target root: {path}"),
            FsError::Io(message) => write!(f, "io error: {message}"),
        }
    }
}

impl std::error::Error for FsError {}
