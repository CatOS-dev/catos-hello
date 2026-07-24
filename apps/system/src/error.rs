//! Centralised error model and stable process exit codes.
//!
//! No `unwrap`/`expect`/`panic!` in expected error paths. Real invariant
//! violations use `assume!` (defined here) so they are explicit and greppable.

use std::fmt;
use std::path::PathBuf;

/// Stable exit codes. Numbers are part of the public CLI contract and must
/// not be renumbered without a schema-version bump.
pub mod exit_code {
    pub const SUCCESS: i32 = 0;
    pub const ARG_ERROR: i32 = 2;
    pub const INVALID_ROOT: i32 = 3;
    pub const PERMISSION_DENIED: i32 = 4;
    pub const PROBE_FAILED: i32 = 5;
    pub const SERIALIZE_FAILED: i32 = 6;
}

/// Top-level error surfaced by the library. Each variant maps to a stable
/// exit code via [`Error::exit_code`].
#[derive(Debug)]
pub enum Error {
    /// CLI argument error (unknown flag, missing value, malformed input).
    InvalidArgument { message: String },
    /// `--root` target does not exist or is not a directory.
    InvalidRoot { path: PathBuf, reason: String },
    /// Permission denied while reading a critical path.
    PermissionDenied { path: PathBuf, detail: String },
    /// Probe layer could not gather enough information to produce a report.
    ProbeFailed { detail: String },
    /// JSON serialisation failed.
    SerializeFailed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArgument { message } => write!(f, "argument error: {message}"),
            Error::InvalidRoot { path, reason } => {
                write!(f, "invalid target root {path:?}: {reason}")
            }
            Error::PermissionDenied { path, detail } => {
                write!(f, "permission denied reading {path:?}: {detail}")
            }
            Error::ProbeFailed { detail } => write!(f, "probe failed: {detail}"),
            Error::SerializeFailed(msg) => write!(f, "serialisation failed: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::InvalidArgument { .. } => exit_code::ARG_ERROR,
            Error::InvalidRoot { .. } => exit_code::INVALID_ROOT,
            Error::PermissionDenied { .. } => exit_code::PERMISSION_DENIED,
            Error::ProbeFailed { .. } => exit_code::PROBE_FAILED,
            Error::SerializeFailed(_) => exit_code::SERIALIZE_FAILED,
        }
    }
}

/// Filesystem-probe level error. Designed to be transformed into `Evidence`
/// or `Warning` rather than bubbling up as a hard failure.
#[derive(Debug, Clone)]
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
            FsError::OutsideRoot(path) => {
                write!(f, "resolved path escapes target root: {path}")
            }
            FsError::Io(msg) => write!(f, "io error: {msg}"),
        }
    }
}
