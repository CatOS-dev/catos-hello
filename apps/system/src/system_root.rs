//! Target root abstraction. All target-side paths must be constructed via
//! [`SystemRoot::join`] so a `--root /mnt` never accidentally reads the
//! host `/etc`. This module is the single chokepoint for that.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::Error;

/// A validated, absolute target root directory.
///
/// Construction verifies the path exists and is a directory. The original
/// string form is preserved for stable display in JSON (`targetRoot` field)
/// while joins normalise trailing slashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRoot {
    raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootError {
    /// Path was not absolute.
    Relative(String),
    /// Path did not exist.
    DoesNotExist(String),
    /// Path existed but was not a directory.
    NotADirectory(String),
    /// Path existed but could not be stat'd due to permissions.
    PermissionDenied(String),
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RootError::Relative(p) => {
                write!(f, "target root must be absolute, got {p:?}")
            }
            RootError::DoesNotExist(p) => write!(f, "target root {p:?} does not exist"),
            RootError::NotADirectory(p) => write!(f, "target root {p:?} is not a directory"),
            RootError::PermissionDenied(p) => {
                write!(f, "permission denied stat'ing target root {p:?}")
            }
        }
    }
}

impl std::error::Error for RootError {}

impl SystemRoot {
    /// Build from a user-supplied string. Rejects relative paths and
    /// non-existent / non-directory entries.
    pub fn from_user_input(input: &str) -> Result<Self, Error> {
        let path = Path::new(input);
        if !path.is_absolute() {
            return Err(Error::InvalidRoot {
                path: PathBuf::from(input),
                reason: "path must be absolute".to_string(),
            });
        }
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_dir() => Ok(SystemRoot {
                raw: input.to_string(),
            }),
            Ok(_) => Err(Error::InvalidRoot {
                path: PathBuf::from(input),
                reason: "path is not a directory".to_string(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(Error::PermissionDenied {
                    path: PathBuf::from(input),
                    detail: "cannot stat target root".to_string(),
                })
            }
            Err(_) => Err(Error::InvalidRoot {
                path: PathBuf::from(input),
                reason: "target root does not exist or is unreachable".to_string(),
            }),
        }
    }

    /// Constructor for tests / probes that have already validated the path
    /// via a fixture (which may not be backed by a real filesystem). The
    /// path is still required to be absolute.
    pub fn from_absolute_unchecked(input: &str) -> Result<Self, RootError> {
        if !Path::new(input).is_absolute() {
            return Err(RootError::Relative(input.to_string()));
        }
        Ok(SystemRoot {
            raw: input.to_string(),
        })
    }

    /// Join a sub-path under this root. Leading slashes on `rel` are
    /// stripped, so both `"etc/os-release"` and `"/etc/os-release"` give the
    /// same result. The root form is normalised so `/` and `/mnt/` both
    /// produce clean results without double slashes.
    pub fn join(&self, rel: &str) -> PathBuf {
        let rel_trimmed = rel.trim_start_matches('/');
        let base = self.raw.trim_end_matches('/');
        if rel_trimmed.is_empty() {
            return PathBuf::from(if base.is_empty() { "/" } else { base });
        }
        if base.is_empty() {
            // raw was "/" (or "///") -> avoid "//" prefix.
            PathBuf::from(format!("/{rel_trimmed}"))
        } else {
            PathBuf::from(format!("{base}/{rel_trimmed}"))
        }
    }

    /// Original string form, for stable JSON display.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn as_path(&self) -> &Path {
        Path::new(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(input: &str) -> SystemRoot {
        SystemRoot::from_absolute_unchecked(input).expect("absolute path")
    }

    #[test]
    fn join_handles_root_slash() {
        let r = root("/");
        assert_eq!(r.join("etc/os-release"), PathBuf::from("/etc/os-release"));
        assert_eq!(r.join("/etc/os-release"), PathBuf::from("/etc/os-release"));
        assert_eq!(r.join(""), PathBuf::from("/"));
    }

    #[test]
    fn join_handles_mnt_trailing_slash() {
        let r = root("/mnt/");
        assert_eq!(
            r.join("etc/os-release"),
            PathBuf::from("/mnt/etc/os-release")
        );
        assert_eq!(r.join(""), PathBuf::from("/mnt"));
    }

    #[test]
    fn rejects_relative_path() {
        let err = SystemRoot::from_absolute_unchecked("mnt").unwrap_err();
        assert!(matches!(err, RootError::Relative(_)));
    }

    #[test]
    fn rejects_empty() {
        let err = SystemRoot::from_absolute_unchecked("").unwrap_err();
        assert!(matches!(err, RootError::Relative(_)));
    }

    #[test]
    fn display_preserves_user_input() {
        let r = root("/mnt/");
        assert_eq!(r.as_str(), "/mnt/");
    }

    #[test]
    fn double_root_normalised() {
        // Joining should never produce // even with weird trailing slashes.
        let r = root("////");
        assert_eq!(r.join("etc"), PathBuf::from("/etc"));
    }
}
