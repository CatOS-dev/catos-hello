//! Target root abstraction (migrated from `shared::system_root`).
//!
//! All target-side paths must be constructed via [`SystemRoot::join`] so a
//! `--root /mnt` never accidentally reads the host `/etc`.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::shared::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRoot {
    raw: String,
    canonical: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootError {
    Relative(String),
    DoesNotExist(String),
    NotADirectory(String),
    PermissionDenied(String),
    EscapeAttempt(String),
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
            RootError::EscapeAttempt(p) => write!(
                f,
                "sub-path {p:?} would escape the target root (contains .. or absolute components)"
            ),
        }
    }
}

impl std::error::Error for RootError {}

impl SystemRoot {
    pub fn from_user_input(input: &str) -> Result<Self, Error> {
        let path = Path::new(input);
        if !path.is_absolute() {
            return Err(Error::InvalidRoot {
                path: PathBuf::from(input),
                reason: "path must be absolute".to_string(),
            });
        }
        match std::fs::canonicalize(path) {
            Ok(canonical) if canonical.is_dir() => Ok(SystemRoot {
                raw: input.to_string(),
                canonical,
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

    pub fn from_absolute_unchecked(input: &str) -> Result<Self, RootError> {
        if !Path::new(input).is_absolute() {
            return Err(RootError::Relative(input.to_string()));
        }
        Ok(SystemRoot {
            raw: input.to_string(),
            canonical: normalise_absolute_root(input),
        })
    }

    pub fn join(&self, rel: &str) -> PathBuf {
        self.try_join(rel)
            .expect("SystemRoot::join received escaping path; use try_join for user input")
    }

    pub fn try_join(&self, rel: &str) -> Result<PathBuf, RootError> {
        validate_relative_path(rel)?;
        let rel_trimmed = rel.trim_start_matches('/');
        let base = self.canonical.to_string_lossy();
        let base = base.trim_end_matches('/');
        let joined = if rel_trimmed.is_empty() {
            PathBuf::from(if base.is_empty() { "/" } else { base })
        } else if base.is_empty() {
            PathBuf::from(format!("/{rel_trimmed}"))
        } else {
            PathBuf::from(format!("{base}/{rel_trimmed}"))
        };
        Ok(joined)
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn as_path(&self) -> &Path {
        &self.canonical
    }

    pub fn canonical_path(&self) -> &Path {
        &self.canonical
    }
}

impl std::fmt::Display for SystemRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

fn normalise_absolute_root(input: &str) -> PathBuf {
    if input.chars().all(|c| c == '/') {
        PathBuf::from("/")
    } else {
        PathBuf::from(input.trim_end_matches('/'))
    }
}

fn validate_relative_path(rel: &str) -> Result<(), RootError> {
    use std::path::Component;

    if rel.is_empty() {
        return Ok(());
    }

    let parsed = Path::new(rel);
    let mut components = parsed.components();

    if matches!(components.clone().next(), Some(Component::RootDir)) {
        components.next();
    }

    for comp in components {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(RootError::EscapeAttempt(rel.to_string()));
            }
        }
    }
    Ok(())
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
    fn try_join_rejects_parent_dir() {
        let r = root("/mnt");
        let err = r.try_join("../../etc/passwd").unwrap_err();
        assert!(matches!(err, RootError::EscapeAttempt(_)));
    }

    #[test]
    fn try_join_rejects_parent_dir_in_middle() {
        let r = root("/mnt");
        let err = r.try_join("etc/../etc/passwd").unwrap_err();
        assert!(matches!(err, RootError::EscapeAttempt(_)));
    }

    #[test]
    fn rejects_relative_path() {
        let err = SystemRoot::from_absolute_unchecked("mnt").unwrap_err();
        assert!(matches!(err, RootError::Relative(_)));
    }
}
