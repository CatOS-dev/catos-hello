//! Rooted-path construction and escape validation.
//!
//! Pure functions: no I/O, no writes. Mirrors the safety contract of the
//! legacy `SystemRoot::try_join` validator (re-implemented locally so
//! `target::path` does not depend on `shared::system_root`).

use std::path::{Component, Path};

/// Error returned by [`validate_relative`] when a sub-path would escape
/// the controlled target root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The sub-path contains a `..`, an embedded absolute component, or a
    /// platform prefix that would escape the target root.
    Escape(String),
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::Escape(p) => write!(
                f,
                "sub-path {p:?} would escape the target root (contains .. or absolute components)"
            ),
        }
    }
}

impl std::error::Error for PathError {}

/// Validate that `rel` is a safe sub-path under a target root: no `..`,
/// no embedded absolute path, no platform prefix. A single leading slash
/// is allowed (the codebase convention that both `etc/...` and `/etc/...`
/// work).
pub fn validate_relative(rel: &str) -> Result<(), PathError> {
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
                return Err(PathError::Escape(rel.to_string()));
            }
        }
    }
    Ok(())
}

/// Join `root` and `rel`, validating `rel` first. Leading slashes on
/// `rel` are stripped.
pub fn join_rooted(root: &Path, rel: &str) -> Result<std::path::PathBuf, PathError> {
    validate_relative(rel)?;
    let rel_trimmed = rel.trim_start_matches('/');
    let base = root.to_string_lossy();
    let base = base.trim_end_matches('/');
    Ok(if rel_trimmed.is_empty() {
        if base.is_empty() {
            std::path::PathBuf::from("/")
        } else {
            std::path::PathBuf::from(base)
        }
    } else if base.is_empty() {
        std::path::PathBuf::from(format!("/{rel_trimmed}"))
    } else {
        std::path::PathBuf::from(format!("{base}/{rel_trimmed}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_dir() {
        assert!(validate_relative("../etc/passwd").is_err());
    }

    #[test]
    fn rejects_parent_dir_in_middle() {
        assert!(validate_relative("etc/../etc/passwd").is_err());
    }

    #[test]
    fn accepts_normal_relative() {
        validate_relative("etc/os-release").unwrap();
        validate_relative("/etc/os-release").unwrap();
        validate_relative("").unwrap();
    }
}
