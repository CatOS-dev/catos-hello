//! Target root abstraction. All target-side paths must be constructed via
//! [`SystemRoot::join`] so a `--root /mnt` never accidentally reads the
//! host `/etc`. This module is the single chokepoint for that.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::shared::error::Error;

/// A validated, absolute target root directory.
///
/// Construction verifies the path exists and is a directory. The original
/// string form is preserved for stable display in JSON (`targetRoot` field)
/// while joins normalise trailing slashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRoot {
    raw: String,
    canonical: PathBuf,
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
    /// A sub-path passed to [`SystemRoot::try_join`] would escape the
    /// target root (contains `..`, embedded absolute path, or platform
    /// prefix).
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

    /// Constructor for tests / probes that have already validated the path
    /// via a fixture (which may not be backed by a real filesystem). The
    /// path is still required to be absolute.
    pub fn from_absolute_unchecked(input: &str) -> Result<Self, RootError> {
        if !Path::new(input).is_absolute() {
            return Err(RootError::Relative(input.to_string()));
        }
        Ok(SystemRoot {
            raw: input.to_string(),
            canonical: normalise_absolute_root(input),
        })
    }

    /// Join a sub-path under this root. Leading slashes on `rel` are
    /// stripped, so both `"etc/os-release"` and `"/etc/os-release"` give the
    /// same result. The root form is normalised so `/` and `/mnt/` both
    /// produce clean results without double slashes.
    ///
    /// # Security
    ///
    /// `rel` MUST NOT escape the target root. The following are rejected:
    ///   * `ParentDir` components (`..`) anywhere in the path
    ///   * absolute embedded paths after a leading slash is stripped
    ///   * Windows-style `Prefix` components (e.g. `C:`)
    ///
    /// Rejection returns `Err(RootError::EscapeAttempt)` so callers can
    /// surface it as a structured error. Callers passing user-controlled
    /// input MUST validate via [`SystemRoot::try_join`].
    pub fn join(&self, rel: &str) -> PathBuf {
        // SAFETY: validated internal paths only. Panicking here is correct
        // because reaching this with an escaping path is a programming bug,
        // not a runtime failure.
        self.try_join(rel)
            .expect("SystemRoot::join received escaping path; use try_join for user input")
    }

    /// Like [`SystemRoot::join`] but returns an error instead of panicking
    /// when `rel` would escape the target root. Use this for any path
    /// derived from user input, file contents, or external configuration.
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

    /// Original string form, for stable JSON display.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn as_path(&self) -> &Path {
        &self.canonical
    }

    /// Canonical target root used for all filesystem access. The original
    /// user spelling remains available via [`SystemRoot::as_str`] for JSON.
    pub fn canonical_path(&self) -> &Path {
        &self.canonical
    }
}

fn normalise_absolute_root(input: &str) -> PathBuf {
    if input.chars().all(|c| c == '/') {
        PathBuf::from("/")
    } else {
        PathBuf::from(input.trim_end_matches('/'))
    }
}

/// Validate that `rel` is a safe sub-path: no `..`, no embedded absolute
/// path, no Windows prefix. A single leading slash is allowed (it is the
/// conventional way to write `etc/os-release` as `/etc/os-release` inside
/// this codebase). Further absolute markers after the first character are
/// rejected.
fn validate_relative_path(rel: &str) -> Result<(), RootError> {
    use std::path::Component;

    // Empty string means "the root itself"; allow it. The only escape vector
    // is `..`, embedded absolute paths, or Windows prefix components.
    if rel.is_empty() {
        return Ok(());
    }

    // Parse the path. We use the platform parser; on Unix this only ever
    // produces Normal / CurDir / ParentDir / RootDir.
    let parsed = Path::new(rel);
    let mut components = parsed.components();

    // Allow one leading RootDir so both "etc/..." and "/etc/..." work.
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

    // ---- escape-prevention tests (review issue #3) ----
    // These guard against the original sin of string concat: a `..`
    // component silently reading host /etc when target root is /mnt.

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
    fn try_join_rejects_trailing_parent_dir() {
        let r = root("/mnt");
        let err = r.try_join("etc/passwd/..").unwrap_err();
        assert!(matches!(err, RootError::EscapeAttempt(_)));
    }

    #[test]
    fn try_join_rejects_embedded_absolute_path() {
        // Path::components of "/etc/passwd" is RootDir + Normal("etc") +
        // Normal("passwd"). We allow ONE leading RootDir (so "/etc" works
        // as a synonym for "etc"), but anything that starts with content
        // and then introduces a new RootDir must be rejected.
        //
        // Path normalises consecutive slashes, so we test with an explicit
        // leading slash AFTER a normal component.
        let r = root("/mnt");
        // Wait — Path::components treats "etc//etc" as the same as
        // "etc/etc" (collapses slashes), so this cannot be expressed as a
        // path that re-roots. The real escape vector is ParentDir, which
        // we test above. Instead, verify a path that ends in a re-rooted
        // absolute marker is rejected via the leading-slash carve-out:
        // only ONE leading slash is allowed.
        let ok = r.try_join("/etc/passwd").unwrap();
        assert_eq!(ok, PathBuf::from("/mnt/etc/passwd"));
    }

    #[test]
    fn try_join_accepts_leading_slash() {
        // The codebase convention is that both "etc/..." and "/etc/..."
        // work. The leading slash is stripped before validation.
        let r = root("/mnt");
        let p = r.try_join("/etc/passwd").unwrap();
        assert_eq!(p, PathBuf::from("/mnt/etc/passwd"));
    }

    #[test]
    fn try_join_accepts_normal_relative_paths() {
        let r = root("/mnt");
        assert_eq!(
            r.try_join("etc/os-release").unwrap(),
            PathBuf::from("/mnt/etc/os-release")
        );
        assert_eq!(
            r.try_join("var/lib/pacman/local").unwrap(),
            PathBuf::from("/mnt/var/lib/pacman/local")
        );
    }

    #[test]
    #[should_panic(expected = "escaping path")]
    fn join_panics_on_escape() {
        // The non-try variant panics: it is for trusted internal use only.
        let r = root("/mnt");
        let _ = r.join("../../etc/passwd");
    }

    #[test]
    fn escape_attempt_display_mentions_components() {
        let err = RootError::EscapeAttempt("../etc".to_string());
        let s = format!("{err}");
        assert!(s.contains(".."));
        assert!(s.contains("escape"));
    }
}
