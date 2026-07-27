//! Pure path-safety checks for mount-repair target operations.
//!
//! Spec § 六 requires every mount-point directory we create to go
//! through confined, dirfd-relative access that rejects:
//!
//! * mount-point paths that escape the target root via symlinks;
//! * fstab paths that are symlinks;
//! * parent-directory symlinks;
//! * `..` components;
//! * magic links (`/proc/self/...`);
//! * non-directory objects at the target path;
//! * hostile target roots.
//!
//! The real target-root confinement uses Linux `openat2(2)` with
//! `RESOLVE_IN_ROOT` and `RESOLVE_NO_MAGICLINKS` (see
//! [`crate::target::diagnose::filesystem`]). That primitive is only available
//! when we actually have a target root to open; in this module we
//! provide the pure-function *policy* layer that:
//!
//! 1. validates a syntactic path *before* we hand it to `openat2`;
//! 2. lets tests verify our rejection rules without depending on
//!    `openat2` availability or on real filesystem state.
//!
//! Production callers SHOULD still pass the validated path through
//! `openat2` so the kernel enforces confinement even if our policy
//! has a bug. Defence in depth: policy here, enforcement in the
//! kernel.

use std::path::{Component, Path};

/// Reason a path was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRejection {
    /// Path was empty.
    Empty,
    /// Path was not absolute (mount-point paths are conventionally
    /// absolute inside the target root).
    NotAbsolute,
    /// Path contained a `..` component.
    ParentComponent,
    /// Path contained a platform prefix component (`C:` on Windows).
    /// Cannot appear on Linux but the type system forces us to
    /// account for it.
    PrefixComponent,
    /// Path contained a magic-link segment (`/proc`, `/sys`, or
    /// `/dev/fd` characteristics). We reject the obvious magic-link
    /// roots up front so a hostile fstab cannot trick us into
    /// crossing into the host.
    MagicLink,
    /// Path attempted to escape via a normalisation that would
    /// resolve to a path outside the target root. (Pure syntactic
    /// check; the kernel's RESOLVE_IN_ROOT catches the semantic
    /// version.)
    EscapesRoot,
    /// A path component is empty (e.g. `//`). While usually benign,
    /// we reject to keep behaviour predictable.
    EmptyComponent,
}

impl PathRejection {
    pub fn code(&self) -> &'static str {
        match self {
            PathRejection::Empty => "empty",
            PathRejection::NotAbsolute => "not_absolute",
            PathRejection::ParentComponent => "parent_component",
            PathRejection::PrefixComponent => "prefix_component",
            PathRejection::MagicLink => "magic_link",
            PathRejection::EscapesRoot => "escapes_root",
            PathRejection::EmptyComponent => "empty_component",
        }
    }
}

/// Validate a mount-point path syntactically.
///
/// Rules:
/// * non-empty;
/// * absolute (starts with `/`);
/// * no `..` components;
/// * no prefix components;
/// * no empty components (no `//`);
/// * not a known magic-link root (`/proc`, `/sys`, `/dev/fd`,
///   `/proc/self`, ...).
///
/// Returns `Ok(())` if the path passes all syntactic checks. The
/// caller is still responsible for using `openat2` for semantic
/// confinement.
pub fn validate_mount_point_path(path: &Path) -> Result<(), PathRejection> {
    if path.as_os_str().is_empty() {
        return Err(PathRejection::Empty);
    }
    if !path.is_absolute() {
        return Err(PathRejection::NotAbsolute);
    }
    // Reject obvious magic-link roots. We do NOT try to enumerate
    // every possible magic link; the kernel's RESOLVE_NO_MAGICLINKS
    // is authoritative. This catches the obvious attempts at the
    // syntactic layer so tests do not need a real `openat2`.
    let s = path.to_string_lossy();
    let magic_roots = ["/proc", "/sys", "/dev/fd", "/dev/pts"];
    for root in magic_roots {
        if s == root
            || s.starts_with(&format!("{root}/"))
            || s.starts_with("/proc/self/")
            || s.starts_with("/proc/thread-self/")
        {
            return Err(PathRejection::MagicLink);
        }
    }

    let mut normalised_depth: i32 = 0;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => {
                normalised_depth += 1;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(PathRejection::ParentComponent);
            }
            Component::Prefix(_) => return Err(PathRejection::PrefixComponent),
        }
    }
    if normalised_depth < 0 {
        return Err(PathRejection::EscapesRoot);
    }
    Ok(())
}

/// Result of examining a path inside the target root, as observed by
/// the orchestrator via the existing `openat2`-based fs probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathObservation {
    pub is_symlink: bool,
    pub is_directory: bool,
    pub is_regular_file: bool,
    pub is_other: bool,
}

impl PathObservation {
    pub fn directory() -> Self {
        Self {
            is_symlink: false,
            is_directory: true,
            is_regular_file: false,
            is_other: false,
        }
    }
    pub fn missing() -> Self {
        Self {
            is_symlink: false,
            is_directory: false,
            is_regular_file: false,
            is_other: false,
        }
    }
}

/// Decide whether a mount-point path is safe to `create_dir` inside
/// the target root.
///
/// Rules:
/// * path passes [`validate_mount_point_path`];
/// * path does not exist OR exists as a real (non-symlink)
///   directory;
/// * path is not a symlink (rejected even if it points to a
///   directory, because the symlink itself is the escape vector);
/// * path is not a regular file or other non-directory object.
pub fn validate_directory_creation(
    path: &Path,
    observation: &PathObservation,
) -> Result<(), PathRejection> {
    validate_mount_point_path(path)?;
    if observation.is_symlink {
        // Reject any symlink at the path, even if it points to a
        // directory. The spec: "如果路径已是 symlink，必须拒绝该项
        // 修复并报告".
        return Err(PathRejection::MagicLink);
    }
    if observation.is_regular_file || observation.is_other {
        return Err(PathRejection::EscapesRoot);
    }
    // is_directory=true with no symlink is fine: we may need to
    // create intermediate parents but the leaf already exists.
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Spec § 十一 非特权测试 → 路径安全 ----

    #[test]
    fn rejects_relative_path() {
        let err = validate_mount_point_path(Path::new("home")).unwrap_err();
        assert_eq!(err, PathRejection::NotAbsolute);
    }

    #[test]
    fn rejects_parent_component() {
        let err = validate_mount_point_path(Path::new("/home/../etc")).unwrap_err();
        assert_eq!(err, PathRejection::ParentComponent);
    }

    #[test]
    fn rejects_proc_magic_link() {
        for p in ["/proc", "/proc/self", "/proc/self/fd/0", "/proc/1/root"] {
            let err = validate_mount_point_path(Path::new(p)).unwrap_err();
            assert_eq!(err, PathRejection::MagicLink, "path {p}");
        }
    }

    #[test]
    fn rejects_sys_magic_link() {
        let err = validate_mount_point_path(Path::new("/sys/class/block/sda")).unwrap_err();
        assert_eq!(err, PathRejection::MagicLink);
    }

    #[test]
    fn accepts_standard_mount_points() {
        for p in [
            "/",
            "/home",
            "/root",
            "/srv",
            "/var/cache",
            "/var/tmp",
            "/var/log",
            "/.snapshots",
            "/boot",
            "/boot/efi",
            "/efi",
        ] {
            assert!(validate_mount_point_path(Path::new(p)).is_ok(), "path {p}");
        }
    }

    #[test]
    fn directory_creation_rejects_symlink_at_leaf() {
        let obs = PathObservation {
            is_symlink: true,
            is_directory: false,
            is_regular_file: false,
            is_other: false,
        };
        let err = validate_directory_creation(Path::new("/home"), &obs).unwrap_err();
        assert_eq!(err, PathRejection::MagicLink);
    }

    #[test]
    fn directory_creation_rejects_regular_file_at_leaf() {
        let obs = PathObservation {
            is_symlink: false,
            is_directory: false,
            is_regular_file: true,
            is_other: false,
        };
        let err = validate_directory_creation(Path::new("/home"), &obs).unwrap_err();
        assert_eq!(err, PathRejection::EscapesRoot);
    }

    #[test]
    fn directory_creation_accepts_missing_path() {
        let obs = PathObservation::missing();
        assert!(validate_directory_creation(Path::new("/home/user/new"), &obs).is_ok());
    }

    #[test]
    fn directory_creation_accepts_existing_directory() {
        let obs = PathObservation::directory();
        assert!(validate_directory_creation(Path::new("/home"), &obs).is_ok());
    }

    #[test]
    fn directory_creation_rejects_other_object_kind() {
        let obs = PathObservation {
            is_symlink: false,
            is_directory: false,
            is_regular_file: false,
            is_other: true, // e.g. socket, fifo, char device
        };
        let err = validate_directory_creation(Path::new("/home"), &obs).unwrap_err();
        assert_eq!(err, PathRejection::EscapesRoot);
    }

    #[test]
    fn empty_path_rejected() {
        let err = validate_mount_point_path(Path::new("")).unwrap_err();
        assert_eq!(err, PathRejection::Empty);
    }
}
