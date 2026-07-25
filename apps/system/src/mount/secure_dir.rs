//! Secure runtime directory primitives shared by phase 2 (read-only
//! target mount) and phase 3 (read-write recovery transaction).
//!
//! Phase 2 builds session directories under
//! `/run/catos-system/sessions/` for its short-lived read-only
//! probe mounts. Phase 3 builds a session directory under the SAME
//! parent for the read-write btrfs top-level mount.
//!
//! Both phases MUST apply identical security semantics:
//!
//! * the trusted runtime root `/run/catos-system` and its
//!   `sessions/` child must be real directories (no symlinks), owned
//!   by the invoking user, and never group- or world-writable;
//! * the per-session directory MUST be created with
//!   [`std::fs::create_dir`] (exclusive) so an attacker cannot
//!   pre-place a symlink or honeypot directory at the predicted
//!   path;
//! * after creation, the directory is re-stat'd to confirm it is a
//!   real directory owned by the invoking user with mode `0o700`.
//!
//! Centralising the rules here prevents phase 3 from shipping a
//! weaker local copy. Phase 2's existing helper stays as a thin
//! wrapper that pins the parent path.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::model::recovery::{RecoveryError, RecoveryErrorKind};

pub const SESSION_ROOT_PARENT: &str = "/run/catos-system/sessions";

pub fn effective_uid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

pub fn validate_real_dir(path: &Path, required_owner: Option<u32>) -> Result<(), RecoveryError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!("cannot inspect {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!("{} is not a real directory", path.display()),
        ));
    }
    if let Some(owner) = required_owner {
        if metadata.uid() != owner {
            return Err(RecoveryError::new(
                RecoveryErrorKind::SessionDirectoryNotSecure,
                format!(
                    "{} has unexpected owner {} (expected {})",
                    path.display(),
                    metadata.uid(),
                    owner
                ),
            ));
        }
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!("{} is group/world writable", path.display()),
        ));
    }
    Ok(())
}

pub fn create_or_validate_runtime_dir(path: &Path, mode: u32) -> Result<(), RecoveryError> {
    match std::fs::create_dir(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(
                |error| {
                    RecoveryError::new(
                        RecoveryErrorKind::SessionDirectoryNotSecure,
                        format!("cannot set mode {} on {}: {error}", mode, path.display()),
                    )
                },
            )?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::SessionDirectoryNotSecure,
                format!("cannot create {}: {error}", path.display()),
            ))
        }
    }
    validate_real_dir(path, Some(effective_uid()))
}

pub fn validate_trusted_root_chain() -> Result<(), RecoveryError> {
    validate_real_dir(Path::new("/run"), None)?;
    create_or_validate_runtime_dir(Path::new("/run/catos-system"), 0o700)?;
    create_or_validate_runtime_dir(Path::new(SESSION_ROOT_PARENT), 0o700)?;
    Ok(())
}

pub fn validate_session_dir(path: &Path) -> Result<(), RecoveryError> {
    let parent = Path::new(SESSION_ROOT_PARENT);
    if path.parent() != Some(parent) || path.file_name().is_none() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!(
                "session path {} must be a direct child of {SESSION_ROOT_PARENT}",
                path.display()
            ),
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!("cannot stat {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!("{} is a symlink", path.display()),
        ));
    }
    if !metadata.is_dir() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!("{} is not a directory", path.display()),
        ));
    }
    let euid = effective_uid();
    if metadata.uid() != euid {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!(
                "{} is owned by uid {} (expected {})",
                path.display(),
                metadata.uid(),
                euid
            ),
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryNotSecure,
            format!(
                "{} has unsafe mode {:o} (group or world access)",
                path.display(),
                metadata.mode() & 0o777
            ),
        ));
    }
    Ok(())
}

/// Atomically generate a session directory name that does NOT collide
/// on PID reuse. The name format is `<prefix>-<pid>-<random_hex>`.
/// Two near-simultaneous invocations of the same prefix MUST receive
/// distinct paths even if they share a PID (test:
/// `session_directory_does_not_collide_on_concurrent_creation`).
pub fn fresh_session_name(prefix: &str) -> Result<String, RecoveryError> {
    let mut random_bytes = [0u8; 8];
    match getrandom::getrandom(&mut random_bytes) {
        Ok(()) => Ok(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            hex_bytes(&random_bytes)
        )),
        Err(error) => Err(RecoveryError::new(
            RecoveryErrorKind::RandomSourceFailed,
            format!("kernel random source failed while generating session directory name: {error}"),
        )),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn create_session_dir(parent: &Path, prefix: &str) -> Result<PathBuf, RecoveryError> {
    validate_trusted_root_chain()?;
    let attempts: u32 = 8;
    for _ in 0..attempts {
        let name = fresh_session_name(prefix)?;
        let candidate = parent.join(&name);
        match std::fs::create_dir(&candidate) {
            Ok(()) => {
                std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| {
                        RecoveryError::new(
                            RecoveryErrorKind::SessionDirectoryNotSecure,
                            format!("cannot set mode 0700 on {}: {error}", candidate.display()),
                        )
                    })?;
                validate_session_dir(&candidate)?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(RecoveryError::new(
                    RecoveryErrorKind::SessionDirectoryConflict,
                    format!("cannot exclusively create {}: {error}", candidate.display()),
                ))
            }
        }
    }
    Err(RecoveryError::new(
        RecoveryErrorKind::SessionDirectoryConflict,
        format!(
            "could not allocate a unique session name under {} after {attempts} attempts; \
                 a concurrent invocation or stale leftover may be blocking creation",
            parent.display()
        ),
    ))
}

pub fn remove_session_dir(parent: &Path, path: &Path) -> Result<(), RecoveryError> {
    if path.parent() != Some(parent) {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryCleanupFailed,
            format!(
                "refusing to remove {}: not a direct child of {}",
                path.display(),
                parent.display()
            ),
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryCleanupFailed,
            format!("refusing to remove symlink {}", path.display()),
        )),
        Ok(_) => std::fs::remove_dir_all(path).map_err(|error| {
            RecoveryError::new(
                RecoveryErrorKind::SessionDirectoryCleanupFailed,
                format!("cannot remove {}: {error}", path.display()),
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RecoveryError::new(
            RecoveryErrorKind::SessionDirectoryCleanupFailed,
            format!("cannot stat {} for cleanup: {error}", path.display()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "catos-secure-dir-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn fresh_session_name_includes_pid_and_randomness() {
        let a = fresh_session_name("recovery-rw").unwrap();
        let b = fresh_session_name("recovery-rw").unwrap();
        assert!(a.starts_with("recovery-rw-"));
        assert!(b.starts_with("recovery-rw-"));
        assert_ne!(a, b, "two consecutive names must differ");
    }

    #[test]
    fn validate_real_dir_rejects_regular_file() {
        let root = scratch("regular-file");
        let target = root.join("target");
        std::fs::write(&target, b"x").unwrap();
        let err = validate_real_dir(&target, None).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::SessionDirectoryNotSecure);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn validate_real_dir_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let root = scratch("symlink");
        let target = root.join("link");
        symlink("/etc", &target).unwrap();
        let err = validate_real_dir(&target, None).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::SessionDirectoryNotSecure);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn validate_real_dir_rejects_wrong_mode() {
        let root = scratch("wrong-mode");
        let target = root.join("dir");
        std::fs::create_dir(&target).unwrap();
        // 0o770 sets the group-write bit; validate_real_dir rejects
        // any path whose mode bit-AND 0o022 is non-zero (i.e. group
        // or world writable).
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = validate_real_dir(&target, None).unwrap_err();
        assert!(err.message.contains("group/world writable"));
        assert_eq!(err.kind, RecoveryErrorKind::SessionDirectoryNotSecure);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remove_session_dir_refuses_outside_parent() {
        let parent = scratch("remove-outside-parent");
        let elsewhere = scratch("remove-elsewhere");
        let err = remove_session_dir(&parent, &elsewhere).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::SessionDirectoryCleanupFailed);
        assert!(err.message.contains("not a direct child"));
        let _ = std::fs::remove_dir_all(parent);
        let _ = std::fs::remove_dir_all(elsewhere);
    }

    #[test]
    fn remove_session_dir_is_idempotent_on_missing_path() {
        let parent = scratch("remove-idempotent");
        let target = parent.join("does-not-exist");
        remove_session_dir(&parent, &target).unwrap();
        let _ = std::fs::remove_dir_all(parent);
    }
}
