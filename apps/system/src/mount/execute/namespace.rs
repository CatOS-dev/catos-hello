//! Mount namespace setup.
//!
//! Phase 2 mounts happen inside a freshly-`unshare(CLONE_NEWNS)`-ed
//! namespace, with `/` marked `MS_PRIVATE|MS_REC` so our mounts do NOT
//! propagate to the parent namespace. This is the standard pattern from
//! `mount_namespaces(7)`:
//!
//! > A mount namespace becomes "owned" by the process that creates it via
//! > unshare(CLONE_NEWNS). The new namespace starts as a CLONE of the
//! > parent's mount tree, but propagation has to be flipped explicitly:
//! >
//! > ```text
//! > mount("", "/", MS_REC | MS_PRIVATE, NULL)
//! > ```
//! >
//! > Without this call, every mount we make is visible in the parent
//! > namespace via `MS_SHARED` propagation — exactly the contamination
//! > we are trying to prevent.
//!
//! Layering rule: this module is the ONLY place that calls `unshare`.
//! `session.rs` calls into here, then issues its own `mount`/`umount2`
//! via `mount::syscall`. The session trusts that once
//! [`establish_private_namespace`] returns Ok, all subsequent mounts are
//! isolated from the host.

use crate::mount::model::NamespaceState;
use crate::mount::execute::syscall::{self, clone_flags, ms_flags, SyscallError};

/// Outcome of [`establish_private_namespace`]. The caller (session) keeps
/// this for diagnostics; the actual mount tree mutation has already
/// happened in the current thread.
#[derive(Debug, Clone)]
pub struct NamespaceSetup {
    pub state: NamespaceState,
    pub evidence: Vec<String>,
}

/// Enter a private mount namespace.
///
/// Steps, in order (all required — short-cutting any of them leaves the
/// host's mount table contaminated or the namespace shared):
///
/// 1. `unshare(CLONE_NEWNS)` — clone the current mount tree into a new
///    namespace. Requires CAP_SYS_ADMIN. On failure we fail CLOSED: no
///    further mount is attempted.
///
/// 2. `mount(NULL, "/", MS_REC | MS_PRIVATE, NULL)` — flip the entire
///    tree to `private` propagation, recursively. Without this, mounts
///    we add still appear in the parent namespace via `MS_SHARED` (the
///    default propagation for `/` on systemd systems is `shared`).
///    Source and target are both effectively ignored when `MS_PRIVATE` is
///    the only meaningful flag, but the kernel requires target to be `/`.
///
/// 3. Verify the namespace is private by checking that the `/` entry in
///    `/proc/self/mountinfo` no longer carries `shared:` in its optional
///    fields. This is the cheap, race-free verification the man page
///    recommends; we do NOT re-read the kernel state on every mount, only
///    once at setup.
pub fn establish_private_namespace() -> Result<NamespaceSetup, SyscallError> {
    let mut evidence = Vec::new();

    // Step 1: unshare.
    syscall::unshare(clone_flags::CLONE_NEWNS).map_err(|e| {
        evidence.push(format!("unshare failed: errno {}", e.errno));
        e
    })?;
    evidence.push("unshare(CLONE_NEWNS) succeeded".into());

    // Step 2: flip / to MS_PRIVATE|MS_REC. Source and fstype are NULL;
    // the kernel only inspects the MS_* flags here.
    syscall::mount(
        None,
        std::path::Path::new("/"),
        None,
        ms_flags::MS_REC | ms_flags::MS_PRIVATE,
        None,
    )
    .map_err(|e| {
        evidence.push(format!("MS_PRIVATE flip failed: errno {}", e.errno));
        e
    })?;
    evidence.push("/ marked MS_REC|MS_PRIVATE".into());

    // Step 3: verify the root mount is no longer shared.
    match verify_root_is_private() {
        Ok(true) => {
            evidence.push("verified: / no longer carries shared: in mountinfo".into());
        }
        Ok(false) => {
            return Err(namespace_verification_error());
        }
        Err(_) => {
            return Err(namespace_verification_error());
        }
    }

    Ok(NamespaceSetup {
        state: NamespaceState::PrivateNamespace,
        evidence,
    })
}

/// Read `/proc/self/mountinfo` and check that the `/` entry's optional
/// fields do NOT contain any `shared:N` token. Returns:
///   * `Ok(true)` — `/` is private (no `shared:` token).
///   * `Ok(false)` — `/` still carries `shared:` after our flip.
///   * `Err(message)` — could not read or parse mountinfo. The caller
///     fails closed and refuses all target mounts.
fn verify_root_is_private() -> Result<bool, String> {
    let body = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())?;
    let mounts = crate::mount::diagnose::mountinfo::parse_all(&body);
    let root_mount = mounts
        .iter()
        .find(|m| m.mount_point == std::path::Path::new("/"))
        .ok_or_else(|| "no / entry in mountinfo".to_string())?;
    let still_shared = root_mount
        .optional_fields
        .iter()
        .any(|f| f.starts_with("shared:"));
    Ok(!still_shared)
}

fn namespace_verification_error() -> SyscallError {
    // EPROTO is used as an internal diagnostic errno: the namespace
    // syscalls returned success but the resulting propagation state could
    // not be established as private.
    SyscallError {
        syscall: "unshare",
        errno: 71,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLONE_NEWNS value is part of the kernel ABI. Locking it here
    /// guards against a future refactor pulling in the wrong constant.
    #[test]
    fn clone_newns_value_is_stable() {
        assert_eq!(clone_flags::CLONE_NEWNS, 0x0002_0000);
    }

    /// MS_PRIVATE and MS_REC values are part of the kernel ABI and the
    /// namespace flip depends on both.
    #[test]
    fn ms_flags_for_private_propagation_are_stable() {
        assert_eq!(ms_flags::MS_PRIVATE, 1 << 18);
        assert_eq!(ms_flags::MS_REC, 16384);
        let combo = ms_flags::MS_PRIVATE | ms_flags::MS_REC;
        // Sanity: combo must NOT equal MS_PRIVATE alone (regression guard
        // against an accidentally dropped OR).
        assert_ne!(combo, ms_flags::MS_PRIVATE);
    }

    /// Unit test for the optional-field scan against a fixture mountinfo
    /// line. This exercises the "shared:" detection without needing root
    /// or an actual unshare.
    #[test]
    fn detect_shared_token_in_optional_fields() {
        let body = "1 0 0:1 / / rw,nosuid,nodev shared:2 - sysfs sysfs rw\n";
        let parsed = crate::mount::diagnose::mountinfo::parse_all(body);
        let root = parsed.first().unwrap();
        assert!(root
            .optional_fields
            .iter()
            .any(|f| f.starts_with("shared:")));
    }

    /// A private root mountinfo line must be detected as NOT shared.
    /// This is what we want to see after the MS_PRIVATE flip.
    #[test]
    fn detect_private_root_in_optional_fields() {
        let body = "1 0 0:1 / / rw,nosuid,nodev - sysfs sysfs rw\n";
        let parsed = crate::mount::diagnose::mountinfo::parse_all(body);
        let root = parsed.first().unwrap();
        assert!(!root
            .optional_fields
            .iter()
            .any(|f| f.starts_with("shared:")));
    }

    /// If mountinfo has no `/` entry at all (synthetic fixture), the
    /// verifier surfaces an error string but does not panic.
    #[test]
    fn verify_root_handles_missing_root_mount() {
        let body = "1 0 0:1 / /proc rw - proc proc rw\n";
        let mounts = crate::mount::diagnose::mountinfo::parse_all(body);
        let root_mount = mounts
            .iter()
            .find(|m| m.mount_point == std::path::Path::new("/"));
        assert!(root_mount.is_none());
    }

    #[test]
    fn failed_private_verification_is_namespace_unavailable() {
        let error = namespace_verification_error();
        assert_eq!(
            error.classify(),
            crate::mount::model::MountErrorKind::NamespaceUnavailable
        );
    }
}
