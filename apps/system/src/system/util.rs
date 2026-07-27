use super::Phase2Outcome;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{exit_code, Error};
use crate::mount::execute::secure_dir::SESSION_ROOT_PARENT;
use crate::mount::model::MountError;
use crate::target::model::Warning;

pub(crate) static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(super) fn fresh_session_root() -> PathBuf {
    let id = generate_session_id();
    Path::new(SESSION_ROOT_PARENT).join(id)
}

/// Generate a process-local unique session id without relying on an early
/// initramfs random pool. Exclusive directory creation remains the final
/// collision and stale-session guard.
pub(super) fn generate_session_id() -> String {
    let sequence = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("s{}-{sequence}", std::process::id())
}

pub(super) fn merge_warnings(a: Vec<Warning>, b: Vec<Warning>) -> Vec<Warning> {
    let mut out = a;
    out.extend(b);
    out
}

pub(super) fn mount_error_to_top_error(err: MountError) -> Error {
    Error::MountFailed(err)
}

/// Convenience used by entry.rs to detect whether a phase-2 command
/// should set a non-success exit code based on its outcome.
pub fn exit_code_for(outcome: &Phase2Outcome) -> i32 {
    match outcome {
        Phase2Outcome::StorageScan(report) if !report.ambiguities.is_empty() => {
            // Ambiguities are surfaced but not fatal: the report still
            // contains useful device data. We exit 0 so downstream
            // tooling can consume the JSON.
            exit_code::SUCCESS
        }
        Phase2Outcome::TargetMount { cleanup, .. } if !cleanup.all_clean => exit_code::PROBE_FAILED,
        _ => exit_code::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::exit_code;
    use crate::mount::model::MountSession;
    use crate::target::model::TargetInspection;
    use std::path::PathBuf;

    /// generate_session_id must produce a non-empty, filesystem-safe
    /// string. Locking the format guards against a refactor that
    /// accidentally introduces a `/` and breaks the session_root path.
    #[test]
    fn session_id_is_filesystem_safe() {
        let id = generate_session_id();
        assert!(id.starts_with('s'));
        assert!(!id.contains('/'));
        assert!(!id.is_empty());
    }

    /// exit_code_for returns SUCCESS for a clean TargetMount outcome.
    #[test]
    fn exit_code_for_clean_target_mount_is_success() {
        let outcome = Phase2Outcome::TargetMount {
            session: MountSession {
                id: "test".into(),
                state: crate::mount::model::MountSessionState::Active,
                namespace: crate::mount::model::NamespaceState::PrivateNamespace,
                session_root: PathBuf::from("/tmp/x"),
                target_root: PathBuf::from("/tmp/x/target"),
                mounts: vec![],
                warnings: vec![],
            },
            inspection: Box::new(TargetInspection::default()),
            cleanup: crate::mount::model::CleanupReport::default(),
            warnings: vec![],
        };
        assert_eq!(exit_code_for(&outcome), exit_code::SUCCESS);
    }

    /// exit_code_for returns PROBE_FAILED when residuals remain.
    #[test]
    fn exit_code_for_residual_target_mount_is_probe_failed() {
        let outcome = Phase2Outcome::TargetMount {
            session: MountSession {
                id: "test".into(),
                state: crate::mount::model::MountSessionState::CleanupIncomplete,
                namespace: crate::mount::model::NamespaceState::PrivateNamespace,
                session_root: PathBuf::from("/tmp/x"),
                target_root: PathBuf::from("/tmp/x/target"),
                mounts: vec![],
                warnings: vec![],
            },
            inspection: Box::new(TargetInspection::default()),
            cleanup: crate::mount::model::CleanupReport {
                residual: vec![crate::mount::model::ResidualMount {
                    resource: crate::mount::model::MountedResource {
                        order: 1,
                        source: "/dev/sda1".into(),
                        target: PathBuf::from("/tmp/x/target"),
                        fstype: "ext4".into(),
                        options: "ro".into(),
                    },
                    reason: "test".into(),
                    error_code: "test".into(),
                }],
                directory_cleanup_error: None,
                all_clean: false,
                ..Default::default()
            },
            warnings: vec![],
        };
        assert_eq!(exit_code_for(&outcome), exit_code::PROBE_FAILED);
    }
}
