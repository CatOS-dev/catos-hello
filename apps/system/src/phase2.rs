//! Phase-2 orchestrators: storage scan, target plan, target mount.
//!
//! These functions sit between `entry.rs` (which dispatches by command)
//! and the probe/mount/output layers. They own the side-effects that
//! probes deliberately avoid: spawning blkid, reading the target fstab,
//! entering the mount namespace, and producing the final structured
//! output that `output/` renders.
//!
//! Hard rule: every function here is READ-ONLY with respect to the target.
//! `run_target_mount` mounts inside a private namespace but every mount
//! is read-only with filesystem-specific safety options applied by
//! `mount::plan`. No write to the target device is ever performed.

use std::path::{Path, PathBuf};

use crate::error::{exit_code, Error};
use crate::model::fstab::FstabEntry;
use crate::model::inspection::Warning;
use crate::model::mount::{MountError, MountPlan, MountSession};
use crate::model::storage::StorageReport;
use crate::mount::plan::{build_plan, PlanInputs};
use crate::mount::session::{Session, SESSION_ROOT_PARENT};
use crate::parse::fstab::parse_all as parse_fstab;
use crate::probe::fs_probe::RealFilesystem;
use crate::probe::{discover_devices, identify_candidates};
use crate::system_root::SystemRoot;

/// Outcome of a phase-2 command. Each variant carries the structured
/// model that the matching output renderer consumes.
pub enum Phase2Outcome {
    StorageScan(StorageReport),
    TargetPlan {
        plan: MountPlan,
        warnings: Vec<Warning>,
    },
    TargetMount {
        session: MountSession,
        cleanup: crate::model::mount::CleanupReport,
        warnings: Vec<Warning>,
    },
}

/// Run `storage scan`: enumerate devices, identify candidates, emit a
/// [`StorageReport`]. Pure read; no mounts, no namespace entry.
pub fn run_storage_scan(_root: &SystemRoot) -> Result<Phase2Outcome, Error> {
    let fs = RealFilesystem;
    let (devices, dev_warnings) = discover_devices(&fs);
    let fstab = read_host_fstab();
    let (root_candidates, esp_candidates, ambiguities, cand_warnings) =
        identify_candidates(&devices, &fstab);

    Ok(Phase2Outcome::StorageScan(StorageReport {
        devices,
        root_candidates,
        esp_candidates,
        warnings: merge_warnings(dev_warnings, cand_warnings),
        ambiguities,
    }))
}

/// Run `target plan`: read the target fstab, discover devices, build a
/// [`MountPlan`] WITHOUT executing any mount. Returns the plan plus any
/// non-fatal warnings (e.g. ambiguous device references that were
/// resolved conservatively).
pub fn run_target_plan(root: &SystemRoot) -> Result<Phase2Outcome, Error> {
    let fs = RealFilesystem;
    let (devices, dev_warnings) = discover_devices(&fs);
    let fstab = read_target_fstab(root)?;
    let session_root = fresh_session_root();
    let plan = build_plan(PlanInputs {
        session_root,
        devices: &devices,
        fstab: &fstab,
        include_boot: true,
    })
    .map_err(mount_error_to_top_error)?;
    Ok(Phase2Outcome::TargetPlan {
        plan,
        warnings: dev_warnings,
    })
}

/// Run `target mount`: build a plan, then execute it inside a private
/// mount namespace. On success the session snapshot and cleanup report
/// are returned. On failure the session rolls back automatically and the
/// error is propagated (the cleanup report is embedded in the error).
pub fn run_target_mount(root: &SystemRoot) -> Result<Phase2Outcome, Error> {
    let fs = RealFilesystem;
    let (devices, dev_warnings) = discover_devices(&fs);
    let fstab = read_target_fstab(root)?;
    let session_root = fresh_session_root();
    let plan = build_plan(PlanInputs {
        session_root,
        devices: &devices,
        fstab: &fstab,
        include_boot: true,
    })
    .map_err(mount_error_to_top_error)?;

    let session_id = plan
        .session_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("anon")
        .to_string();
    let mut session = Session::new(session_id, &plan);
    match session.run(&plan) {
        Ok(snapshot) => {
            let cleanup = session.cleanup();
            Ok(Phase2Outcome::TargetMount {
                session: snapshot,
                cleanup,
                warnings: dev_warnings,
            })
        }
        Err(mount_err) => {
            // Session already rolled back; surface the structured mount
            // error (which carries residual_mounts from cleanup) as a
            // top-level Error::ProbeFailed.
            let cleanup = session.cleanup();
            Err(mount_error_with_cleanup(mount_err, cleanup))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_host_fstab() -> Vec<FstabEntry> {
    read_fstab_path(Path::new("/etc/fstab"))
}

fn read_target_fstab(root: &SystemRoot) -> Result<Vec<FstabEntry>, Error> {
    let path = Path::new(root.as_str()).join("etc/fstab");
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(read_fstab_path(&path))
}

fn read_fstab_path(path: &Path) -> Vec<FstabEntry> {
    match std::fs::read_to_string(path) {
        Ok(body) => parse_fstab(&body),
        Err(_) => Vec::new(),
    }
}

fn fresh_session_root() -> PathBuf {
    let id = generate_session_id();
    Path::new(SESSION_ROOT_PARENT).join(id)
}

/// Generate an opaque session id from the current time. No randomness
/// source is required (initramfs may have no /dev/urandom yet).
fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("s{nanos:x}")
}

fn merge_warnings(a: Vec<Warning>, b: Vec<Warning>) -> Vec<Warning> {
    let mut out = a;
    out.extend(b);
    out
}

fn mount_error_to_top_error(err: MountError) -> Error {
    Error::ProbeFailed {
        detail: format!("mount plan error: {err}"),
    }
}

fn mount_error_with_cleanup(
    err: MountError,
    _cleanup: crate::model::mount::CleanupReport,
) -> Error {
    // The cleanup report's residuals are already embedded in
    // MountError::residual_mounts; we surface the MountError directly.
    Error::ProbeFailed {
        detail: format!("mount session error: {err}"),
    }
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

    /// read_fstab_path returns an empty vec on read failure, NOT an
    /// error. Guards against a regression that turns "fstab missing"
    /// into a probe failure (the spec says unknown, not failure).
    #[test]
    fn read_fstab_missing_returns_empty_vec() {
        let entries = read_fstab_path(Path::new("/definitely/not/here/12345"));
        assert!(entries.is_empty());
    }

    /// exit_code_for returns SUCCESS for a clean TargetMount outcome.
    #[test]
    fn exit_code_for_clean_target_mount_is_success() {
        let outcome = Phase2Outcome::TargetMount {
            session: MountSession {
                id: "test".into(),
                state: crate::model::mount::MountSessionState::Active,
                namespace: crate::model::mount::NamespaceState::PrivateNamespace,
                session_root: PathBuf::from("/tmp/x"),
                target_root: PathBuf::from("/tmp/x/target"),
                mounts: vec![],
                warnings: vec![],
            },
            cleanup: crate::model::mount::CleanupReport::default(),
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
                state: crate::model::mount::MountSessionState::CleanupIncomplete,
                namespace: crate::model::mount::NamespaceState::PrivateNamespace,
                session_root: PathBuf::from("/tmp/x"),
                target_root: PathBuf::from("/tmp/x/target"),
                mounts: vec![],
                warnings: vec![],
            },
            cleanup: crate::model::mount::CleanupReport {
                residual: vec![crate::model::mount::ResidualMount {
                    resource: crate::model::mount::MountedResource {
                        order: 1,
                        source: "/dev/sda1".into(),
                        target: PathBuf::from("/tmp/x/target"),
                        fstype: "ext4".into(),
                        options: "ro".into(),
                    },
                    reason: "test".into(),
                    error_code: "test".into(),
                }],
                all_clean: false,
                ..Default::default()
            },
            warnings: vec![],
        };
        assert_eq!(exit_code_for(&outcome), exit_code::PROBE_FAILED);
    }
}
