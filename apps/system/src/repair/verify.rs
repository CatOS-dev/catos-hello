//! Post-repair read-only verification mount.
//!
//! After a successful repair, we mount the target ONCE read-only in
//! a private namespace to confirm the filesystem is structurally
//! usable, then unmount before returning. This is the spec's "修复
//! 完成后可以由程序建立一次只读验证挂载".
//!
//! ## What this is NOT
//!
//! * It is NOT a write probe. We use the same read-only safety
//!   options as phase 2 (`noload`, `norecovery`, etc.) so the
//!   verification mount never replays a journal or writes the
//!   superblock.
//! * It is NOT an excuse to skip the fsck tool's own check. The
//!   fsck tool is authoritative; the verification mount is a second
//!   signal that catches "fsck exited 0 but the filesystem still
//!   cannot be mounted" cases (e.g. on corrupt xfs after -L).
//! * It does NOT touch mounts that existed before this invocation.
//!   The session module's existing pre-existing-mount tracking
//!   guarantees this.
//!
//! ## Why we reuse `mount::session::Session`
//!
//! The session module already:
//!
//! * enters a private namespace,
//! * tracks which mounts it created (vs pre-existing),
//! * unmounts only what it created,
//! * produces a `CleanupReport` that surfaces residuals.
//!
//! Reusing it means a verification-mount failure produces exactly
//! the same structured cleanup report as a phase-2 target mount
//! failure, which is what the JSON contract promises.

use std::path::{Path, PathBuf};

use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount::{CleanupReport, MountError, MountPlan};
use crate::shared::model::repair::VerificationMount;
use crate::shared::mount::plan::build_probe_plan;
use crate::shared::mount::session::{Session, SESSION_ROOT_PARENT};
use crate::shared::parse::mountinfo;

/// Outcome of the verification mount. Distinct from
/// [`VerificationMount`] (the model) because the orchestrator needs
/// to know whether to retry, escalate, or proceed. The model is what
/// we render.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerificationOutcome {
    /// The structured model that goes into the report.
    pub model: VerificationMount,
    /// The cleanup report for the verification session. `all_clean =
    /// true` means the session unmounted cleanly. Always present
    /// when we attempted a mount.
    pub cleanup: CleanupReport,
    /// Evidence trail.
    pub evidence: Vec<Evidence>,
}

/// Mount `device` read-only, observe its fstype via the kernel, then
/// unmount and clean up. Returns a structured outcome; never panics.
///
/// `device` must be a `/dev/...` path. `fstype` is the filesystem
/// type we believe the device has (from blkid); we pass it to
/// `build_probe_plan` so the right safety options are applied.
pub fn verify(device: &Path, fstype: &str) -> VerificationOutcome {
    let runner = RealRepairProbe;
    verify_with(&runner, device, fstype)
}

/// Testable form: takes an explicit probe runner so we can inject a
/// fake "what does /proc/self/mountinfo look like now?" for unit
/// tests. The default `RealRepairProbe` reads real `/proc`.
pub fn verify_with<R: RepairRunnerProbe>(
    runner: &R,
    device: &Path,
    fstype: &str,
) -> VerificationOutcome {
    let device_str = match device.to_str() {
        Some(s) => s.to_string(),
        None => {
            return VerificationOutcome {
                model: VerificationMount {
                    mounted: false,
                    observed_fstype: None,
                    failure_message: Some(
                        "device path is not valid UTF-8; cannot verification-mount".into(),
                    ),
                },
                cleanup: CleanupReport::default(),
                evidence: vec![Evidence::new(
                    "VERIFICATION_REFUSED",
                    "repair::verify",
                    "device path is not valid UTF-8".to_string(),
                )],
            };
        }
    };

    let session_root = match fresh_verification_session_root() {
        Ok(p) => p,
        Err(message) => {
            return VerificationOutcome {
                model: VerificationMount {
                    mounted: false,
                    observed_fstype: None,
                    failure_message: Some(format!(
                        "could not allocate verification session directory: {message}"
                    )),
                },
                cleanup: CleanupReport::default(),
                evidence: vec![Evidence::new(
                    "VERIFICATION_SESSION_REFUSED",
                    "repair::verify",
                    message,
                )],
            };
        }
    };

    let plan = match build_probe_plan(session_root.clone(), &device_str, fstype, None) {
        Ok(p) => p,
        Err(error) => {
            return VerificationOutcome {
                model: VerificationMount {
                    mounted: false,
                    observed_fstype: None,
                    failure_message: Some(format!(
                        "verification mount plan refused for {device_str} ({:?}): {}",
                        error.kind, error.message
                    )),
                },
                cleanup: CleanupReport::default(),
                evidence: vec![Evidence::new(
                    "VERIFICATION_PLAN_REFUSED",
                    "repair::verify",
                    format!("fstype={fstype} refused by mount::plan::FstypePolicy"),
                )],
            };
        }
    };

    let session_id = session_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("verify")
        .to_string();
    let mut session = Session::new(session_id, &plan);
    let mounted_snapshot = match session.run(&plan) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            // Session::run already cleaned up on the step failure
            // (its cleanup_internal runs in the error path). Calling
            // cleanup() again returns the cached report, which is
            // what we want for surfacing residuals.
            let cleanup = session.cleanup();
            return VerificationOutcome {
                model: VerificationMount {
                    mounted: false,
                    observed_fstype: None,
                    failure_message: Some(format!(
                        "verification mount failed for {device_str} ({:?}): {}",
                        error.kind, error.message
                    )),
                },
                cleanup,
                evidence: vec![Evidence::new(
                    "VERIFICATION_MOUNT_FAILED",
                    "repair::verify",
                    format!("mount error kind={:?}", error.kind),
                )],
            };
        }
    };

    // The mount succeeded. Observe the fstype the kernel actually
    // reports for our target path so we can detect a mismatch
    // (e.g. we asked for ext4 but the kernel mounted it as ext3).
    let observed_fstype = runner.read_fstype_at(&mounted_snapshot.target_root);
    let observed_fstype_for_evidence = observed_fstype.clone();
    let fstype_matches = observed_fstype.as_deref() == Some(fstype);

    // Cleanup. The session only unmounts what IT created; pre-
    // existing mounts are never touched.
    let cleanup = session.cleanup();

    VerificationOutcome {
        model: VerificationMount {
            mounted: fstype_matches,
            observed_fstype,
            failure_message: (!fstype_matches).then(|| {
                format!(
                    "verification mount fstype mismatch: expected {fstype}, observed {:?}",
                    observed_fstype_for_evidence
                )
            }),
        },
        cleanup,
        evidence: vec![Evidence::new(
            if fstype_matches {
                "VERIFICATION_MOUNT_OK"
            } else {
                "VERIFICATION_FSTYPE_MISMATCH"
            },
            "repair::verify",
            format!(
                "target {device_str} mounted read-only and unmounted cleanly; observed_fstype={:?}",
                observed_fstype_for_evidence
            ),
        )],
    }
}

/// Trait the verification module uses to talk to `/proc` (so tests
/// can inject a fake). The default implementation,
/// [`RealRepairProbe`], reads real `/proc/self/mountinfo`. There is
/// no `CommandRunner`-style fake for the mount itself: the mount
/// uses real `mount(2)` syscalls via `mount::session::Session`, so
/// tests that exercise a failure path run as root in the QEMU smoke
/// harness. Unit tests use the safety/fs_flows/orchestrator flow
/// without a real mount.
pub trait RepairRunnerProbe: Default {
    /// Read the fstype the kernel reports for `target` in
    /// `/proc/self/mountinfo`. `None` if not found.
    fn read_fstype_at(&self, target: &Path) -> Option<String>;
}

#[derive(Default, Debug, Clone, Copy)]
pub struct RealRepairProbe;

impl RepairRunnerProbe for RealRepairProbe {
    fn read_fstype_at(&self, target: &Path) -> Option<String> {
        let body = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        mountinfo::parse_all(&body)
            .into_iter()
            .find(|entry| entry.mount_point == target)
            .map(|entry| entry.fstype)
    }
}

fn fresh_verification_session_root() -> Result<PathBuf, String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let id = format!("v{}-{n}", std::process::id());
    Ok(Path::new(SESSION_ROOT_PARENT).join(id))
}

// ---------------------------------------------------------------------------
// Helpers re-exported for the orchestrator
// ---------------------------------------------------------------------------

/// Build a one-step read-only probe plan, used by [`verify`] when the
/// caller does not already have a plan. Re-exports
/// `mount::plan::build_probe_plan` so the orchestrator does not need
/// to depend on the mount layer directly.
pub fn build_verification_plan(
    session_root: PathBuf,
    source: &str,
    fstype: &str,
) -> Result<MountPlan, MountError> {
    build_probe_plan(session_root, source, fstype, None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Debug, Clone, Copy)]
    struct StubProbe {}

    impl RepairRunnerProbe for StubProbe {
        fn read_fstype_at(&self, _target: &Path) -> Option<String> {
            None
        }
    }

    #[test]
    fn fresh_session_root_is_under_trusted_parent() {
        let root = fresh_verification_session_root().unwrap();
        assert_eq!(root.parent(), Some(Path::new(SESSION_ROOT_PARENT)));
        assert!(root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|s| s.starts_with('v')));
    }

    #[test]
    fn verification_outcome_default_is_unmounted_clean() {
        // Default outcome: no mount, clean cleanup, no evidence. This
        // is the shape the orchestrator starts from when it does not
        // run verification (e.g. for refusals).
        let outcome = VerificationOutcome::default();
        assert!(!outcome.model.mounted);
        assert!(outcome.cleanup.all_clean);
        assert!(outcome.evidence.is_empty());
    }

    #[test]
    fn non_utf8_device_path_is_refused_without_io() {
        // A non-UTF-8 device path is impossible to express in &str,
        // but we exercise the defensive branch with a constructed
        // OsStr to confirm the early-return logic.
        use std::os::unix::ffi::OsStrExt;
        let bytes = &[0xFFu8, 0xFE];
        let osstr = std::ffi::OsStr::from_bytes(bytes);
        let path: &Path = Path::new(osstr);
        let outcome = verify_with(&StubProbe {}, path, "ext4");
        assert!(!outcome.model.mounted);
        assert!(outcome
            .model
            .failure_message
            .as_ref()
            .is_some_and(|m| m.contains("UTF-8")));
    }
}
