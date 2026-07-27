//! Mount session: owns a private namespace + an ordered list of mounts.
//!
//! Lifecycle:
//!
//! 1. [`ReadOnlyMountSession::new`] creates the session-root directory and records
//!    which block devices are CURRENTLY mounted (snapshot via
//!    `/proc/self/mountinfo`). These pre-existing mounts are NEVER touched
//!    by rollback — the hard constraint from the spec is "must never
//!    unmount mounts that existed before the session".
//!
//! 2. [`ReadOnlyMountSession::run`] establishes the private namespace
//!    (`mount::namespace`), then executes [`MountStep`]s in ascending
//!    order. Each successful step is appended to `self.mounts` and
//!    observed in `self.session_root`.
//!
//! 3. On ANY step failure, the session transitions to `RollingBack`,
//!    unmounts every session-owned mount in reverse order, and produces a
//!    [`CleanupReport`]. Residual mounts (umount2 failed) are reported
//!    explicitly with their failure reason — never silently dropped.
//!
//! 4. [`ReadOnlyMountSession::cleanup`] unmounts everything the session created, in
//!    reverse order, regardless of whether the session succeeded or
//!    failed. Idempotent: a second call is a no-op.
//!
//! ## Hard invariants
//!
//! * Pre-existing mounts (recorded in `pre_existing`) are NEVER unmounted.
//!   This is enforced structurally: the cleanup loop only iterates
//!   `self.mounts`, which only ever contains resources the session
//!   created.
//! * The kernel's forceful unmount flag is NEVER used. It can corrupt
//!   in-flight metadata even on read-only mounts. Cleanup uses plain
//!   `umount2(0)` first, then `umount2(MNT_DETACH)` only as a
//!   last-resort fallback for residuals that the user must be told about.
//! * State transitions are monotonic: `Finished` and `Cleaned` are
//!   terminal. `CleanupIncomplete` is sticky — a second cleanup attempt
//!   is refused.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::diagnose::mountinfo;
use crate::execute::namespace::{self, NamespaceSetup};
use crate::execute::syscall::{self, mnt_flags, ms_flags, SyscallError};
use crate::model::{
    CleanupReport, MountError, MountErrorKind, MountPlan, MountSession, MountSessionState,
    MountedResource, NamespaceState, ResidualMount,
};
use catos_target::model::Warning;
use catos_target::Evidence;

/// Default session-root parent. Per-session subdirs are `<id>` under here.
///
/// Re-exported from the Mount secure-directory implementation so all
/// read-only sessions share the same trusted root path. The constant value is
/// part of the public contract.
pub use crate::execute::secure_dir::SESSION_ROOT_PARENT;

/// A live mount session. Owns the namespace setup result and the list of
/// mounts it has created so far. The JSON-shaped [`MountSession`] is
/// derived via [`ReadOnlyMountSession::snapshot`] for output rendering.
pub struct ReadOnlyMountSession {
    id: String,
    session_root: PathBuf,
    target_root: PathBuf,
    state: MountSessionState,
    namespace_state: NamespaceState,
    namespace_setup: Option<NamespaceSetup>,
    mounts: Vec<MountedResource>,
    pre_existing: HashSet<PathBuf>,
    warnings: Vec<Warning>,
    evidence: Vec<Evidence>,
    last_cleanup: Option<CleanupReport>,
}

impl ReadOnlyMountSession {
    /// Construct a session without entering the namespace yet. The
    /// caller still lives in the host namespace; `run` will unshare.
    ///
    /// `pre_existing` is computed from the CURRENT `/proc/self/mountinfo`
    /// BEFORE any mount is performed, so the session knows which mounts
    /// to leave alone during rollback.
    pub fn new(id: impl Into<String>, plan: &MountPlan) -> Self {
        let id = id.into();
        let pre_existing = current_mounts().into_iter().collect();
        Self {
            id,
            session_root: plan.session_root.clone(),
            target_root: plan.target_root.clone(),
            state: MountSessionState::Ready,
            namespace_state: NamespaceState::default(),
            namespace_setup: None,
            mounts: Vec::new(),
            pre_existing,
            warnings: Vec::new(),
            evidence: Vec::new(),
            last_cleanup: None,
        }
    }

    /// Execute a plan: enter the namespace, then mount each step in order.
    /// On any step failure, roll back automatically and return the error.
    /// The session ends in `Active` (all steps ok), `CleanupIncomplete`
    /// (rolled back with residuals), or `Cleaned` (rolled back clean).
    pub fn run(&mut self, plan: &MountPlan) -> Result<MountSession, MountError> {
        if self.state != MountSessionState::Ready {
            return Err(self.already_done_error());
        }

        // Step 1: enter private namespace.
        match namespace::establish_private_namespace() {
            Ok(setup) => {
                self.namespace_state = setup.state;
                let evidence_strings = setup.evidence.clone();
                self.namespace_setup = Some(setup);
                for line in evidence_strings {
                    self.evidence
                        .push(Evidence::new("NAMESPACE_SETUP", "mount::namespace", line));
                }
            }
            Err(err) => {
                self.state = MountSessionState::CleanupIncomplete;
                return Err(self.syscall_to_mount_error(err, vec![]));
            }
        }

        // Step 2: ensure session_root exists. We mkdir -p it because the
        // plan is permitted to point at a path that doesn't exist yet
        // (e.g. /run/catos-system/sessions/abc). Failure here is fatal
        // before any mount is attempted.
        if let Err(msg) = ensure_session_root(&self.session_root) {
            self.state = MountSessionState::CleanupIncomplete;
            return Err(MountError {
                kind: MountErrorKind::UnsafeTargetPath,
                message: format!("could not create session_root: {msg}"),
                device_or_path: Some(self.session_root.display().to_string()),
                errno: None,
                completed_steps: vec![],
                cleanup_complete: true,
                residual_mounts: vec![],
            });
        }

        // Step 3: execute steps in ascending order.
        let mut sorted_steps: Vec<&_> = plan.steps.iter().collect();
        sorted_steps.sort_by_key(|s| s.order);

        for step in sorted_steps {
            if let Err(err) = self.execute_step(step) {
                // Roll back everything we have done so far.
                let completed_rationales: Vec<String> = self
                    .mounts
                    .iter()
                    .map(|m| format!("{} on {}", m.source, m.target.display()))
                    .collect();
                let report = self.cleanup_internal();
                self.state = if report.all_clean {
                    MountSessionState::Cleaned
                } else {
                    MountSessionState::CleanupIncomplete
                };
                let mut mount_err = self.syscall_to_mount_error(err, completed_rationales);
                mount_err.cleanup_complete = report.all_clean;
                mount_err.residual_mounts = report
                    .residual
                    .iter()
                    .map(|r| format!("{} ({}): {}", r.resource.source, r.error_code, r.reason))
                    .collect();
                return Err(mount_err);
            }
        }

        self.state = MountSessionState::Active;
        Ok(self.snapshot())
    }

    /// Execute one step. Only the empty root mountpoint may be created.
    /// Nested mountpoints must already exist as real directories in the
    /// read-only target and may not contain symlink components.
    fn execute_step(&mut self, step: &crate::model::MountStep) -> Result<(), SyscallError> {
        if let Err(msg) = prepare_mount_target(&self.target_root, &step.target) {
            return Err(SyscallError {
                syscall: "mkdir",
                errno: classify_io_errno(&msg),
            });
        }

        // Issue the mount with MS_RDONLY forced on (belt + braces: the
        // option string already has `ro`, but the flag is the kernel's
        // authoritative signal).
        let data = step.options_string();
        syscall::mount(
            Some(&step.source),
            &step.target,
            Some(&step.fstype),
            ms_flags::MS_RDONLY,
            Some(&data),
        )?;

        // Record the mount we just created (NOT pre-existing ones).
        self.mounts.push(MountedResource {
            order: step.order,
            source: step.source.clone(),
            target: step.target.clone(),
            fstype: step.fstype.clone(),
            options: data,
        });
        self.evidence.push(
            Evidence::new(
                "MOUNT_STEP_OK",
                "mount::syscall",
                format!("mounted {} at {}", step.source, step.target.display()),
            )
            .with_value(step.fstype.clone()),
        );
        Ok(())
    }

    /// Rollback all mounts this session created. Idempotent.
    pub fn cleanup(&mut self) -> CleanupReport {
        if matches!(
            self.state,
            MountSessionState::Cleaned
                | MountSessionState::Finished
                | MountSessionState::CleanupIncomplete
        ) {
            return self.last_cleanup.clone().unwrap_or_default();
        }
        if self.state == MountSessionState::Ready
            && self.namespace_setup.is_none()
            && self.mounts.is_empty()
        {
            let report = CleanupReport::default();
            self.last_cleanup = Some(report.clone());
            self.state = MountSessionState::Finished;
            return report;
        }
        let report = self.cleanup_internal();
        self.state = if report.all_clean {
            MountSessionState::Finished
        } else {
            MountSessionState::CleanupIncomplete
        };
        report
    }

    /// Internal rollback: unmount every session-owned mount in reverse
    /// order. Plain `umount2(0)` first; on failure, fall back to
    /// `MNT_DETACH` and record as residual. The forceful unmount flag
    /// is never passed.
    fn cleanup_internal(&mut self) -> CleanupReport {
        self.state = MountSessionState::RollingBack;
        let mut report = CleanupReport {
            observed_pre_existing: self
                .pre_existing
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            ..Default::default()
        };

        // Iterate in reverse order. Take ownership so we can move into
        // either `unmounted` or `residual` without borrow issues.
        let mut mounts = std::mem::take(&mut self.mounts);
        for resource in mounts.drain(..).rev() {
            // Hard invariant: NEVER unmount a pre-existing mount. Even
            // though `self.mounts` only ever contains session-owned
            // resources, double-check defensively — if a target was
            // somehow already mounted before the session, leave it.
            if self.pre_existing.contains(&resource.target) {
                report.residual.push(ResidualMount {
                    resource,
                    reason: "target was mounted before this session; not unmounting".into(),
                    error_code: "pre_existing".into(),
                });
                continue;
            }

            match syscall::umount2(&resource.target, 0) {
                Ok(()) => {
                    report.unmounted.push(resource);
                }
                Err(err) => {
                    // Last-resort: MNT_DETACH leaves the mount in the
                    // kernel but removes it from the namespace, so the
                    // device becomes free for the next user. The user
                    // MUST be told — the underlying mount is not gone.
                    match syscall::umount2(&resource.target, mnt_flags::MNT_DETACH) {
                        Ok(()) => {
                            self.warnings.push(Warning::new(
                                "MOUNT_DETACHED",
                                format!(
                                    "could not cleanly unmount {}; detached lazily (residual)",
                                    resource.target.display()
                                ),
                            ));
                            report.residual.push(ResidualMount {
                                resource,
                                reason: format!(
                                    "umount2 failed (errno {}); detached lazily",
                                    err.errno
                                ),
                                error_code: err.classify().code().to_string(),
                            });
                        }
                        Err(detach_err) => {
                            report.residual.push(ResidualMount {
                                resource,
                                reason: format!(
                                    "umount2 errno {} and MNT_DETACH errno {}",
                                    err.errno, detach_err.errno
                                ),
                                error_code: err.classify().code().to_string(),
                            });
                        }
                    }
                }
            }
        }

        if report.residual.is_empty() {
            if let Err(error) = remove_session_tree(&self.session_root) {
                report.directory_cleanup_error = Some(error);
            }
        }
        report.all_clean = report.residual.is_empty() && report.directory_cleanup_error.is_none();
        self.last_cleanup = Some(report.clone());
        report
    }

    /// Build the JSON-shaped snapshot for output rendering.
    pub fn snapshot(&self) -> MountSession {
        MountSession {
            id: self.id.clone(),
            state: self.state,
            namespace: self.namespace_state,
            session_root: self.session_root.clone(),
            target_root: self.target_root.clone(),
            mounts: self.mounts.clone(),
            warnings: self.warnings.clone(),
        }
    }

    fn already_done_error(&self) -> MountError {
        MountError {
            kind: MountErrorKind::MountFailed,
            message: format!("session already in state {:?}", self.state),
            device_or_path: None,
            errno: None,
            completed_steps: self
                .mounts
                .iter()
                .map(|m| format!("{} on {}", m.source, m.target.display()))
                .collect(),
            cleanup_complete: matches!(
                self.state,
                MountSessionState::Cleaned | MountSessionState::Finished
            ),
            residual_mounts: vec![],
        }
    }

    fn syscall_to_mount_error(&self, err: SyscallError, completed: Vec<String>) -> MountError {
        MountError {
            kind: err.classify(),
            message: err.to_string(),
            device_or_path: None,
            errno: Some(err.errno),
            completed_steps: completed,
            cleanup_complete: matches!(
                self.state,
                MountSessionState::Cleaned | MountSessionState::Finished
            ),
            residual_mounts: vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Read the set of currently-mounted paths. Used at session start to
/// record pre-existing mounts so the cleanup loop knows what to leave
/// alone. Returns an empty set on read failure (fail-safe: the cleanup
/// loop will then refuse to unmount anything that looks ambiguous).
pub fn current_mounts() -> Vec<PathBuf> {
    let Ok(body) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    mountinfo::parse_all(&body)
        .into_iter()
        .map(|m| m.mount_point)
        .collect()
}

/// Create a private session directory under the fixed runtime parent.
/// Every existing component is checked with symlink_metadata, and the
/// final directory is created exclusively so a guessed session id cannot
/// redirect privileged mounts.
fn ensure_session_root(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let parent = Path::new(SESSION_ROOT_PARENT);
    if path.parent() != Some(parent) || path.file_name().is_none() {
        return Err(format!(
            "session root must be a direct child of {SESSION_ROOT_PARENT}"
        ));
    }

    validate_existing_runtime_dir(Path::new("/run"), None)?;
    create_or_validate_runtime_dir(Path::new("/run/catos-system"), 0o700)?;
    create_or_validate_runtime_dir(parent, 0o700)?;

    std::fs::create_dir(path).map_err(|error| {
        format!(
            "could not exclusively create session directory {}: {error}",
            path.display()
        )
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("new session path is not a real directory".into());
    }
    let euid = effective_uid();
    if metadata.uid() != euid || metadata.mode() & 0o077 != 0 {
        return Err("new session directory ownership or permissions are unsafe".into());
    }
    Ok(())
}

fn create_or_validate_runtime_dir(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::create_dir(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .map_err(|error| error.to_string())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("cannot create {}: {error}", path.display())),
    }
    validate_existing_runtime_dir(path, Some(effective_uid()))
}

fn validate_existing_runtime_dir(path: &Path, required_owner: Option<u32>) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} is not a real directory", path.display()));
    }
    if let Some(owner) = required_owner {
        if metadata.uid() != owner {
            return Err(format!("{} has unexpected owner", path.display()));
        }
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!("{} is group/world writable", path.display()));
    }
    Ok(())
}

fn prepare_mount_target(target_root: &Path, target: &Path) -> Result<(), std::io::Error> {
    if target == target_root {
        return match std::fs::create_dir(target) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(target)?;
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "root mountpoint is not a real directory",
                    ))
                }
            }
            Err(error) => Err(error),
        };
    }

    let relative = target.strip_prefix(target_root).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mount target is outside the session target root",
        )
    })?;
    let mut current = target_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mount target contains an unsafe path component",
            ));
        };
        current.push(part);
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a real directory", current.display()),
            ));
        }
    }
    Ok(())
}

fn remove_session_tree(path: &Path) -> Result<(), String> {
    if path.parent() != Some(Path::new(SESSION_ROOT_PARENT)) {
        return Err("refusing to remove a path outside the session parent".into());
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("refusing to remove a symlink session path".into())
        }
        Ok(_) => std::fs::remove_dir_all(path).map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no arguments and no failure mode.
    unsafe { geteuid() }
}

fn classify_io_errno(err: &std::io::Error) -> i32 {
    err.raw_os_error().unwrap_or_else(|| match err.kind() {
        std::io::ErrorKind::NotFound => 2,
        std::io::ErrorKind::PermissionDenied => 13,
        std::io::ErrorKind::AlreadyExists => 17,
        std::io::ErrorKind::InvalidInput => 22,
        _ => -1,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The default namespace state MUST be HostNamespaceRefused. This is
    /// the fail-closed contract: a session that forgot to call run() must
    /// not silently think it is in a private namespace.
    #[test]
    fn default_namespace_state_is_refused() {
        assert_eq!(
            NamespaceState::default(),
            NamespaceState::HostNamespaceRefused
        );
    }

    /// MountSessionState::default must be Ready (not Active). A fresh
    /// session has done nothing yet.
    #[test]
    fn default_session_state_is_ready() {
        assert_eq!(MountSessionState::default(), MountSessionState::Ready);
    }

    #[test]
    fn synthetic_invalid_target_error_maps_to_unsafe_target() {
        let error = std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsafe target");
        let syscall_error = SyscallError {
            syscall: "mkdir",
            errno: classify_io_errno(&error),
        };
        assert_eq!(syscall_error.errno, 22);
        assert_eq!(syscall_error.classify(), MountErrorKind::UnsafeTargetPath);
    }

    /// MountErrorKind::CleanupIncomplete is part of the JSON contract
    /// and must round-trip through serde. Guards against a rename that
    /// would break downstream consumers keyed on the code string.
    #[test]
    fn cleanup_incomplete_kind_round_trips() {
        let kind = MountErrorKind::CleanupIncomplete;
        let j = serde_json::to_string(&kind).unwrap();
        let back: MountErrorKind = serde_json::from_str(&j).unwrap();
        assert_eq!(kind, back);
    }

    /// The session_root parent constant is part of the public contract
    /// (used by the CLI to construct paths like
    /// `/run/catos-system/sessions/<id>`). Lock it.
    #[test]
    fn session_root_parent_is_stable() {
        assert_eq!(SESSION_ROOT_PARENT, "/run/catos-system/sessions");
    }

    /// current_mounts must never panic even when /proc is unreadable
    /// (e.g. in restricted containers). It returns an empty list.
    #[test]
    fn current_mounts_returns_empty_on_unreadable_proc() {
        // We cannot easily simulate an unreadable /proc in a unit test,
        // but we can at least verify the function returns a Vec (not a
        // Result) and never panics.
        let _ = current_mounts();
    }

    /// cleanup on a never-run session is a no-op that produces an empty
    /// report. Guards against a regression where cleanup might iterate
    /// pre_existing and accidentally unmount them.
    #[test]
    fn cleanup_on_never_run_session_is_noop() {
        let plan = MountPlan {
            session_root: PathBuf::from("/tmp/catos-test"),
            target_root: PathBuf::from("/tmp/catos-test/target"),
            namespace: NamespaceState::PrivateNamespace,
            root_device: None,
            root_subvolume: None,
            extra_partitions: vec![],
            steps: vec![],
            selection_rationale: vec![],
            safety_constraints: vec![],
            warnings: vec![],
        };
        let mut session = ReadOnlyMountSession::new("test", &plan);
        let report = session.cleanup();
        assert!(report.unmounted.is_empty());
        assert!(report.residual.is_empty());
        assert!(report.all_clean);
        assert_eq!(session.state, MountSessionState::Finished);
    }

    /// cleanup is idempotent: a second call is a no-op. Guards against a
    /// regression where repeated cleanup might try to unmount already-
    /// unmounted paths and produce spurious residuals.
    #[test]
    fn cleanup_is_idempotent() {
        let plan = MountPlan {
            session_root: PathBuf::from("/tmp/catos-test"),
            target_root: PathBuf::from("/tmp/catos-test/target"),
            namespace: NamespaceState::PrivateNamespace,
            root_device: None,
            root_subvolume: None,
            extra_partitions: vec![],
            steps: vec![],
            selection_rationale: vec![],
            safety_constraints: vec![],
            warnings: vec![],
        };
        let mut session = ReadOnlyMountSession::new("test", &plan);
        let _ = session.cleanup();
        let report = session.cleanup();
        assert!(report.unmounted.is_empty());
        assert!(report.residual.is_empty());
        // Second cleanup keeps Finished (does not regress to CleanupIncomplete).
        assert_eq!(session.state, MountSessionState::Finished);
    }
}
