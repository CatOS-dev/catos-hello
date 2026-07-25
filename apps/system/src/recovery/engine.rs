//! Transaction engine.
//!
//! The engine drives the recovery state machine. It receives a
//! freshly-mounted btrfs top-level (mount point inside a private
//! namespace, subvolid=5) and an immutable [`RecoveryPlan`], and
//! performs the persistent writes the plan describes.
//!
//! ## Crash safety
//!
//! Every transition is persisted *before* the next one starts. The
//! on-disk record is the source of truth after a crash. On resume
//! the engine re-reads the record, reconciles it with disk facts
//! via [`crate::recovery::state::reconcile_with_disk_facts`], and
//! continues from the reconciled state.
//!
//! ## Test-only fault injection
//!
//! When built with the `recovery_fault_injection` cargo feature,
//! the engine consults the `CATOS_RECOVERY_FAULT_AT` environment
//! variable after persisting each successful transition. If the
//! value matches the just-reached state's snake_case code (e.g.
//! `backup_created`), the engine aborts the process via `raise(9)`
//! — the same signal a `kill -9` produces. This lets the QEMU
//! crash-resume test simulate a hard failure after every persistent
//! step without modifying production behaviour.
//!
//! The feature is gated by a Cargo feature, NOT by a runtime
//! variable, so production binaries cannot be triggered into
//! fault injection by an attacker who sets an environment
//! variable.

use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::recovery::{
    CompletedStep, DiskFacts, RecoveryError, RecoveryErrorKind, RecoveryPlan, TransactionPaths,
    TransactionRecord, TransactionState, TX_RECORD_SCHEMA_VERSION,
};
use crate::recovery::external as btrfs;
use crate::recovery::identity::{
    detect_running_root, drift_between, is_protected_recovery_path, target_is_running_root,
};
use crate::recovery::state::{reconcile_with_disk_facts, AdvanceAction, Intent};
use crate::recovery::store;

/// Engine options. Built by the orchestrator (phase3.rs) before the
/// engine runs. All paths are absolute; the orchestrator validates
/// them.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub top_level_mount: PathBuf,
    pub device_path: PathBuf,
}

/// The engine. Owns the transaction record and drives the state
/// machine forward (or backward, on revert).
pub struct Engine {
    opts: EngineOptions,
    record: TransactionRecord,
}

impl Engine {
    /// Load an existing transaction record from disk. Used by
    /// `resume` and `status`.
    pub fn load(opts: EngineOptions, transaction_id: &str) -> Result<Self, RecoveryError> {
        let state_path = top_level_state_path(&opts.top_level_mount, transaction_id);
        let record = store::load_record(&state_path)?;
        Ok(Self { opts, record })
    }

    /// Construct an engine from a freshly-built plan and persist the
    /// initial record. Used by `apply`.
    pub fn begin(opts: EngineOptions, plan: RecoveryPlan) -> Result<Self, RecoveryError> {
        let transaction_id = plan.plan_id.clone();
        let now = now_unix();
        let record = TransactionRecord {
            schema_version: TX_RECORD_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            created_at_unix: now,
            last_updated_unix: now,
            plan,
            state: TransactionState::Planned,
            completed_steps: vec![CompletedStep {
                state: TransactionState::Planned,
                completed_at_unix: now,
                description: "transaction record created".into(),
            }],
            last_error: None,
            last_disk_facts: None,
            last_cleanup: None,
        };
        let mut engine = Self { opts, record };
        engine.persist_record("begin")?;
        Ok(engine)
    }

    /// Read-only access to the current record.
    pub fn record(&self) -> &TransactionRecord {
        &self.record
    }

    /// Drive the transaction forward as far as it can go without
    /// failing. Returns the final state on success or the first
    /// failure encountered.
    pub fn drive(&mut self) -> Result<TransactionState, RecoveryError> {
        loop {
            let state = self.record.state;
            if state.is_terminal() {
                return Ok(state);
            }
            let action = match state.advance_action() {
                Some(action) => action,
                None => return Ok(state),
            };
            self.perform_action(action)?;
            #[cfg(feature = "recovery_fault_injection")]
            self.maybe_inject_fault();
        }
    }

    /// Run the revert path. Idempotent: re-running on an already-
    /// reverted transaction returns success without doing anything.
    pub fn revert(&mut self) -> Result<TransactionState, RecoveryError> {
        let state = self.record.state;
        if state == TransactionState::Reverted {
            return Ok(state);
        }
        // Mark intent and persist.
        self.transition(Intent::Revert, "revert-begin")?;

        // Revert actions depend on the LAST persisted state before
        // the Reverting marker. Recover it from the completed_steps
        // history.
        let last_persistent = self
            .record
            .completed_steps
            .iter()
            .rev()
            .find(|step| step.state != TransactionState::Reverting)
            .map(|step| step.state)
            .unwrap_or(TransactionState::Planned);

        match last_persistent {
            TransactionState::Planned
            | TransactionState::PreflightVerified
            | TransactionState::Locked => {
                // No persistent write happened; just delete the
                // transaction record.
                self.remove_record()?;
                return Ok(TransactionState::Reverted);
            }
            TransactionState::BackupCreated => {
                // Backup subvolume exists; no swap happened. Remove
                // the backup subvolume is NOT done automatically —
                // we promised to preserve user data. Instead, leave
                // the backup in place and mark Reverted.
                self.persist_reverted("revert-after-backup")?;
            }
            TransactionState::ReplacementCreated => {
                // Staging subvolume exists but no swap. Same
                // principle: leave artifacts, mark Reverted.
                self.persist_reverted("revert-after-replacement")?;
            }
            TransactionState::OldRootMoved
            | TransactionState::NewRootInstalled
            | TransactionState::Verifying => {
                // Swap happened; the staging path now contains the
                // OLD /@, and the active /@ is the new root. Swapping
                // them back is the correct revert.
                self.swap_roots_back()?;
                self.persist_reverted("revert-after-swap")?;
            }
            TransactionState::Reverting | TransactionState::Reverted => {
                // Already mid-revert; nothing to do.
            }
            TransactionState::FailedRecoverable | TransactionState::FailedManualIntervention => {
                // Allow the operator to revert out of a failure.
                // Same logic as above based on completed_steps.
                match last_persistent {
                    TransactionState::OldRootMoved
                    | TransactionState::NewRootInstalled
                    | TransactionState::Verifying => {
                        self.swap_roots_back()?;
                    }
                    _ => {}
                }
                self.persist_reverted("revert-after-failure")?;
            }
            TransactionState::Completed => {
                // Reverting a Completed transaction is allowed but
                // the swap direction is the same: exchange /@ and
                // the staging path back. The staging path is the
                // pre-recovery root.
                self.swap_roots_back()?;
                self.persist_reverted("revert-completed")?;
            }
        }
        Ok(TransactionState::Reverted)
    }

    /// Reconcile the persisted state with the disk facts observed
    /// now. Used by `status`.
    pub fn reconcile_status(&mut self) -> DiskFacts {
        let facts = self.observe_disk_facts();
        let reconciled = reconcile_with_disk_facts(self.record.state, &facts);
        if reconciled != self.record.state {
            // Persist the reconciled state so future calls see it.
            self.record.state = reconciled;
            self.record.last_updated_unix = now_unix();
            self.record.last_disk_facts = Some(facts.clone());
            let _ = self.persist_record("reconcile-status");
        }
        facts
    }

    // -----------------------------------------------------------------
    // Action implementations
    // -----------------------------------------------------------------

    fn perform_action(&mut self, action: AdvanceAction) -> Result<(), RecoveryError> {
        match action {
            AdvanceAction::Preflight => self.do_preflight(),
            AdvanceAction::AcquireLock => self.do_acquire_lock(),
            AdvanceAction::CreateBackup => self.do_create_backup(),
            AdvanceAction::CreateReplacement => self.do_create_replacement(),
            AdvanceAction::SwapRoots => self.do_swap_roots(),
            AdvanceAction::VerifyNewRoot => self.do_verify_new_root(),
            AdvanceAction::VerifyFinal => self.do_verify_final(),
            AdvanceAction::MarkCompleted => {
                self.transition(Intent::Complete, "complete")?;
                Ok(())
            }
        }
    }

    /// Re-check the plan's identity against the current disk reality.
    fn do_preflight(&mut self) -> Result<(), RecoveryError> {
        let plan = &self.record.plan;
        if is_protected_recovery_path(&plan.current_root.path)
            || is_protected_recovery_path(&plan.source_snapshot.path)
        {
            return Err(self.failure(
                RecoveryErrorKind::TargetChanged,
                "refusing to plan against the protected /.catos-recovery path",
                true,
                false,
            ));
        }

        // Re-observe filesystem + subvolume identities.
        let filesystem = btrfs::show_filesystem(&self.opts.top_level_mount)?;
        let current_root_mounted = self.mount_of(&plan.current_root.path);
        let source_snapshot_mounted = self.mount_of(&plan.source_snapshot.path);
        let current_root = btrfs::show_subvolume(&current_root_mounted)?;
        let source_snapshot = btrfs::show_subvolume(&source_snapshot_mounted)?;

        let drift = drift_between(plan, &filesystem, &current_root, &source_snapshot);
        if let Some(error) = drift.into_error() {
            return Err(self.failure_from(error, true, false));
        }
        if !source_snapshot.read_only {
            return Err(self.failure(
                RecoveryErrorKind::SnapshotNotReadonly,
                "source snapshot is no longer readonly",
                true,
                false,
            ));
        }
        if filesystem.fsid
            != source_snapshot_fsid_via_path(&source_snapshot_mounted, &self.opts.top_level_mount)
        {
            // The snapshot must live in the same filesystem as the
            // current root. We approximate by comparing FSID values
            // observed at the top-level mount.
            return Err(self.failure(
                RecoveryErrorKind::SnapshotBelongsToAnotherFsid,
                "source snapshot belongs to a different btrfs filesystem",
                false,
                true,
            ));
        }

        // Refuse to recover the running root.
        let running = detect_running_root();
        if target_is_running_root(
            plan,
            &filesystem.device_major_minor,
            current_root.subvolume_id,
            running.as_ref(),
        ) {
            return Err(self.failure(
                RecoveryErrorKind::CurrentRootRefused,
                "the recovery target is the currently running root; refusing to swap it",
                false,
                false,
            ));
        }

        // Verify the backup and staging paths are not already
        // occupied by a foreign object.
        let backup_path = self.top_level_path(&plan.backup_root_path);
        let staging_path = self.top_level_path(&plan.staging_root_path);
        if backup_path.exists() {
            return Err(self.failure(
                RecoveryErrorKind::BackupPathOccupied,
                format!("backup path {} already exists", backup_path.display()),
                true,
                true,
            ));
        }
        if staging_path.exists() {
            return Err(self.failure(
                RecoveryErrorKind::StagingPathOccupied,
                format!("staging path {} already exists", staging_path.display()),
                true,
                true,
            ));
        }

        self.transition(Intent::Advance, "preflight")?;
        Ok(())
    }

    /// Acquire an exclusive lock on the filesystem. The lock file
    /// lives at `<top_level>/.catos-recovery/locks/<fsid>.lock` and
    /// is held via `flock(LOCK_EX)` for the lifetime of the engine.
    /// On resume the engine re-acquires the lock; a held lock from a
    /// still-running apply will block here, which is the desired
    /// behaviour.
    fn do_acquire_lock(&mut self) -> Result<(), RecoveryError> {
        // The lock is acquired here but never released explicitly;
        // process exit releases flock automatically.
        let plan = &self.record.plan;
        let lock_dir = self.opts.top_level_mount.join(".catos-recovery/locks");
        std::fs::create_dir_all(&lock_dir).map_err(|e| {
            self.failure(
                RecoveryErrorKind::SyscallFailed,
                format!("cannot create lock dir {}: {e}", lock_dir.display()),
                true,
                false,
            )
        })?;
        let lock_path = lock_dir.join(format!("{}.lock", sanitize_fsid(&plan.filesystem.fsid)));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                self.failure(
                    RecoveryErrorKind::SyscallFailed,
                    format!("cannot open lock file {}: {e}", lock_path.display()),
                    true,
                    false,
                )
            })?;
        let rc = libc_flock(file.as_raw_fd(), LOCK_EX);
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return Err(self.failure(
                RecoveryErrorKind::TransactionAlreadyActive,
                format!(
                    "cannot acquire exclusive lock on {}: errno={errno}",
                    lock_path.display()
                ),
                true,
                false,
            ));
        }
        // Leak the file descriptor so the lock outlives this function.
        // Process exit releases it.
        std::mem::forget(file);

        self.transition(Intent::Advance, "acquire-lock")?;
        Ok(())
    }

    fn do_create_backup(&mut self) -> Result<(), RecoveryError> {
        let plan = &self.record.plan;
        let current_mounted = self.mount_of(&plan.current_root.path);
        let backup_mounted = self.top_level_path(&plan.backup_root_path);
        ensure_parent(&backup_mounted)?;
        btrfs::create_readonly_snapshot(&current_mounted, &backup_mounted)
            .map_err(|e| self.failure_from(e, true, true))?;
        self.record.last_disk_facts = Some(self.observe_disk_facts());
        self.transition(Intent::Advance, "create-backup")?;
        Ok(())
    }

    fn do_create_replacement(&mut self) -> Result<(), RecoveryError> {
        let plan = &self.record.plan;
        let snapshot_mounted = self.mount_of(&plan.source_snapshot.path);
        let staging_mounted = self.top_level_path(&plan.staging_root_path);
        ensure_parent(&staging_mounted)?;
        btrfs::create_writable_snapshot(&snapshot_mounted, &staging_mounted)
            .map_err(|e| self.failure_from(e, true, true))?;
        self.record.last_disk_facts = Some(self.observe_disk_facts());
        self.transition(Intent::Advance, "create-replacement")?;
        Ok(())
    }

    /// Swap the active root and the staging subvolume via
    /// `renameat2(RENAME_EXCHANGE)`. On modern Linux + btrfs this is
    /// a single atomic metadata transaction that exchanges two
    /// subvolumes in place, regardless of whether either is mounted
    /// elsewhere.
    fn do_swap_roots(&mut self) -> Result<(), RecoveryError> {
        let plan = &self.record.plan;
        let active_root = self.mount_of(&plan.current_root.path);
        let staging_root = self.top_level_path(&plan.staging_root_path);

        // Verify both paths exist and are subvolumes before we swap.
        if !active_root.exists() {
            return Err(self.failure(
                RecoveryErrorKind::RootSwitchConflict,
                format!("active root {} does not exist", active_root.display()),
                true,
                true,
            ));
        }
        if !staging_root.exists() {
            return Err(self.failure(
                RecoveryErrorKind::RootSwitchConflict,
                format!("staging root {} does not exist", staging_root.display()),
                true,
                true,
            ));
        }

        // renameat2 with RENAME_EXCHANGE. We pass the same directory
        // fd (AT_FDCWD) for both sides and use absolute paths; the
        // kernel resolves them through the current namespace.
        let active_c = cpath(&active_root)?;
        let staging_c = cpath(&staging_root)?;
        let rc = libc_renameat2(
            AT_FDCWD,
            active_c.as_ptr(),
            AT_FDCWD,
            staging_c.as_ptr(),
            RENAME_EXCHANGE,
        );
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return Err(self.failure(
                RecoveryErrorKind::SyscallFailed,
                format!(
                    "renameat2(RENAME_EXCHANGE) {} <-> {} failed: errno={errno}",
                    active_root.display(),
                    staging_root.display()
                ),
                true,
                true,
            ));
        }

        self.record.last_disk_facts = Some(self.observe_disk_facts());
        self.transition(Intent::Advance, "swap-roots")?;
        Ok(())
    }

    fn do_verify_new_root(&mut self) -> Result<(), RecoveryError> {
        let plan = &self.record.plan;
        let new_root = self.mount_of(&plan.current_root.path);
        // The new root must look like a CatOS root.
        if !new_root.join("etc/os-release").exists()
            && !new_root.join("usr/lib/os-release").exists()
        {
            return Err(self.failure(
                RecoveryErrorKind::TargetChanged,
                "new root does not contain /etc/os-release or /usr/lib/os-release",
                true,
                true,
            ));
        }
        if !new_root.join("usr/lib/modules").exists() {
            return Err(self.failure(
                RecoveryErrorKind::TargetChanged,
                "new root does not contain /usr/lib/modules",
                true,
                true,
            ));
        }
        self.transition(Intent::Advance, "verify-new-root")?;
        Ok(())
    }

    // TODO(phase-3 follow-up, boot-consistency gate): the future
    // READ-ONLY boot-consistency check is a PRE-WRITE refusal gate, NOT
    // a post-swap verification. By the time the engine reaches
    // `NewRootInstalled` (the state this function transitions OUT of),
    // the pre-recovery backup snapshot, the writable replacement
    // subvolume, AND the `renameat2(RENAME_EXCHANGE)` root switch have
    // ALL been persisted to disk. There is no "first persistent write"
    // left to refuse here. The pre-write gate therefore belongs at the
    // very start of apply — between `do_preflight` and
    // `do_create_backup` — where it can still abort the transaction
    // with zero on-disk side effects. A check placed at THIS location
    // (between `NewRootInstalled` and `Verifying`) could only refuse
    // to mark the transaction `Completed` and surface a diagnostic for
    // the operator; it could not undo the root swap.
    //
    // Whatever shape the gate takes, it MUST be read-only: it MUST NOT
    // call any bootloader tool or write any boot resource. Recovery no
    // longer finalizes boot; do not reintroduce a call to
    // catos-firmware-boot-update, bootctl, grub-mkconfig, or any other
    // boot-update interface from this engine.

    fn do_verify_final(&mut self) -> Result<(), RecoveryError> {
        // Re-run the new-root verification as a final sanity check.
        self.do_verify_new_root()?;
        // The transition to Verifying was already done by
        // do_verify_new_root's call to `transition(Intent::Advance)`.
        // We do not call transition here; the next action
        // (MarkCompleted) does that.
        Ok(())
    }

    /// Reverse the root swap. The active root and the staging path
    /// (which now contains the pre-recovery root) are exchanged
    /// again.
    fn swap_roots_back(&mut self) -> Result<(), RecoveryError> {
        let plan = &self.record.plan;
        let active_root = self.mount_of(&plan.current_root.path);
        let staging_root = self.top_level_path(&plan.staging_root_path);
        if !active_root.exists() || !staging_root.exists() {
            // Nothing to swap back; assume the swap never completed.
            return Ok(());
        }
        let active_c = cpath(&active_root)?;
        let staging_c = cpath(&staging_root)?;
        let rc = libc_renameat2(
            AT_FDCWD,
            active_c.as_ptr(),
            AT_FDCWD,
            staging_c.as_ptr(),
            RENAME_EXCHANGE,
        );
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return Err(self.failure(
                RecoveryErrorKind::SyscallFailed,
                format!(
                    "reverse renameat2 {} <-> {} failed: errno={errno}",
                    active_root.display(),
                    staging_root.display()
                ),
                false,
                false,
            ));
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // State persistence helpers
    // -----------------------------------------------------------------

    fn transition(&mut self, intent: Intent, description: &str) -> Result<(), RecoveryError> {
        let next = self.record.state.transition(intent).map_err(|mut e| {
            e.transaction_id = Some(self.record.transaction_id.clone());
            e
        })?;
        let now = now_unix();
        self.record.state = next;
        self.record.last_updated_unix = now;
        self.record.completed_steps.push(CompletedStep {
            state: next,
            completed_at_unix: now,
            description: description.to_string(),
        });
        self.record.last_error = None;
        self.persist_record(description)?;
        Ok(())
    }

    fn persist_reverted(&mut self, description: &str) -> Result<(), RecoveryError> {
        // Transition from Reverting to Reverted.
        let now = now_unix();
        self.record.state = TransactionState::Reverted;
        self.record.last_updated_unix = now;
        self.record.completed_steps.push(CompletedStep {
            state: TransactionState::Reverted,
            completed_at_unix: now,
            description: description.to_string(),
        });
        self.persist_record(description)?;
        Ok(())
    }

    fn persist_record(&mut self, reason: &str) -> Result<(), RecoveryError> {
        let state_path =
            top_level_state_path(&self.opts.top_level_mount, &self.record.transaction_id);
        let mut err = match store::persist_record(&state_path, &self.record) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        err.transaction_id = Some(self.record.transaction_id.clone());
        err.failed_step = Some(reason.to_string());
        Err(err)
    }

    fn remove_record(&mut self) -> Result<(), RecoveryError> {
        let state_path =
            top_level_state_path(&self.opts.top_level_mount, &self.record.transaction_id);
        store::remove_record(&state_path)?;
        Ok(())
    }

    fn failure(
        &self,
        kind: RecoveryErrorKind,
        message: impl Into<String>,
        resume_possible: bool,
        revert_possible: bool,
    ) -> RecoveryError {
        let mut error = RecoveryError::new(kind, message);
        error.transaction_id = Some(self.record.transaction_id.clone());
        error.current_state = Some(self.record.state);
        error.completed_steps = self
            .record
            .completed_steps
            .iter()
            .map(|s| format!("{:?}: {}", s.state, s.description))
            .collect();
        error.resume_possible = resume_possible;
        error.revert_possible = revert_possible;
        error.manual_intervention_required = !resume_possible && !revert_possible;
        error.disk_facts = self.record.last_disk_facts.clone();
        error
    }

    fn failure_from(
        &self,
        mut error: RecoveryError,
        resume_possible: bool,
        revert_possible: bool,
    ) -> RecoveryError {
        error.transaction_id = Some(self.record.transaction_id.clone());
        error.current_state = Some(self.record.state);
        error.completed_steps = self
            .record
            .completed_steps
            .iter()
            .map(|s| format!("{:?}: {}", s.state, s.description))
            .collect();
        error.resume_possible = resume_possible;
        error.revert_possible = revert_possible;
        error.manual_intervention_required = !resume_possible && !revert_possible;
        error.disk_facts = self.record.last_disk_facts.clone();
        error
    }

    // -----------------------------------------------------------------
    // Disk observation helpers
    // -----------------------------------------------------------------

    fn observe_disk_facts(&self) -> DiskFacts {
        let plan = &self.record.plan;
        let backup_path = self.top_level_path(&plan.backup_root_path);
        let staging_path = self.top_level_path(&plan.staging_root_path);
        let active_root = self.mount_of(&plan.current_root.path);
        let filesystem = btrfs::show_filesystem(&self.opts.top_level_mount).ok();
        let active_root_generation = btrfs::show_subvolume(&active_root)
            .ok()
            .map(|identity| identity.generation);
        DiskFacts {
            backup_root_exists: backup_path.exists(),
            staging_root_exists: staging_path.exists(),
            active_root_exists: active_root.exists(),
            active_root_generation,
            filesystem_fsid: filesystem
                .map(|f| f.fsid)
                .unwrap_or_else(|| plan.filesystem.fsid.clone()),
        }
    }

    fn mount_of(&self, subvol_path: &str) -> PathBuf {
        // The btrfs top-level is mounted at opts.top_level_mount.
        // Subvolume paths are absolute relative to the toplevel; we
        // strip the leading slash and join.
        let rel = subvol_path.trim_start_matches('/');
        self.opts.top_level_mount.join(rel)
    }

    fn top_level_path(&self, abs_path: &str) -> PathBuf {
        // The plan stores paths absolute relative to the host root
        // (e.g. `/.catos-recovery/...`). The engine sees them under
        // the top-level mount.
        let rel = abs_path.trim_start_matches('/');
        self.opts.top_level_mount.join(rel)
    }

    // -----------------------------------------------------------------
    // Test-only fault injection
    // -----------------------------------------------------------------

    #[cfg(feature = "recovery_fault_injection")]
    fn maybe_inject_fault(&self) {
        let target = match std::env::var_os("CATOS_RECOVERY_FAULT_AT") {
            Some(value) => value.to_string_lossy().into_owned(),
            None => return,
        };
        let just_reached = self.record.state.code();
        if just_reached == target {
            // Simulate SIGKILL. Use raise(9) so the process dies the
            // same way a real kill -9 would, which exercises the
            // crash-recovery code path the same way the QEMU test
            // will.
            extern "C" {
                fn raise(sig: std::os::raw::c_int) -> std::os::raw::c_int;
            }
            unsafe {
                raise(9);
            }
            // unreachable, but be explicit
            std::process::exit(137);
        }
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn top_level_state_path(top_level_mount: &Path, transaction_id: &str) -> PathBuf {
    let rel = TransactionPaths::transactions_dir()
        .trim_start_matches('/')
        .to_string();
    top_level_mount
        .join(rel)
        .join(transaction_id)
        .join("state.json")
}

fn ensure_parent(path: &Path) -> Result<(), RecoveryError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                RecoveryError::new(
                    RecoveryErrorKind::SyscallFailed,
                    format!("cannot create {}: {e}", parent.display()),
                )
            })?;
        }
    }
    Ok(())
}

fn sanitize_fsid(fsid: &str) -> String {
    fsid.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn cpath(path: &Path) -> Result<std::ffi::CString, RecoveryError> {
    std::ffi::CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("path {} contains NUL", path.display()),
        )
    })
}

fn source_snapshot_fsid_via_path(snapshot_mounted: &Path, top_level_mount: &Path) -> String {
    // Best-effort FSID probe: the snapshot lives inside the same
    // filesystem as the top-level, so a show_filesystem on either
    // path returns the same FSID. If the call fails, fall back to an
    // empty string so the comparison is conservatively false.
    if let Ok(fs) = btrfs::show_filesystem(snapshot_mounted) {
        return fs.fsid;
    }
    if let Ok(fs) = btrfs::show_filesystem(top_level_mount) {
        return fs.fsid;
    }
    String::new()
}

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------

const AT_FDCWD: std::os::raw::c_int = -100;
const RENAME_EXCHANGE: std::os::raw::c_uint = 2;
const LOCK_EX: std::os::raw::c_int = 2;
// renameat2(2) syscall number on x86_64. musl does not ship a libc
// wrapper for renameat2 (glibc added one only in 2.28), so we issue
// the raw syscall directly.
const SYS_RENAMEAT2: i64 = 316;
// flock(2) is part of musl's libc, so we use the extern binding.
extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

fn libc_renameat2(
    olddirfd: std::os::raw::c_int,
    oldpath: *const std::os::raw::c_char,
    newdirfd: std::os::raw::c_int,
    newpath: *const std::os::raw::c_char,
    flags: std::os::raw::c_uint,
) -> std::os::raw::c_int {
    extern "C" {
        fn syscall(number: std::os::raw::c_long, ...) -> std::os::raw::c_long;
    }
    // SAFETY: renameat2 is a kernel syscall with the documented
    // signature. The pointers are owned by CString produced from
    // already-validated paths.
    unsafe {
        syscall(
            SYS_RENAMEAT2 as std::os::raw::c_long,
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags as std::os::raw::c_uint,
        ) as std::os::raw::c_int
    }
}

fn libc_flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int {
    // SAFETY: flock(2) is a kernel syscall with the documented
    // signature; the file descriptor is owned by the caller.
    unsafe { flock(fd, operation) }
}
