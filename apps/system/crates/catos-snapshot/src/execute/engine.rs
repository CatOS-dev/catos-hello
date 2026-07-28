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
//! via [`crate::plan::reconcile::reconcile_with_disk_facts`], and
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

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::diagnose::consistency::drift_between;
use crate::diagnose::enumerate as btrfs;
use crate::diagnose::identity::{ensure_target_is_not_running_root, is_protected_recovery_path};
use crate::execute::btrfs as btrfs_ops;
use crate::model::{
    BtrfsFilesystemIdentity, CompletedStep, DiskFacts, RecoveryPlan, SnapshotError,
    SnapshotErrorKind, SubvolumeFacts, TransactionPaths, TransactionRecord, TransactionState,
    TX_RECORD_SCHEMA_VERSION,
};
use crate::plan::reconcile::reconcile_with_disk_facts;
use crate::plan::verify_revert_confirmation_token;
use crate::store;
use crate::transaction::{lock_file_path, TransactionLock};
use crate::transaction::{resume_checkpoint, AdvanceAction, Intent};
use catos_target::execute::lock::{DeviceLock, DeviceLockError, DeviceLockErrorKind};

/// Engine options. Built by the orchestrator (phase3.rs) before the
/// engine runs. All paths are absolute; the orchestrator validates
/// them.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub top_level_mount: PathBuf,
    pub device_path: PathBuf,
    pub validated_filesystem: BtrfsFilesystemIdentity,
}

/// The engine. Owns the transaction record and drives the state
/// machine forward (or backward, on revert). Holds the per-FSID
/// exclusive lock for its entire lifetime when constructed via
/// [`Engine::begin`] or [`Engine::load_for_write`].
pub struct Engine {
    opts: EngineOptions,
    record: TransactionRecord,
    /// RAII guard for the per-FSID transaction lock. `None` only
    /// when the engine was loaded read-only via [`Engine::load`]
    /// (used by `status`). Construction via `begin` or
    /// `load_for_write` always holds a lock.
    lock: Option<TransactionLock>,
    _device_lock: Option<DeviceLock>,
}

impl Engine {
    /// Load an existing transaction record from disk for READ-ONLY
    /// access. Used by `status`. Does NOT acquire the per-FSID lock;
    /// concurrent write transactions are not blocked.
    pub fn load(opts: EngineOptions, transaction_id: &str) -> Result<Self, SnapshotError> {
        let state_path = top_level_state_path(&opts.top_level_mount, transaction_id);
        let record = store::load_record(&state_path)?;
        ensure_target_matches_plan(&record.plan, &opts.validated_filesystem)?;
        Ok(Self {
            opts,
            record,
            lock: None,
            _device_lock: None,
        })
    }

    /// Load an existing transaction record from disk for WRITE access
    /// and re-acquire the per-FSID lock. Used by `resume` and
    /// `revert`. Returns `TransactionAlreadyActive` immediately if
    /// another process holds the lock for the same FSID — the call
    /// does NOT block.
    //
    // Local allow: SnapshotError's size is the existing Phase-3
    // baseline trade-off (the task permits keeping structured
    // operator-facing fields rather than Boxing them away). All
    // other Result<_, SnapshotError> returns in this crate carry the
    // same warning; this new entry point inherits the same
    // allowance rather than shrink the error type.
    //
    // Boxing alternative considered and rejected: `Box<SnapshotError>`
    // would silence this warning but would force every caller in
    // phase3.rs and main.rs to dereference the box to read
    // `last_error.kind`, `last_error.resume_possible`, etc. — fields
    // the CLI's JSON envelope serialises by value. The cost
    // (touching the public `RecoveryOutcome` enum, the JSON renderer,
    // and the human formatter) outweighs the silence here.
    #[allow(clippy::result_large_err)]
    pub fn load_for_write(
        opts: EngineOptions,
        transaction_id: &str,
    ) -> Result<Self, SnapshotError> {
        let (record, lock, device_lock) = load_record_under_lock(&opts, transaction_id)?;
        let mut engine = Self {
            opts,
            record,
            lock: Some(lock),
            _device_lock: device_lock,
        };
        // Reconcile the persisted state with current disk facts BEFORE
        // any action runs. This is the load-bearing fix for the
        // pre-persist crash window: if the previous apply/revert
        // created a subvolume (or performed the renameat2 swap) and
        // then crashed before persisting the matching state advance,
        // the on-disk record lags reality. Without this reconcile,
        // `drive()` would re-execute the destructive action.
        // The reconciled state is persisted so subsequent `status`
        // and a crash during this resume observe the corrected state.
        engine.reconcile_state_for_write("resume-reconcile")?;
        Ok(engine)
    }

    /// Load an existing transaction for an explicit revert. The FSID
    /// lock is acquired first, then the confirmation token is checked
    /// against freshly observed disk facts before any reconciliation is
    /// persisted or any reverse exchange can run.
    pub fn load_for_revert(
        opts: EngineOptions,
        transaction_id: &str,
        presented_confirmation: &str,
    ) -> Result<Self, SnapshotError> {
        let (record, lock, device_lock) = load_record_under_lock(&opts, transaction_id)?;
        let mut engine = Self {
            opts,
            record,
            lock: Some(lock),
            _device_lock: device_lock,
        };

        let facts = engine.reconcile_status();
        verify_revert_confirmation_token(
            &engine.record.transaction_id,
            &engine.record.plan.plan_digest,
            &facts.filesystem_fsid,
            engine.record.state.code(),
            &engine.record.plan.nonce,
            presented_confirmation,
        )?;
        if engine.record.state == TransactionState::FailedManualIntervention {
            return Err(engine.failure(
                SnapshotErrorKind::RootSwitchConflict,
                "transaction facts require manual intervention; explicit revert is not safe",
                false,
                false,
            ));
        }
        engine.reconcile_state_for_write("revert-reconcile")?;
        Ok(engine)
    }

    /// Reconcile the persisted state against current disk facts and
    /// persist the reconciled state. Used by `load_for_write` on the
    /// write path. Differs from `reconcile_status` (which is
    /// read-only and drift-tolerant) in that it MUST persist the
    /// reconciled state, because `drive()` and `revert()` consult
    /// `record.state` to pick their next action.
    fn reconcile_state_for_write(&mut self, reason: &str) -> Result<(), SnapshotError> {
        let facts = self.observe_disk_facts();
        let checkpoint =
            resume_checkpoint(&self.record).unwrap_or(TransactionState::FailedManualIntervention);
        let reconciled = reconcile_with_disk_facts(checkpoint, &self.record.plan, &facts);
        if reconciled != self.record.state {
            self.record.state = reconciled;
            self.record.last_updated_unix = now_unix();
            self.record.last_disk_facts = Some(facts);
            self.persist_record(reason)?;
        } else if self.record.last_disk_facts.as_ref() != Some(&facts) {
            self.record.last_disk_facts = Some(facts);
            self.persist_record(reason)?;
        }
        Ok(())
    }

    /// Construct an engine from a freshly-built plan and persist the
    /// initial record. Used by `apply`. Acquires the per-FSID lock
    /// BEFORE the initial record is written, so two concurrent
    /// `apply` invocations against the same FSID cannot both reach
    /// the persist step.
    pub fn begin(opts: EngineOptions, plan: RecoveryPlan) -> Result<Self, SnapshotError> {
        crate::verify::validate_plan_shape(&plan)?;
        let transaction_id = plan.plan_id.clone();
        ensure_target_matches_plan(&plan, &opts.validated_filesystem)?;
        let fsid = opts.validated_filesystem.fsid.clone();
        let lock = acquire_lock_guard(&opts.top_level_mount, &fsid).map_err(|e| *e)?;
        let device_lock = DeviceLock::try_acquire_if_block_device(&opts.device_path)
            .map_err(snapshot_device_lock_error)?;
        let plan_path = top_level_plan_path(&opts.top_level_mount, &transaction_id);
        store::persist_plan(&plan_path, &plan)?;
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
        let mut engine = Self {
            opts,
            record,
            lock: Some(lock),
            _device_lock: device_lock,
        };
        engine.persist_record("begin")?;
        Ok(engine)
    }

    /// Persist the recovery rw session's [`CleanupSummary`] into the
    /// transaction record's `last_cleanup` field. Atomic and fsynced
    /// via the standard record-persist path.
    ///
    /// Persistence rules:
    ///
    /// * `last_error` is preserved. A cleanup failure MUST NOT erase
    ///   the operation failure that preceded it; both are part of
    ///   the durable record.
    /// * If the persistence itself fails, the original operation
    ///   error (if any) is preserved and the persistence failure is
    ///   attached via `record_persistence_error`. The caller
    ///   surfaces both.
    /// * `last_updated_unix` advances so dashboards can see the
    ///   cleanup actually happened.
    pub fn attach_cleanup(
        &mut self,
        summary: crate::model::CleanupSummary,
    ) -> Result<(), SnapshotError> {
        self.record.last_cleanup = Some(summary);
        self.record.last_updated_unix = now_unix();
        self.persist_record("attach-cleanup")
    }

    /// Read-only access to the current record.
    pub fn record(&self) -> &TransactionRecord {
        &self.record
    }

    /// Mutable access to the in-memory record. Used by phase3's
    /// post-cleanup restamping: after the rw mount session is torn
    /// down the on-disk record is unreachable, but the in-memory
    /// record is still serialised into the process's JSON output.
    /// Restamping the in-memory record with the real cleanup
    /// summary lets the renderer emit the truth even though the
    /// on-disk record carries the pre-teardown placeholder.
    pub fn record_mut(&mut self) -> &mut TransactionRecord {
        &mut self.record
    }

    /// Drive the transaction forward as far as it can go without
    /// failing. Returns the final state on success or the first
    /// failure encountered. On failure, the failure state is
    /// persisted to disk BEFORE the error is returned, so `status`
    /// and `resume` observe `failed_recoverable` /
    /// `failed_manual_intervention` rather than the last
    /// successfully-persisted pre-failure state.
    pub fn drive(&mut self) -> Result<TransactionState, SnapshotError> {
        match self.drive_inner() {
            Ok(state) => Ok(state),
            Err(error) => {
                let with_state = self.attach_transaction_context(*error);
                let final_error = self.persist_failure_state(with_state);
                Err(final_error)
            }
        }
    }

    // Private helper: returns `Box<SnapshotError>` so the result fits
    // in a single machine word. Boxing here has zero API cost (the
    // caller is `drive`, which immediately dereferences via
    // `attach_transaction_context`) and silences clippy's
    // large-result lint without weakening structured error info.
    fn drive_inner(&mut self) -> Result<TransactionState, Box<SnapshotError>> {
        loop {
            let state = self.record.state;
            if state.is_terminal() {
                return Ok(state);
            }
            let action = match state.advance_action() {
                Some(action) => action,
                None => return Ok(state),
            };
            self.perform_action(action).map_err(Box::new)?;
            #[cfg(feature = "recovery_fault_injection")]
            self.maybe_inject_fault();
        }
    }

    /// Run the revert path. Idempotent: re-running on an already-
    /// reverted transaction returns success without doing anything.
    /// On failure, the failure state is persisted before the error
    /// is returned.
    // Public API entry point. Local allow: this is the only public
    // signature that still returns `Result<_, SnapshotError>`
    // unboxed (apart from `drive`, `begin`, `load_for_write`,
    // `load`). Boxing here would change the public API consumed by
    // phase3.rs::run_revert, which surfaces the error via the JSON
    // envelope `RecoveryOutcome`. Boxing would force recovery code to
    // dereference before serialising, and would change the visible
    // signature in any future external consumer of `Engine::revert`.
    // The internal helpers (`drive_inner`, `revert_inner`,
    // `acquire_lock_guard`) ARE boxed (see each) so the only
    // unboxed returns are the public entry points the JSON envelope
    // depends on.
    #[allow(clippy::result_large_err)]
    pub fn revert(&mut self) -> Result<TransactionState, SnapshotError> {
        match self.revert_inner() {
            Ok(state) => Ok(state),
            Err(error) => {
                let with_state = self.attach_transaction_context(*error);
                let final_error = self.persist_failure_state(with_state);
                Err(final_error)
            }
        }
    }

    // Private helper: same Box<SnapshotError> rationale as
    // `drive_inner`. Caller (`revert`) immediately dereferences.
    fn revert_inner(&mut self) -> Result<TransactionState, Box<SnapshotError>> {
        let state = self.record.state;
        if state == TransactionState::Reverted {
            return Ok(state);
        }

        // When the persisted state is `Reverting` (a previous revert
        // crashed mid-revert), consult disk facts to decide whether
        // the reverse swap already happened. If it did, persist
        // `Reverted` and return; otherwise fall through to perform
        // the reverse swap. This is the symmetric counterpart of the
        // apply-path pre-persist crash window.
        if state == TransactionState::Reverting {
            return self.resume_reverting();
        }

        // `Completed + Intent::Revert -> Reverting` is a legal
        // transition (see state.rs::transition); the state machine
        // permits it as the only terminal-state exception. Routing
        // uniformly through `transition()` keeps the engine in sync
        // with the authoritative transition table.
        self.transition(Intent::Revert, "revert-begin")?;

        // Revert actions depend on the LAST persisted state before
        // the Reverting marker. Recover it from the completed_steps
        // history.
        let last_persistent = last_revert_checkpoint(&self.record.completed_steps);

        match last_persistent {
            TransactionState::Planned
            | TransactionState::PreflightVerified
            | TransactionState::Locked => {
                self.remove_record()?;
                return Ok(TransactionState::Reverted);
            }
            TransactionState::BackupCreated => {
                self.persist_reverted("revert-after-backup")?;
            }
            TransactionState::ReplacementCreated => {
                self.persist_reverted("revert-after-replacement")?;
            }
            TransactionState::OldRootMoved
            | TransactionState::NewRootInstalled
            | TransactionState::Verifying => {
                self.swap_roots_back()?;
                self.persist_reverted("revert-after-swap")?;
            }
            TransactionState::Reverting | TransactionState::Reverted => {}
            TransactionState::FailedRecoverable | TransactionState::FailedManualIntervention => {
                unreachable!("failure markers are filtered by last_revert_checkpoint")
            }
            TransactionState::Completed => {
                self.swap_roots_back()?;
                self.persist_reverted("revert-completed")?;
            }
        }
        Ok(TransactionState::Reverted)
    }

    /// Resume a revert that crashed after entering `Reverting`. The
    /// previous revert may have already performed the reverse swap
    /// (renameat2 succeeded, persist of `Reverted` did not). Consult
    /// disk facts to decide:
    /// * if the active root is back to the planned current root AND
    ///   the staging path still exists, the reverse swap is done —
    ///   persist `Reverted` and return.
    /// * if the active root is still the post-swap (new) root, the
    ///   reverse swap has NOT happened — perform it, then persist
    ///   `Reverted`.
    /// * otherwise (ambiguous), surface `FailedManualIntervention`.
    // Private helper: same Box<SnapshotError> rationale as
    // `revert_inner`.
    fn resume_reverting(&mut self) -> Result<TransactionState, Box<SnapshotError>> {
        let facts = self.observe_disk_facts();
        let reverse_done =
            crate::plan::reconcile::reverse_swap_appears_done(&self.record.plan, &facts);
        let swap_done = crate::plan::reconcile::swap_appears_done(&self.record.plan, &facts);
        if reverse_done {
            self.persist_reverted("revert-resume-after-reverse-swap")?;
            return Ok(TransactionState::Reverted);
        }
        if swap_done {
            self.swap_roots_back()?;
            self.persist_reverted("revert-resume-perform-reverse-swap")?;
            return Ok(TransactionState::Reverted);
        }
        Err(Box::new(self.failure(
            SnapshotErrorKind::RootSwitchConflict,
            "cannot resume revert: disk facts are ambiguous about whether the reverse swap happened",
            false,
            false,
        )))
    }

    /// Reconcile the persisted state with the disk facts observed
    /// now. Used by `status`. READ-ONLY: this method does NOT persist
    /// anything. The reconciled state is returned via the in-memory
    /// `record.state` for the caller to render in the status report;
    /// the on-disk record is left untouched so `status` cannot
    /// accidentally mutate the transaction. The CLI's `status`
    /// command also mounts the btrfs top-level read-only (see
    /// `recovery::mount_btrfs_toplevel_ro`), giving a two-layer
    /// guarantee that status is non-mutating.
    ///
    /// Detects terminal-state drift: if the persisted state is
    /// terminal (Completed / Reverted) but the current disk facts
    /// disagree with the last-persisted disk facts in a load-bearing
    /// way, the reconciled state is downgraded to
    /// `FailedManualIntervention` in the in-memory view so the
    /// operator is forced to review before any further action.
    pub fn reconcile_status(&mut self) -> DiskFacts {
        let facts = self.observe_disk_facts();
        let persisted_state = self.record.state;
        let checkpoint =
            resume_checkpoint(&self.record).unwrap_or(TransactionState::FailedManualIntervention);
        let reconciled = reconcile_with_disk_facts(checkpoint, &self.record.plan, &facts);

        // Terminal drift detection: a Completed / Reverted record
        // whose disk facts have drifted since persist is NOT
        // trustworthy. Surface as FailedManualIntervention in the
        // in-memory view (NOT persisted).
        let reconciled = if persisted_state.is_terminal()
            && reconciled.is_terminal()
            && self.terminal_drift_detected(&facts)
        {
            self.record.last_error = Some(self.terminal_drift_error(&facts));
            TransactionState::FailedManualIntervention
        } else {
            reconciled
        };

        // Mutate the in-memory record only. Callers that need the
        // reconciled view (status report) read it via `record()`.
        // The on-disk record is NOT touched.
        self.record.state = reconciled;
        self.record.last_disk_facts = Some(facts.clone());
        facts
    }

    /// Compare the freshly observed disk facts against the
    /// last-persisted disk facts. Returns `true` when a load-bearing
    /// identity axis has drifted. Existence-only checks are used for
    /// backup / staging because the recovery model does not pin a
    /// "expected" UUID for them post-completion (the post-swap
    // staging path legitimately holds either the old root OR the
    // new root depending on the operation); for the active root and
    // the filesystem FSID we compare directly against the persisted
    // facts AND the plan.
    fn terminal_drift_detected(&self, facts: &DiskFacts) -> bool {
        // FSID drift is always load-bearing: a different btrfs
        // filesystem means we are no longer looking at the recovery
        // we performed.
        if facts.filesystem_fsid != self.record.plan.filesystem.fsid {
            return true;
        }
        let Some(expected) = self.record.last_disk_facts.as_ref() else {
            return true;
        };
        expected.active_root_exists != facts.active_root_exists
            || expected.staging_root_exists != facts.staging_root_exists
            || expected.backup_root_exists != facts.backup_root_exists
            || expected.source_snapshot_exists != facts.source_snapshot_exists
            || !stable_subvolume_identity_matches(
                expected.active_root.as_ref(),
                facts.active_root.as_ref(),
                false,
            )
            || !stable_subvolume_identity_matches(
                expected.staging_root.as_ref(),
                facts.staging_root.as_ref(),
                false,
            )
            || !stable_subvolume_identity_matches(
                expected.backup.as_ref(),
                facts.backup.as_ref(),
                true,
            )
            || !stable_subvolume_identity_matches(
                expected.source_snapshot.as_ref(),
                facts.source_snapshot.as_ref(),
                true,
            )
    }

    fn terminal_drift_error(&self, facts: &DiskFacts) -> SnapshotError {
        let mut msg = String::from("terminal state drift detected: ");
        if facts.filesystem_fsid != self.record.plan.filesystem.fsid {
            msg.push_str(&format!(
                "filesystem fsid changed from {} to {}",
                self.record.plan.filesystem.fsid, facts.filesystem_fsid
            ));
        } else {
            msg.push_str(
                "active root, staging, backup, or source snapshot identity no longer matches the persisted record",
            );
        }
        let mut err = SnapshotError::new(SnapshotErrorKind::TargetChanged, msg);
        err.transaction_id = Some(self.record.transaction_id.clone());
        err.current_state = Some(self.record.state);
        err.manual_intervention_required = true;
        err.resume_possible = false;
        err.revert_possible = false;
        err.disk_facts = Some(Box::new(facts.clone()));
        err
    }

    // -----------------------------------------------------------------
    // Action implementations
    // -----------------------------------------------------------------

    fn perform_action(&mut self, action: AdvanceAction) -> Result<(), SnapshotError> {
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
    fn do_preflight(&mut self) -> Result<(), SnapshotError> {
        let plan = &self.record.plan;
        if is_protected_recovery_path(&plan.current_root.path)
            || is_protected_recovery_path(&plan.source_snapshot.path)
        {
            return Err(self.failure(
                SnapshotErrorKind::TargetChanged,
                "refusing to plan against the protected /.catos-recovery path",
                true,
                false,
            ));
        }

        // Re-observe filesystem + subvolume identities.
        let filesystem = self.opts.validated_filesystem.clone();
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
                SnapshotErrorKind::SnapshotNotReadonly,
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
                SnapshotErrorKind::SnapshotBelongsToAnotherFsid,
                "source snapshot belongs to a different btrfs filesystem",
                false,
                true,
            ));
        }

        ensure_target_is_not_running_root(&filesystem, &current_root)
            .map_err(|error| self.failure_from(error, false, false))?;

        // Verify the backup and staging paths are not already
        // occupied by a foreign object.
        let backup_path = self.top_level_path(&plan.backup_root_path);
        let staging_path = self.top_level_path(&plan.staging_root_path);
        if backup_path.exists() {
            return Err(self.failure(
                SnapshotErrorKind::BackupPathOccupied,
                format!("backup path {} already exists", backup_path.display()),
                true,
                true,
            ));
        }
        if staging_path.exists() {
            return Err(self.failure(
                SnapshotErrorKind::StagingPathOccupied,
                format!("staging path {} already exists", staging_path.display()),
                true,
                true,
            ));
        }

        self.transition(Intent::Advance, "preflight")?;
        Ok(())
    }

    /// State-machine-only passthrough. The lock itself is acquired at
    /// engine construction ([`Engine::begin`] / [`Engine::load_for_write`]);
    /// this hook exists so the persisted record reaches the `Locked`
    /// state in the same order the happy-path spec describes.
    ///
    /// We DO verify the lock guard is held: a code bug that constructs
    /// a write-engine without the lock would otherwise silently
    /// regress to the pre-Group-1 race.
    fn do_acquire_lock(&mut self) -> Result<(), SnapshotError> {
        if self.lock.is_none() {
            return Err(self.failure(
                SnapshotErrorKind::SyscallFailed,
                "engine invariant violation: write-path action reached do_acquire_lock \
                 without a held TransactionLock guard",
                false,
                false,
            ));
        }
        self.transition(Intent::Advance, "acquire-lock")?;
        Ok(())
    }

    fn do_create_backup(&mut self) -> Result<(), SnapshotError> {
        let plan = &self.record.plan;
        #[cfg(feature = "recovery_fault_injection")]
        self.maybe_inject_before_fault("create_backup");
        btrfs_ops::create_btrfs_snapshot(
            &self.opts.top_level_mount,
            &plan.current_root.path,
            &plan.backup_root_path,
            true,
        )
        .map_err(|e| {
            let mut err = self.failure_from(e, true, true);
            err.failed_step = Some("create-backup".into());
            err
        })?;
        self.record.last_disk_facts = Some(self.observe_disk_facts());
        #[cfg(feature = "recovery_fault_injection")]
        self.maybe_inject_pre_fault("create_backup");
        self.transition(Intent::Advance, "create-backup")?;
        Ok(())
    }

    fn do_create_replacement(&mut self) -> Result<(), SnapshotError> {
        let plan = &self.record.plan;
        #[cfg(feature = "recovery_fault_injection")]
        self.maybe_inject_before_fault("create_replacement");
        btrfs_ops::create_btrfs_snapshot(
            &self.opts.top_level_mount,
            &plan.source_snapshot.path,
            &plan.staging_root_path,
            false,
        )
        .map_err(|e| {
            let mut err = self.failure_from(e, true, true);
            err.failed_step = Some("create-replacement".into());
            err
        })?;
        self.record.last_disk_facts = Some(self.observe_disk_facts());
        #[cfg(feature = "recovery_fault_injection")]
        self.maybe_inject_pre_fault("create_replacement");
        self.transition(Intent::Advance, "create-replacement")?;
        Ok(())
    }

    /// Swap the active root and the staging subvolume via
    /// `renameat2(RENAME_EXCHANGE)`. On modern Linux + btrfs this is
    /// a single atomic metadata transaction that exchanges two
    /// subvolumes in place, regardless of whether either is mounted
    /// elsewhere.
    fn do_swap_roots(&mut self) -> Result<(), SnapshotError> {
        let plan = &self.record.plan;
        #[cfg(feature = "recovery_fault_injection")]
        self.maybe_inject_before_fault("swap_roots");
        btrfs_ops::exchange_rooted_paths(
            &self.opts.top_level_mount,
            &plan.current_root.path,
            &plan.staging_root_path,
        )
        .map_err(|error| {
            let mut error = self.failure_from(error, true, true);
            error.failed_step = Some("swap-roots".into());
            error
        })?;

        self.record.last_disk_facts = Some(self.observe_disk_facts());
        #[cfg(feature = "recovery_fault_injection")]
        self.maybe_inject_pre_fault("swap_roots");
        self.transition(Intent::Advance, "swap-roots")?;
        Ok(())
    }

    fn do_verify_new_root(&mut self) -> Result<(), SnapshotError> {
        let plan = &self.record.plan;
        let new_root = self.mount_of(&plan.current_root.path);
        // The new root must look like a CatOS root.
        if !new_root.join("etc/os-release").exists()
            && !new_root.join("usr/lib/os-release").exists()
        {
            return Err(self
                .failure(
                    SnapshotErrorKind::TargetChanged,
                    "new root does not contain /etc/os-release or /usr/lib/os-release",
                    true,
                    true,
                )
                .with_failed_step("verify-new-root"));
        }
        if !new_root.join("usr/lib/modules").exists() {
            return Err(self
                .failure(
                    SnapshotErrorKind::TargetChanged,
                    "new root does not contain /usr/lib/modules",
                    true,
                    true,
                )
                .with_failed_step("verify-new-root"));
        }
        self.transition(Intent::Advance, "verify-new-root")?;
        Ok(())
    }

    // Boot consistency is intentionally not checked here: phase3
    // recomputes the read-only BootConsistencyReport and enforces it
    // before Engine::begin, so refusal still has zero target-side
    // writes. This engine must never call a bootloader tool or write
    // `/boot`, the ESP, UKIs, initramfs images, or firmware entries.

    fn do_verify_final(&mut self) -> Result<(), SnapshotError> {
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
    fn swap_roots_back(&mut self) -> Result<(), SnapshotError> {
        let plan = &self.record.plan;
        #[cfg(feature = "recovery_fault_injection")]
        self.maybe_inject_before_fault("swap_roots_back");
        btrfs_ops::exchange_rooted_paths(
            &self.opts.top_level_mount,
            &plan.current_root.path,
            &plan.staging_root_path,
        )
        .map_err(|error| {
            let mut error = self.failure_from(error, false, false);
            error.failed_step = Some("swap-roots-back".into());
            error
        })?;
        #[cfg(feature = "recovery_fault_injection")]
        self.maybe_inject_pre_fault("swap_roots_back");
        Ok(())
    }

    // -----------------------------------------------------------------
    // State persistence helpers
    // -----------------------------------------------------------------

    fn transition(&mut self, intent: Intent, description: &str) -> Result<(), SnapshotError> {
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

    fn persist_reverted(&mut self, description: &str) -> Result<(), SnapshotError> {
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

    fn persist_record(&mut self, reason: &str) -> Result<(), SnapshotError> {
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

    fn remove_record(&mut self) -> Result<(), SnapshotError> {
        let state_path =
            top_level_state_path(&self.opts.top_level_mount, &self.record.transaction_id);
        store::remove_record(&state_path)?;
        Ok(())
    }

    fn failure(
        &self,
        kind: SnapshotErrorKind,
        message: impl Into<String>,
        resume_possible: bool,
        revert_possible: bool,
    ) -> SnapshotError {
        let mut error = SnapshotError::new(kind, message);
        error.transaction_id = Some(self.record.transaction_id.clone());
        error.current_state = Some(self.record.state);
        error.completed_steps = Box::new(
            self.record
                .completed_steps
                .iter()
                .map(|s| format!("{:?}: {}", s.state, s.description))
                .collect(),
        );
        error.resume_possible = resume_possible;
        error.revert_possible = revert_possible;
        error.manual_intervention_required = !resume_possible && !revert_possible;
        error.disk_facts = self.record.last_disk_facts.clone().map(Box::new);
        error
    }

    fn failure_from(
        &self,
        mut error: SnapshotError,
        resume_possible: bool,
        revert_possible: bool,
    ) -> SnapshotError {
        error.transaction_id = Some(self.record.transaction_id.clone());
        error.current_state = Some(self.record.state);
        error.completed_steps = Box::new(
            self.record
                .completed_steps
                .iter()
                .map(|s| format!("{:?}: {}", s.state, s.description))
                .collect(),
        );
        error.resume_possible = resume_possible;
        error.revert_possible = revert_possible;
        error.manual_intervention_required = !resume_possible && !revert_possible;
        error.disk_facts = self.record.last_disk_facts.clone().map(Box::new);
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
        let snapshot_mounted = self.mount_of(&plan.source_snapshot.path);
        let filesystem_fsid = self.opts.validated_filesystem.fsid.clone();

        let active_root_facts = if active_root.exists() {
            btrfs::probe_subvolume_facts(&active_root).ok()
        } else {
            None
        };
        let staging_facts = if staging_path.exists() {
            btrfs::probe_subvolume_facts(&staging_path).ok()
        } else {
            None
        };
        let backup_facts = if backup_path.exists() {
            btrfs::probe_subvolume_facts(&backup_path).ok()
        } else {
            None
        };
        let source_facts = if snapshot_mounted.exists() {
            btrfs::probe_subvolume_facts(&snapshot_mounted).ok()
        } else {
            None
        };

        DiskFacts {
            filesystem_fsid,
            active_root_exists: active_root.exists(),
            active_root: active_root_facts,
            staging_root_exists: staging_path.exists(),
            staging_root: staging_facts,
            backup_root_exists: backup_path.exists(),
            backup: backup_facts,
            source_snapshot_exists: snapshot_mounted.exists(),
            source_snapshot: source_facts,
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
            kill_for_fault_injection();
        }
    }

    /// Before-operation fault injection. Triggered by
    /// `CATOS_RECOVERY_FAULT_BEFORE_AT=<step>`. This runs before the
    /// first persistent side effect of the named action.
    #[cfg(feature = "recovery_fault_injection")]
    fn maybe_inject_before_fault(&self, step: &str) {
        let target = match std::env::var_os("CATOS_RECOVERY_FAULT_BEFORE_AT") {
            Some(value) => value.to_string_lossy().into_owned(),
            None => return,
        };
        if target == step {
            kill_for_fault_injection();
        }
    }

    /// Pre-persist fault injection. Triggered by
    /// `CATOS_RECOVERY_FAULT_PRE_AT=<step>` where `<step>` matches
    /// one of the engine action codes (`create_backup`,
    /// `create_replacement`, `swap_roots`, `swap_roots_back`).
    ///
    /// Distinct from `CATOS_RECOVERY_FAULT_AT` (which fires AFTER a
    /// state transition is persisted): this hook fires AFTER the
    /// on-disk side-effect of an action is visible but BEFORE the
    /// state transition is persisted, so the next `resume` observes
    /// the side-effect without the matching state advance. This is
    /// the load-bearing window for forward-progress reconciliation.
    #[cfg(feature = "recovery_fault_injection")]
    fn maybe_inject_pre_fault(&self, step: &str) {
        let target = match std::env::var_os("CATOS_RECOVERY_FAULT_PRE_AT") {
            Some(value) => value.to_string_lossy().into_owned(),
            None => return,
        };
        if target == step {
            kill_for_fault_injection();
        }
    }

    // -----------------------------------------------------------------
    // Failure-state persistence
    // -----------------------------------------------------------------

    /// Stamp a freshly-built `SnapshotError` with the engine's
    /// transaction id, current state, completed-step history, and
    /// freshly observed disk facts so the persisted record carries
    /// the full context an operator needs to triage.
    fn attach_transaction_context(&self, mut error: SnapshotError) -> SnapshotError {
        if error.transaction_id.is_none() {
            error.transaction_id = Some(self.record.transaction_id.clone());
        }
        if error.current_state.is_none() {
            error.current_state = Some(self.record.state);
        }
        if error.completed_steps.is_empty() {
            error.completed_steps = Box::new(
                self.record
                    .completed_steps
                    .iter()
                    .map(|s| format!("{:?}: {}", s.state, s.description))
                    .collect(),
            );
        }
        if error.disk_facts.is_none() {
            error.disk_facts = Some(Box::new(self.observe_disk_facts()));
        }
        error
    }

    /// Persist the failure state to disk so `status` and `resume`
    /// observe `failed_recoverable` / `failed_manual_intervention`
    /// instead of the last successfully-persisted pre-failure state.
    ///
    /// If the persistence itself fails, the original error is
    /// returned with `record_persistence_error` populated so the
    /// operator sees BOTH the operation failure and the persistence
    /// failure.
    fn persist_failure_state(&mut self, mut error: SnapshotError) -> SnapshotError {
        let intent = if error.manual_intervention_required || !error.resume_possible {
            Intent::FailManual
        } else {
            Intent::FailRecoverable
        };
        let now = now_unix();
        let next_state = match self.record.state.transition(intent) {
            Ok(next) => next,
            // Already terminal (e.g. a verification failure happened
            // after the engine already reached Completed via a race).
            // We cannot persist a failure state from a terminal
            // state; surface the original error as-is.
            Err(_) => return error,
        };
        self.record.state = next_state;
        self.record.last_updated_unix = now;
        self.record.last_error = Some(error.clone());
        self.record.last_disk_facts = error.disk_facts.as_deref().cloned();
        match self.persist_record("persist-failure-state") {
            Ok(()) => error,
            Err(persist_err) => {
                error.record_persistence_error = Some(
                    format!(
                        "failed to persist failure state to disk: {} (kind={})",
                        persist_err.message,
                        persist_err.kind.code()
                    )
                    .into_boxed_str(),
                );
                error
            }
        }
    }

    /// Test-only entry point for verifying the on-disk failure record
    /// contract without pretending an ordinary temporary directory can
    /// provide real btrfs subvolume identity. Real operation failures
    /// remain covered by the QEMU acceptance scenarios.
    #[cfg(feature = "test-helpers")]
    pub fn persist_failure_for_test(&mut self, error: SnapshotError) -> SnapshotError {
        self.persist_failure_state(error)
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

fn last_revert_checkpoint(completed_steps: &[CompletedStep]) -> TransactionState {
    completed_steps
        .iter()
        .rev()
        .find(|step| {
            !matches!(
                step.state,
                TransactionState::Reverting
                    | TransactionState::FailedRecoverable
                    | TransactionState::FailedManualIntervention
            )
        })
        .map(|step| step.state)
        .unwrap_or(TransactionState::Planned)
}

fn stable_subvolume_identity_matches(
    expected: Option<&SubvolumeFacts>,
    observed: Option<&SubvolumeFacts>,
    compare_generation: bool,
) -> bool {
    match (expected, observed) {
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
        (Some(expected), Some(observed)) => {
            expected.path == observed.path
                && expected.subvolume_id == observed.subvolume_id
                && expected.uuid == observed.uuid
                && expected.parent_uuid == observed.parent_uuid
                && expected.read_only == observed.read_only
                && (!compare_generation || expected.generation == observed.generation)
        }
    }
}

#[cfg(feature = "recovery_fault_injection")]
fn kill_for_fault_injection() -> ! {
    extern "C" {
        fn raise(sig: std::os::raw::c_int) -> std::os::raw::c_int;
    }
    unsafe {
        raise(9);
    }
    std::process::exit(137)
}

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

fn top_level_plan_path(top_level_mount: &Path, transaction_id: &str) -> PathBuf {
    let rel = TransactionPaths::transactions_dir().trim_start_matches('/');
    top_level_mount
        .join(rel)
        .join(transaction_id)
        .join("plan.json")
}

fn ensure_target_matches_plan(
    plan: &RecoveryPlan,
    observed: &BtrfsFilesystemIdentity,
) -> Result<(), SnapshotError> {
    if plan.filesystem.fsid != observed.fsid
        || plan.filesystem.device_major_minor != observed.device_major_minor
    {
        return Err(SnapshotError::new(
            SnapshotErrorKind::StalePlan,
            format!(
                "target filesystem identity changed: plan fsid={} major:minor={}, observed fsid={} major:minor={}",
                plan.filesystem.fsid,
                plan.filesystem.device_major_minor,
                observed.fsid,
                observed.device_major_minor
            ),
        ));
    }
    Ok(())
}

/// Open the per-FSID lock through the confined storage layer and
/// acquire the non-blocking exclusive lock. Returns a guard whose Drop releases. Used by
/// [`Engine::begin`] and [`Engine::load_for_write`].
//
// Private free helper. Returns `Box<SnapshotError>` for the same
// reason as `drive_inner` / `revert_inner`: callers (`Engine::begin`
// and `Engine::load_for_write`) propagate via `?` and surface the
// unboxed error to their own callers, so the box never escapes the
// engine module.
fn snapshot_device_lock_error(error: DeviceLockError) -> SnapshotError {
    let kind = if error.kind == DeviceLockErrorKind::Busy {
        SnapshotErrorKind::TransactionAlreadyActive
    } else {
        SnapshotErrorKind::SyscallFailed
    };
    SnapshotError::new(kind, error.message)
}

fn acquire_lock_guard(
    top_level_mount: &Path,
    fsid: &str,
) -> Result<TransactionLock, Box<SnapshotError>> {
    let lock_path = lock_file_path(top_level_mount, fsid);
    TransactionLock::try_acquire(&lock_path, fsid).map_err(Box::new)
}

/// Acquire the per-FSID write lock before reading mutable transaction
/// state. Reading first would leave a TOCTOU window where another writer
/// could update the record and release the lock before this process
/// acquired it, causing the stale record to be replayed under a valid
/// lock.
#[allow(clippy::result_large_err)]
fn load_record_under_lock(
    opts: &EngineOptions,
    transaction_id: &str,
) -> Result<(TransactionRecord, TransactionLock, Option<DeviceLock>), SnapshotError> {
    let fsid = opts.validated_filesystem.fsid.clone();
    let lock = acquire_lock_guard(&opts.top_level_mount, &fsid).map_err(|error| *error)?;
    let device_lock = DeviceLock::try_acquire_if_block_device(&opts.device_path)
        .map_err(snapshot_device_lock_error)?;
    let state_path = top_level_state_path(&opts.top_level_mount, transaction_id);
    let record = store::load_record(&state_path)?;
    ensure_target_matches_plan(&record.plan, &opts.validated_filesystem)?;
    Ok((record, lock, device_lock))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn step(state: TransactionState) -> CompletedStep {
        CompletedStep {
            state,
            completed_at_unix: 1,
            description: state.code().into(),
        }
    }

    fn facts(uuid: &str, generation: u64, read_only: bool) -> SubvolumeFacts {
        SubvolumeFacts {
            path: "/@".into(),
            subvolume_id: Some(256),
            generation: Some(generation),
            uuid: Some(uuid.into()),
            parent_uuid: Some("parent-uuid".into()),
            read_only: Some(read_only),
        }
    }

    #[test]
    fn revert_checkpoint_ignores_failure_and_reverting_markers() {
        let completed = vec![
            step(TransactionState::Planned),
            step(TransactionState::OldRootMoved),
            step(TransactionState::FailedRecoverable),
            step(TransactionState::Reverting),
        ];
        assert_eq!(
            last_revert_checkpoint(&completed),
            TransactionState::OldRootMoved
        );
    }

    #[test]
    fn writable_identity_allows_generation_advance_but_not_uuid_drift() {
        let expected = facts("root-uuid", 10, false);
        let mut observed = facts("root-uuid", 20, false);
        assert!(stable_subvolume_identity_matches(
            Some(&expected),
            Some(&observed),
            false
        ));
        observed.uuid = Some("foreign-uuid".into());
        assert!(!stable_subvolume_identity_matches(
            Some(&expected),
            Some(&observed),
            false
        ));
    }

    #[test]
    fn readonly_identity_requires_generation_to_remain_stable() {
        let expected = facts("snapshot-uuid", 10, true);
        let observed = facts("snapshot-uuid", 11, true);
        assert!(!stable_subvolume_identity_matches(
            Some(&expected),
            Some(&observed),
            true
        ));
    }
}
