//! Phase-3 recovery orchestrators.
//!
//! Sits between `entry.rs` and the `recovery/*` engine. Owns the
//! side-effects the engine does NOT own: discovering the target
//! filesystem, mounting the btrfs top-level inside a private
//! namespace, surfacing structured errors as JSON envelopes.
//!
//! All seven recovery subcommands route through here:
//! `list`, `inspect`, `plan`, `apply`, `status`, `resume`, `revert`.
//!
//! `list`, `inspect`, `plan` are READ-ONLY. They mount targets only
//! via the read-only `mount::probe` infrastructure from phase 2.
//!
//! `apply`, `resume`, `revert` mount the btrfs top-level READ-WRITE.
//! This is the only place in catos-system that performs persistent
//! writes to a target device.

use std::path::{Path, PathBuf};

use crate::cli::{RecoveryArgs, RecoverySubcommand};
use crate::error::{exit_code, Error};
use crate::model::inspection::Warning;
use crate::model::recovery::{
    BootConsistencyReport, BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CleanupSummary,
    DiskFacts, RecoveryError, RecoveryErrorKind, RecoveryInspectReport, RecoveryListReport,
    RecoveryPlan, RecoveryStatusReport, TransactionPaths, TransactionRecord, TransactionState,
    TransactionSummary,
};
use crate::mount::namespace;
use crate::mount::plan::build_probe_plan;
use crate::mount::session::{Session, SESSION_ROOT_PARENT};
use crate::mount::syscall::{self, ms_flags};
use crate::parse::fstab::{self, FstabEntry, FstabEntryKind, FstabSource};
use crate::recovery::confined;
use crate::recovery::engine::{Engine, EngineOptions};
use crate::recovery::external as btrfs;
use crate::recovery::identity::{
    canonical_block_identity, ensure_supported_snapshot_layout, ensure_target_is_not_running_root,
    validate_mounted_filesystem, validate_recovery_id, SubvolumePath,
};
use crate::recovery::plan::{
    build_plan as build_recovery_plan, build_revert_confirmation_token, PlanInputs,
};
use crate::recovery::store;

/// Outcome of a phase-3 subcommand. Each variant carries the model
/// the matching output renderer consumes.
//
// `Error` boxes `RecoveryError` so the variant stays small relative
// to the others. Boxing here keeps clippy's `large_enum_variant`
// quiet (the alternatives — making every variant boxed or accepting
// the warning globally — are worse). The renderer dereferences once.
pub enum Phase3Outcome {
    List(RecoveryListReport),
    Inspect(RecoveryInspectReport),
    Plan(RecoveryPlan),
    Apply {
        record: TransactionRecord,
        final_state: TransactionState,
    },
    Status(Box<RecoveryStatusReport>),
    Resume {
        record: TransactionRecord,
        final_state: TransactionState,
    },
    Revert {
        record: TransactionRecord,
        final_state: TransactionState,
    },
    Error(Box<RecoveryError>),
}

/// Run a recovery subcommand. Called by `entry.rs` after the CLI has
/// routed `recovery <SUB>` here.
pub fn run_recovery(args: RecoveryArgs) -> Phase3Outcome {
    match args.subcommand {
        RecoverySubcommand::List => match run_list(&args) {
            Ok(report) => Phase3Outcome::List(report),
            Err(error) => Phase3Outcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Inspect => match run_inspect(&args) {
            Ok(report) => Phase3Outcome::Inspect(report),
            Err(error) => Phase3Outcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Plan => match run_plan(&args) {
            Ok(plan) => Phase3Outcome::Plan(plan),
            Err(error) => Phase3Outcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Apply => match run_apply(&args) {
            Ok((record, final_state)) => Phase3Outcome::Apply {
                record,
                final_state,
            },
            Err(error) => Phase3Outcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Status => match run_status(&args) {
            Ok(report) => Phase3Outcome::Status(Box::new(report)),
            Err(error) => Phase3Outcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Resume => match run_resume(&args) {
            Ok((record, final_state)) => Phase3Outcome::Resume {
                record,
                final_state,
            },
            Err(error) => Phase3Outcome::Error(Box::new(error)),
        },
        RecoverySubcommand::Revert => match run_revert(&args) {
            Ok((record, final_state)) => Phase3Outcome::Revert {
                record,
                final_state,
            },
            Err(error) => Phase3Outcome::Error(Box::new(error)),
        },
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn run_list(args: &RecoveryArgs) -> Result<RecoveryListReport, RecoveryError> {
    let selection = args.require_target_selection()?;
    let (canonical_device, _) = canonical_block_identity(&selection.root_device)?;
    let session_root =
        PathBuf::from(SESSION_ROOT_PARENT).join(format!("recovery-list-{}", std::process::id()));
    let source = canonical_device.to_str().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("device {} is not valid UTF-8", canonical_device.display()),
        )
    })?;
    let mount_plan = build_probe_plan(session_root, source, "btrfs", Some("subvolid=5"))
        .map_err(|error| RecoveryError::new(RecoveryErrorKind::SyscallFailed, error.to_string()))?;
    let mut session = Session::new(format!("recovery-list-{}", std::process::id()), &mount_plan);
    let mounted = session.run(&mount_plan).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("cannot mount recovery-list target read-only: {error}"),
        )
    })?;

    let result = (|| {
        let target = validate_mounted_filesystem(&mounted.target_root, &canonical_device)?;
        let readonly_snapshots = btrfs::list_readonly_subvolumes(&mounted.target_root)?;
        let transactions_dir = mounted
            .target_root
            .join(TransactionPaths::transactions_dir().trim_start_matches('/'));
        let (records, errs) = store::list_records(&transactions_dir);
        Ok((target.filesystem, readonly_snapshots, records, errs))
    })();

    let cleanup = cleanup_summary(session.cleanup());
    if !cleanup.all_clean {
        return Err(RecoveryError::new(
            RecoveryErrorKind::CleanupIncomplete,
            format!(
                "recovery list mount cleanup was incomplete: {:?}",
                cleanup.residual
            ),
        ));
    }
    let (filesystem, readonly_snapshots, records, errs) = result?;
    let mut report = RecoveryListReport {
        source_device: Some(canonical_device.display().to_string()),
        source_filesystem_fsid: Some(filesystem.fsid.clone()),
        mount_cleanup: Some(cleanup),
        filesystems: vec![filesystem],
        readonly_snapshots,
        transactions: Vec::new(),
        warnings: Vec::new(),
    };
    for (_, record) in &records {
        report.transactions.push(TransactionSummary {
            transaction_id: record.transaction_id.clone(),
            state: record.state,
            plan_id: record.plan.plan_id.clone(),
            created_at_unix: record.created_at_unix,
            last_updated_unix: record.last_updated_unix,
            source_snapshot_path: record.plan.source_snapshot.path.clone(),
        });
    }
    for error in errs {
        report.warnings.push(Warning::new(
            "RECOVERY_LIST_ERROR",
            format!("could not read transaction: {error}"),
        ));
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

fn run_inspect(args: &RecoveryArgs) -> Result<RecoveryInspectReport, RecoveryError> {
    let selection = args.require_target_selection()?;
    let device = selection.root_device;
    let root_subvolume = selection.root_subvolume;
    let snapshot = args.snapshot_subvolume.clone().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "insufficient space: --snapshot-subvolume is required for inspect",
        )
    })?;

    // Probe the device with a short-lived read-only mount and read
    // identities through it.
    let probe = probe_target_readonly(&device, root_subvolume.as_deref(), Some(&snapshot))?;
    let filesystem = probe.filesystem;
    let current_root_identity = probe.current_root;
    let snapshot_identity = probe.snapshot;
    let boot_layout = probe.boot_layout;
    let boot_consistency = probe.boot_consistency;
    let catos_identity = probe.catos_identity;

    Ok(RecoveryInspectReport {
        filesystem,
        current_root: current_root_identity,
        source_snapshot: snapshot_identity,
        boot_layout,
        boot_consistency,
        target_catos_identity: catos_identity,
        warnings: vec![],
    })
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

fn run_plan(args: &RecoveryArgs) -> Result<RecoveryPlan, RecoveryError> {
    let selection = args.require_target_selection()?;
    let device = selection.root_device;
    let root_subvolume = selection.root_subvolume;
    let snapshot = args.snapshot_subvolume.clone().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "insufficient space: --snapshot-subvolume is required for plan",
        )
    })?;
    let _ = selection.esp_device;

    let probe = probe_target_readonly(&device, root_subvolume.as_deref(), Some(&snapshot))?;

    let plan_id = generate_plan_id()?;
    let entropy = generate_entropy()?;
    let fstab_root_definition = probe.fstab_root_definition;

    let inputs = PlanInputs {
        filesystem: probe.filesystem,
        current_root: probe.current_root,
        source_snapshot: probe.snapshot,
        boot_layout: probe.boot_layout.clone(),
        catos_identity: probe.catos_identity,
        fstab_root_definition,
        plan_id,
        generated_on_host: current_hostname(),
        confirmation_token_entropy: entropy,
    };
    let plan = build_recovery_plan(inputs)?;
    // run_plan is read-only. The plan is emitted to stdout; the
    // operator (or a wrapper script) saves it and feeds it back to
    // `apply --plan-file <path>`.
    Ok(plan)
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

fn run_apply(args: &RecoveryArgs) -> Result<(TransactionRecord, TransactionState), RecoveryError> {
    let plan_id_arg = args.plan_id.as_deref().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::ConfirmationTokenMismatch,
            "apply requires --plan-id",
        )
    })?;
    let confirm = args.confirm.as_deref().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::ConfirmationTokenMismatch,
            "apply requires --confirm <token>",
        )
    })?;
    let plan_file = args.plan_file.as_deref().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TransactionNotFound,
            "apply requires --plan-file <path>",
        )
    })?;

    require_root()?;

    let plan = store::load_plan(plan_file)?;
    crate::recovery::identity::validate_plan_shape(&plan)?;
    crate::recovery::identity::verify_confirmation_token(&plan, plan_id_arg, confirm)?;

    let selection = args.require_target_selection()?;
    ensure_cli_root_matches_plan(selection.root_subvolume.as_deref(), &plan.current_root.path)?;
    ensure_supported_snapshot_layout(&plan.current_root.path, &plan.source_snapshot.path)?;

    // Re-establish every execution-relevant identity through a
    // read-only mount before the first persistent write. The supplied
    // plan file may be stale even though its own digest is intact.
    let fresh = probe_target_readonly(
        &selection.root_device,
        Some(&plan.current_root.path),
        Some(&plan.source_snapshot.path),
    )?;
    if let Some(error) = crate::recovery::identity::drift_between(
        &plan,
        &fresh.filesystem,
        &fresh.current_root,
        &fresh.snapshot,
    )
    .into_error()
    {
        return Err(error);
    }
    if fresh.fstab_root_definition != plan.fstab_root_definition {
        return Err(RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "target fstab root definition changed after the plan was generated",
        ));
    }
    if fresh.boot_layout != plan.boot_layout {
        return Err(RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "target boot layout changed after the plan was generated",
        ));
    }
    if fresh.boot_consistency != plan.boot_consistency {
        return Err(RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "boot consistency report changed after the plan was generated",
        ));
    }
    crate::recovery::boot::require_boot_consistency(&fresh.boot_consistency)?;
    ensure_target_is_not_running_root(&fresh.filesystem, &fresh.current_root)?;
    let device = fresh.canonical_device;

    let mount_session = mount_btrfs_toplevel_rw(&device)?;
    let top_level_mount = mount_session.top_level_mount.clone();
    let rw_target = validate_mounted_filesystem(&top_level_mount, &device)?;

    let mut engine = Engine::begin(
        EngineOptions {
            top_level_mount,
            device_path: device,
            validated_filesystem: rw_target.filesystem,
        },
        plan,
    )?;

    let final_state = engine.drive()?;
    Ok((engine.record().clone(), final_state))
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

struct ExistingTransactionProbe {
    canonical_device: PathBuf,
    filesystem: BtrfsFilesystemIdentity,
    record: TransactionRecord,
    disk_facts: DiskFacts,
    cleanup: CleanupSummary,
}

fn probe_existing_transaction_readonly(
    device: &Path,
    explicit_root: Option<&str>,
    transaction_id: &str,
    protect_running_root: bool,
) -> Result<ExistingTransactionProbe, RecoveryError> {
    let (canonical_device, _) = canonical_block_identity(device)?;
    let session_root = PathBuf::from(SESSION_ROOT_PARENT).join(format!(
        "recovery-existing-{}-{}",
        std::process::id(),
        transaction_id
    ));
    let source = canonical_device.to_str().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("device {} is not valid UTF-8", canonical_device.display()),
        )
    })?;
    let mount_plan = build_probe_plan(session_root, source, "btrfs", Some("subvolid=5"))
        .map_err(|error| RecoveryError::new(RecoveryErrorKind::SyscallFailed, error.to_string()))?;
    let mut session = Session::new(format!("recovery-existing-{transaction_id}"), &mount_plan);
    let mounted = session.run(&mount_plan).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("cannot mount existing recovery transaction read-only: {error}"),
        )
    })?;

    let result = (|| {
        let target = validate_mounted_filesystem(&mounted.target_root, &canonical_device)?;
        let mut engine = Engine::load(
            EngineOptions {
                top_level_mount: mounted.target_root.clone(),
                device_path: canonical_device.clone(),
                validated_filesystem: target.filesystem.clone(),
            },
            transaction_id,
        )?;
        ensure_cli_root_matches_plan(explicit_root, &engine.record().plan.current_root.path)?;
        ensure_supported_snapshot_layout(
            &engine.record().plan.current_root.path,
            &engine.record().plan.source_snapshot.path,
        )?;

        if protect_running_root {
            let root_path = engine.record().plan.current_root.path.clone();
            let mut active_root = btrfs::show_subvolume(
                &mounted.target_root.join(root_path.trim_start_matches('/')),
            )?;
            active_root.path = root_path;
            ensure_target_is_not_running_root(&target.filesystem, &active_root)?;
        }

        let disk_facts = engine.reconcile_status();
        let record = engine.record().clone();
        Ok((target.filesystem, record, disk_facts))
    })();

    let cleanup = cleanup_summary(session.cleanup());
    if !cleanup.all_clean {
        let primary = result
            .as_ref()
            .err()
            .map(|error: &RecoveryError| format!("; primary probe error: {error}"))
            .unwrap_or_default();
        return Err(RecoveryError::new(
            RecoveryErrorKind::CleanupIncomplete,
            format!(
                "existing transaction probe left residual mounts: {:?}{primary}",
                cleanup.residual
            ),
        ));
    }
    let (filesystem, record, disk_facts) = result?;
    Ok(ExistingTransactionProbe {
        canonical_device,
        filesystem,
        record,
        disk_facts,
        cleanup,
    })
}

fn run_status(args: &RecoveryArgs) -> Result<RecoveryStatusReport, RecoveryError> {
    let transaction_id = require_transaction_id(args.transaction.as_deref(), "status")?;
    let selection = args.require_target_selection()?;
    let probe = probe_existing_transaction_readonly(
        &selection.root_device,
        selection.root_subvolume.as_deref(),
        transaction_id,
        false,
    )?;
    let disk_facts = probe.disk_facts;
    let record = probe.record;
    let reconciled_state = record.state;
    let recommendation = recommend(&record);
    let revert_confirmation_token = if !revert_confirmation_is_safe(reconciled_state) {
        None
    } else {
        Some(build_revert_confirmation_token(
            &record.transaction_id,
            &record.plan.plan_digest,
            &disk_facts.filesystem_fsid,
            reconciled_state.code(),
            &record.plan.nonce,
        ))
    };
    Ok(RecoveryStatusReport {
        transaction_id: transaction_id.to_string(),
        reconciled_state,
        record,
        disk_facts,
        recommendation,
        mount_cleanup: Some(probe.cleanup),
        revert_confirmation_token,
        warnings: vec![],
    })
}

fn revert_confirmation_is_safe(state: TransactionState) -> bool {
    state != TransactionState::FailedManualIntervention
}

// ---------------------------------------------------------------------------
// resume
// ---------------------------------------------------------------------------

fn run_resume(args: &RecoveryArgs) -> Result<(TransactionRecord, TransactionState), RecoveryError> {
    require_root()?;
    let transaction_id = require_transaction_id(args.transaction.as_deref(), "resume")?;
    let selection = args.require_target_selection()?;
    let probe = probe_existing_transaction_readonly(
        &selection.root_device,
        selection.root_subvolume.as_deref(),
        transaction_id,
        true,
    )?;
    let device = probe.canonical_device;
    let mount_session = mount_btrfs_toplevel_rw(&device)?;
    let target = validate_mounted_filesystem(&mount_session.top_level_mount, &device)?;
    if target.filesystem != probe.filesystem {
        return Err(RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "target filesystem identity changed between read-only preflight and write mount",
        ));
    }
    let mut engine = Engine::load_for_write(
        EngineOptions {
            top_level_mount: mount_session.top_level_mount.clone(),
            device_path: device.clone(),
            validated_filesystem: target.filesystem,
        },
        transaction_id,
    )?;
    let final_state = engine.drive()?;
    Ok((engine.record().clone(), final_state))
}

// ---------------------------------------------------------------------------
// revert
// ---------------------------------------------------------------------------

fn run_revert(args: &RecoveryArgs) -> Result<(TransactionRecord, TransactionState), RecoveryError> {
    require_root()?;
    let transaction_id = require_transaction_id(args.transaction.as_deref(), "revert")?;
    let confirm = args.confirm.as_deref().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::ConfirmationTokenMismatch,
            "revert requires --confirm <token>",
        )
    })?;
    let selection = args.require_target_selection()?;
    let probe = probe_existing_transaction_readonly(
        &selection.root_device,
        selection.root_subvolume.as_deref(),
        transaction_id,
        true,
    )?;
    let device = probe.canonical_device;
    let mount_session = mount_btrfs_toplevel_rw(&device)?;
    let target = validate_mounted_filesystem(&mount_session.top_level_mount, &device)?;
    if target.filesystem != probe.filesystem {
        return Err(RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "target filesystem identity changed between read-only preflight and write mount",
        ));
    }
    let mut engine = Engine::load_for_revert(
        EngineOptions {
            top_level_mount: mount_session.top_level_mount.clone(),
            device_path: device.clone(),
            validated_filesystem: target.filesystem,
        },
        transaction_id,
        confirm,
    )?;
    let final_state = engine.revert()?;
    Ok((engine.record().clone(), final_state))
}

// ---------------------------------------------------------------------------
// Mount helpers
// ---------------------------------------------------------------------------

/// A private mount namespace with the btrfs top-level mounted
/// read-write at a fixed path. Drop cleans up the namespace.
struct RecoveryMountSession {
    top_level_mount: PathBuf,
    // Held to keep the path alive; we explicitly do NOT unmount here
    // because the engine performs writes that must outlive the
    // syscall (e.g. fsync). The namespace teardown on process exit
    // is the authoritative cleanup.
    _marker: std::marker::PhantomData<*const u8>,
}

fn mount_btrfs_toplevel_rw(device: &Path) -> Result<RecoveryMountSession, RecoveryError> {
    // Enter a private namespace so the rw mount does not propagate
    // to the host.
    namespace::establish_private_namespace().map_err(|e| RecoveryError {
        kind: RecoveryErrorKind::SyscallFailed,
        message: format!("cannot establish private namespace: {e}").into(),
        transaction_id: None,
        current_state: None,
        failed_step: Some("namespace".into()),
        errno: Some(e.errno),
        external_exit_code: None,
        completed_steps: Box::default(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: true,
        record_persistence_error: None,
    })?;

    let mount_point =
        PathBuf::from(SESSION_ROOT_PARENT).join(format!("recovery-rw-{}", std::process::id()));
    std::fs::create_dir_all(&mount_point).map_err(|e| RecoveryError {
        kind: RecoveryErrorKind::SyscallFailed,
        message: format!("cannot create {}: {e}", mount_point.display()).into(),
        transaction_id: None,
        current_state: None,
        failed_step: Some("mkdir".into()),
        errno: None,
        external_exit_code: None,
        completed_steps: Box::default(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: true,
        record_persistence_error: None,
    })?;

    // Mount the btrfs top-level read-write. We use subvolid=5 to be
    // explicit; the rw mode is required because the recovery engine
    // performs snapshot operations and renameat2.
    let data = "subvolid=5";
    let source = device.to_str().ok_or_else(|| RecoveryError {
        kind: RecoveryErrorKind::SyscallFailed,
        message: format!("device path {} is not valid UTF-8", device.display()).into(),
        transaction_id: None,
        current_state: None,
        failed_step: Some("mount".into()),
        errno: None,
        external_exit_code: None,
        completed_steps: Box::default(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: false,
        record_persistence_error: None,
    })?;

    syscall::mount(
        Some(source),
        &mount_point,
        Some("btrfs"),
        ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
        Some(data),
    )
    .map_err(|e| RecoveryError {
        kind: RecoveryErrorKind::SyscallFailed,
        message: format!("cannot mount btrfs rw at {}: {e}", mount_point.display()).into(),
        transaction_id: None,
        current_state: None,
        failed_step: Some("mount".into()),
        errno: Some(e.errno),
        external_exit_code: None,
        completed_steps: Box::default(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: false,
        record_persistence_error: None,
    })?;

    Ok(RecoveryMountSession {
        top_level_mount: mount_point,
        _marker: std::marker::PhantomData,
    })
}

// ---------------------------------------------------------------------------
// Probe helpers (read-only mount of the target device)
// ---------------------------------------------------------------------------

struct TargetProbe {
    canonical_device: PathBuf,
    filesystem: BtrfsFilesystemIdentity,
    current_root: BtrfsSubvolumeIdentity,
    snapshot: BtrfsSubvolumeIdentity,
    boot_layout: crate::model::recovery::BootLayout,
    boot_consistency: BootConsistencyReport,
    catos_identity: Option<crate::model::recovery::CatosIdentity>,
    fstab_root_definition: crate::model::recovery::FstabRootDefinition,
}

fn probe_target_readonly(
    device: &Path,
    root_subvolume: Option<&str>,
    snapshot_subvolume: Option<&str>,
) -> Result<TargetProbe, RecoveryError> {
    let snapshot_btrfs_path = snapshot_subvolume
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
                "--snapshot-subvolume is required; no snapshot path is inferred",
            )
        })?;
    SubvolumePath::parse(snapshot_btrfs_path)?;
    let (canonical_device, _) = canonical_block_identity(device)?;

    let session_root =
        PathBuf::from(SESSION_ROOT_PARENT).join(format!("recovery-ro-{}", std::process::id()));
    let source = canonical_device.to_str().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("device {} is not valid UTF-8", canonical_device.display()),
        )
    })?;
    let mount_plan = build_probe_plan(session_root, source, "btrfs", Some("subvolid=5"))
        .map_err(|error| RecoveryError::new(RecoveryErrorKind::SyscallFailed, error.to_string()))?;
    let id = format!("recovery-ro-{}", std::process::id());
    let mut session = Session::new(id, &mount_plan);
    let mounted = session.run(&mount_plan).map_err(|error| {
        let mut recovery_error = RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("cannot mount target read-only: {error}"),
        );
        recovery_error.failed_step = Some("probe-mount".into());
        recovery_error
    })?;

    let result = (|| {
        let top_level = &mounted.target_root;
        let target = validate_mounted_filesystem(top_level, &canonical_device)?;
        let filesystem = target.filesystem;

        let all_subvolumes = btrfs::list_subvolumes(top_level)?;
        let default_subvolume = btrfs::default_subvolume_path(top_level)?;
        let (root_candidates, self_describing_fstab) =
            discover_root_candidates(top_level, &all_subvolumes)?;
        let candidates_for_selection = if root_subvolume.is_some() {
            all_subvolumes.as_slice()
        } else {
            root_candidates.as_slice()
        };
        let selected_root = select_root_subvolume(
            root_subvolume,
            self_describing_fstab.as_ref(),
            default_subvolume.as_deref(),
            candidates_for_selection,
        )?;

        let mut current_root =
            btrfs::show_subvolume(&top_level.join(selected_root.trim_start_matches('/')))?;
        current_root.path = selected_root.clone();
        if current_root.read_only {
            return Err(RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
                format!("selected root subvolume {selected_root} is readonly"),
            ));
        }

        let mut snapshot_identity =
            btrfs::show_subvolume(&top_level.join(snapshot_btrfs_path.trim_start_matches('/')))?;
        snapshot_identity.path = snapshot_btrfs_path.to_string();
        let fstab_root_definition =
            read_fstab_root(top_level, snapshot_btrfs_path)?.ok_or_else(|| {
                RecoveryError::new(
                    RecoveryErrorKind::AmbiguousTarget,
                    format!(
                        "source snapshot {snapshot_btrfs_path} has no parseable /etc/fstab root entry"
                    ),
                )
            })?;

        let snapshot_root = top_level.join(snapshot_btrfs_path.trim_start_matches('/'));
        let snapshot_fstab =
            read_fstab_entries(top_level, snapshot_btrfs_path)?.ok_or_else(|| {
                RecoveryError::new(
                    RecoveryErrorKind::BootConsistencyUnknown,
                    format!("source snapshot {snapshot_btrfs_path} has no /etc/fstab"),
                )
            })?;
        let boot_layout = crate::recovery::boot::detect_layout(&snapshot_root, &snapshot_fstab);
        let boot_consistency = crate::recovery::boot::evaluate_readonly_consistency(&boot_layout);
        let catos_identity = read_catos_identity(top_level, snapshot_btrfs_path);

        Ok(TargetProbe {
            canonical_device: canonical_device.clone(),
            filesystem,
            current_root,
            snapshot: snapshot_identity,
            boot_layout,
            boot_consistency,
            catos_identity,
            fstab_root_definition,
        })
    })();

    let cleanup = session.cleanup();
    if !cleanup.all_clean {
        return Err(RecoveryError::new(
            RecoveryErrorKind::CleanupIncomplete,
            format!(
                "read-only target probe left residual mounts: {:?}; directory cleanup: {:?}",
                cleanup.residual, cleanup.directory_cleanup_error
            ),
        ));
    }
    result
}

fn cleanup_summary(report: crate::model::mount::CleanupReport) -> CleanupSummary {
    let mut residual = report
        .residual
        .iter()
        .map(|entry| {
            format!(
                "{}: {} ({})",
                entry.resource.target.display(),
                entry.reason,
                entry.error_code
            )
        })
        .collect::<Vec<_>>();
    if let Some(error) = report.directory_cleanup_error {
        residual.push(format!("session directory cleanup: {error}"));
    }
    CleanupSummary {
        unmounted: report
            .unmounted
            .iter()
            .map(|entry| entry.target.display().to_string())
            .collect(),
        residual,
        all_clean: report.all_clean,
    }
}

fn discover_root_candidates(
    top_level: &Path,
    subvolumes: &[BtrfsSubvolumeIdentity],
) -> Result<
    (
        Vec<BtrfsSubvolumeIdentity>,
        Option<crate::model::recovery::FstabRootDefinition>,
    ),
    RecoveryError,
> {
    let mut candidates = Vec::new();
    let mut self_describing = Vec::new();
    for candidate in subvolumes {
        if candidate.path == "/.catos-recovery" || candidate.path.starts_with("/.catos-recovery/") {
            continue;
        }
        let fstab = read_fstab_root(top_level, &candidate.path)?;
        let has_os_release = rooted_file_exists(top_level, &candidate.path, "/etc/os-release")
            || rooted_file_exists(top_level, &candidate.path, "/usr/lib/os-release");
        if fstab.is_none() && !has_os_release {
            continue;
        }
        let mut identity =
            btrfs::show_subvolume(&top_level.join(candidate.path.trim_start_matches('/')))?;
        identity.path = candidate.path.clone();
        if identity.read_only {
            continue;
        }
        if let Some(definition) = fstab {
            if root_definition_matches_candidate(&definition, &identity) {
                self_describing.push(definition);
            }
        }
        candidates.push(identity);
    }
    let fstab = match self_describing.len() {
        0 => None,
        1 => self_describing.pop(),
        count => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::AmbiguousTarget,
                format!("{count} writable subvolumes self-identify as the root in fstab"),
            ));
        }
    };
    Ok((candidates, fstab))
}

fn root_definition_matches_candidate(
    definition: &crate::model::recovery::FstabRootDefinition,
    candidate: &BtrfsSubvolumeIdentity,
) -> bool {
    let path = definition
        .options
        .iter()
        .find_map(|option| option.strip_prefix("subvol="))
        .map(|value| {
            if value.starts_with('/') {
                value.to_string()
            } else {
                format!("/{value}")
            }
        });
    let id = definition
        .options
        .iter()
        .find_map(|option| option.strip_prefix("subvolid="))
        .and_then(|value| value.parse::<u64>().ok());
    path.as_deref()
        .map_or(true, |value| value == candidate.path)
        && id.map_or(true, |value| value == candidate.subvolume_id)
        && (path.is_some() || id.is_some())
}

fn rooted_file_exists(top_level: &Path, subvolume: &str, suffix: &str) -> bool {
    let path = rooted_join(subvolume, suffix);
    confined::read_rooted_file(top_level, &path).is_ok()
}

fn rooted_join(subvolume: &str, suffix: &str) -> String {
    format!(
        "{}/{}",
        subvolume.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
}

fn read_catos_identity(
    top_level: &Path,
    subvolume: &str,
) -> Option<crate::model::recovery::CatosIdentity> {
    let body = confined::read_rooted_file(top_level, &rooted_join(subvolume, "/etc/os-release"))
        .or_else(|_| {
            confined::read_rooted_file(top_level, &rooted_join(subvolume, "/usr/lib/os-release"))
        })
        .ok()?;
    let body = String::from_utf8(body).ok()?;
    let mut out = crate::model::recovery::CatosIdentity::default();
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_matches('"');
        match key {
            "NAME" => out.name = Some(value.into()),
            "ID" => out.id = Some(value.into()),
            "VERSION_ID" => out.version = Some(value.into()),
            "PRETTY_NAME" => out.pretty_name = Some(value.into()),
            _ => {}
        }
    }
    Some(out)
}

fn read_fstab_root(
    top_level: &Path,
    subvolume: &str,
) -> Result<Option<crate::model::recovery::FstabRootDefinition>, RecoveryError> {
    let path = rooted_join(subvolume, "/etc/fstab");
    let Some(entries) = read_fstab_entries(top_level, subvolume)? else {
        return Ok(None);
    };
    let roots: Vec<_> = entries
        .into_iter()
        .filter(|entry| entry.kind == FstabEntryKind::Root)
        .collect();
    match roots.len() {
        0 => Ok(None),
        1 => {
            let root = &roots[0];
            Ok(Some(crate::model::recovery::FstabRootDefinition {
                source: fstab_source_string(&root.source),
                fstype: root.fstype.clone(),
                options: root.options.clone(),
            }))
        }
        count => Err(RecoveryError::new(
            RecoveryErrorKind::AmbiguousTarget,
            format!("{path} contains {count} root entries"),
        )),
    }
}

fn read_fstab_entries(
    top_level: &Path,
    subvolume: &str,
) -> Result<Option<Vec<FstabEntry>>, RecoveryError> {
    let path = rooted_join(subvolume, "/etc/fstab");
    let bytes = match confined::read_rooted_file(top_level, &path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind == RecoveryErrorKind::TransactionNotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let body = String::from_utf8(bytes).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::AmbiguousTarget,
            format!("{path} is not valid UTF-8: {error}"),
        )
    })?;
    let (entries, diagnostics) = fstab::parse_all_with_diagnostics(&body);
    if !diagnostics.is_empty() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::AmbiguousTarget,
            format!("{path} contains malformed fstab lines: {diagnostics:?}"),
        ));
    }
    Ok(Some(entries))
}

fn fstab_source_string(source: &FstabSource) -> String {
    match source {
        FstabSource::Uuid(value) => format!("UUID={value}"),
        FstabSource::PartUuid(value) => format!("PARTUUID={value}"),
        FstabSource::Label(value) => format!("LABEL={value}"),
        FstabSource::PartLabel(value) => format!("PARTLABEL={value}"),
        FstabSource::Path(value) | FstabSource::Pseudo(value) => value.clone(),
    }
}

fn select_root_subvolume(
    explicit: Option<&str>,
    fstab: Option<&crate::model::recovery::FstabRootDefinition>,
    default_subvolume: Option<&str>,
    high_confidence_candidates: &[BtrfsSubvolumeIdentity],
) -> Result<String, RecoveryError> {
    let normalise = |raw: &str| -> Result<String, RecoveryError> {
        let path = if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("/{raw}")
        };
        SubvolumePath::parse(&path)?;
        Ok(path)
    };
    let candidate_by_path = |path: &str| {
        high_confidence_candidates
            .iter()
            .find(|candidate| candidate.path == path)
    };

    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        let path = normalise(explicit)?;
        if candidate_by_path(&path).is_none() {
            return Err(RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
                format!("explicit root subvolume {path} does not exist on the target"),
            ));
        }
        return Ok(path);
    }

    if let Some(fstab) = fstab {
        let by_path = fstab
            .options
            .iter()
            .find_map(|option| option.strip_prefix("subvol="))
            .map(normalise)
            .transpose()?;
        let by_id = fstab
            .options
            .iter()
            .find_map(|option| option.strip_prefix("subvolid="))
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    RecoveryError::new(
                        RecoveryErrorKind::AmbiguousTarget,
                        format!("invalid root subvolid in fstab: {value:?}"),
                    )
                })
            })
            .transpose()?
            .map(|id| {
                high_confidence_candidates
                    .iter()
                    .find(|candidate| candidate.subvolume_id == id)
                    .map(|candidate| candidate.path.clone())
                    .ok_or_else(|| {
                        RecoveryError::new(
                            RecoveryErrorKind::TargetChanged,
                            format!("fstab root subvolid={id} does not exist on the target"),
                        )
                    })
            })
            .transpose()?;

        if let (Some(path), Some(id_path)) = (&by_path, &by_id) {
            if path != id_path {
                return Err(RecoveryError::new(
                    RecoveryErrorKind::AmbiguousTarget,
                    format!("fstab root subvol={path} conflicts with subvolid path {id_path}"),
                ));
            }
        }
        if let Some(path) = by_path.or(by_id) {
            if candidate_by_path(&path).is_none() {
                return Err(RecoveryError::new(
                    RecoveryErrorKind::TargetChanged,
                    format!("fstab root subvolume {path} does not exist on the target"),
                ));
            }
            return Ok(path);
        }
    }

    if let Some(default_subvolume) = default_subvolume.filter(|value| *value != "/") {
        let path = normalise(default_subvolume)?;
        if candidate_by_path(&path).is_some() {
            return Ok(path);
        }
    }

    if high_confidence_candidates.len() == 1 {
        return Ok(high_confidence_candidates[0].path.clone());
    }
    Err(RecoveryError::new(
        RecoveryErrorKind::AmbiguousTarget,
        format!(
            "could not select a unique root subvolume ({} high-confidence candidates)",
            high_confidence_candidates.len()
        ),
    ))
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn generate_plan_id() -> Result<String, RecoveryError> {
    let bytes = kernel_random_bytes::<16>()?;
    Ok(format!("tx-{}", hex(&bytes)))
}

fn generate_entropy() -> Result<Vec<u8>, RecoveryError> {
    Ok(kernel_random_bytes::<32>()?.to_vec())
}

fn kernel_random_bytes<const N: usize>() -> Result<[u8; N], RecoveryError> {
    random_bytes_with(|buffer| getrandom::getrandom(buffer).map_err(|error| error.to_string()))
}

fn random_bytes_with<const N: usize>(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<[u8; N], RecoveryError> {
    let mut bytes = [0u8; N];
    fill(&mut bytes).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::RandomSourceFailed,
            format!("kernel random source failed: {error}"),
        )
    })?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn current_hostname() -> Option<String> {
    std::env::var("HOSTNAME").ok().or_else(|| {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
    })
}

fn require_transaction_id<'a>(
    transaction_id: Option<&'a str>,
    command: &str,
) -> Result<&'a str, RecoveryError> {
    let transaction_id = transaction_id.ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TransactionNotFound,
            format!("{command} requires --transaction <id>"),
        )
    })?;
    validate_recovery_id(transaction_id)?;
    Ok(transaction_id)
}

fn ensure_cli_root_matches_plan(
    explicit_root: Option<&str>,
    sealed_root: &str,
) -> Result<(), RecoveryError> {
    let Some(explicit_root) = explicit_root.filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let normalised = if explicit_root.starts_with('/') {
        explicit_root.to_string()
    } else {
        format!("/{explicit_root}")
    };
    SubvolumePath::parse(&normalised)?;
    if normalised != sealed_root {
        return Err(RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            format!(
                "CLI root subvolume {normalised} does not match sealed transaction root {sealed_root}"
            ),
        ));
    }
    Ok(())
}

fn require_root() -> Result<(), RecoveryError> {
    let uid = unsafe {
        extern "C" {
            fn geteuid() -> u32;
        }
        geteuid()
    };
    if uid != 0 {
        return Err(RecoveryError::new(
            RecoveryErrorKind::CurrentRootRefused,
            "recovery apply/resume/revert must run as root",
        ));
    }
    Ok(())
}

fn recommend(record: &TransactionRecord) -> crate::model::recovery::RecoveryRecommendation {
    use crate::model::recovery::{RecoveryRecommendation as R, TransactionState as S};
    match record.state {
        S::Completed => R::None,
        S::Reverted => R::None,
        S::FailedManualIntervention => R::ManualIntervention,
        S::FailedRecoverable => R::ResumeAfterFailure,
        S::Reverting => R::Resume,
        S::Planned
        | S::PreflightVerified
        | S::Locked
        | S::BackupCreated
        | S::ReplacementCreated
        | S::OldRootMoved
        | S::NewRootInstalled
        | S::Verifying => R::Resume,
    }
}

impl RecoveryArgs {
    fn require_target_selection(&self) -> Result<TargetSelectionResolved, RecoveryError> {
        let root_device = self.target.root_device.clone().ok_or_else(|| {
            RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
                "this subcommand requires --root-device",
            )
        })?;
        Ok(TargetSelectionResolved {
            root_device,
            root_subvolume: self.target.root_subvolume.clone(),
            esp_device: self.target.esp_device.clone(),
        })
    }
}

struct TargetSelectionResolved {
    root_device: PathBuf,
    root_subvolume: Option<String>,
    esp_device: Option<PathBuf>,
}

/// Convert a [`RecoveryError`] into a top-level [`Error`]. Used by
/// `entry.rs` when the recovery subcommand returned
/// `Phase3Outcome::Error`.
pub fn recovery_error_to_phase3_exit_code(_error: &RecoveryError) -> i32 {
    exit_code::PROBE_FAILED
}

/// Convenience used by `entry.rs` to detect whether a phase-3 command
/// should set a non-success exit code based on its outcome.
pub fn exit_code_for(outcome: &Phase3Outcome) -> i32 {
    match outcome {
        Phase3Outcome::Error(error) => {
            if matches!(error.kind, RecoveryErrorKind::CurrentRootRefused) {
                exit_code::PERMISSION_DENIED
            } else {
                exit_code::PROBE_FAILED
            }
        }
        Phase3Outcome::Status(report) => {
            if matches!(
                report.reconciled_state,
                TransactionState::FailedManualIntervention | TransactionState::FailedRecoverable
            ) {
                exit_code::PROBE_FAILED
            } else {
                exit_code::SUCCESS
            }
        }
        Phase3Outcome::Apply { final_state, .. } | Phase3Outcome::Resume { final_state, .. } => {
            if *final_state == TransactionState::Completed {
                exit_code::SUCCESS
            } else {
                exit_code::PROBE_FAILED
            }
        }
        Phase3Outcome::Revert { final_state, .. } => {
            if *final_state == TransactionState::Reverted {
                exit_code::SUCCESS
            } else {
                exit_code::PROBE_FAILED
            }
        }
        _ => exit_code::SUCCESS,
    }
}

/// Suppress unused-symbol warnings while the orchestrators wire up.
#[allow(dead_code)]
fn _force_use(_p: SubvolumePath, _e: Error) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_source_failure_is_not_replaced_with_zero_bytes() {
        let error = random_bytes_with::<32>(|_| Err("injected rng failure".into())).unwrap_err();
        assert_eq!(error.kind, RecoveryErrorKind::RandomSourceFailed);
        assert!(error.message.contains("injected rng failure"));
    }

    #[test]
    fn generated_plan_id_uses_strict_recovery_id_grammar() {
        let bytes = random_bytes_with::<16>(|buffer| {
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = index as u8;
            }
            Ok(())
        })
        .unwrap();
        let id = format!("tx-{}", hex(&bytes));
        crate::recovery::identity::validate_recovery_id(&id).unwrap();
        assert_eq!(id, "tx-000102030405060708090a0b0c0d0e0f");
    }

    #[test]
    fn reconciled_reverted_state_still_offers_idempotent_revert_confirmation() {
        assert!(revert_confirmation_is_safe(TransactionState::Reverted));
        assert!(revert_confirmation_is_safe(TransactionState::Completed));
        assert!(!revert_confirmation_is_safe(
            TransactionState::FailedManualIntervention
        ));
    }

    #[test]
    fn explicit_root_subvolume_wins_over_fstab_and_default() {
        let fstab = crate::model::recovery::FstabRootDefinition {
            source: "UUID=root".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        };
        let candidates = vec![candidate("/@", 256), candidate("/@root", 300)];
        assert_eq!(
            select_root_subvolume(Some("/@root"), Some(&fstab), Some("/@"), &candidates,).unwrap(),
            "/@root"
        );
    }

    #[test]
    fn fstab_subvol_and_subvolid_select_non_default_root() {
        let candidates = vec![candidate("/@", 256), candidate("/@root", 300)];
        let by_path = crate::model::recovery::FstabRootDefinition {
            source: "UUID=root".into(),
            fstype: "btrfs".into(),
            options: vec!["rw".into(), "subvol=@root".into()],
        };
        assert_eq!(
            select_root_subvolume(None, Some(&by_path), Some("/@"), &candidates).unwrap(),
            "/@root"
        );
        let by_id = crate::model::recovery::FstabRootDefinition {
            source: "UUID=root".into(),
            fstype: "btrfs".into(),
            options: vec!["subvolid=300".into()],
        };
        assert_eq!(
            select_root_subvolume(None, Some(&by_id), Some("/@"), &candidates).unwrap(),
            "/@root"
        );
    }

    #[test]
    fn missing_or_ambiguous_root_selection_never_invents_at() {
        let error = select_root_subvolume(None, None, None, &[]).unwrap_err();
        assert_eq!(error.kind.code(), "ambiguous_target");
        let candidates = vec![candidate("/@", 256), candidate("/@root", 300)];
        let error = select_root_subvolume(None, None, None, &candidates).unwrap_err();
        assert_eq!(error.kind.code(), "ambiguous_target");
    }

    #[test]
    fn nested_snapshot_layout_is_rejected_before_any_write() {
        let error = ensure_supported_snapshot_layout("/@", "/@/.snapshots/1/snapshot").unwrap_err();
        assert_eq!(
            error.kind,
            RecoveryErrorKind::UnsupportedNestedSnapshotLayout
        );
    }

    #[test]
    fn non_nested_snapshot_layout_is_supported() {
        ensure_supported_snapshot_layout("/@", "/@snapshots/1").unwrap();
        ensure_supported_snapshot_layout("/@root", "/snapshots/root-1").unwrap();
    }

    #[test]
    fn transaction_cli_id_is_validated_before_path_construction() {
        let valid = "tx-00000000000000000000000000000001";
        assert_eq!(
            require_transaction_id(Some(valid), "status").unwrap(),
            valid
        );
        let error = require_transaction_id(Some("../../outside"), "status").unwrap_err();
        assert_eq!(error.kind, RecoveryErrorKind::InvalidRecoveryId);
        let missing = require_transaction_id(None, "status").unwrap_err();
        assert_eq!(missing.kind, RecoveryErrorKind::TransactionNotFound);
    }

    #[test]
    fn existing_transaction_requires_cli_root_to_match_sealed_root() {
        ensure_cli_root_matches_plan(Some("@root"), "/@root").unwrap();
        ensure_cli_root_matches_plan(Some("/@root"), "/@root").unwrap();
        ensure_cli_root_matches_plan(None, "/@root").unwrap();
        let error = ensure_cli_root_matches_plan(Some("/@"), "/@root").unwrap_err();
        assert_eq!(error.kind, RecoveryErrorKind::TargetChanged);
    }

    fn candidate(path: &str, subvolume_id: u64) -> BtrfsSubvolumeIdentity {
        BtrfsSubvolumeIdentity {
            path: path.into(),
            subvolume_id,
            generation: 1,
            uuid: Some(format!("uuid-{subvolume_id}")),
            parent_uuid: None,
            read_only: false,
            evidence: vec![],
        }
    }
}
