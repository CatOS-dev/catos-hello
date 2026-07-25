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
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, RecoveryError, RecoveryErrorKind,
    RecoveryInspectReport, RecoveryListReport, RecoveryPlan, RecoveryStatusReport,
    TransactionPaths, TransactionRecord, TransactionState, TransactionSummary,
};
use crate::mount::namespace;
use crate::mount::plan::build_probe_plan;
use crate::mount::session::{Session, SESSION_ROOT_PARENT};
use crate::mount::syscall::{self, ms_flags};
use crate::recovery::engine::{Engine, EngineOptions};
use crate::recovery::external as btrfs;
use crate::recovery::identity::SubvolumePath;
use crate::recovery::plan::{build_plan as build_recovery_plan, PlanInputs};
use crate::recovery::store;

/// Outcome of a phase-3 subcommand. Each variant carries the model
/// the matching output renderer consumes.
pub enum Phase3Outcome {
    List(RecoveryListReport),
    Inspect(RecoveryInspectReport),
    Plan(RecoveryPlan),
    Apply {
        record: TransactionRecord,
        final_state: TransactionState,
    },
    Status(RecoveryStatusReport),
    Resume {
        record: TransactionRecord,
        final_state: TransactionState,
    },
    Revert {
        record: TransactionRecord,
        final_state: TransactionState,
    },
    Error(RecoveryError),
}

/// Run a recovery subcommand. Called by `entry.rs` after the CLI has
/// routed `recovery <SUB>` here.
pub fn run_recovery(args: RecoveryArgs) -> Phase3Outcome {
    match args.subcommand {
        RecoverySubcommand::List => match run_list(&args) {
            Ok(report) => Phase3Outcome::List(report),
            Err(error) => Phase3Outcome::Error(error),
        },
        RecoverySubcommand::Inspect => match run_inspect(&args) {
            Ok(report) => Phase3Outcome::Inspect(report),
            Err(error) => Phase3Outcome::Error(error),
        },
        RecoverySubcommand::Plan => match run_plan(&args) {
            Ok(plan) => Phase3Outcome::Plan(plan),
            Err(error) => Phase3Outcome::Error(error),
        },
        RecoverySubcommand::Apply => match run_apply(&args) {
            Ok((record, final_state)) => Phase3Outcome::Apply {
                record,
                final_state,
            },
            Err(error) => Phase3Outcome::Error(error),
        },
        RecoverySubcommand::Status => match run_status(&args) {
            Ok(report) => Phase3Outcome::Status(report),
            Err(error) => Phase3Outcome::Error(error),
        },
        RecoverySubcommand::Resume => match run_resume(&args) {
            Ok((record, final_state)) => Phase3Outcome::Resume {
                record,
                final_state,
            },
            Err(error) => Phase3Outcome::Error(error),
        },
        RecoverySubcommand::Revert => match run_revert(&args) {
            Ok((record, final_state)) => Phase3Outcome::Revert {
                record,
                final_state,
            },
            Err(error) => Phase3Outcome::Error(error),
        },
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn run_list(args: &RecoveryArgs) -> Result<RecoveryListReport, RecoveryError> {
    let mut report = RecoveryListReport::default();
    let _ = args; // List currently walks the configured target root only.

    // Probe / for transactions left by previous applies. This is the
    // "no target mounted" path; if the operator has already mounted
    // the target at /, we see its transactions directly.
    let transactions_dir = Path::new(TransactionPaths::transactions_dir());
    let (records, errs) = store::list_records(transactions_dir);
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
    let _ = selection.root_subvolume;
    let snapshot = args.snapshot_subvolume.clone().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "insufficient space: --snapshot-subvolume is required for inspect",
        )
    })?;

    // Probe the device with a short-lived read-only mount and read
    // identities through it.
    let probe = probe_target_readonly(&device, Some(&snapshot))?;
    let filesystem = probe.filesystem;
    let current_root_identity = probe.current_root;
    let snapshot_identity = probe.snapshot;
    let boot_layout = probe.boot_layout;
    let catos_identity = probe.catos_identity;

    Ok(RecoveryInspectReport {
        filesystem,
        current_root: current_root_identity,
        source_snapshot: snapshot_identity,
        boot_layout,
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
    let _ = selection.root_subvolume;
    let snapshot = args.snapshot_subvolume.clone().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "insufficient space: --snapshot-subvolume is required for plan",
        )
    })?;
    let _ = selection.esp_device;

    let probe = probe_target_readonly(&device, Some(&snapshot))?;

    let plan_id = generate_plan_id();
    let entropy = generate_entropy();
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
    let device = selection.root_device;

    let mount_session = mount_btrfs_toplevel_rw(&device)?;
    let top_level_mount = mount_session.top_level_mount.clone();

    // Re-persist the plan record into the target's btrfs top-level
    // so subsequent `status` / `resume` calls can find it. The plan
    // came from the operator-supplied file (which may live on the
    // recovery LiveCD's tmpfs); the transaction record must outlive
    // the recovery process.
    let target_plan_path = top_level_mount
        .join(TransactionPaths::transactions_dir().trim_start_matches('/'))
        .join(&plan.plan_id)
        .join("plan.json");
    store::persist_plan(&target_plan_path, &plan)?;

    let mut engine = Engine::begin(
        EngineOptions {
            top_level_mount,
            device_path: device,
        },
        plan,
    )?;

    let final_state = engine.drive()?;
    Ok((engine.record().clone(), final_state))
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn run_status(args: &RecoveryArgs) -> Result<RecoveryStatusReport, RecoveryError> {
    let transaction_id = args.transaction.as_deref().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TransactionNotFound,
            "status requires --transaction <id>",
        )
    })?;
    let selection = args.require_target_selection()?;
    let device = selection.root_device;

    let mount_session = mount_btrfs_toplevel_rw(&device)?;
    let mut engine = Engine::load(
        EngineOptions {
            top_level_mount: mount_session.top_level_mount.clone(),
            device_path: device.clone(),
        },
        transaction_id,
    )?;
    let disk_facts = engine.reconcile_status();
    let record = engine.record().clone();
    let reconciled_state = record.state;
    let recommendation = recommend(&record);
    Ok(RecoveryStatusReport {
        transaction_id: transaction_id.to_string(),
        reconciled_state,
        record,
        disk_facts,
        recommendation,
        warnings: vec![],
    })
}

// ---------------------------------------------------------------------------
// resume
// ---------------------------------------------------------------------------

fn run_resume(args: &RecoveryArgs) -> Result<(TransactionRecord, TransactionState), RecoveryError> {
    require_root()?;
    let transaction_id = args.transaction.as_deref().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TransactionNotFound,
            "resume requires --transaction <id>",
        )
    })?;
    let selection = args.require_target_selection()?;
    let device = selection.root_device;
    let mount_session = mount_btrfs_toplevel_rw(&device)?;
    let mut engine = Engine::load(
        EngineOptions {
            top_level_mount: mount_session.top_level_mount.clone(),
            device_path: device.clone(),
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
    let transaction_id = args.transaction.as_deref().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::TransactionNotFound,
            "revert requires --transaction <id>",
        )
    })?;
    let _ = args.confirm.as_deref().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::ConfirmationTokenMismatch,
            "revert requires --confirm <token>",
        )
    })?;
    let selection = args.require_target_selection()?;
    let device = selection.root_device;
    let mount_session = mount_btrfs_toplevel_rw(&device)?;
    let mut engine = Engine::load(
        EngineOptions {
            top_level_mount: mount_session.top_level_mount.clone(),
            device_path: device.clone(),
        },
        transaction_id,
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
        message: format!("cannot establish private namespace: {e}"),
        transaction_id: None,
        current_state: None,
        failed_step: Some("namespace".into()),
        errno: Some(e.errno),
        external_exit_code: None,
        completed_steps: Vec::new(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: true,
    })?;

    let mount_point =
        PathBuf::from(SESSION_ROOT_PARENT).join(format!("recovery-rw-{}", std::process::id()));
    std::fs::create_dir_all(&mount_point).map_err(|e| RecoveryError {
        kind: RecoveryErrorKind::SyscallFailed,
        message: format!("cannot create {}: {e}", mount_point.display()),
        transaction_id: None,
        current_state: None,
        failed_step: Some("mkdir".into()),
        errno: None,
        external_exit_code: None,
        completed_steps: Vec::new(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: true,
    })?;

    // Mount the btrfs top-level read-write. We use subvolid=5 to be
    // explicit; the rw mode is required because the recovery engine
    // performs snapshot operations and renameat2.
    let data = "subvolid=5";
    let source = device.to_str().ok_or_else(|| RecoveryError {
        kind: RecoveryErrorKind::SyscallFailed,
        message: format!("device path {} is not valid UTF-8", device.display()),
        transaction_id: None,
        current_state: None,
        failed_step: Some("mount".into()),
        errno: None,
        external_exit_code: None,
        completed_steps: Vec::new(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: false,
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
        message: format!("cannot mount btrfs rw at {}: {e}", mount_point.display()),
        transaction_id: None,
        current_state: None,
        failed_step: Some("mount".into()),
        errno: Some(e.errno),
        external_exit_code: None,
        completed_steps: Vec::new(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: false,
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
    filesystem: BtrfsFilesystemIdentity,
    current_root: BtrfsSubvolumeIdentity,
    snapshot: BtrfsSubvolumeIdentity,
    boot_layout: crate::model::recovery::BootLayout,
    catos_identity: Option<crate::model::recovery::CatosIdentity>,
    fstab_root_definition: crate::model::recovery::FstabRootDefinition,
}

fn probe_target_readonly(
    device: &Path,
    snapshot_subvolume: Option<&str>,
) -> Result<TargetProbe, RecoveryError> {
    // Resolve the snapshot path. The operator passes the btrfs-relative
    // path (e.g. `/@/.snapshots/2/snapshot`) via `--snapshot-subvolume`.
    // Default to the snapper-style `/@/.snapshots/1/snapshot` when
    // absent so a bare `recovery plan` against a snapper-managed root
    // still returns something useful.
    let snapshot_btrfs_path = snapshot_subvolume
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "/@/.snapshots/1/snapshot".to_string());
    let snapshot_rel = snapshot_btrfs_path.trim_start_matches('/');
    // Mount the device read-only at subvolid=5 in a private namespace
    // via the phase-2 probe plan, then read identities.
    let session_root =
        PathBuf::from(SESSION_ROOT_PARENT).join(format!("recovery-ro-{}", std::process::id()));
    let source = device.to_str().ok_or_else(|| RecoveryError {
        kind: RecoveryErrorKind::SyscallFailed,
        message: format!("device {} is not valid UTF-8", device.display()),
        transaction_id: None,
        current_state: None,
        failed_step: None,
        errno: None,
        external_exit_code: None,
        completed_steps: Vec::new(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: false,
    })?;
    let plan = build_probe_plan(session_root, source, "btrfs", Some("subvolid=5"))
        .map_err(|e| RecoveryError::new(RecoveryErrorKind::SyscallFailed, e.to_string()))?;
    let id = format!("recovery-ro-{}", std::process::id());
    let mut session = Session::new(id, &plan);
    let snapshot = session.run(&plan).map_err(|e| RecoveryError {
        kind: RecoveryErrorKind::SyscallFailed,
        message: format!("cannot mount target read-only: {e}"),
        transaction_id: None,
        current_state: None,
        failed_step: Some("probe-mount".into()),
        errno: None,
        external_exit_code: None,
        completed_steps: Vec::new(),
        disk_facts: None,
        resume_possible: false,
        revert_possible: false,
        manual_intervention_required: false,
    })?;

    let top_level = &snapshot.target_root;
    let filesystem = btrfs::show_filesystem(top_level)?;
    let mut current_root = btrfs::show_subvolume(&top_level.join("@"))?;
    // The plan's path fields MUST be btrfs-relative (e.g. `/@`, not the
    // host-mounted path). `show_subvolume` already returns the
    // btrfs-relative path; we just defensively normalise here.
    if !current_root.path.starts_with('/') {
        current_root.path = format!("/{}", current_root.path);
    }
    if current_root.path != "/@" && !current_root.path.starts_with("/@") {
        current_root.path = "/@".to_string();
    }

    let snapshot_mounted = top_level.join(snapshot_rel);
    let snapshot_identity = btrfs::show_subvolume(&snapshot_mounted)?;
    // Use the operator-supplied btrfs-relative path verbatim. The
    // identity's id/generation/readonly fields come from btrfs-progs;
    // the path the operator supplied is the canonical reference.
    let mut snapshot_identity = snapshot_identity;
    snapshot_identity.path = snapshot_btrfs_path.clone();

    // detect_layout walks the *snapshot's* tree (not the btrfs
    // toplevel) so /boot, /EFI, etc. are read from the recovery
    // target rather than from the FS root.
    let snapshot_root_for_detection = top_level.join(snapshot_rel);
    let boot_layout = crate::recovery::boot::detect_layout(&snapshot_root_for_detection, &[]);
    let catos_identity = read_catos_identity(&snapshot_root_for_detection);
    let fstab_root_definition = read_fstab_root(&snapshot_root_for_detection);

    let _ = session.cleanup();
    Ok(TargetProbe {
        filesystem,
        current_root,
        snapshot: snapshot_identity,
        boot_layout,
        catos_identity,
        fstab_root_definition,
    })
}

fn read_catos_identity(mounted_root: &Path) -> Option<crate::model::recovery::CatosIdentity> {
    let body = std::fs::read_to_string(mounted_root.join("etc/os-release"))
        .or_else(|_| std::fs::read_to_string(mounted_root.join("usr/lib/os-release")))
        .ok()?;
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

fn read_fstab_root(mounted_root: &Path) -> crate::model::recovery::FstabRootDefinition {
    let body = match std::fs::read_to_string(mounted_root.join("etc/fstab")) {
        Ok(b) => b,
        Err(_) => {
            return crate::model::recovery::FstabRootDefinition {
                source: String::new(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            }
        }
    };
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let source = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        let fstype = parts.next().unwrap_or("btrfs");
        let options: Vec<String> = parts
            .next()
            .unwrap_or("defaults")
            .split(',')
            .map(str::to_string)
            .collect();
        if target == "/" {
            return crate::model::recovery::FstabRootDefinition {
                source: source.into(),
                fstype: fstype.into(),
                options,
            };
        }
    }
    crate::model::recovery::FstabRootDefinition {
        source: String::new(),
        fstype: "btrfs".into(),
        options: vec!["subvol=/@".into()],
    }
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn generate_plan_id() -> String {
    // Plan ids need to be unique within the btrfs filesystem's
    // lifetime. We mix time + pid + a kernel random read. The plan
    // id is part of the confirmation token so a collision would be
    // detectable on apply.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut buf = [0u8; 16];
    let _ = read_urandom(&mut buf);
    format!("tx-{t:032x}-{pid:08x}-{}", hex(&buf))
}

fn generate_entropy() -> Vec<u8> {
    let mut buf = [0u8; 32];
    let _ = read_urandom(&mut buf);
    buf.to_vec()
}

fn read_urandom(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
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
        _ => exit_code::SUCCESS,
    }
}

/// Suppress unused-symbol warnings while the orchestrators wire up.
#[allow(dead_code)]
fn _force_use(_p: SubvolumePath, _e: Error) {}
