use crate::target::diagnose::system_root::SystemRoot;
use std::path::PathBuf;

/// One of the phase-1, phase-2, or phase-3 commands.
///
/// Phase 1 commands (`environment`, `capabilities`, `inspect`) share a
/// rendering [`View`] over the same underlying inspection report.
///
/// Phase 2 commands are read-only storage discovery and target mount:
///   * `storage scan` — walks sysfs + blkid + mountinfo and emits a
///     [`crate::target::model::StorageReport`].
///   * `target plan` — reads a target fstab + discovers devices and emits
///     a [`crate::mount::model::MountPlan`] without executing any mount.
///   * `target mount` — same as `target plan` then executes the plan in a
///     private mount namespace, inspects the target, cleans up, and emits
///     the final session/cleanup report.
///
/// Phase 3 commands drive the btrfs snapshot recovery transaction.
/// See [`crate::recovery`] for the orchestrators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Environment,
    Capabilities,
    Inspect,
    StorageScan,
    TargetPlan,
    TargetMount,
    Recovery(RecoverySubcommand),
}

/// Phase-3 recovery subcommands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RecoverySubcommand {
    #[default]
    List,
    Inspect,
    Plan,
    Apply,
    Status,
    Resume,
    Revert,
}

impl RecoverySubcommand {
    pub fn parse_name(s: &str) -> Option<RecoverySubcommand> {
        match s {
            "list" => Some(RecoverySubcommand::List),
            "inspect" => Some(RecoverySubcommand::Inspect),
            "plan" => Some(RecoverySubcommand::Plan),
            "apply" => Some(RecoverySubcommand::Apply),
            "status" => Some(RecoverySubcommand::Status),
            "resume" => Some(RecoverySubcommand::Resume),
            "revert" => Some(RecoverySubcommand::Revert),
            _ => None,
        }
    }
}

impl Command {
    pub fn parse_name(s: &str) -> Option<Command> {
        match s {
            "environment" => Some(Command::Environment),
            "capabilities" => Some(Command::Capabilities),
            "inspect" => Some(Command::Inspect),
            _ => None,
        }
    }

    /// True iff this command emits a phase-1 InspectionReport (vs a
    /// phase-2 StorageReport / MountPlan / MountSession or a phase-3
    /// recovery outcome).
    pub fn is_phase1(self) -> bool {
        matches!(
            self,
            Command::Environment | Command::Capabilities | Command::Inspect
        )
    }

    /// True iff this command is a phase-2 command.
    pub fn is_phase2(self) -> bool {
        matches!(
            self,
            Command::StorageScan | Command::TargetPlan | Command::TargetMount
        )
    }

    /// True iff this command is a phase-3 recovery command.
    pub fn is_phase3(self) -> bool {
        matches!(self, Command::Recovery(_))
    }

    /// The rendering view this command selects. The probe layer always
    /// builds the full report (cheap); the view filters what is emitted.
    /// Panics for phase-2 commands (they do not use View).
    pub fn view(self) -> View {
        match self {
            Command::Environment => View {
                runtime: true,
                capabilities: false,
                target: false,
            },
            Command::Capabilities => View {
                runtime: false,
                capabilities: true,
                target: false,
            },
            Command::Inspect => View {
                runtime: true,
                capabilities: true,
                target: true,
            },
            other => panic!("view() called on phase-2 command {other:?}"),
        }
    }
}

/// Which sections of an [`InspectionReport`] to render. JSON keeps the
/// schemaVersion/programVersion/invocation/targetRoot/warnings keys
/// unconditionally; runtime/capabilities/target are present iff the
/// corresponding flag is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    pub runtime: bool,
    pub capabilities: bool,
    pub target: bool,
}

/// Parsed CLI invocation.
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub command: Command,
    pub root: SystemRoot,
    pub json: bool,
    pub target: TargetSelection,
    /// Phase-3 recovery arguments. Only present when `command` is a
    /// `Command::Recovery(_)` variant; `None` otherwise.
    pub recovery: Option<RecoveryArgs>,
}

/// Phase-3 recovery arguments. Built by the parser when the user
/// invokes `catos-system recovery <SUB>`.
#[derive(Debug, Clone, Default)]
pub struct RecoveryArgs {
    pub subcommand: RecoverySubcommand,
    pub target: TargetSelection,
    pub snapshot_subvolume: Option<String>,
    /// `--plan-id <id>` (apply): cross-checks the plan file's id.
    pub plan_id: Option<String>,
    /// `--plan-file <path>` (apply): path to a JSON plan emitted by
    /// `recovery plan`. The plan is read from this file rather than
    /// from a target-side directory, so `plan` is purely read-only
    /// with respect to the target device.
    pub plan_file: Option<PathBuf>,
    /// `--confirm <token>` (apply, revert)
    pub confirm: Option<String>,
    /// `--transaction <id>` (status, resume, revert)
    pub transaction: Option<String>,
}

/// Explicit storage choices for a target that is not already mounted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetSelection {
    pub root_device: Option<PathBuf>,
    pub root_subvolume: Option<String>,
    pub esp_device: Option<PathBuf>,
}

/// Top-level options that bypass subcommand routing (help/version).
#[derive(Debug, Clone)]
pub enum ParseOutcome {
    Run(Box<CliArgs>),
    /// Print this text to stdout and exit 0.
    Help(String),
    /// Print this text to stdout and exit 0.
    Version(String),
}
