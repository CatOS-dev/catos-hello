//! Multicall entry. argv[0] selects one of the public CatOS entry points.
//! They share one physical binary; the invocation name is
//! **informational only** and never gates any permission.

use std::fmt;

use crate::error::{exit_code, Error};

/// The set of argv[0] names this binary recognises. Anything else falls
/// back silently to the canonical `catos-system` name. The fallback is
/// deliberate so the binary is still usable when renamed or copied; we do
/// not warn because there is no caller-configured warning channel in
/// phase 1 (warnings in the JSON report are probe-level, not invocation-
/// level). A future phase may surface this via a `--strict-invocation`
/// flag if downstream tooling wants to detect renaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    CatosSystem,
    CatosUpdate,
    CatosRecovery,
    CatosDoctor,
    CatosRepair,
}

impl Invocation {
    /// Canonical string form used in JSON output and help text.
    pub fn as_str(&self) -> &'static str {
        match self {
            Invocation::CatosSystem => "catos-system",
            Invocation::CatosUpdate => "catos-update",
            Invocation::CatosRecovery => "catos-recovery",
            Invocation::CatosDoctor => "catos-doctor",
            Invocation::CatosRepair => "catos-repair",
        }
    }

    /// Determine invocation from argv[0]. Only the basename is considered so
    /// both the canonical binary and every installed alias resolve correctly.
    pub fn from_argv0(argv0: &str) -> Invocation {
        let base = argv0.rsplit('/').next().unwrap_or(argv0);
        match base {
            "catos-update" => Invocation::CatosUpdate,
            "catos-recovery" => Invocation::CatosRecovery,
            "catos-doctor" => Invocation::CatosDoctor,
            "catos-repair" => Invocation::CatosRepair,
            // Includes "catos-system" and any unknown caller: silently fall
            // back to the canonical name so probes still run.
            _ => Invocation::CatosSystem,
        }
    }
}

impl fmt::Display for Invocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Build the report (probe everything) and return it. This is the function
/// `main.rs` calls once argv has been parsed.
pub fn build_report(
    invocation: Invocation,
    target_root: &crate::system_root::SystemRoot,
) -> Result<crate::model::inspection::InspectionReport, Error> {
    use crate::model::inspection::Warning;
    use crate::probe::fs_probe::RealFilesystem;
    use crate::probe::{detect_capabilities, detect_runtime, inspect_target};
    use crate::SCHEMA_VERSION;

    let fs = RealFilesystem;
    let runtime = detect_runtime(&fs);

    let capabilities = detect_capabilities(&fs, target_root);

    let mut warnings_strings: Vec<String> = Vec::new();
    let target = inspect_target(&fs, target_root, &mut warnings_strings);
    let warnings: Vec<Warning> = warnings_strings
        .into_iter()
        .map(|m| Warning::new("PROBE_WARNING", m))
        .collect();

    Ok(crate::model::inspection::InspectionReport {
        schema_version: SCHEMA_VERSION,
        program_version: crate::PROGRAM_VERSION.to_string(),
        invocation: invocation.as_str().to_string(),
        target_root: std::path::PathBuf::from(target_root.as_str()),
        runtime,
        capabilities,
        target,
        warnings,
    })
}

/// The repair domains `catos-repair` recognises. Anything else is rejected
/// before work starts. Filesystem and mount repair are implemented; boot
/// remains a stable reserved domain until its provider stage.
const REPAIR_DOMAINS: &[&str] = &["fs", "mount", "boot"];

/// Run the program. Returns the exit code; `main.rs` forwards it to
/// `std::process::exit`.
pub fn run(invocation: Invocation, argv: &[String]) -> i32 {
    // Per-invocation `--help` / `--version` handling.
    //
    // `catos-doctor` keeps its strict single-argument contract: any
    // non-help / non-version argument is an error, and the help text is
    // only emitted for the exact `[--help]` / `[-h]` shape. The other
    // entry points follow the conventional Unix behaviour of
    // short-circuiting on `--help` / `--version` appearing anywhere in
    // argv.
    if invocation == Invocation::CatosDoctor {
        match argv {
            [arg] if matches!(arg.as_str(), "-h" | "--help") => {
                return print_help(invocation);
            }
            [arg] if matches!(arg.as_str(), "-V" | "--version") => {
                println!("{invocation} {}", crate::PROGRAM_VERSION);
                return exit_code::SUCCESS;
            }
            [] => {}
            _ => {
                eprintln!("{invocation}: argument error: catos-doctor does not accept arguments");
                return exit_code::ARG_ERROR;
            }
        }
    } else if argv.iter().any(|a| a == "--help" || a == "-h") {
        if invocation == Invocation::CatosRecovery {
            if let Some(command) = argv
                .iter()
                .find(|argument| !argument.starts_with('-'))
                .map(String::as_str)
            {
                return print_recovery_command_help(command);
            }
        }
        return print_help(invocation);
    } else if argv.iter().any(|a| a == "--version" || a == "-V") {
        println!("{invocation} {}", crate::PROGRAM_VERSION);
        return exit_code::SUCCESS;
    }

    invocation_dispatch(invocation, argv)
}

/// Per-invocation routing once help / version has been handled. Each
/// arm owns its own dispatch surface; in particular `catos-repair` and
/// `catos-update` never reach the generic `catos-system` parser.
fn invocation_dispatch(invocation: Invocation, argv: &[String]) -> i32 {
    match invocation {
        Invocation::CatosDoctor => {
            // Empty argv (the only shape that escapes the strict doctor
            // contract above) runs the full diagnosis. Internally the
            // generic parser is fed `inspect` so the existing phase-1
            // orchestrator produces the report.
            run_via_full_parser(invocation, &["inspect".to_string()])
        }
        Invocation::CatosRepair => run_repair(argv),
        Invocation::CatosUpdate => run_update(argv),
        Invocation::CatosRecovery => {
            // The public recovery surface drops the duplicated
            // `recovery` token: `catos-recovery list`, not
            // `catos-recovery recovery list`. Internally we still feed
            // the existing parser by re-adding the prefix. The legacy
            // doubled form becomes argv `["recovery", "recovery", ...]`
            // and the parser rejects the inner `recovery` token as an
            // unknown recovery subcommand, preserving the rejection
            // contract without requiring a duplicate parser.
            let mut prefixed: Vec<String> = Vec::with_capacity(argv.len() + 1);
            prefixed.push("recovery".to_string());
            prefixed.extend(argv.iter().cloned());
            run_via_full_parser(invocation, &prefixed)
        }
        Invocation::CatosSystem => run_via_full_parser(invocation, argv),
    }
}

/// Drive the canonical `catos-system` parser + phase orchestrators.
/// Used by every invocation that intentionally reuses the full command
/// surface (`catos-system`, `catos-recovery`, and the argumentless
/// `catos-doctor` diagnosis).
fn run_via_full_parser(invocation: Invocation, argv: &[String]) -> i32 {
    use std::io::Write;
    // Validate the default target root. In phase 1 the default is `/`;
    // if `/` is somehow inaccessible we cannot proceed.
    let default_root = match crate::system_root::SystemRoot::from_user_input("/") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{invocation}: {e}");
            return e.exit_code();
        }
    };

    match crate::cli::parse(argv, default_root) {
        Ok(crate::cli::ParseOutcome::Help(text)) => {
            // Replace the program name in the canned help text so users
            // invoking via a symlink see their invocation.
            let text = text.replacement_help_name(invocation);
            print!("{text}");
            std::io::stdout().flush().ok();
            exit_code::SUCCESS
        }
        Ok(crate::cli::ParseOutcome::Version(text)) => {
            print!("{text}");
            std::io::stdout().flush().ok();
            exit_code::SUCCESS
        }
        Ok(crate::cli::ParseOutcome::Run(args)) => {
            if args.command.is_phase1() {
                run_phase1(invocation, *args)
            } else if args.command.is_phase2() {
                run_phase2(invocation, *args)
            } else {
                run_phase3(invocation, *args)
            }
        }
        Err(e) => {
            eprintln!("{invocation}: {e}");
            e.exit_code()
        }
    }
}

/// `catos-repair` routing. `fs` is implemented in stage 2; `mount`
/// and `boot` remain stable "not implemented" results. Any other
/// name — including names that exist on `catos-system` or
/// `catos-recovery` (inspect, recovery, plan, apply, status, ...) —
/// is rejected with `ARG_ERROR` before any work happens. This is
/// what keeps the repair surface from accidentally inheriting other
/// entry points' commands.
fn run_repair(argv: &[String]) -> i32 {
    let domain_list = REPAIR_DOMAINS.join("|");
    match argv.first().map(String::as_str) {
        None => {
            eprintln!(
                "catos-repair: argument error: missing repair domain; expected one of {domain_list}"
            );
            exit_code::ARG_ERROR
        }
        Some("fs") => run_repair_fs(&argv[1..]),
        Some("mount") => run_repair_mount(&argv[1..]),
        Some(domain) if REPAIR_DOMAINS.contains(&domain) => {
            eprintln!(
                "catos-repair: {domain}: repair domain recognised but not implemented in this stage"
            );
            exit_code::ARG_ERROR
        }
        Some(other) => {
            eprintln!(
                "catos-repair: argument error: unknown repair domain {other:?}; expected one of {domain_list}"
            );
            exit_code::ARG_ERROR
        }
    }
}

/// `catos-repair fs` parsing + dispatch. The accepted forms are:
///
/// ```text
/// catos-repair fs [--json] [<device>]
/// catos-repair fs <device> [--json]
/// ```
///
/// `<device>` is an optional positional `/dev/...` path. When
/// omitted, the orchestrator runs auto-discovery and refuses on
/// ambiguity.
///
/// `--help` / `--version` are handled by the top-level dispatcher
/// before this function is reached.
fn run_repair_fs(argv: &[String]) -> i32 {
    use std::io::Write;

    let mut json = false;
    let mut explicit_device: Option<String> = None;
    let mut idx = 0;
    while idx < argv.len() {
        let arg = &argv[idx];
        match arg.as_str() {
            "--json" => {
                json = true;
                idx += 1;
            }
            other if !other.starts_with('-') => {
                if explicit_device.is_some() {
                    eprintln!(
                        "catos-repair: argument error: only one positional <device> may be supplied"
                    );
                    return exit_code::ARG_ERROR;
                }
                explicit_device = Some(other.to_string());
                idx += 1;
            }
            other => {
                eprintln!(
                    "catos-repair: argument error: unknown flag {other:?}; expected [--json] [<device>]"
                );
                return exit_code::ARG_ERROR;
            }
        }
    }

    let selection = match explicit_device {
        Some(device) => {
            let path = std::path::Path::new(&device);
            if !validate_repair_device_arg(path) {
                eprintln!(
                    "catos-repair: argument error: <device> must be an absolute /dev/... path without .. or prefix components"
                );
                return exit_code::ARG_ERROR;
            }
            crate::repair::safety::RepairTargetSelection {
                explicit_device: Some(path.to_path_buf()),
            }
        }
        None => crate::repair::safety::RepairTargetSelection::default(),
    };

    let report = crate::repair::run_fs_repair(selection);
    let exit = outcome_exit_code(report.final_outcome);

    let render_result = if json {
        crate::output::render_repair_json(&report, "catos-repair", std::path::Path::new("/"))
            .and_then(|s| {
                write_json_stdout(&s)
                    .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
            })
    } else {
        let mut out = std::io::stdout();
        crate::output::render_repair_human(&report, &mut out)
            .and_then(|_| out.flush())
            .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
    };
    match render_result {
        Ok(()) => exit,
        Err(e) => {
            eprintln!("catos-repair: {e}");
            e.exit_code()
        }
    }
}

/// Compute the process exit code for a repair outcome. The exit
/// codes are chosen to align with the existing phase-1 contract:
///
/// * `0` for any success (clean / repaired / repaired_with_risk).
///   RepairedWithRisk is still a success: the spec says repair may
///   fail honestly, but a successful repair — even a risky one — is
///   what the user asked for. The risk is in the report.
/// * `5` (PROBE_FAILED) for repairable-but-failed outcomes
///   (unrepaired, verification_failed). Matches the existing
///   "we could not produce the requested result" semantics.
/// * `5` for unsupported / tool_missing: the orchestrator COULD not
///   run the request.
/// * `2` (ARG_ERROR) for refusals that map back to "the operator
///   needs to do something different": ambiguous_target,
///   refused_mounted, refused_running_root. This mirrors how
///   "missing argument" and "you must disambiguate" are the same
///   user-facing class.
/// * `5` for Unknown (defensive; should never appear in practice).
fn outcome_exit_code(outcome: crate::model::repair::FsRepairOutcome) -> i32 {
    use crate::model::repair::FsRepairOutcome;
    match outcome {
        FsRepairOutcome::Clean | FsRepairOutcome::Repaired | FsRepairOutcome::RepairedWithRisk => {
            exit_code::SUCCESS
        }
        FsRepairOutcome::Unrepaired
        | FsRepairOutcome::Unsupported
        | FsRepairOutcome::ToolMissing
        | FsRepairOutcome::VerificationFailed
        | FsRepairOutcome::Unknown => exit_code::PROBE_FAILED,
        FsRepairOutcome::RefusedMounted
        | FsRepairOutcome::RefusedRunningRoot
        | FsRepairOutcome::AmbiguousTarget => exit_code::ARG_ERROR,
    }
}

/// `catos-repair mount` parsing + dispatch. Accepted forms:
///
/// ```text
/// catos-repair mount [--json]
///                    [--root-device /dev/...] [--root-subvolume PATH]
///                    [--esp-device /dev/...]
/// ```
///
/// Running `catos-repair mount` itself expresses user authorisation
/// to apply the repair (spec § 一). The orchestrator may build an
/// internal plan but the spec forbids expanding internal steps into
/// new public CLI tiers (no `mount inspect`, `mount plan`,
/// `mount apply`, ...).
///
/// `--help` / `--version` are handled by the top-level dispatcher
/// before this function is reached.
fn run_repair_mount(argv: &[String]) -> i32 {
    use std::io::Write;

    let mut json = false;
    let mut root_device: Option<String> = None;
    let mut root_subvolume: Option<String> = None;
    let mut esp_device: Option<String> = None;

    let mut idx = 0;
    while idx < argv.len() {
        let arg = &argv[idx];
        match arg.as_str() {
            "--json" => {
                json = true;
                idx += 1;
            }
            "--root-device" => {
                idx += 1;
                if idx >= argv.len() {
                    eprintln!(
                        "catos-repair: argument error: --root-device requires a /dev/... value"
                    );
                    return exit_code::ARG_ERROR;
                }
                root_device = Some(argv[idx].clone());
                idx += 1;
            }
            "--root-subvolume" => {
                idx += 1;
                if idx >= argv.len() {
                    eprintln!(
                        "catos-repair: argument error: --root-subvolume requires a PATH value"
                    );
                    return exit_code::ARG_ERROR;
                }
                root_subvolume = Some(argv[idx].clone());
                idx += 1;
            }
            "--esp-device" => {
                idx += 1;
                if idx >= argv.len() {
                    eprintln!(
                        "catos-repair: argument error: --esp-device requires a /dev/... value"
                    );
                    return exit_code::ARG_ERROR;
                }
                esp_device = Some(argv[idx].clone());
                idx += 1;
            }
            other if other.starts_with("--root-device=") => {
                root_device = Some(other["--root-device=".len()..].to_string());
                idx += 1;
            }
            other if other.starts_with("--root-subvolume=") => {
                root_subvolume = Some(other["--root-subvolume=".len()..].to_string());
                idx += 1;
            }
            other if other.starts_with("--esp-device=") => {
                esp_device = Some(other["--esp-device=".len()..].to_string());
                idx += 1;
            }
            other => {
                eprintln!(
                    "catos-repair: argument error: unknown flag {other:?}; expected [--json] [--root-device /dev/...] [--root-subvolume PATH] [--esp-device /dev/...]"
                );
                return exit_code::ARG_ERROR;
            }
        }
    }

    if let Some(rd) = root_device.as_deref() {
        if !validate_repair_device_arg(std::path::Path::new(rd)) {
            eprintln!(
                "catos-repair: argument error: --root-device must be an absolute /dev/... path without .. or prefix components"
            );
            return exit_code::ARG_ERROR;
        }
    }
    if let Some(ed) = esp_device.as_deref() {
        if !validate_repair_device_arg(std::path::Path::new(ed)) {
            eprintln!(
                "catos-repair: argument error: --esp-device must be an absolute /dev/... path without .. or prefix components"
            );
            return exit_code::ARG_ERROR;
        }
    }

    let report = crate::repair::mount_repair::run_mount_repair_via_cli(
        root_device.as_deref(),
        root_subvolume.as_deref(),
        esp_device.as_deref(),
        true,
    );
    let exit = mount_outcome_exit_code(report.final_outcome);

    let render_result = if json {
        crate::output::render_mount_repair_json(&report, "catos-repair", std::path::Path::new("/"))
            .and_then(|s| {
                write_json_stdout(&s)
                    .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
            })
    } else {
        let mut out = std::io::stdout();
        crate::output::render_mount_repair_human(&report, &mut out)
            .and_then(|_| out.flush())
            .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
    };
    match render_result {
        Ok(()) => exit,
        Err(e) => {
            eprintln!("catos-repair: {e}");
            e.exit_code()
        }
    }
}

fn mount_outcome_exit_code(outcome: crate::model::mount_repair::MountRepairOutcome) -> i32 {
    use crate::model::mount_repair::MountRepairOutcome as O;
    match outcome {
        O::Clean | O::Repaired | O::PartiallyRepaired => exit_code::SUCCESS,
        O::AmbiguousTarget
        | O::NotCatos
        | O::UnsafePath
        | O::ConflictingFstab
        | O::SubvolumeConflict
        | O::UnsupportedLayout => exit_code::ARG_ERROR,
        O::DeviceChanged
        | O::FstabChanged
        | O::DataConflict
        | O::VerificationFailed
        | O::RollbackFailed
        | O::CleanupIncomplete
        | O::Unknown => exit_code::PROBE_FAILED,
    }
}

/// Validate the positional `<device>` argument: absolute, under
/// `/dev/`, no `..` or platform prefix. Reuses the same checks as
/// `cli::parse_device_path` without dragging in the phase-2
/// TargetSelection parser (which has its own per-option quirks).
fn validate_repair_device_arg(path: &std::path::Path) -> bool {
    use std::path::Component;
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal("dev".as_ref()))
    {
        return false;
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return false;
    }
    true
}

/// `catos-update` routing. The entry point is intentionally recognised
/// but defines no commands in this stage. It MUST NOT inherit any
/// `catos-system` subcommand (no `catos-update inspect`, etc.). Future
/// stages will define the update workflow.
fn run_update(argv: &[String]) -> i32 {
    if argv.is_empty() {
        eprintln!(
            "catos-update: no commands defined in this stage; this entry point is reserved for future update workflows"
        );
        return exit_code::ARG_ERROR;
    }
    let other = argv.first().map(String::as_str).unwrap_or("");
    eprintln!(
        "catos-update: argument error: unknown command {other:?}; no update commands are defined in this stage"
    );
    exit_code::ARG_ERROR
}

fn print_recovery_command_help(command: &str) -> i32 {
    use std::io::Write;
    let version = crate::PROGRAM_VERSION;
    let common_target = "    --root-device /dev/...      Target Btrfs block device (required).\n    --root-subvolume PATH      Current root subvolume (optional; validated against the plan).\n    --json                     Emit stable JSON on stdout.\n    -h, --help                 Show this help message and exit.\n    -V, --version              Print program version and exit.\n";
    let body = match command {
        "list" => format!(
            "catos-recovery {version} - list snapshots and recovery transactions\n\nUSAGE:\n    catos-recovery list --root-device /dev/... [OPTIONS]\n\nOPTIONS:\n{common_target}"
        ),
        "inspect" => format!(
            "catos-recovery {version} - inspect a recovery source read-only\n\nUSAGE:\n    catos-recovery inspect --root-device /dev/... --snapshot-subvolume PATH [OPTIONS]\n\nOPTIONS:\n{common_target}    --snapshot-subvolume PATH  Read-only snapshot to inspect (required).\n"
        ),
        "plan" => format!(
            "catos-recovery {version} - create an immutable recovery plan\n\nUSAGE:\n    catos-recovery plan --root-device /dev/... --snapshot-subvolume PATH [OPTIONS]\n\nOPTIONS:\n{common_target}    --snapshot-subvolume PATH  Read-only snapshot used as the replacement root (required).\n\nOUTPUT:\n    The plan is written to stdout. Save it verbatim and pass the file to `apply --plan-file`.\n"
        ),
        "apply" => format!(
            "catos-recovery {version} - apply a confirmed recovery plan\n\nUSAGE:\n    catos-recovery apply --root-device /dev/... --plan-file PATH --plan-id ID --confirm TOKEN [OPTIONS]\n\nOPTIONS:\n{common_target}    --plan-file PATH            Plan JSON emitted by `catos-recovery plan` (required).\n    --plan-id ID               Expected immutable plan id (required).\n    --confirm TOKEN            Confirmation token embedded in the plan (required).\n"
        ),
        "status" => format!(
            "catos-recovery {version} - inspect and reconcile one transaction\n\nUSAGE:\n    catos-recovery status --root-device /dev/... --transaction ID [OPTIONS]\n\nOPTIONS:\n{common_target}    --transaction ID            Recovery transaction id (required).\n"
        ),
        "resume" => format!(
            "catos-recovery {version} - resume an interrupted transaction\n\nUSAGE:\n    catos-recovery resume --root-device /dev/... --transaction ID [OPTIONS]\n\nOPTIONS:\n{common_target}    --transaction ID            Recovery transaction id (required).\n"
        ),
        "revert" => format!(
            "catos-recovery {version} - restore the pre-recovery root\n\nUSAGE:\n    catos-recovery revert --root-device /dev/... --transaction ID --confirm TOKEN [OPTIONS]\n\nOPTIONS:\n{common_target}    --transaction ID            Recovery transaction id (required).\n    --confirm TOKEN            Revert token emitted by `status` (required).\n"
        ),
        _ => {
            eprintln!(
                "catos-recovery: argument error: unknown recovery command {command:?}; expected list|inspect|plan|apply|status|resume|revert"
            );
            return exit_code::ARG_ERROR;
        }
    };
    print!("{body}");
    std::io::stdout().flush().ok();
    exit_code::SUCCESS
}

/// Print the per-invocation help. Each entry point owns a focused
/// message describing its own surface rather than the full
/// `catos-system` parser contract.
fn print_help(invocation: Invocation) -> i32 {
    use std::io::Write;
    let version = crate::PROGRAM_VERSION;
    match invocation {
        Invocation::CatosDoctor => {
            print!(
                "catos-doctor {version} - CatOS diagnosis\n\nUSAGE:\n    catos-doctor\n\nOPTIONS:\n    -h, --help    Show this help message and exit.\n    -V, --version Print program version and exit.\n\nNOTES:\n    * catos-doctor takes no functional arguments. The full\n      diagnosis is printed with no args.\n    * catos-doctor has no `inspect` or `preflight` subcommands.\n",
            );
        }
        Invocation::CatosRepair => {
            print!(
                "catos-repair {version} - CatOS fs/mount/boot repair entry point\n\nUSAGE:\n    catos-repair <DOMAIN> [OPTIONS] [<DEVICE>]\n    catos-repair --help\n    catos-repair --version\n\nREPAIR DOMAINS:\n    fs      Filesystem repair through official system fsck tools.\n            Supports ext2/ext3/ext4, vfat/fat, f2fs, xfs, and\n            single-device btrfs after strict safety checks.\n    mount   Transactional fstab and mount-layout repair. Supports\n            CatOS Btrfs standard subvolumes plus plain ext2/3/4,\n            XFS, and F2FS roots; preserves all six /boot/ESP layouts.\n    boot    Boot-provider repair domain (reserved; not implemented).\n\nOPTIONS:\n    --json        Emit a stable JSON report on stdout.\n    -h, --help    Show this help message and exit.\n    -V, --version Print program version and exit.\n\nFS DOMAIN:\n    catos-repair fs [--json] [<device>]\n        The running root and pre-existing mounts are refused. With no\n        device, only one verified high-confidence CatOS root may be\n        selected automatically; ambiguity fails closed.\n\nMOUNT DOMAIN:\n    catos-repair mount [--json]\n        [--root-device /dev/...] [--root-subvolume /@]\n        [--esp-device /dev/...]\n        The command itself authorises repair. It may repair a uniquely\n        verified running CatOS root without unmounting it, or an offline\n        Btrfs/plain root. Existing data is never migrated or overwritten.\n\nNOTES:\n    * Only fs, mount, and boot are recognised. This entry point does\n      not inherit catos-system or catos-recovery commands.\n    * Filesystem repair is best-effort and reports high-risk fallbacks.\n    * Mount repair preserves comments and unrelated fstab entries,\n      validates the complete repaired mount graph, and rolls back\n      newly-created empty resources if verification fails.\n    * Boot remains a stable not-implemented result until stage 4.\n",
            );
        }
        Invocation::CatosUpdate => {
            print!(
                "catos-update {version} - CatOS update entry point (reserved)\n\nUSAGE:\n    catos-update --help\n    catos-update --version\n\nOPTIONS:\n    -h, --help    Show this help message and exit.\n    -V, --version Print program version and exit.\n\nNOTES:\n    * This entry point is intentionally recognised but defines no\n      update commands in this stage. It does NOT inherit any\n      `catos-system` subcommand (no `catos-update inspect`, etc.).\n    * Future stages will define the update workflow.\n",
            );
        }
        Invocation::CatosRecovery => {
            print!(
                "catos-recovery {version} - CatOS Btrfs snapshot recovery\n\nUSAGE:\n    catos-recovery <COMMAND> [OPTIONS]\n\nCOMMANDS:\n    list      List existing recovery transactions.\n    inspect   Inspect the selected recovery target read-only.\n    plan      Create an immutable recovery plan.\n    apply     Apply a confirmed recovery plan.\n    status    Read and reconcile a transaction record.\n    resume    Continue an in-flight transaction.\n    revert    Restore the pre-recovery root.\n\nOPTIONS:\n    -h, --help    Show this help message and exit.\n    -V, --version Print program version and exit.\n\nNOTES:\n    * Commands are direct: use `catos-recovery plan`, not\n      `catos-recovery recovery plan`.\n    * This entry point does not provide environment, capabilities,\n      storage, or target subcommands.\n",
            );
        }
        Invocation::CatosSystem => {
            // These invocations intentionally reuse the full parser
            // surface, so the full help text is appropriate. The
            // leading name is rebranded so operators invoking via a
            // symlink see their entry point identified.
            let text = crate::cli::help_text().replacement_help_name(invocation);
            print!("{text}");
        }
    }
    std::io::stdout().flush().ok();
    exit_code::SUCCESS
}

/// Dispatch a phase-1 command (environment / capabilities / inspect).
/// Builds an InspectionReport and renders the selected view.
fn run_phase1(invocation: Invocation, args: crate::cli::CliArgs) -> i32 {
    use std::io::Write;

    let view = args.command.view();
    match build_report(invocation, &args.root) {
        Ok(report) => {
            let result = if args.json {
                crate::output::render_json(&report, view).and_then(|s| {
                    write_json_stdout(&s)
                        .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
                })
            } else {
                let mut out = std::io::stdout();
                crate::output::render_human(&report, view, &mut out)
                    .and_then(|_| out.flush())
                    .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
            };
            match result {
                Ok(()) => exit_code::SUCCESS,
                Err(e) => {
                    eprintln!("{invocation}: {e}");
                    e.exit_code()
                }
            }
        }
        Err(e) => {
            eprintln!("{invocation}: {e}");
            e.exit_code()
        }
    }
}

/// Dispatch a phase-2 command (storage scan / target plan / target mount).
/// Builds the phase-2 outcome and renders it via the phase-2 output layer.
fn run_phase2(invocation: Invocation, args: crate::cli::CliArgs) -> i32 {
    use std::io::Write;

    let outcome_result = match args.command {
        crate::cli::Command::StorageScan => crate::phase2::run_storage_scan(&args.root),
        crate::cli::Command::TargetPlan => crate::phase2::run_target_plan(&args.root, &args.target),
        crate::cli::Command::TargetMount => {
            crate::phase2::run_target_mount(&args.root, &args.target)
        }
        // Phase-1 commands never reach here (is_phase1() routes them away).
        other => unreachable!("run_phase2 called with phase-1 command {other:?}"),
    };

    match outcome_result {
        Ok(outcome) => {
            let result = if args.json {
                crate::output::render_phase2_json(
                    &outcome,
                    invocation.as_str(),
                    args.root.as_path(),
                )
                .and_then(|s| {
                    write_json_stdout(&s)
                        .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
                })
            } else {
                let mut out = std::io::stdout();
                crate::output::render_phase2_human(&outcome, &mut out)
                    .and_then(|_| out.flush())
                    .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
            };
            match result {
                Ok(()) => crate::phase2::exit_code_for(&outcome),
                Err(e) => {
                    eprintln!("{invocation}: {e}");
                    e.exit_code()
                }
            }
        }
        Err(e) => {
            let exit = e.exit_code();
            if args.json {
                match crate::output::render_phase2_error_json(
                    &e,
                    invocation.as_str(),
                    args.root.as_path(),
                )
                .and_then(|json| {
                    write_json_stdout(&json)
                        .map_err(|error| Error::SerializeFailed(format!("stdout write: {error}")))
                }) {
                    Ok(()) => exit,
                    Err(render_error) => {
                        eprintln!("{invocation}: {render_error}");
                        render_error.exit_code()
                    }
                }
            } else {
                eprintln!("{invocation}: {e}");
                exit
            }
        }
    }
}

/// Dispatch a phase-3 recovery command.
fn run_phase3(invocation: Invocation, args: crate::cli::CliArgs) -> i32 {
    use std::io::Write;

    let recovery_args = match args.recovery.clone() {
        Some(recovery_args) => recovery_args,
        None => {
            eprintln!("{invocation}: recovery subcommand selected but no recovery args parsed");
            return crate::error::exit_code::ARG_ERROR;
        }
    };
    let outcome = crate::phase3::run_recovery(recovery_args);
    let result = if args.json {
        crate::output::render_phase3_json(&outcome, invocation.as_str(), args.root.as_path())
            .and_then(|s| {
                write_json_stdout(&s)
                    .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
            })
    } else {
        let mut out = std::io::stdout();
        crate::output::render_phase3_human(&outcome, &mut out)
            .and_then(|_| out.flush())
            .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
    };
    match result {
        Ok(()) => crate::phase3::exit_code_for(&outcome),
        Err(e) => {
            eprintln!("{invocation}: {e}");
            e.exit_code()
        }
    }
}

trait HelpRewrite {
    fn replacement_help_name(self, invocation: Invocation) -> String;
}

impl HelpRewrite for String {
    fn replacement_help_name(self, invocation: Invocation) -> String {
        self.replacen("catos-system", invocation.as_str(), 2)
    }
}

/// Write a JSON document to stdout followed by a newline, propagating I/O
/// errors instead of silently dropping them. Phase 1 reports pipe failures
/// (e.g. broken pipe to `head`) as serialization errors so the exit code
/// reflects that the consumer did not receive the full document.
fn write_json_stdout(json: &str) -> std::io::Result<()> {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(json.as_bytes())?;
    lock.write_all(b"\n")?;
    lock.flush()
}
