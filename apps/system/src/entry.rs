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

/// The repair domains `catos-repair` recognises. Anything else on that
/// entry point is rejected before any work runs. This stage routes each
/// domain to a stable "not implemented" result; it does not implement
/// any repair logic.
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

/// `catos-repair` routing. Only `fs`, `mount`, `boot` are recognised;
/// each routes to a stable, distinct "not implemented" result. Any
/// other name — including names that exist on `catos-system` or
/// `catos-recovery` (inspect, recovery, plan, apply, status, ...) — is
/// rejected with `ARG_ERROR` before any work happens. This is what
/// keeps the repair surface from accidentally inheriting other entry
/// points' commands.
fn run_repair(argv: &[String]) -> i32 {
    let domain_list = REPAIR_DOMAINS.join("|");
    match argv.first().map(String::as_str) {
        None => {
            eprintln!(
                "catos-repair: argument error: missing repair domain; expected one of {domain_list}"
            );
            exit_code::ARG_ERROR
        }
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
            let domain_list = REPAIR_DOMAINS.join("|");
            print!(
                "catos-repair {version} - CatOS fs/mount/boot repair entry point\n\nUSAGE:\n    catos-repair <DOMAIN>\n    catos-repair --help\n    catos-repair --version\n\nREPAIR DOMAINS (recognised; not implemented in this stage):\n    fs      Filesystem repair domain.\n    mount   Mount-table / fstab repair domain.\n    boot    Bootloader / boot topology repair domain.\n\nOPTIONS:\n    -h, --help    Show this help message and exit.\n    -V, --version Print program version and exit.\n\nNOTES:\n    * Only the three domains above are recognised. Anything else is\n      rejected with ARG_ERROR; in particular `catos-repair` does NOT\n      inherit `catos-system` or `catos-recovery` subcommands\n      (no `catos-repair inspect`, `catos-repair recovery ...`, ...).\n    * No repair logic is implemented in this stage; each recognised\n      domain ({domain_list}) returns a stable \"not implemented\" result.\n",
            );
        }
        Invocation::CatosUpdate => {
            print!(
                "catos-update {version} - CatOS update entry point (reserved)\n\nUSAGE:\n    catos-update --help\n    catos-update --version\n\nOPTIONS:\n    -h, --help    Show this help message and exit.\n    -V, --version Print program version and exit.\n\nNOTES:\n    * This entry point is intentionally recognised but defines no\n      update commands in this stage. It does NOT inherit any\n      `catos-system` subcommand (no `catos-update inspect`, etc.).\n    * Future stages will define the update workflow.\n",
            );
        }
        Invocation::CatosRecovery | Invocation::CatosSystem => {
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
