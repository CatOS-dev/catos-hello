//! Multicall entry. argv[0] selects one of the public CatOS entry points.
//! They share one physical binary; the invocation name is
//! **informational only** and never gates any permission.

use std::fmt;

use crate::error::{exit_code, Error};

mod chroot;
mod elevation;
mod menu;
mod pager;

/// The set of argv[0] names this binary recognises. Anything else falls
/// back silently to the canonical `catos-system` name. The fallback is
/// deliberate so the binary is still usable when renamed or copied; we do
/// not warn because there is no caller-configured warning channel in
/// low-level inspection (warnings in the JSON report are probe-level, not
/// invocation-level). A future option may surface this via a strict mode
/// flag if downstream tooling wants to detect renaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    CatosSystem,
    CatosUpdate,
    CatosRecovery,
    CatosDoctor,
    CatosRepair,
    CatosChroot,
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
            Invocation::CatosChroot => "catos-chroot",
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
            "catos-chroot" => Invocation::CatosChroot,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandContext {
    role: Invocation,
    program: &'static str,
    report_invocation: Invocation,
}

impl CommandContext {
    fn standalone(role: Invocation) -> Self {
        Self {
            role,
            program: role.as_str(),
            report_invocation: role,
        }
    }

    fn aggregate(role: Invocation) -> Self {
        let program = match role {
            Invocation::CatosDoctor => "catos-system doctor",
            Invocation::CatosChroot => "catos-system chroot",
            Invocation::CatosRepair => "catos-system repair",
            Invocation::CatosRecovery => "catos-system recovery",
            Invocation::CatosUpdate => "catos-system update",
            Invocation::CatosSystem => "catos-system",
        };
        Self {
            role,
            program,
            report_invocation: Invocation::CatosSystem,
        }
    }
}

/// Build the report (probe everything) and return it. This is the function
/// `main.rs` calls once argv has been parsed.
pub fn build_report(
    invocation: Invocation,
    target_root: &crate::target::diagnose::system_root::SystemRoot,
) -> Result<crate::target::model::InspectionReport, Error> {
    use crate::target::diagnose::candidate::inspect_target;
    use crate::target::diagnose::filesystem::RealFilesystem;
    use crate::target::diagnose::runtime::{detect_capabilities, detect_runtime};
    use crate::target::model::Warning;
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

    Ok(crate::target::model::InspectionReport {
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
    if invocation == Invocation::CatosSystem {
        return run_system(argv);
    }

    run_context(CommandContext::standalone(invocation), argv)
}

fn run_context(context: CommandContext, argv: &[String]) -> i32 {
    let invocation = context.role;

    if invocation == Invocation::CatosRepair && argv.is_empty() {
        if !menu::is_interactive() {
            return usage_error(
                context.program,
                "the interactive repair menu requires an interactive terminal",
                "Specify `fs`, `mount`, or `boot` when running non-interactively.",
            );
        }
        return run_repair_menu(context);
    }
    if invocation == Invocation::CatosRecovery && argv.is_empty() {
        if !menu::is_interactive() {
            return usage_error(
                context.program,
                "the interactive recovery menu requires an interactive terminal",
                "Specify a recovery command when running non-interactively.",
            );
        }
        return run_recovery_menu(context);
    }

    if invocation == Invocation::CatosDoctor {
        match argv {
            [arg] if matches!(arg.as_str(), "-h" | "--help") => {
                return print_help(context);
            }
            [arg] if matches!(arg.as_str(), "-V" | "--version") => {
                println!("{} {}", context.program, crate::PROGRAM_VERSION);
                return exit_code::SUCCESS;
            }
            [] => {}
            _ => {
                return usage_error(
                    context.program,
                    "doctor does not take additional arguments",
                    &format!(
                        "Run `{}` by itself, or use `{} --help`.",
                        context.program, context.program
                    ),
                );
            }
        }
        if let Some(exit) = elevation::require_root_or_reexec("doctor", &[], context.program) {
            return exit;
        }
    } else if argv.iter().any(|a| a == "--help" || a == "-h") {
        if let Some(command) = argv
            .iter()
            .find(|argument| !argument.starts_with('-'))
            .map(String::as_str)
        {
            if invocation == Invocation::CatosRecovery {
                return print_recovery_command_help(context, command);
            }
            if invocation == Invocation::CatosRepair {
                return print_repair_command_help(context, command);
            }
        }
        return print_help(context);
    } else if argv.iter().any(|a| a == "--version" || a == "-V") {
        println!("{} {}", context.program, crate::PROGRAM_VERSION);
        return exit_code::SUCCESS;
    }

    if invocation == Invocation::CatosRecovery
        && argv
            .first()
            .is_some_and(|command| matches!(command.as_str(), "apply" | "resume" | "revert"))
        && recovery_write_contract_allows_elevation(argv)
    {
        if let Some(exit) = elevation::require_root_or_reexec("recovery", argv, context.program) {
            return exit;
        }
    }

    invocation_dispatch(context, argv)
}

fn recovery_write_contract_allows_elevation(argv: &[String]) -> bool {
    let Ok(default_root) = crate::target::diagnose::system_root::SystemRoot::from_user_input("/")
    else {
        return false;
    };
    let mut prefixed = Vec::with_capacity(argv.len() + 1);
    prefixed.push("recovery".to_string());
    prefixed.extend(argv.iter().cloned());
    let Ok(crate::cli::ParseOutcome::Run(args)) = crate::cli::parse(&prefixed, default_root) else {
        return false;
    };
    args.recovery
        .as_ref()
        .is_some_and(crate::recovery::write_cli_contract_is_valid)
}

fn run_system(argv: &[String]) -> i32 {
    let Some(command) = argv.first().map(String::as_str) else {
        if !menu::is_interactive() {
            return usage_error(
                "catos-system",
                "the maintenance menu requires an interactive terminal",
                "Specify a command such as `catos-system doctor` when running non-interactively.",
            );
        }
        return run_system_menu();
    };
    let rest = &argv[1..];
    match command {
        "-h" | "--help" => print_help(CommandContext::standalone(Invocation::CatosSystem)),
        "-V" | "--version" => {
            println!("catos-system {}", crate::PROGRAM_VERSION);
            exit_code::SUCCESS
        }
        "help" => run_system_help(rest),
        "doctor" => run_context(CommandContext::aggregate(Invocation::CatosDoctor), rest),
        "chroot" => run_context(CommandContext::aggregate(Invocation::CatosChroot), rest),
        "repair" => run_context(CommandContext::aggregate(Invocation::CatosRepair), rest),
        "recovery" => run_context(CommandContext::aggregate(Invocation::CatosRecovery), rest),
        "update" => run_context(CommandContext::aggregate(Invocation::CatosUpdate), rest),
        "advanced" => {
            if rest.is_empty()
                || rest
                    .iter()
                    .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
            {
                print_advanced_help()
            } else {
                run_via_full_parser(CommandContext::standalone(Invocation::CatosSystem), rest)
            }
        }
        // Compatibility for scripts using the old low-level spellings. They
        // remain functional, but no longer dominate the normal help surface.
        "inspect" | "environment" | "capabilities" | "storage" | "target" => {
            run_via_full_parser(CommandContext::standalone(Invocation::CatosSystem), argv)
        }
        option if is_legacy_low_level_option(option) => {
            run_via_full_parser(CommandContext::standalone(Invocation::CatosSystem), argv)
        }
        other if other.starts_with('-') => usage_error(
            "catos-system",
            &format!("unknown option {other:?}"),
            "Run `catos-system --help` to see the available options.",
        ),
        other => usage_error(
            "catos-system",
            &format!("unknown command {other:?}"),
            "Run `catos-system --help` to see the available maintenance actions.",
        ),
    }
}

fn is_legacy_low_level_option(argument: &str) -> bool {
    matches!(
        argument,
        "--json"
            | "--root"
            | "--root-device"
            | "--root-subvolume"
            | "--esp-device"
            | "--snapshot-subvolume"
            | "--plan-id"
            | "--plan-file"
            | "--confirm"
            | "--transaction"
    ) || [
        "--root=",
        "--root-device=",
        "--root-subvolume=",
        "--esp-device=",
        "--snapshot-subvolume=",
        "--plan-id=",
        "--plan-file=",
        "--confirm=",
        "--transaction=",
    ]
    .iter()
    .any(|prefix| argument.starts_with(prefix))
}

fn run_system_help(topic: &[String]) -> i32 {
    match topic {
        [] => print_help(CommandContext::standalone(Invocation::CatosSystem)),
        [name] if name == "doctor" => {
            print_help(CommandContext::aggregate(Invocation::CatosDoctor))
        }
        [name] if name == "chroot" => {
            print_help(CommandContext::aggregate(Invocation::CatosChroot))
        }
        [name] if name == "repair" => {
            print_help(CommandContext::aggregate(Invocation::CatosRepair))
        }
        [name] if name == "recovery" => {
            print_help(CommandContext::aggregate(Invocation::CatosRecovery))
        }
        [name] if name == "update" => {
            print_help(CommandContext::aggregate(Invocation::CatosUpdate))
        }
        [name] if name == "advanced" => print_advanced_help(),
        [name, command] if name == "recovery" => print_recovery_command_help(
            CommandContext::aggregate(Invocation::CatosRecovery),
            command,
        ),
        [name, command] if name == "repair" => {
            print_repair_command_help(CommandContext::aggregate(Invocation::CatosRepair), command)
        }
        [other, ..] => usage_error(
            "catos-system",
            &format!("no help topic named {other:?}"),
            "Run `catos-system --help` to see the available commands.",
        ),
    }
}

fn run_system_menu() -> i32 {
    loop {
        let selected = match menu::choose(
            "CatOS System Tools",
            &[
                "Check system health",
                "Open installed system",
                "Repair",
                "Recover from a Btrfs snapshot",
                "Update the running system",
                "Advanced diagnostics",
            ],
        ) {
            Ok(selected) => selected,
            Err(error) => {
                eprintln!("catos-system: {error}");
                return exit_code::PROBE_FAILED;
            }
        };
        match selected {
            None => return exit_code::SUCCESS,
            Some(0) => {
                let exit = run_context(CommandContext::aggregate(Invocation::CatosDoctor), &[]);
                if exit != exit_code::SUCCESS {
                    return exit;
                }
            }
            Some(1) => {
                let exit = run_context(CommandContext::aggregate(Invocation::CatosChroot), &[]);
                if exit != exit_code::SUCCESS {
                    return exit;
                }
            }
            Some(2) => {
                let exit = run_repair_menu(CommandContext::aggregate(Invocation::CatosRepair));
                if exit != exit_code::SUCCESS {
                    return exit;
                }
            }
            Some(3) => {
                let exit = run_recovery_menu(CommandContext::aggregate(Invocation::CatosRecovery));
                if exit != exit_code::SUCCESS {
                    return exit;
                }
            }
            Some(4) => {
                let exit = run_context(CommandContext::aggregate(Invocation::CatosUpdate), &[]);
                if exit != exit_code::SUCCESS {
                    return exit;
                }
            }
            Some(5) => match interactive_advanced() {
                Ok(Some(exit)) if exit == exit_code::SUCCESS => {}
                Ok(Some(exit)) => return exit,
                Ok(None) => continue,
                Err(error) => {
                    eprintln!("catos-system: {error}");
                    return exit_code::PROBE_FAILED;
                }
            },
            Some(_) => unreachable!("menu returned an out-of-range action"),
        }
    }
}

fn run_repair_menu(context: CommandContext) -> i32 {
    if let Some(exit) = elevation::elevate_interactive_if_needed("repair", &[], context.program) {
        return exit;
    }
    match interactive_repair(context) {
        Ok(Some(exit)) => exit,
        Ok(None) => exit_code::SUCCESS,
        Err(error) => {
            eprintln!("{}: {error}", context.program);
            exit_code::PROBE_FAILED
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InteractiveTarget {
    Automatic,
    Explicit {
        device: String,
        root_subvolume: Option<String>,
    },
}

fn interactive_repair(context: CommandContext) -> Result<Option<i32>, String> {
    let selected = menu::choose(
        "Repair",
        &[
            "Check and repair a filesystem",
            "Repair fstab and mount layout",
            "Repair the boot setup",
        ],
    )?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    let (domain, description) = match selected {
        0 => ("fs", "Run filesystem repair now?"),
        1 => (
            "mount",
            "Repair the selected system's mount configuration now?",
        ),
        2 => ("boot", "Repair the selected system's boot setup now?"),
        _ => unreachable!("menu returned an out-of-range repair action"),
    };

    let Some(target) = choose_repair_target(context.program)? else {
        return Ok(None);
    };
    let args = repair_args(domain, &target);
    if !menu::confirm(description)? {
        return Ok(None);
    }
    Ok(Some(run_repair(context, &args)))
}

fn choose_repair_target(program: &str) -> Result<Option<InteractiveTarget>, String> {
    let choice = menu::choose(
        "Repair Target",
        &[
            "Choose a detected CatOS installation",
            "Let CatOS choose the only safe target automatically",
            "Enter a root device manually",
        ],
    )?;
    match choice {
        None => Ok(None),
        Some(0) => select_detected_target(program),
        Some(1) => Ok(Some(InteractiveTarget::Automatic)),
        Some(2) => prompt_manual_target(),
        Some(_) => unreachable!("menu returned an out-of-range repair target action"),
    }
}

fn choose_recovery_target(program: &str) -> Result<Option<InteractiveTarget>, String> {
    let choice = menu::choose(
        "Recovery Target",
        &[
            "Choose a detected CatOS installation",
            "Enter a root device manually",
        ],
    )?;
    match choice {
        None => Ok(None),
        Some(0) => select_detected_target(program),
        Some(1) => prompt_manual_target(),
        Some(_) => unreachable!("menu returned an out-of-range recovery target action"),
    }
}

fn select_detected_target(program: &str) -> Result<Option<InteractiveTarget>, String> {
    crate::mount::execute::namespace::establish_private_namespace().map_err(|error| {
        format!("cannot establish a private mount namespace for target discovery: {error}")
    })?;
    let report = crate::target::discovery::discover_targets();
    let cleanup_errors = report
        .cleanup
        .iter()
        .filter(|cleanup| !cleanup.is_clean())
        .map(|cleanup| {
            format!(
                "{}: {}",
                cleanup.mountpoint.display(),
                cleanup
                    .error
                    .as_deref()
                    .unwrap_or("temporary probe was not fully cleaned up")
            )
        })
        .collect::<Vec<_>>();
    if !cleanup_errors.is_empty() {
        return Err(format!(
            "target discovery cleanup was incomplete: {}",
            cleanup_errors.join("; ")
        ));
    }

    match crate::selection_ui::select_target(&report, program) {
        crate::selection_ui::Selection::Selected(candidate) => {
            Ok(Some(InteractiveTarget::Explicit {
                device: candidate.root_device.display().to_string(),
                root_subvolume: candidate.root_subvolume.clone(),
            }))
        }
        crate::selection_ui::Selection::Declined => Ok(None),
        crate::selection_ui::Selection::Unavailable(reason) => Err(reason),
    }
}

fn prompt_manual_target() -> Result<Option<InteractiveTarget>, String> {
    let Some(device) = menu::prompt("Root device, for example /dev/nvme0n1p2")? else {
        return Ok(None);
    };
    Ok(Some(InteractiveTarget::Explicit {
        device,
        root_subvolume: None,
    }))
}

fn repair_args(domain: &str, target: &InteractiveTarget) -> Vec<String> {
    let mut args = vec![domain.to_string()];
    match target {
        InteractiveTarget::Automatic => {}
        InteractiveTarget::Explicit {
            device,
            root_subvolume,
        } if domain == "fs" => args.push(device.clone()),
        InteractiveTarget::Explicit {
            device,
            root_subvolume,
        } => {
            args.extend(["--root-device".into(), device.clone()]);
            if let Some(root_subvolume) = root_subvolume {
                args.extend(["--root-subvolume".into(), root_subvolume.clone()]);
            }
        }
    }
    args
}

fn append_recovery_target_args(args: &mut Vec<String>, target: &InteractiveTarget) {
    let InteractiveTarget::Explicit {
        device,
        root_subvolume,
    } = target
    else {
        unreachable!("recovery target cannot use automatic selection")
    };
    args.extend(["--root-device".into(), device.clone()]);
    if let Some(root_subvolume) = root_subvolume {
        args.extend(["--root-subvolume".into(), root_subvolume.clone()]);
    }
}

fn recovery_target_selection(target: &InteractiveTarget) -> crate::cli::TargetSelection {
    let InteractiveTarget::Explicit {
        device,
        root_subvolume,
    } = target
    else {
        unreachable!("recovery target cannot use automatic selection")
    };
    crate::cli::TargetSelection {
        root_device: Some(std::path::PathBuf::from(device)),
        root_subvolume: root_subvolume.clone(),
        esp_device: None,
    }
}

fn load_recovery_choices(
    target: &InteractiveTarget,
) -> Result<crate::recovery::model::RecoveryListReport, String> {
    let outcome = crate::recovery::run_recovery(crate::cli::RecoveryArgs {
        subcommand: crate::cli::RecoverySubcommand::List,
        target: recovery_target_selection(target),
        ..Default::default()
    });
    match outcome {
        crate::recovery::RecoveryOutcome::List(report) => Ok(report),
        crate::recovery::RecoveryOutcome::Error(error) => {
            Err(format!("cannot enumerate recovery choices: {error}"))
        }
        _ => unreachable!("recovery list returned a non-list outcome"),
    }
}

fn snapshot_menu_items(
    report: &crate::recovery::model::RecoveryListReport,
) -> Vec<(String, String)> {
    report
        .readonly_snapshots
        .iter()
        .filter(|snapshot| {
            !crate::snapshot::diagnose::identity::is_protected_recovery_path(&snapshot.path)
        })
        .map(|snapshot| {
            (
                snapshot.path.clone(),
                format!(
                    "{} (subvolid {}, generation {})",
                    snapshot.path, snapshot.subvolume_id, snapshot.generation
                ),
            )
        })
        .collect()
}

fn transaction_menu_items(
    report: &crate::recovery::model::RecoveryListReport,
) -> Vec<(String, String)> {
    report
        .transactions
        .iter()
        .map(|transaction| {
            (
                transaction.transaction_id.clone(),
                format!(
                    "{} — {} — snapshot {}",
                    transaction.transaction_id,
                    transaction.state.code(),
                    transaction.source_snapshot_path
                ),
            )
        })
        .collect()
}

fn choose_snapshot(target: &InteractiveTarget) -> Result<Option<String>, String> {
    let report = load_recovery_choices(target)?;
    let choices = snapshot_menu_items(&report);
    if choices.is_empty() {
        println!("No eligible read-only snapshots were detected.");
        return menu::prompt("Snapshot subvolume, for example /.snapshots/42/snapshot");
    }
    choose_recovery_item(
        "Recovery Snapshot",
        &choices,
        "Enter a snapshot path manually",
        "Snapshot subvolume, for example /.snapshots/42/snapshot",
    )
}

fn choose_transaction(target: &InteractiveTarget) -> Result<Option<String>, String> {
    let report = load_recovery_choices(target)?;
    let choices = transaction_menu_items(&report);
    if choices.is_empty() {
        println!("No recovery transactions were detected.");
        return menu::prompt("Transaction ID");
    }
    choose_recovery_item(
        "Recovery Transaction",
        &choices,
        "Enter a transaction ID manually",
        "Transaction ID",
    )
}

fn choose_recovery_item(
    title: &str,
    choices: &[(String, String)],
    manual_label: &str,
    manual_prompt: &str,
) -> Result<Option<String>, String> {
    let mut labels = choices
        .iter()
        .map(|(_, label)| label.as_str())
        .collect::<Vec<_>>();
    labels.push(manual_label);
    let Some(selected) = menu::choose(title, &labels)? else {
        return Ok(None);
    };
    if selected == choices.len() {
        menu::prompt(manual_prompt)
    } else {
        Ok(Some(choices[selected].0.clone()))
    }
}

fn load_recovery_status(
    target: &InteractiveTarget,
    transaction: &str,
) -> Result<crate::recovery::model::RecoveryStatusReport, String> {
    let outcome = crate::recovery::run_recovery(crate::cli::RecoveryArgs {
        subcommand: crate::cli::RecoverySubcommand::Status,
        target: recovery_target_selection(target),
        transaction: Some(transaction.to_string()),
        ..Default::default()
    });
    match outcome {
        crate::recovery::RecoveryOutcome::Status(report) => Ok(*report),
        crate::recovery::RecoveryOutcome::Error(error) => Err(format!(
            "cannot inspect recovery transaction {transaction:?}: {error}"
        )),
        _ => unreachable!("recovery status returned a non-status outcome"),
    }
}

fn load_interactive_recovery_plan(
    path: &str,
) -> Result<crate::snapshot::model::RecoveryPlan, String> {
    crate::snapshot::store::load_plan(std::path::Path::new(path))
        .map_err(|error| format!("cannot load recovery plan {path:?}: {error}"))
}

fn print_recovery_plan_summary(plan: &crate::snapshot::model::RecoveryPlan) {
    println!("Recovery plan:");
    println!("  Plan ID         : {}", plan.plan_id);
    println!("  Filesystem      : {}", plan.filesystem.fsid);
    println!("  Current root    : {}", plan.current_root.path);
    println!("  Source snapshot : {}", plan.source_snapshot.path);
    if !plan.risks_and_warnings.is_empty() {
        println!("  Risks and warnings:");
        for warning in &plan.risks_and_warnings {
            println!("    - {warning}");
        }
    }
}

fn run_recovery_menu(context: CommandContext) -> i32 {
    if let Some(exit) = elevation::elevate_interactive_if_needed("recovery", &[], context.program) {
        return exit;
    }
    match interactive_recovery(context) {
        Ok(Some(exit)) => exit,
        Ok(None) => exit_code::SUCCESS,
        Err(error) => {
            eprintln!("{}: {error}", context.program);
            exit_code::PROBE_FAILED
        }
    }
}

fn interactive_recovery(context: CommandContext) -> Result<Option<i32>, String> {
    let selected = menu::choose(
        "Btrfs Snapshot Recovery",
        &[
            "List recovery transactions",
            "Inspect a snapshot",
            "Create a recovery plan",
            "Apply a recovery plan",
            "Check a transaction",
            "Resume an interrupted transaction",
            "Revert a completed transaction",
        ],
    )?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    let command = match selected {
        0 => "list",
        1 => "inspect",
        2 => "plan",
        3 => "apply",
        4 => "status",
        5 => "resume",
        6 => "revert",
        _ => unreachable!("menu returned an out-of-range recovery action"),
    };
    let Some(target) = choose_recovery_target(context.program)? else {
        return Ok(None);
    };
    let mut args = vec![command.to_string()];
    append_recovery_target_args(&mut args, &target);
    match command {
        "inspect" | "plan" => {
            let Some(snapshot) = choose_snapshot(&target)? else {
                return Ok(None);
            };
            args.extend(["--snapshot-subvolume".into(), snapshot]);
        }
        "apply" => {
            let Some(plan_file) = menu::prompt("Recovery plan file")? else {
                return Ok(None);
            };
            let plan = load_interactive_recovery_plan(&plan_file)?;
            print_recovery_plan_summary(&plan);
            args.extend([
                "--plan-file".into(),
                plan_file,
                "--plan-id".into(),
                plan.plan_id.clone(),
                "--confirm".into(),
                plan.confirmation_token.clone(),
            ]);
            if !menu::confirm("Apply this recovery plan now?")? {
                return Ok(None);
            }
        }
        "status" | "resume" | "revert" => {
            let Some(transaction) = choose_transaction(&target)? else {
                return Ok(None);
            };
            if command == "revert" {
                let status = load_recovery_status(&target, &transaction)?;
                println!("Transaction state: {}", status.reconciled_state.code());
                let Some(token) = status.revert_confirmation_token else {
                    return Err(format!(
                        "transaction {transaction:?} cannot be reverted from state {}",
                        status.reconciled_state.code()
                    ));
                };
                args.extend(["--confirm".into(), token]);
            }
            args.extend(["--transaction".into(), transaction]);
            if matches!(command, "resume" | "revert")
                && !menu::confirm(if command == "resume" {
                    "Resume this transaction now?"
                } else {
                    "Revert this transaction now?"
                })?
            {
                return Ok(None);
            }
        }
        "list" => {}
        _ => unreachable!("unknown recovery menu command"),
    }
    Ok(Some(run_context(context, &args)))
}

fn interactive_advanced() -> Result<Option<i32>, String> {
    let selected = menu::choose(
        "Advanced Diagnostics",
        &[
            "Inspect runtime, capabilities, and target",
            "Inspect runtime environment",
            "Inspect maintenance capabilities",
            "Scan storage devices",
            "Build a read-only target mount plan",
            "Mount and inspect a target read-only",
        ],
    )?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    let args = match selected {
        0 => vec!["inspect"],
        1 => vec!["environment"],
        2 => vec!["capabilities"],
        3 => vec!["storage", "scan"],
        4 => vec!["target", "plan"],
        5 => vec!["target", "mount"],
        _ => unreachable!("menu returned an out-of-range advanced action"),
    }
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    Ok(Some(run_via_full_parser(
        CommandContext::standalone(Invocation::CatosSystem),
        &args,
    )))
}

fn print_advanced_help() -> i32 {
    use std::io::Write;
    print!("{}", crate::cli::advanced_help_text());
    std::io::stdout().flush().ok();
    exit_code::SUCCESS
}

fn usage_error(program: &str, message: &str, hint: &str) -> i32 {
    eprintln!("{program}: {message}");
    eprintln!("{hint}");
    exit_code::ARG_ERROR
}

/// Per-invocation routing once help / version has been handled. Each
/// arm owns its own dispatch surface; in particular `catos-repair`,
/// `catos-update`, and `catos-chroot` never reach the generic
/// `catos-system` parser.
fn invocation_dispatch(context: CommandContext, argv: &[String]) -> i32 {
    match context.role {
        Invocation::CatosDoctor => run_doctor(context),
        Invocation::CatosRepair => run_repair(context, argv),
        Invocation::CatosUpdate => run_update(context, argv),
        Invocation::CatosChroot => run_chroot(context, argv),
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
            run_via_full_parser(context, &prefixed)
        }
        Invocation::CatosSystem => run_via_full_parser(context, argv),
    }
}

/// Run the aggregated Doctor diagnosis and render its compact terminal report.
/// Target health is carried by the report; process failure is reserved for a
/// diagnosis that could not start or could not clean up its own resources.
fn run_doctor(context: CommandContext) -> i32 {
    let report = crate::doctor::run_doctor();
    let exit = crate::output::doctor_exit_code_for(&report);
    let mut rendered = Vec::new();
    if let Err(error) = crate::output::render_doctor_human_with_columns(
        &report,
        &mut rendered,
        pager::output_columns(),
    ) {
        eprintln!("{}: {error}", context.program);
        return error.exit_code();
    }
    let rendered = match String::from_utf8(rendered) {
        Ok(rendered) => rendered,
        Err(error) => {
            eprintln!("{}: rendered report is not UTF-8: {error}", context.program);
            return crate::error::exit_code::SERIALIZE_FAILED;
        }
    };
    if let Err(error) = pager::present(&rendered) {
        eprintln!("{}: stdout write failed: {error}", context.program);
        return crate::error::exit_code::PROBE_FAILED;
    }
    if matches!(
        report.target.kind,
        crate::doctor::model::DoctorTargetKind::None
    ) {
        crate::error::exit_code::PROBE_FAILED
    } else {
        exit
    }
}

/// Drive the low-level inspection, storage, and recovery parser.
/// Used by every invocation that intentionally reuses the full command
/// surface (`catos-system`, `catos-recovery`, and the argumentless
/// `catos-doctor` diagnosis).
fn run_via_full_parser(context: CommandContext, argv: &[String]) -> i32 {
    use std::io::Write;
    // Validate the default target root. The default is `/`;
    // if `/` is somehow inaccessible we cannot proceed.
    let default_root = match crate::target::diagnose::system_root::SystemRoot::from_user_input("/")
    {
        Ok(r) => r,
        Err(error) => {
            let error: crate::error::Error = error.into();
            eprintln!("{}: {error}", context.program);
            return error.exit_code();
        }
    };

    match crate::cli::parse(argv, default_root) {
        Ok(crate::cli::ParseOutcome::Help(text)) => {
            // Replace the program name in the canned help text so users
            // invoking via a symlink see their invocation.
            let text = text.replacement_help_name(context.program);
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
            if args.command.is_inspection_command() {
                run_inspection_command(context.report_invocation, *args)
            } else if args.command.is_storage_command() {
                run_storage_command(context.report_invocation, *args)
            } else {
                run_recovery_command(context, *args)
            }
        }
        Err(e) => {
            eprintln!("{}: {e}", context.program);
            e.exit_code()
        }
    }
}

/// `catos-repair` routing for filesystem, mount-layout, and boot repair.
/// Any other name — including names that exist on `catos-system` or
/// `catos-recovery` (inspect, recovery, plan, apply, status, ...) —
/// is rejected with `ARG_ERROR` before any work happens. This is
/// what keeps the repair surface from accidentally inheriting other
/// entry points' commands.
fn run_repair(context: CommandContext, argv: &[String]) -> i32 {
    let domain_list = REPAIR_DOMAINS.join("|");
    match argv.first().map(String::as_str) {
        None => {
            eprintln!(
                "{}: missing repair domain; expected one of {domain_list}",
                context.program
            );
            exit_code::ARG_ERROR
        }
        Some("fs") => run_repair_fs(context, &argv[1..]),
        Some("mount") => run_repair_mount(context, &argv[1..]),
        Some("boot") => run_repair_boot(context, &argv[1..]),
        Some(domain) if REPAIR_DOMAINS.contains(&domain) => {
            eprintln!(
                "{}: {domain}: repair domain recognised but not implemented in this stage",
                context.program
            );
            exit_code::ARG_ERROR
        }
        Some(other) => {
            eprintln!(
                "{}: unknown repair domain {other:?}; expected one of {domain_list}",
                context.program
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
fn run_repair_fs(context: CommandContext, argv: &[String]) -> i32 {
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
                        "{}: only one positional <device> may be supplied",
                        context.program
                    );
                    return exit_code::ARG_ERROR;
                }
                explicit_device = Some(other.to_string());
                idx += 1;
            }
            other => {
                eprintln!(
                    "{}: unknown flag {other:?}; expected [--json] [<device>]",
                    context.program
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
                    "{}: <device> must be an absolute /dev/... path without .. or prefix components",
                    context.program
                );
                return exit_code::ARG_ERROR;
            }
            crate::fs::safety::RepairTargetSelection {
                explicit_device: Some(path.to_path_buf()),
            }
        }
        None => crate::fs::safety::RepairTargetSelection::default(),
    };

    if let Some(exit) = require_repair_root(context, "fs", argv) {
        return exit;
    }

    let report = crate::repair::run_fs_repair(selection);
    let exit = outcome_exit_code(report.final_outcome);

    let render_result = if json {
        crate::output::render_repair_json(
            &report,
            context.report_invocation.as_str(),
            std::path::Path::new("/"),
        )
        .and_then(|s| {
            write_json_stdout(&s).map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
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
            eprintln!("{}: {e}", context.program);
            e.exit_code()
        }
    }
}

/// Compute the process exit code for a repair outcome. The exit
/// Exit codes remain compatible with the existing command contract:
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
fn outcome_exit_code(outcome: crate::fs::model::FsRepairOutcome) -> i32 {
    use crate::fs::model::FsRepairOutcome;
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
fn run_repair_mount(context: CommandContext, argv: &[String]) -> i32 {
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
                        "{}: --root-device requires a /dev/... value",
                        context.program
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
                        "{}: --root-subvolume requires a PATH value",
                        context.program
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
                        "{}: --esp-device requires a /dev/... value",
                        context.program
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
                    "{}: unknown flag {other:?}; expected [--json] [--root-device /dev/...] [--root-subvolume PATH] [--esp-device /dev/...]",
                    context.program
                );
                return exit_code::ARG_ERROR;
            }
        }
    }

    if let Some(rd) = root_device.as_deref() {
        if !validate_repair_device_arg(std::path::Path::new(rd)) {
            eprintln!(
                "{}: --root-device must be an absolute /dev/... path without .. or prefix components",
                context.program
            );
            return exit_code::ARG_ERROR;
        }
    }
    if let Some(ed) = esp_device.as_deref() {
        if !validate_repair_device_arg(std::path::Path::new(ed)) {
            eprintln!(
                "{}: --esp-device must be an absolute /dev/... path without .. or prefix components",
                context.program
            );
            return exit_code::ARG_ERROR;
        }
    }

    if let Some(exit) = require_repair_root(context, "mount", argv) {
        return exit;
    }

    let report = crate::repair::mount::run_mount_repair_via_cli(
        root_device.as_deref(),
        root_subvolume.as_deref(),
        esp_device.as_deref(),
        true,
    );
    let exit = mount_outcome_exit_code(report.final_outcome);

    let render_result = if json {
        crate::output::render_mount_repair_json(
            &report,
            context.report_invocation.as_str(),
            std::path::Path::new("/"),
        )
        .and_then(|s| {
            write_json_stdout(&s).map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
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
            eprintln!("{}: {e}", context.program);
            e.exit_code()
        }
    }
}

fn mount_outcome_exit_code(outcome: crate::mount::model::MountRepairOutcome) -> i32 {
    use crate::mount::model::MountRepairOutcome as O;
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

/// `catos-repair boot` parsing + dispatch. Accepted forms:
///
/// ```text
/// catos-repair boot [--json]
///                   [--root-device /dev/...] [--root-subvolume PATH]
///                   [--esp-device /dev/...]
/// ```
///
/// Running `catos-repair boot` itself expresses user authorisation
/// to re-apply the detected bootloader provider's recipe. There are
/// deliberately no `inspect`, `plan`, `apply`, `status`, or
/// `resume` public subcommands, and no per-provider subcommand
/// (`catos-repair boot grub` is rejected).
fn run_repair_boot(context: CommandContext, argv: &[String]) -> i32 {
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
                        "{}: --root-device requires a /dev/... value",
                        context.program
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
                        "{}: --root-subvolume requires a PATH value",
                        context.program
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
                        "{}: --esp-device requires a /dev/... value",
                        context.program
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
                    "{}: unknown flag {other:?}; expected [--json] [--root-device /dev/...] [--root-subvolume PATH] [--esp-device /dev/...]",
                    context.program
                );
                return exit_code::ARG_ERROR;
            }
        }
    }

    if let Some(rd) = root_device.as_deref() {
        if !validate_repair_device_arg(std::path::Path::new(rd)) {
            eprintln!(
                "{}: --root-device must be an absolute /dev/... path without .. or prefix components",
                context.program
            );
            return exit_code::ARG_ERROR;
        }
    }
    if let Some(ed) = esp_device.as_deref() {
        if !validate_repair_device_arg(std::path::Path::new(ed)) {
            eprintln!(
                "{}: --esp-device must be an absolute /dev/... path without .. or prefix components",
                context.program
            );
            return exit_code::ARG_ERROR;
        }
    }

    if let Some(exit) = require_repair_root(context, "boot", argv) {
        return exit;
    }

    let report = crate::repair::boot::run_boot_repair_via_cli(
        root_device.as_deref(),
        root_subvolume.as_deref(),
        esp_device.as_deref(),
        true,
    );
    let exit = boot_outcome_exit_code(report.final_outcome);

    let render_result = if json {
        crate::repair::boot_output::render_boot_repair_json(
            &report,
            context.report_invocation.as_str(),
            std::path::Path::new("/"),
        )
        .and_then(|s| {
            write_json_stdout(&s).map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
        })
    } else {
        let mut out = std::io::stdout();
        crate::repair::boot_output::render_boot_repair_human(&report, &mut out)
            .and_then(|_| out.flush())
            .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
    };
    match render_result {
        Ok(()) => exit,
        Err(e) => {
            eprintln!("{}: {e}", context.program);
            e.exit_code()
        }
    }
}

fn boot_outcome_exit_code(outcome: crate::boot::model::BootRepairOutcome) -> i32 {
    use crate::boot::model::BootRepairOutcome as O;
    match outcome {
        O::Clean | O::Repaired => exit_code::SUCCESS,
        O::AmbiguousTarget | O::AmbiguousProvider | O::Unsupported => exit_code::ARG_ERROR,
        O::PartiallyRepaired
        | O::VerificationFailed
        | O::CleanupIncomplete
        | O::ManualInterventionRequired
        | O::Unknown => exit_code::PROBE_FAILED,
    }
}

/// Validate the positional `<device>` argument: absolute, under
/// `/dev/`, no `..` or platform prefix. Reuses the same checks as
/// `cli::parse_device_path` without dragging in the target-selection
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

fn require_repair_root(context: CommandContext, domain: &str, argv: &[String]) -> Option<i32> {
    let mut reexec_argv = Vec::with_capacity(argv.len() + 1);
    reexec_argv.push(domain.to_string());
    reexec_argv.extend(argv.iter().cloned());
    elevation::require_root_or_reexec("repair", &reexec_argv, context.program)
}

/// `catos-update` routing. Delegates to the dedicated `update` module
/// which owns the privilege-elevation + `checkupdates` + `pacman -Syu`
/// workflow. The module handles `-c/--check`, `-l/--list`, `-d/--devel`;
/// any other token is rejected before any external command runs. This
/// MUST NOT inherit any `catos-system` subcommand (no `catos-update
/// inspect`, etc.).
fn run_update(context: CommandContext, argv: &[String]) -> i32 {
    crate::update::run(argv, context.program)
}

/// `catos-chroot` routing. Delegates to the dedicated `chroot` module
/// which owns the lsblk + LUKS + btrfs-subvolume + fstab auto-mount +
/// arch-chroot workflow. The module handles `--no-auto-mount`,
/// `--no-systemd-chroot`, and `--show-btrfs-dot-snapshots`; any other token is rejected before
/// any external command runs. This MUST NOT inherit any
/// `catos-system` subcommand.
fn run_chroot(context: CommandContext, argv: &[String]) -> i32 {
    chroot::run(argv, context.program)
}

fn print_repair_command_help(context: CommandContext, command: &str) -> i32 {
    use std::io::Write;
    let version = crate::PROGRAM_VERSION;
    let program = context.program;
    let body = match command {
        "fs" => format!(
            r#"{program} {version} - check and repair a filesystem

USAGE:
    {program} fs [--json] [DEVICE]

DEVICE:
    Optional absolute path below /dev. When omitted, exactly one verified
    offline CatOS root must be discoverable.

OPTIONS:
    --json        Emit machine-readable JSON.
    -h, --help    Show this help message.
"#
        ),
        "mount" => format!(
            r#"{program} {version} - repair fstab and the mount layout

USAGE:
    {program} mount [OPTIONS]

OPTIONS:
    --root-device /dev/...    Select an offline root device.
    --root-subvolume PATH     Select its Btrfs root subvolume.
    --esp-device /dev/...     Select the EFI System Partition.
    --json                    Emit machine-readable JSON.
    -h, --help                Show this help message.

The command preserves comments and unrelated fstab entries, verifies the
resulting mount graph, and reports any cleanup that could not be completed.
"#
        ),
        "boot" => format!(
            r#"{program} {version} - repair the detected boot setup

USAGE:
    {program} boot [OPTIONS]

OPTIONS:
    --root-device /dev/...    Select an offline root device.
    --root-subvolume PATH     Select its Btrfs root subvolume.
    --esp-device /dev/...     Select the EFI System Partition.
    --json                    Emit machine-readable JSON.
    -h, --help                Show this help message.

The existing provider is detected from the selected installation. This
command does not migrate the installation to a different boot provider.
"#
        ),
        other => {
            return usage_error(
                context.program,
                &format!("unknown repair command {other:?}"),
                "Choose `fs`, `mount`, or `boot`.",
            );
        }
    };
    print!("{body}");
    std::io::stdout().flush().ok();
    exit_code::SUCCESS
}

fn print_recovery_command_help(context: CommandContext, command: &str) -> i32 {
    use std::io::Write;
    let version = crate::PROGRAM_VERSION;
    let program = context.program;
    let common_target = "    --root-device /dev/...      Target Btrfs block device (required).\n    --root-subvolume PATH      Current root subvolume (optional; validated against the plan).\n    --json                     Emit stable JSON on stdout.\n    -h, --help                 Show this help message and exit.\n    -V, --version              Print program version and exit.\n";
    let body = match command {
        "list" => format!(
            "{program} {version} - list snapshots and recovery transactions\n\nUSAGE:\n    {program} list --root-device /dev/... [OPTIONS]\n\nOPTIONS:\n{common_target}"
        ),
        "inspect" => format!(
            "{program} {version} - inspect a recovery source read-only\n\nUSAGE:\n    {program} inspect --root-device /dev/... --snapshot-subvolume PATH [OPTIONS]\n\nOPTIONS:\n{common_target}    --snapshot-subvolume PATH  Read-only snapshot to inspect (required).\n"
        ),
        "plan" => format!(
            "{program} {version} - create an immutable recovery plan\n\nUSAGE:\n    {program} plan --root-device /dev/... --snapshot-subvolume PATH [OPTIONS]\n\nOPTIONS:\n{common_target}    --snapshot-subvolume PATH  Read-only snapshot used as the replacement root (required).\n\nOUTPUT:\n    The plan is written to stdout. Save it verbatim and pass the file to `apply --plan-file`.\n"
        ),
        "apply" => format!(
            "{program} {version} - apply a confirmed recovery plan\n\nUSAGE:\n    {program} apply --root-device /dev/... --plan-file PATH --plan-id ID --confirm TOKEN [OPTIONS]\n\nOPTIONS:\n{common_target}    --plan-file PATH            Plan JSON emitted by `{program} plan` (required).\n    --plan-id ID               Expected immutable plan id (required).\n    --confirm TOKEN            Confirmation token embedded in the plan (required).\n"
        ),
        "status" => format!(
            "{program} {version} - inspect and reconcile one transaction\n\nUSAGE:\n    {program} status --root-device /dev/... --transaction ID [OPTIONS]\n\nOPTIONS:\n{common_target}    --transaction ID            Recovery transaction id (required).\n"
        ),
        "resume" => format!(
            "{program} {version} - resume an interrupted transaction\n\nUSAGE:\n    {program} resume --root-device /dev/... --transaction ID [OPTIONS]\n\nOPTIONS:\n{common_target}    --transaction ID            Recovery transaction id (required).\n"
        ),
        "revert" => format!(
            "{program} {version} - restore the pre-recovery root\n\nUSAGE:\n    {program} revert --root-device /dev/... --transaction ID --confirm TOKEN [OPTIONS]\n\nOPTIONS:\n{common_target}    --transaction ID            Recovery transaction id (required).\n    --confirm TOKEN            Revert token emitted by `status` (required).\n"
        ),
        _ => {
            eprintln!(
                "{}: unknown recovery command {command:?}; expected list|inspect|plan|apply|status|resume|revert",
                context.program
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
fn print_help(context: CommandContext) -> i32 {
    use std::io::Write;
    let version = crate::PROGRAM_VERSION;
    let program = context.program;
    match context.role {
        Invocation::CatosDoctor => {
            print!(
                r#"{program} {version} - check a CatOS installation

USAGE:
    {program}

CHECKS:
    Runtime environment and target selection
    Filesystem health
    fstab and mount layout
    Boot setup and Secure Boot policy
    Snapshot recovery state

The check is read-only. Administrator privileges are requested before storage
probing. Reports that exceed the terminal height use an internal pager:
Enter advances and q quits. Exit status is zero when a selected target was
diagnosed, even when problems were found; privilege, target-selection,
namespace, and cleanup failures return non-zero. Run without arguments.
"#
            );
        }
        Invocation::CatosRepair => {
            print!(
                r#"{program} {version} - repair a CatOS installation

USAGE:
    {program}
    {program} <COMMAND> [OPTIONS]

COMMANDS:
    fs       Check and repair a filesystem.
    mount    Repair fstab and the mount layout.
    boot     Repair the detected boot setup.

OPTIONS:
    --json           Emit machine-readable JSON.
    --root-device    Select an offline root device.
    --root-subvolume Select its Btrfs root subvolume.
    --esp-device     Select the EFI System Partition.
    -h, --help       Show this help message.

Run without a command to choose the repair interactively.
"#
            );
        }
        Invocation::CatosUpdate => crate::update::print_help(program),
        Invocation::CatosChroot => chroot::print_help(program),
        Invocation::CatosRecovery => {
            print!(
                r#"{program} {version} - recover a Btrfs CatOS installation

USAGE:
    {program}
    {program} <COMMAND> [OPTIONS]

COMMANDS:
    list      List recovery transactions.
    inspect   Inspect a snapshot and target read-only.
    plan      Create a recovery plan.
    apply     Apply a confirmed recovery plan.
    status    Check a transaction.
    resume    Resume an interrupted transaction.
    revert    Restore the previous root.

Run without a command to choose an action interactively.
"#
            );
        }
        Invocation::CatosSystem => print!("{}", crate::cli::help_text()),
    }
    std::io::stdout().flush().ok();
    exit_code::SUCCESS
}

/// Dispatch a low-level inspection command.
/// Builds an InspectionReport and renders the selected view.
fn run_inspection_command(invocation: Invocation, args: crate::cli::CliArgs) -> i32 {
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

/// Dispatch a storage or read-only target-mount command.
/// Build and render the selected storage outcome.
fn run_storage_command(invocation: Invocation, args: crate::cli::CliArgs) -> i32 {
    use std::io::Write;

    let outcome_result = match args.command {
        crate::cli::Command::StorageScan => crate::system::run_storage_scan(&args.root),
        crate::cli::Command::TargetPlan => crate::system::run_target_plan(&args.root, &args.target),
        crate::cli::Command::TargetMount => {
            crate::system::run_target_mount(&args.root, &args.target)
        }
        // Inspection commands never reach this function.
        other => unreachable!("run_storage_command called with non-storage command {other:?}"),
    };

    match outcome_result {
        Ok(outcome) => {
            let result = if args.json {
                crate::output::render_system_json(
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
                crate::output::render_system_human(&outcome, &mut out)
                    .and_then(|_| out.flush())
                    .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
            };
            match result {
                Ok(()) => crate::system::exit_code_for(&outcome),
                Err(e) => {
                    eprintln!("{invocation}: {e}");
                    e.exit_code()
                }
            }
        }
        Err(e) => {
            let exit = e.exit_code();
            if args.json {
                match crate::output::render_system_error_json(
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

/// Dispatch a snapshot recovery command.
fn run_recovery_command(context: CommandContext, args: crate::cli::CliArgs) -> i32 {
    use std::io::Write;

    let recovery_args = match args.recovery.clone() {
        Some(recovery_args) => recovery_args,
        None => {
            eprintln!(
                "{}: recovery subcommand selected but no recovery args parsed",
                context.program
            );
            return crate::error::exit_code::ARG_ERROR;
        }
    };
    let outcome = crate::recovery::run_recovery(recovery_args);
    let result = if args.json {
        crate::recovery::output::render_recovery_json(
            &outcome,
            context.report_invocation.as_str(),
            args.root.as_path(),
        )
        .and_then(|s| {
            write_json_stdout(&s).map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
        })
    } else {
        let mut out = std::io::stdout();
        crate::recovery::output::render_recovery_human(&outcome, &mut out)
            .and_then(|_| out.flush())
            .map_err(|e| Error::SerializeFailed(format!("stdout write: {e}")))
    };
    match result {
        Ok(()) => crate::recovery::exit_code_for(&outcome),
        Err(e) => {
            eprintln!("{}: {e}", context.program);
            e.exit_code()
        }
    }
}

trait HelpRewrite {
    fn replacement_help_name(self, program: &str) -> String;
}

impl HelpRewrite for String {
    fn replacement_help_name(self, program: &str) -> String {
        self.replacen("catos-system", program, 2)
    }
}

/// Write a JSON document to stdout followed by a newline, propagating I/O
/// errors instead of silently dropping them. Inspection reports treat pipe failures
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::model::BootRepairOutcome;

    #[test]
    fn recovery_choice_labels_preserve_machine_values() {
        let report = crate::recovery::model::RecoveryListReport {
            readonly_snapshots: vec![crate::snapshot::model::BtrfsSubvolumeIdentity {
                path: "/.snapshots/42/snapshot".into(),
                subvolume_id: 420,
                generation: 99,
                uuid: None,
                parent_uuid: None,
                read_only: true,
                evidence: Vec::new(),
            }],
            transactions: vec![crate::recovery::model::TransactionSummary {
                transaction_id: "tx-123".into(),
                state: crate::snapshot::model::TransactionState::Completed,
                plan_id: "plan-123".into(),
                created_at_unix: 1,
                last_updated_unix: 2,
                source_snapshot_path: "/.snapshots/42/snapshot".into(),
            }],
            ..Default::default()
        };
        let snapshots = snapshot_menu_items(&report);
        assert_eq!(snapshots[0].0, "/.snapshots/42/snapshot");
        assert!(snapshots[0].1.contains("subvolid 420"));
        let transactions = transaction_menu_items(&report);
        assert_eq!(transactions[0].0, "tx-123");
        assert!(transactions[0].1.contains("completed"));
    }

    #[test]
    fn protected_recovery_subvolumes_are_not_offered_as_snapshots() {
        let report = crate::recovery::model::RecoveryListReport {
            readonly_snapshots: vec![crate::snapshot::model::BtrfsSubvolumeIdentity {
                path: "/.catos-recovery/backups/tx/root-before".into(),
                subvolume_id: 500,
                generation: 1,
                uuid: None,
                parent_uuid: None,
                read_only: true,
                evidence: Vec::new(),
            }],
            ..Default::default()
        };
        assert!(snapshot_menu_items(&report).is_empty());
    }

    #[test]
    fn repair_arguments_follow_the_two_valid_command_shapes() {
        let target = InteractiveTarget::Explicit {
            device: "/dev/nvme0n1p2".into(),
            root_subvolume: Some("/@".into()),
        };
        assert_eq!(repair_args("fs", &target), ["fs", "/dev/nvme0n1p2"]);
        assert_eq!(
            repair_args("mount", &target),
            [
                "mount",
                "--root-device",
                "/dev/nvme0n1p2",
                "--root-subvolume",
                "/@",
            ]
        );
        assert_eq!(repair_args("boot", &InteractiveTarget::Automatic), ["boot"]);
    }

    #[test]
    fn recovery_target_arguments_preserve_the_selected_subvolume() {
        let mut args = vec!["plan".to_string()];
        append_recovery_target_args(
            &mut args,
            &InteractiveTarget::Explicit {
                device: "/dev/vda2".into(),
                root_subvolume: Some("/@".into()),
            },
        );
        assert_eq!(
            args,
            [
                "plan",
                "--root-device",
                "/dev/vda2",
                "--root-subvolume",
                "/@",
            ]
        );
    }

    #[test]
    fn partially_repaired_boot_is_not_a_success_exit() {
        assert_ne!(
            boot_outcome_exit_code(BootRepairOutcome::PartiallyRepaired),
            crate::error::exit_code::SUCCESS
        );
    }
}
