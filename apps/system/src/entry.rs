//! Multicall entry. argv[0] decides the invocation name (catos-system,
//! catos-update, catos-recovery, catos-doctor). The invocation name is
//! **informational only** and never gates any permission.

use std::fmt;

use crate::error::{exit_code, Error};

/// The set of argv[0] names this binary recognises. Anything else falls back
/// to the canonical `catos-system` name with a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    CatosSystem,
    CatosUpdate,
    CatosRecovery,
    CatosDoctor,
}

impl Invocation {
    /// Canonical string form used in JSON output and help text.
    pub fn as_str(&self) -> &'static str {
        match self {
            Invocation::CatosSystem => "catos-system",
            Invocation::CatosUpdate => "catos-update",
            Invocation::CatosRecovery => "catos-recovery",
            Invocation::CatosDoctor => "catos-doctor",
        }
    }

    /// Determine invocation from argv[0]. Only the basename is considered so
    /// both `/usr/lib/catos/catos-system` and `/usr/bin/catos-doctor`
    /// resolve correctly.
    pub fn from_argv0(argv0: &str) -> Invocation {
        let base = argv0.rsplit('/').next().unwrap_or(argv0);
        match base {
            "catos-update" => Invocation::CatosUpdate,
            "catos-recovery" => Invocation::CatosRecovery,
            "catos-doctor" => Invocation::CatosDoctor,
            // Includes "catos-system" and any unknown caller: fall back to the
            // canonical name so probes still run.
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

/// Run the program. Returns the exit code; `main.rs` forwards it to
/// `std::process::exit`.
pub fn run(invocation: Invocation, argv: &[String]) -> i32 {
    use std::io::Write;

    // Validate the default target root. In phase 1 the default is `/`; if
    // `/` is somehow inaccessible we cannot proceed.
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
        Ok(crate::cli::ParseOutcome::Run(args)) => match build_report(invocation, &args.root) {
            Ok(report) => {
                let result = if args.json {
                    crate::output::render_json(&report).map(|s| {
                        let mut out = std::io::stdout();
                        let _ = writeln!(out, "{s}");
                        let _ = out.flush();
                    })
                } else {
                    let mut out = std::io::stdout();
                    crate::output::render_human(&report, &mut out)
                        .map_err(|e| Error::SerializeFailed(e.to_string()))
                        .map(|_| {
                            let _ = out.flush();
                        })
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
        },
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
        // Only swap leading standalone occurrences of `catos-system` so we
        // do not mangle the explanatory text. Two occurrences appear in the
        // help header: the title line and the USAGE block.
        self.replacen("catos-system", invocation.as_str(), 2)
    }
}
