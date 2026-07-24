//! Hand-rolled CLI parser. No external CLI framework: the surface is small
//! (three subcommands + a few flags) and a hand-rolled parser keeps the
//! dependency surface minimal, which matters for a static binary intended to
//! run in initramfs.

use crate::error::{exit_code, Error};
use crate::system_root::SystemRoot;

/// One of the three phase-1 commands. They share the same flags but each
/// selects a different rendering [`View`] of the same underlying report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Environment,
    Capabilities,
    Inspect,
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

    /// The rendering view this command selects. The probe layer always
    /// builds the full report (cheap); the view filters what is emitted.
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
}

/// Top-level options that bypass subcommand routing (help/version).
#[derive(Debug, Clone)]
pub enum ParseOutcome {
    Run(CliArgs),
    /// Print this text to stdout and exit 0.
    Help(String),
    /// Print this text to stdout and exit 0.
    Version(String),
}

/// Parse `argv[1..]`. argv[0] is handled separately by [`crate::entry`].
///
/// `default_root` is the `SystemRoot` to use when `--root` is not supplied
/// (the caller has already validated that this default exists).
///
/// Flags (`--json`, `--root PATH`, `--root=PATH`) and the subcommand may
/// appear in any order, matching typical Unix tool behaviour.
pub fn parse(argv: &[String], default_root: SystemRoot) -> Result<ParseOutcome, Error> {
    // First pass: scan for top-level help/version flags before any
    // subcommand. These are intentionally allowed to short-circuit even
    // when followed by junk, matching the `--help`-then-anything UX users
    // expect from small Unix tools.
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(ParseOutcome::Help(help_text()));
    }
    if argv.iter().any(|a| a == "--version" || a == "-V") {
        return Ok(ParseOutcome::Version(version_text()));
    }

    let mut command: Option<Command> = None;
    let mut root: Option<SystemRoot> = None;
    let mut json = false;

    let mut idx = 0;
    while idx < argv.len() {
        let arg = &argv[idx];
        match arg.as_str() {
            "--json" => {
                json = true;
                idx += 1;
            }
            "--root" => {
                let val = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--root requires a path argument".to_string(),
                })?;
                root = Some(SystemRoot::from_user_input(val)?);
                idx += 2;
            }
            a if a.starts_with("--root=") => {
                let val = &a["--root=".len()..];
                if val.is_empty() {
                    return Err(Error::InvalidArgument {
                        message: "--root=PATH requires a non-empty path".to_string(),
                    });
                }
                root = Some(SystemRoot::from_user_input(val)?);
                idx += 1;
            }
            // First positional (no leading dash) becomes the subcommand.
            positional if !positional.starts_with('-') && command.is_none() => {
                command = Some(Command::parse_name(positional).ok_or_else(|| Error::InvalidArgument {
                    message: format!(
                        "unknown subcommand {positional:?}; expected environment|capabilities|inspect"
                    ),
                })?);
                idx += 1;
            }
            // A second positional after we already have the subcommand is an
            // error (no subcommand takes a positional argument in phase 1).
            extra_positional if !extra_positional.starts_with('-') => {
                return Err(Error::InvalidArgument {
                    message: format!(
                        "unexpected positional argument {extra_positional:?} (subcommand already given)"
                    ),
                });
            }
            other => {
                return Err(Error::InvalidArgument {
                    message: format!("unexpected argument {other:?}"),
                });
            }
        }
    }

    let command = command.ok_or_else(|| Error::InvalidArgument {
        message: "no subcommand supplied. Try --help.".to_string(),
    })?;

    Ok(ParseOutcome::Run(CliArgs {
        command,
        root: root.unwrap_or(default_root),
        json,
    }))
}

pub fn help_text() -> String {
    format!(
        "\
catos-system {version} - CatOS read-only system backend (phase 1)

USAGE:
    catos-system <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    environment   Print detected runtime environment facts.
    capabilities  Print detected capabilities (read-only).
    inspect       Print combined runtime + capabilities + target inspection.

OPTIONS:
    --root PATH   Inspect a different target root (default: /).
                  PATH must be an absolute path to an existing directory.
    --json        Emit a stable JSON report on stdout instead of human text.
    -h, --help    Show this help message and exit.
    -V, --version Print program version and exit.

EXIT CODES:
    {ok}   success
    {arg}   argument error
    {root} target root invalid (does not exist, not a directory, etc.)
    {perm} permission denied reading a critical path
    {probe} environment probe could not produce a report
    {ser}  JSON serialisation failed

NOTES:
    * This is a phase-1 read-only tool. It never mounts, never writes, never
      unlocks devices, never invokes pacman, never modifies the target root.
    * argv[0] is honoured only for the JSON 'invocation' field and for help
      text. The three symlinks catos-update / catos-recovery / catos-doctor
      all accept the same subcommands and produce identical probe results.
",
        version = crate::PROGRAM_VERSION,
        ok = exit_code::SUCCESS,
        arg = exit_code::ARG_ERROR,
        root = exit_code::INVALID_ROOT,
        perm = exit_code::PERMISSION_DENIED,
        probe = exit_code::PROBE_FAILED,
        ser = exit_code::SERIALIZE_FAILED,
    )
}

pub fn version_text() -> String {
    format!("catos-system {}\n", crate::PROGRAM_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_root() -> SystemRoot {
        SystemRoot::from_absolute_unchecked("/").unwrap()
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_inspect_default() {
        let r = parse(&args(&["inspect"]), default_root()).unwrap();
        match r {
            ParseOutcome::Run(c) => {
                assert_eq!(c.command, Command::Inspect);
                assert!(!c.json);
                assert_eq!(c.root.as_str(), "/");
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parses_json_flag_in_any_position() {
        let r = parse(&args(&["inspect", "--json"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert!(c.json);
        } else {
            panic!();
        }
        let r = parse(&args(&["--json", "inspect"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert!(c.json);
        } else {
            panic!();
        }
    }

    #[test]
    fn rejects_unknown_subcommand_with_arg_error() {
        let err = parse(&args(&["frobnicate"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_unknown_flag_with_arg_error() {
        let err = parse(&args(&["inspect", "--frobnicate"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_root_without_value() {
        let err = parse(&args(&["inspect", "--root"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_relative_root_with_invalid_root_code() {
        let err = parse(&args(&["inspect", "--root", "mnt"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::INVALID_ROOT);
    }

    #[test]
    fn rejects_nonexistent_root_with_invalid_root_code() {
        let err = parse(
            &args(&["inspect", "--root", "/definitely/not/here/12345"]),
            default_root(),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), exit_code::INVALID_ROOT);
    }

    #[test]
    fn help_short_circuits() {
        let r = parse(&args(&["--help"]), default_root()).unwrap();
        assert!(matches!(r, ParseOutcome::Help(_)));
    }

    #[test]
    fn version_short_circuits() {
        let r = parse(&args(&["inspect", "--version"]), default_root()).unwrap();
        assert!(matches!(r, ParseOutcome::Version(_)));
    }

    #[test]
    fn empty_args_is_arg_error() {
        let err = parse(&[], default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn root_equals_form_is_accepted() {
        // Use existing directory for this case.
        let r = parse(&args(&["inspect", "--root=/"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert_eq!(c.root.as_str(), "/");
        } else {
            panic!();
        }
    }
}
