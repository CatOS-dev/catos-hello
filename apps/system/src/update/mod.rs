//! `catos-update` entry point. A lightweight Rust reimplementation of
//! the canonical Arch/Cachy update flow:
//!
//! * pick a privilege elevation command (`sudo`, `sudo-rs`, `doas`, `run0`)
//! * list pending updates via `checkupdates`
//! * require an interactive terminal before any state-changing flow
//! * confirm with the user
//! * run `<su> pacman -Syu` with inherited stdio so pacman's interactive
//!   prompts work
//!
//! Deliberately narrow: no AUR helper integration, no flatpak, no news
//! scraping, no systray. Those belong in desktop-side tooling. This is
//! the minimal, auditable host-side updater that does not depend on
//! bash or any external library script.
//!
//! Argument contract (mirrors the subset of `arch-update` options that
//! make sense in this minimal form):
//!
//! ```text
//! catos-update                 List pending updates, confirm, apply.
//! catos-update -c, --check     Print pending updates only.
//! catos-update -l, --list      Alias for --check.
//! catos-update -h, --help      Show help.
//! catos-update -V, --version   Show version.
//! ```

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::Command;

use crate::error::exit_code;

pub mod pacman;
pub mod su;

/// Parsed `catos-update` arguments. Owned by [`run`]; constructed by
/// [`parse_argv`] which is the only place that interprets the argv
/// contract.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UpdateOptions {
    /// `-c` / `--check`: only print pending updates, do not apply.
    pub check_only: bool,
}

/// Parse `catos-update` argv. Returns the selected options or an
/// error message describing the first offending argument. Help and
/// version are handled by the top-level dispatcher before this runs.
fn parse_argv(argv: &[String]) -> Result<UpdateOptions, String> {
    let mut opts = UpdateOptions::default();
    for arg in argv {
        match arg.as_str() {
            "-c" | "--check" | "-l" | "--list" => opts.check_only = true,
            "-d" | "--devel" => {
                return Err(
                    "--devel is not supported; use an AUR helper directly for development-package updates"
                        .to_string(),
                )
            }
            other => {
                return Err(format!(
                    "unknown option {other:?}; expected -c/--check or -l/--list"
                ))
            }
        }
    }
    Ok(opts)
}

fn validate_interaction(opts: UpdateOptions, stdin_is_terminal: bool) -> Result<(), &'static str> {
    if opts.check_only || stdin_is_terminal {
        Ok(())
    } else {
        Err("applying updates requires an interactive terminal")
    }
}

/// Entry point invoked from `entry::invocation_dispatch`. `--help` /
/// `--version` have already been handled by the top-level dispatcher.
pub fn run(argv: &[String], program: &str) -> i32 {
    let opts = match parse_argv(argv) {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("{program}: {message}");
            return exit_code::ARG_ERROR;
        }
    };
    if let Err(message) = validate_interaction(opts, io::stdin().is_terminal()) {
        eprintln!("{program}: {message}");
        eprintln!("Use `{program} --check` for a non-interactive update check.");
        return exit_code::ARG_ERROR;
    }

    // Discover pending updates. checkupdates is the canonical Arch
    // helper: it performs a temporary pacman DB sync so the host's DB
    // is never mutated as a side effect of listing.
    let pending = match pacman::list_pending_updates() {
        Ok(lines) => lines,
        Err(message) => {
            eprintln!("{program}: {message}");
            return exit_code::PROBE_FAILED;
        }
    };

    if pending.is_empty() {
        return match write_status_line(&format!("{program}: system is up to date")) {
            Ok(()) => exit_code::SUCCESS,
            Err(error) => output_error(program, error),
        };
    }

    if let Err(error) = write_pending_updates(&pending) {
        return output_error(program, error);
    }

    if opts.check_only {
        return exit_code::SUCCESS;
    }

    // Confirm with the user on stdin. Default to "no" so a stray
    // newline never triggers an unprompted system mutation.
    let confirmed = match confirm_yes_no("Proceed with update? [y/N] ", false) {
        Ok(confirmed) => confirmed,
        Err(error) => return output_error(program, error),
    };
    if !confirmed {
        eprintln!("{program}: update aborted by user");
        return exit_code::SUCCESS;
    }

    let Some(pacman_path) = catos_process::trusted_tool_path("pacman") else {
        eprintln!("{program}: trusted pacman executable was not found");
        return exit_code::PROBE_FAILED;
    };

    // Run pacman -Syu with inherited stdio so its interactive prompts
    // (signature confirmations, conflict resolution) reach the user.
    // A non-zero pacman exit code is surfaced as PROBE_FAILED.
    let (mut command, command_name) = match update_command(&pacman_path) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{program}: {message}");
            return exit_code::PERMISSION_DENIED;
        }
    };
    command.arg("-Syu");
    let status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{program}: failed to run {command_name}: {error}");
            return exit_code::PROBE_FAILED;
        }
    };
    if !status.success() {
        eprintln!("{program}: pacman exited with status {status}");
        return exit_code::PROBE_FAILED;
    }
    match write_status_line(&format!("{program}: update applied")) {
        Ok(()) => exit_code::SUCCESS,
        Err(error) => output_error(program, error),
    }
}

fn update_command(pacman_path: &Path) -> Result<(Command, String), String> {
    let su_path = su::pick_su_cmd();
    build_update_command(unsafe { libc::geteuid() }, su_path.as_deref(), pacman_path)
}

fn build_update_command(
    effective_uid: u32,
    su_path: Option<&Path>,
    pacman_path: &Path,
) -> Result<(Command, String), String> {
    if effective_uid == 0 {
        return Ok((
            Command::new(pacman_path),
            format!("{} -Syu", pacman_path.display()),
        ));
    }
    let Some(su_path) = su_path else {
        return Err("no privilege elevation command found (sudo, sudo-rs, doas, run0)".to_string());
    };
    let mut command = Command::new(su_path);
    command.arg(pacman_path);
    Ok((
        command,
        format!("{} {} -Syu", su_path.display(), pacman_path.display()),
    ))
}

fn write_pending_updates(pending: &[String]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_pending_updates_to(&mut output, pending)
}

fn write_pending_updates_to<W: Write>(output: &mut W, pending: &[String]) -> io::Result<()> {
    writeln!(output, "Pending updates ({}):", pending.len())?;
    for line in pending {
        writeln!(output, "  {line}")?;
    }
    output.flush()
}

fn write_status_line(message: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{message}")?;
    output.flush()
}

fn output_error(program: &str, error: io::Error) -> i32 {
    eprintln!("{program}: stdout write failed: {error}");
    exit_code::SERIALIZE_FAILED
}

/// Build the per-invocation help text. The top-level dispatcher owns stdout
/// error handling so every public help path follows the same contract.
pub fn help_text(program: &str) -> String {
    let version = crate::PROGRAM_VERSION;
    format!(
        "{program} {version} - CatOS interactive system updater\n\nUSAGE:\n    {program}\n    {program} --check\n\nOPTIONS:\n    -c, --check       Print pending updates without applying them.\n    -l, --list        Alias for --check.\n    -h, --help        Show this help message and exit.\n    -V, --version     Print program version and exit.\n\nRunning without --check requires an interactive terminal. The updater asks\nfor confirmation before pacman starts.\n\nEXIT CODES:\n    0   Updates listed, applied, or system up to date.\n    2   Invalid options or no interactive terminal for applying updates.\n    4   No privilege elevation command available.\n    5   Could not enumerate or apply updates.\n    6   Output could not be written completely.\n"
    )
}

/// Read a single line from stdin and treat it as a yes/no answer.
/// Empty input falls back to `default`.
fn confirm_yes_no(prompt: &str, default: bool) -> io::Result<bool> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    confirm_yes_no_with(&mut input, &mut output, prompt, default)
}

fn confirm_yes_no_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    prompt: &str,
    default: bool,
) -> io::Result<bool> {
    loop {
        write!(output, "{prompt}")?;
        output.flush()?;
        let mut line = String::new();
        let read = input.read_line(&mut line)?;
        if read == 0 {
            writeln!(output)?;
            return Ok(default);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(output, "Please enter y or n.")?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_flags() {
        let opts = parse_argv(&["-c".to_string()]).expect("known flags must parse");
        assert!(opts.check_only);
    }

    #[test]
    fn devel_flag_is_rejected_instead_of_silently_doing_nothing() {
        let error = parse_argv(&["--devel".to_string()])
            .expect_err("unsupported flags must not be accepted as no-ops");
        assert!(error.contains("not supported"), "{error}");
    }

    #[test]
    fn applying_updates_requires_interactive_stdin() {
        assert!(validate_interaction(UpdateOptions::default(), false).is_err());
        assert!(validate_interaction(UpdateOptions { check_only: true }, false).is_ok());
    }

    #[test]
    fn list_alias_means_check() {
        let opts = parse_argv(&["--list".to_string()]).expect("--list accepted");
        assert!(opts.check_only);
    }

    #[test]
    fn parse_rejects_unknown_flag() {
        let err = parse_argv(&["--nonsense".to_string()]).expect_err("unknown flag rejected");
        assert!(err.contains("unknown option"), "unexpected message: {err}");
    }

    #[test]
    fn empty_argv_means_full_flow() {
        let opts = parse_argv(&[]).expect("empty argv");
        assert!(!opts.check_only);
    }

    #[test]
    fn pending_update_output_propagates_write_failures() {
        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let error = write_pending_updates_to(&mut BrokenWriter, &["pkg 1 -> 2".into()])
            .expect_err("write failure must be returned");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn confirmation_prompt_propagates_write_failures() {
        let mut input = io::Cursor::new(b"maybe\ny\n".to_vec());
        let mut output = io::Cursor::new(Vec::<u8>::new());
        assert!(confirm_yes_no_with(&mut input, &mut output, "Proceed? ", false).unwrap());
        let rendered = String::from_utf8(output.into_inner()).unwrap();
        assert!(rendered.contains("Please enter y or n."));

        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut input = io::Cursor::new(b"y\n".to_vec());
        assert!(confirm_yes_no_with(&mut input, &mut BrokenWriter, "Proceed? ", false).is_err());
    }

    #[test]
    fn update_command_uses_only_absolute_trusted_paths() {
        let pacman = Path::new("/usr/bin/pacman");

        let (root_command, _) = build_update_command(0, None, pacman).unwrap();
        assert_eq!(root_command.get_program(), pacman.as_os_str());

        let sudo = Path::new("/usr/bin/sudo");
        let (user_command, _) = build_update_command(1000, Some(sudo), pacman).unwrap();
        assert_eq!(user_command.get_program(), sudo.as_os_str());
        assert_eq!(
            user_command.get_args().next(),
            Some(pacman.as_os_str()),
            "the trusted pacman path must be passed as an absolute argument"
        );
    }

    #[test]
    fn non_root_update_without_an_elevation_tool_is_rejected() {
        let error = build_update_command(1000, None, Path::new("/usr/bin/pacman"))
            .expect_err("non-root update needs an elevation tool");
        assert!(error.contains("no privilege elevation command"), "{error}");
    }
}
