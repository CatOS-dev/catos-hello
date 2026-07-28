//! `catos-update` entry point. A lightweight Rust reimplementation of
//! the canonical Arch/Cachy update flow:
//!
//! * pick a privilege elevation command (`sudo`, `sudo-rs`, `doas`, `run0`)
//! * list pending updates via `checkupdates`
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
//! catos-update -d, --devel     Pass --devel to the AUR helper (reserved;
//!                              accepted for flag-compat, no-op without
//!                              an AUR helper wired up).
//! catos-update -h, --help      Show help.
//! catos-update -V, --version   Show version.
//! ```

use std::io::Write;
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
    /// `-d` / `--devel`: reserved flag, currently a no-op.
    pub devel: bool,
}

/// Parse `catos-update` argv. Returns the selected options or an
/// error message describing the first offending argument. Help and
/// version are handled by the top-level dispatcher before this runs.
fn parse_argv(argv: &[String]) -> Result<UpdateOptions, String> {
    let mut opts = UpdateOptions::default();
    for arg in argv {
        match arg.as_str() {
            "-c" | "--check" | "-l" | "--list" => opts.check_only = true,
            "-d" | "--devel" => opts.devel = true,
            other => {
                return Err(format!(
                    "unknown option {other:?}; expected -c/--check, -l/--list, -d/--devel"
                ))
            }
        }
    }
    Ok(opts)
}

/// Entry point invoked from `entry::invocation_dispatch`. `--help` /
/// `--version` have already been handled by the top-level dispatcher.
pub fn run(argv: &[String]) -> i32 {
    let opts = match parse_argv(argv) {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("catos-update: {message}");
            return exit_code::ARG_ERROR;
        }
    };

    // Discover pending updates. checkupdates is the canonical Arch
    // helper: it performs a temporary pacman DB sync so the host's DB
    // is never mutated as a side effect of listing.
    let pending = match pacman::list_pending_updates() {
        Ok(lines) => lines,
        Err(message) => {
            eprintln!("catos-update: {message}");
            return exit_code::PROBE_FAILED;
        }
    };

    if pending.is_empty() {
        println!("catos-update: system is up to date");
        return exit_code::SUCCESS;
    }

    println!("Pending updates ({}):", pending.len());
    let mut out = std::io::stdout();
    for line in &pending {
        let _ = writeln!(out, "  {line}");
    }
    let _ = out.flush();

    if opts.check_only {
        return exit_code::SUCCESS;
    }

    // Confirm with the user on stdin. Default to "no" so a stray
    // newline never triggers an unprompted system mutation.
    if !confirm_yes_no("Proceed with update? [y/N] ", false) {
        eprintln!("catos-update: update aborted by user");
        return exit_code::SUCCESS;
    }

    let su_cmd = match su::pick_su_cmd() {
        Some(cmd) => cmd,
        None => {
            eprintln!(
                "catos-update: no privilege elevation command found (sudo, sudo-rs, doas, run0)"
            );
            return exit_code::PERMISSION_DENIED;
        }
    };

    // Run pacman -Syu with inherited stdio so its interactive prompts
    // (signature confirmations, conflict resolution) reach the user.
    // A non-zero pacman exit code is surfaced as PROBE_FAILED.
    let mut command = Command::new(&su_cmd);
    command.arg("pacman").arg("-Syu");
    let status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("catos-update: failed to run {su_cmd} pacman -Syu: {error}");
            return exit_code::PROBE_FAILED;
        }
    };
    if !status.success() {
        eprintln!("catos-update: pacman exited with status {status}");
        return exit_code::PROBE_FAILED;
    }
    println!("catos-update: update applied");
    exit_code::SUCCESS
}

/// Print the per-invocation help. Called from `entry::print_help` when
/// `catos-update --help` is used.
pub fn print_help() {
    let version = crate::PROGRAM_VERSION;
    print!(
        "catos-update {version} - CatOS interactive system updater\n\nUSAGE:\n    catos-update [OPTIONS]\n\nOPTIONS:\n    -c, --check       Print pending updates without applying them.\n    -l, --list        Alias for --check.\n    -d, --devel       Reserved for AUR --devel (currently a no-op).\n    -h, --help        Show this help message and exit.\n    -V, --version     Print program version and exit.\n\nEXIT CODES:\n    0   Updates listed, applied, or system up to date.\n    2   An option was not recognised.\n    4   No privilege elevation command available.\n    5   Could not enumerate or apply updates.\n"
    );
}

/// Read a single line from stdin and treat it as a yes/no answer.
/// Empty input falls back to `default`.
fn confirm_yes_no(prompt: &str, default: bool) -> bool {
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = write!(out, "{prompt}");
    let _ = out.flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    let trimmed = line.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return default;
    }
    matches!(trimmed.as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_flags() {
        let opts =
            parse_argv(&["-c".to_string(), "-d".to_string()]).expect("known flags must parse");
        assert!(opts.check_only);
        assert!(opts.devel);
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
}
