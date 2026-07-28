//! Privilege elevation shared by interactive maintenance entry points.

use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use crate::error::exit_code;

pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments and no failure mode.
    unsafe { libc::geteuid() }
}

/// Elevate an interactive menu before it starts doing privileged discovery.
/// Non-interactive callers are left alone so JSON and automation paths retain
/// their existing structured failure behavior.
pub fn elevate_interactive_if_needed(role: &str, argv: &[String], program: &str) -> Option<i32> {
    if effective_uid() == 0 || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return None;
    }
    Some(reexec_as_root(role, argv, program, true))
}

/// Chroot cannot proceed at all without administrator privileges. Interactive
/// callers are elevated; non-interactive callers receive an actionable error
/// rather than an elevation tool waiting on an unavailable terminal.
pub fn require_root_or_reexec(role: &str, argv: &[String], program: &str) -> Option<i32> {
    if effective_uid() == 0 {
        return None;
    }
    Some(reexec_as_root(role, argv, program, false))
}

fn reexec_as_root(role: &str, argv: &[String], program: &str, interactive_only: bool) -> i32 {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        if interactive_only {
            return exit_code::PERMISSION_DENIED;
        }
        eprintln!("{program}: administrator privileges are required");
        eprintln!("Run `sudo catos-system {role}` from an interactive terminal.");
        return exit_code::PERMISSION_DENIED;
    }
    let Some(tool) = crate::update::su::pick_su_cmd() else {
        eprintln!("{program}: administrator privileges are required");
        eprintln!("No supported elevation tool was found. Run `catos-system {role}` as root.");
        return exit_code::PERMISSION_DENIED;
    };
    let Some(tool_path) = catos_process::trusted_tool_path(&tool) else {
        eprintln!("{program}: the selected elevation tool disappeared: {tool}");
        return exit_code::PERMISSION_DENIED;
    };
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{program}: cannot locate the current executable: {error}");
            return exit_code::PROBE_FAILED;
        }
    };
    println!("Administrator privileges are required. Starting {tool}...");
    let mut command = Command::new(tool_path);
    for argument in reexec_arguments(&executable, role, argv) {
        command.arg(argument);
    }
    match command.status() {
        Ok(status) => status.code().unwrap_or(exit_code::PROBE_FAILED),
        Err(error) => {
            eprintln!("{program}: failed to start {tool}: {error}");
            exit_code::PROBE_FAILED
        }
    }
}

fn reexec_arguments(executable: &Path, role: &str, argv: &[String]) -> Vec<String> {
    let mut arguments = Vec::with_capacity(argv.len() + 2);
    arguments.push(executable.display().to_string());
    arguments.push(role.to_string());
    arguments.extend(argv.iter().cloned());
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexec_uses_the_aggregate_role_shape() {
        assert_eq!(
            reexec_arguments(
                Path::new("/usr/lib/catos/catos-system"),
                "repair",
                &["mount".into(), "--json".into()],
            ),
            ["/usr/lib/catos/catos-system", "repair", "mount", "--json",]
        );
    }

    #[test]
    fn doctor_reexec_uses_the_aggregate_command_shape() {
        assert_eq!(
            reexec_arguments(Path::new("/usr/lib/catos/catos-system"), "doctor", &[]),
            ["/usr/lib/catos/catos-system", "doctor"]
        );
    }
}
