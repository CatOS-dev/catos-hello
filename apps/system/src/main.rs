//! Binary entry point. Reads argv, dispatches to the library, exits with
//! the stable code returned by `entry::run`.

use std::process::ExitCode;

use catos_system::entry;

fn main() -> ExitCode {
    // SAFETY / contract: argv[0] is conventionally the program name. On the
    // rare platforms where this is not guaranteed we fall back to the
    // canonical name.
    let raw_argv: Vec<String> = std::env::args().collect();
    let invocation = raw_argv
        .first()
        .map(|s| entry::Invocation::from_argv0(s))
        .unwrap_or(entry::Invocation::CatosSystem);
    let rest: Vec<String> = raw_argv.into_iter().skip(1).collect();

    // Convert the i32 exit code to ExitCode for a clean stdlib exit.
    let code = entry::run(invocation, &rest);
    ExitCode::from(code as u8)
}
