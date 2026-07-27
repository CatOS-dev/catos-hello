//! Test-only helper: hold the per-FSID recovery lock for a fixed
//! duration so the Group 1 lock-conflict tests can verify the second
//! invoker gets `TransactionAlreadyActive` immediately.
//!
//! Compiled only when the `test-helpers` cargo feature is enabled.
//! Invoked by `tests/test_recovery_lock.rs` via `std::process::Command`.
//!
//! Protocol:
//!   argv[1] = top_level_mount
//!   argv[2] = fsid
//!   argv[3] = hold_seconds
//!
//! On successful lock acquisition, prints `LOCK_HELD <path>\n` to
//! stdout (line-buffered, flushed) so the parent can synchronise.
//! Then sleeps for `hold_seconds` and exits 0. On failure prints
//! `LOCK_FAILED <kind> <message>\n` to stdout and exits 1.

#![cfg(feature = "test-helpers")]

use std::env;
use std::process::ExitCode;
use std::time::Duration;

use catos_system::snapshot::transaction::{lock_file_path, TransactionLock};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <top_level_mount> <fsid> <hold_seconds>",
            args.first().map(String::as_str).unwrap_or("helper")
        );
        return ExitCode::from(2);
    }
    let top = &args[1];
    let fsid = &args[2];
    let hold_secs: u64 = match args[3].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("hold_seconds must be a u64");
            return ExitCode::from(2);
        }
    };

    let lock_path = lock_file_path(std::path::Path::new(top), fsid);
    match TransactionLock::try_acquire(&lock_path, fsid) {
        Ok(guard) => {
            // Keep the RAII guard in scope for the entire hold window;
            // dropping it after the sleep releases the flock normally.
            println!("LOCK_HELD {}", lock_path.display());
            // Flush so the parent can read the marker before we sleep.
            use std::io::Write;
            let _ = std::io::stdout().flush();
            std::thread::sleep(Duration::from_secs(hold_secs));
            drop(guard);
            ExitCode::from(0)
        }
        Err(err) => {
            println!("LOCK_FAILED {} {}", err.kind.code(), err.message);
            use std::io::Write;
            let _ = std::io::stdout().flush();
            ExitCode::from(1)
        }
    }
}
