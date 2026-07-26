//! CatOS system backend library.
//!
//! Exposed publicly so unit tests can drive probe logic with injected
//! fixture filesystems. Not intended as a general-purpose API.
//!
//! Layering:
//! ```text
//! model   <- pure data + serde (no I/O)
//! parse   <- pure parsers (mountinfo, fstab, blkid output); no I/O
//! probe   <- reads filesystem via FilesystemProbe trait, returns model
//! mount   <- state-changing mount/unmount (phase 2+; only read-only mounts)
//! output  <- renders model as human text or JSON
//! cli     <- parses argv into commands
//! entry   <- main.rs glue: argv[0] multicall + dispatch
//! ```

pub mod cli;
pub mod doctor;
pub mod entry;
pub mod error;
pub mod model;
pub mod mount;
pub mod output;
pub mod parse;
pub mod phase2;
pub mod phase3;
pub mod probe;
pub mod process;
pub mod recovery;
pub mod repair;
pub mod system_root;
pub mod update;

pub use error::{exit_code, Error, FsError};

/// Program version string, single source of truth.
pub const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// JSON schema version. Bumped only on backward-incompatible report changes.
pub const SCHEMA_VERSION: u32 = 2;
