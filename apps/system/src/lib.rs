//! CatOS system backend library.
//!
//! Exposed publicly so unit tests can drive probe logic with injected
//! fixture filesystems. Not intended as a general-purpose API.
//!
//! Workspace layering:
//! ```text
//! catos-process
//!      ↓
//! catos-target
//!      ↓
//! catos-mount ──→ catos-fs / catos-boot / catos-chroot
//!                    ↓
//!               catos-snapshot
//!                    ↓
//! catos-app (CLI + multicall + application orchestration + output)
//! ```

pub use catos_boot as boot;
pub use catos_chroot as chroot;
pub mod cli;
pub mod doctor;
pub mod entry;
pub mod error;
pub use catos_fs as fs;
pub use catos_mount as mount;
pub mod output;
pub mod recovery;
pub mod repair;
pub mod selection_ui;
pub use catos_snapshot as snapshot;
pub mod system;
pub use catos_target as target;
pub mod update;

pub use catos_target::FsError;
pub use error::{exit_code, Error};

/// Program version string, single source of truth.
pub const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// JSON schema version. Bumped only on backward-incompatible report changes.
pub const SCHEMA_VERSION: u32 = 2;
