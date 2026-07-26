//! Cross-exec shared infrastructure.
//!
//! Modules here are reused by two or more CatOS multicall entry points
//! (`catos-system`, `catos-recovery`, `catos-doctor`, `catos-repair`,
//! `catos-update`, `catos-chroot`). Exec-specific code lives in the
//! top-level exec directories (`system/`, `recovery/`, ...).

pub mod error;
pub mod model;
pub mod mount;
pub mod output;
pub mod parse;
pub mod process;
pub mod probe;
