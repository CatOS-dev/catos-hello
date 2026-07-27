//! Storage-domain model: fstab + mount entries.
//!
//! Phase-1 target refactor: the block-device, candidate, and storage
//! report types moved to [`crate::target::model`]. Only the fstab thin
//! re-exports and the mount plan/session/error taxonomy remain here.

pub mod fstab;
pub mod mount;

pub use fstab::*;
pub use mount::*;
