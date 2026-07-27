//! Chroot capability.
//!
//! The capability is split into read-only diagnosis, pure planning,
//! authorised execution, target verification, and session lifecycle. CLI
//! parsing and interactive selection live under `entry::chroot`.

pub mod diagnose;
pub mod execute;
pub mod model;
pub mod plan;
pub mod session;
pub mod verify;
