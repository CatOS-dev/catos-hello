//! Boot diagnosis, planning, execution, and verification capability.
//!
//! Application modules may compose this capability, but Boot never depends
//! on `repair`, `doctor`, `recovery`, `system`, or CLI/output layers.

pub mod diagnose;
pub mod execute;
pub mod model;
pub mod plan;
pub mod verify;

mod io;
