//! System-domain model: Doctor aggregated-diagnosis data model.
//!
//! Phase-1 target refactor: capability / inspection / runtime types
//! moved to [`crate::target::model`]. Only `doctor` remains here.

pub mod doctor;

pub use doctor::*;
