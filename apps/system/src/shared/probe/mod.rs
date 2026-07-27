//! Probe layer.
//!
//! Phase-1 target refactor: device discovery, candidate identification,
//! the filesystem probe abstraction, runtime + capability detection, and
//! target-root inspection all moved to [`crate::target::diagnose`]. This
//! module is intentionally empty of submodules now; the historical
//! `pub use` re-exports have been removed because every consumer now
//! imports directly from `crate::target::diagnose::*`.
