//! Mount planning: build a [`MountPlan`] from fstab + device hints, and the
//! read-only probe helpers reused by phase 3 and boot repair.

pub mod plan;
pub mod probe;

pub use plan::*;
pub use probe::*;
