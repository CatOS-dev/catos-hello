//! `catos-system` exec: phase-2 orchestrators (storage scan, target plan,
//! target mount). These sit between `entry.rs` and the shared probe/mount
//! layers and own the side-effects probes avoid. Hard rule: every function
//! here is READ-ONLY with respect to the target.

pub mod scan;
pub mod target;
pub mod util;

pub use scan::*;
pub use target::*;
pub use util::*;

use crate::target::model::{TargetInspection, Warning};
use crate::mount::model::{MountPlan, MountSession};
use crate::target::model::StorageReport;

/// Outcome of a phase-2 command. Each variant carries the structured
/// model that the matching output renderer consumes.
pub enum Phase2Outcome {
    StorageScan(StorageReport),
    TargetPlan {
        plan: MountPlan,
        warnings: Vec<Warning>,
    },
    TargetMount {
        session: MountSession,
        inspection: Box<TargetInspection>,
        cleanup: crate::mount::model::CleanupReport,
        warnings: Vec<Warning>,
    },
}

