//! Low-level storage scan, target-plan, and read-only target-mount commands.
//! These sit between `entry.rs` and the shared probe/mount
//! layers and own the side-effects probes avoid. Hard rule: every function
//! here is READ-ONLY with respect to the target.

pub mod scan;
pub mod target;
pub mod util;

pub use scan::*;
pub use target::*;
pub use util::*;

use crate::mount::model::{MountPlan, MountSession};
use crate::target::model::StorageReport;
use crate::target::model::{TargetInspection, Warning};

/// Outcome of a low-level system command. Each variant carries the structured
/// model that the matching output renderer consumes.
pub enum SystemCommandOutcome {
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
