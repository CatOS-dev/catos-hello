//! Data model layer. Pure data + serde, no I/O.

pub mod capability;
pub mod evidence;
pub mod inspection;
pub mod runtime;

pub use capability::{Capability, CapabilityKind, CapabilityStatus};
pub use evidence::Evidence;
pub use inspection::{InspectionReport, OsRelease, TargetInspection, ToolPath, Warning};
pub use runtime::{Detection, DetectionStatus, PrimaryRuntimeMode, RuntimeFacts};
