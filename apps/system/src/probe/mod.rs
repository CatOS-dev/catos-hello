//! Probe layer. Reads the world via the [`FilesystemProbe`] trait so unit
//! tests can swap in fixtures. All probes return structured models, never
//! print directly.

pub mod capability;
pub mod fs_probe;
pub mod runtime;
pub mod target;

pub use capability::detect_capabilities;
pub use fs_probe::{FilesystemProbe, FixtureFilesystem, MetaData, RealFilesystem};
pub use runtime::detect_runtime;
pub use target::inspect_target;
