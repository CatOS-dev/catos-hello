//! Probe layer. Reads the world via the [`FilesystemProbe`] trait so unit
//! tests can swap in fixtures. All probes return structured models, never
//! print directly.

pub mod devices;
pub mod fs_probe;
pub mod system;

pub use devices::*;
pub use fs_probe::{FilesystemProbe, FixtureFilesystem, MetaData, RealFilesystem};
pub use system::*;
