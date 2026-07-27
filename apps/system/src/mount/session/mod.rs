//! Mount session submodules: read-only session, target read-write
//! session, btrfs top-level read-write session, and shared cleanup
//! data + error taxonomy.
pub mod btrfs_top_level;
pub mod cleanup;
pub mod readonly;
pub mod readwrite;

pub use btrfs_top_level::BtrfsTopLevelRwSession;
pub use cleanup::{MountSessionError, MountSessionErrorKind};
pub use readonly::ReadOnlyMountSession;
pub use readwrite::TargetMountRwSession;
