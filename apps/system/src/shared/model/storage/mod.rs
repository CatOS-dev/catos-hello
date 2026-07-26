//! Storage-domain model: block devices, mounts, fstab entries.

pub mod fstab;
pub mod mount;
pub mod storage;

pub use fstab::*;
pub use mount::*;
pub use storage::*;
