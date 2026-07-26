//! Confined recovery operations: openat2-confined storage, btrfs snapshot
//! ioctls, identity re-verification, and read-only boot topology gates.

pub mod boot;
pub mod confined;
pub mod external;
pub mod identity;

pub use boot::*;
pub use confined::*;
pub use external::*;
pub use identity::*;
