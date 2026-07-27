//! Target discovery, target identity, rooted path access, and write-capability
//! primitives. This is the lowest domain crate in catos-system.

pub mod diagnose;
pub mod discovery;
pub mod error;
pub mod evidence;
pub mod execute;
pub mod fingerprint;
pub mod fstab;
pub mod model;
pub mod mountinfo;
pub mod path;
pub mod plan;
pub mod verify;
pub mod view;

pub use error::FsError;
pub use evidence::Evidence;
