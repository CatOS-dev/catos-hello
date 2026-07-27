//! Execution primitives for the target capability: rooted-filesystem
//! confinement, target write lock, and LUKS open/close.

pub mod confined;
pub mod lock;
pub mod luks;
