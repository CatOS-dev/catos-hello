//! Data model layer. Pure data + serde, no I/O.
//!
//! Only genuinely cross-domain primitives remain here. Domain-owned models
//! live with their capability modules (`target`, `mount`, `fs`, `snapshot`,
//! `boot`).

pub mod evidence;
pub mod storage;
pub mod system;

pub use evidence::Evidence;
pub use storage::*;
pub use system::*;
