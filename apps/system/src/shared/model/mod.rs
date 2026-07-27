//! Data model layer. Pure data + serde, no I/O.
//!
//! Organised by domain (`storage`, `repair`, `snapshot`, `system`).
//! Each sub-module re-exports its types so callers can use either the
//! short path (`crate::shared::model::<Type>`) or the qualified domain
//! path (`crate::target::model::<Type>`).

pub mod evidence;
pub mod repair;
pub mod snapshot;
pub mod storage;
pub mod system;

pub use evidence::Evidence;
pub use repair::*;
pub use snapshot::*;
pub use storage::*;
pub use system::*;
