//! Effectful snapshot execution. All persistent Btrfs changes live here.

pub mod btrfs;
pub mod engine;
pub mod external;

pub use engine::{Engine, EngineOptions};
