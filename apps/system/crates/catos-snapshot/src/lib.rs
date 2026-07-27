//! Btrfs snapshot capability: read-only diagnosis, pure planning,
//! authorized execution, durable transactions, and verification.

pub mod diagnose;
pub mod execute;
pub mod model;
pub mod plan;
pub mod store;
pub mod transaction;
pub mod verify;
