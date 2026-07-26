//! Btrfs root-snapshot recovery transaction engine.
//!
//! Layering:
//! * `engine` — transaction executor. Owns the per-FSID lock, drives the
//!   state machine, persists every transition, performs the
//!   `renameat2(RENAME_EXCHANGE)` root swap.
//! * `tx` — pure state machine (allowed/denied transitions) and the
//!   `RecoveryPlan` builder with confirmation-token binding.
//! * `confined` — `openat2`-confined storage, btrfs snapshot ioctls,
//!   identity re-verification, and the read-only boot topology gate.
//! * `store` — schema checks plus confined, durable state/plan I/O, and
//!   the non-blocking per-FSID flock.
//!
//! Hard rules:
//! * The transaction record lives on the btrfs top-level, never inside a
//!   subvolume that may be replaced.
//! * `apply`, `resume`, `revert` are the only commands that perform
//!   persistent recovery writes, all under the per-FSID lock.
//! * Every destructive path refuses the currently running root.
//! * The source snapshot is never made writable, renamed, or deleted.

pub mod confined;
pub mod engine;
pub mod store;
pub mod tx;

pub use confined::*;
pub use engine::{Engine, EngineOptions};
pub use store::*;
pub use tx::plan::{build_plan as build_recovery_plan, PlanInputs};
pub use tx::*;
