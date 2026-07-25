//! Phase-3 recovery engine.
//!
//! Implements the durable, interruptible, explicitly-authorised btrfs
//! root-snapshot recovery transaction described by the phase-3 spec.
//!
//! ## Layering
//!
//! ```text
//! recovery/
//!   state.rs      Pure state machine: allowed/denied transitions.
//!   identity.rs   Pure helpers + read-only probes: current-root
//!                 detection, path-escape guards, subvolume identity
//!                 re-verification.
//!   plan.rs       RecoveryPlan builder, confirmation token binding,
//!                 stale-plan rejection.
//!   store.rs      Durable state file: temp + fsync + atomic rename +
//!                 parent fsync. Schema version check.
//!   external.rs   Trusted btrfs-progs invocations (subvolume show /
//!                 snapshot / set-default). Bounded output, parameter
//!                 arrays, no shell.
//!   boot.rs       Boot / ESP layout detection. Safely refuses
//!                 finalization when no stable CatOS bootloadu
//!                 interface is available.
//!   engine.rs     Transaction executor. Owns the per-FSID lock,
//!                 drives the state machine, persists every transition,
//!                 performs the renameat2(RENAME_EXCHANGE) root swap.
//! ```
//!
//! Hard rules enforced by this module:
//!
//! * The transaction record lives on the btrfs top-level
//!   (`/.catos-recovery/transactions/<id>/state.json`), never inside
//!   a subvolume that may be replaced.
//! * `apply` is the only command that performs persistent writes.
//! * `apply` MUST re-verify every identity field before the first
//!   persistent write.
//! * `apply` MUST refuse to operate on the currently running root.
//! * The source snapshot is NEVER made writable, renamed, or deleted.
//! * The original root is NEVER deleted; it is preserved as a
//!   pre-recovery backup at
//!   `/.catos-recovery/backups/<id>/root-before`.

pub mod boot;
pub mod engine;
pub mod external;
pub mod identity;
pub mod plan;
pub mod state;
pub mod store;

pub use engine::{Engine, EngineOptions};
pub use plan::{build_plan as build_recovery_plan, PlanInputs};
