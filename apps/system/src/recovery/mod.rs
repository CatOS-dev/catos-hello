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
//!   confined.rs   openat2-confined recovery storage, Btrfs snapshot
//!                 ioctl, and dirfd-relative root exchange.
//!   lock.rs       Non-blocking per-FSID flock held by write engines.
//!   store.rs      Schema checks plus confined, durable state/plan I/O.
//!   external.rs   Trusted read-only btrfs-progs probes. Bounded output,
//!                 parameter arrays, no shell.
//!   boot.rs       Read-only boot/ESP topology and consistency gate;
//!                 recovery performs no boot-resource writes.
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
//! * `apply`, `resume`, and `revert` are the only commands that perform
//!   persistent recovery writes, all under the per-FSID lock.
//! * `apply` MUST re-verify every identity field and boot-consistency
//!   decision before the first persistent write.
//! * Every destructive path MUST refuse the currently running root.
//! * The source snapshot is NEVER made writable, renamed, or deleted.
//! * The original root is NEVER deleted; it is preserved as a
//!   pre-recovery backup at
//!   `/.catos-recovery/backups/<id>/root-before`.

pub mod boot;
pub mod confined;
pub mod engine;
pub mod external;
pub mod identity;
pub mod lock;
pub mod plan;
pub mod state;
pub mod store;

pub use engine::{Engine, EngineOptions};
pub use lock::{lock_file_path, TransactionLock};
pub use plan::{build_plan as build_recovery_plan, PlanInputs};
