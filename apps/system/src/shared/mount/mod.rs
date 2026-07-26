//! Mount layer. State-changing: actual mount/umount syscalls.
//!
//! Layering:
//! * `syscall` — thin FFI wrappers. errno classified into [`MountError`].
//! * `ops` — runtime sessions: private namespaces, ordered mounts, and the
//!   trusted session-directory primitives shared by phase 2 (read-only) and
//!   phase 3 (read-write recovery).
//! * `planning` — build a [`MountPlan`] from fstab + device hints, plus the
//!   read-only probe helpers. Pure-ish: only reads to resolve device
//!   references; never mounts.

pub mod ops;
pub mod planning;
pub mod syscall;

pub use ops::*;
pub use planning::*;
