//! Mount layer (phase 2). State-changing: actual mount/umount syscalls.
//!
//! Strict layering rule enforced by code review:
//! * `syscall` — thin FFI wrappers. errno classified into MountError.
//! * `namespace` — unshare + private propagation. fail-closed when unavailable.
//! * `plan` — build a MountPlan from fstab + device hints. Pure-ish: only
//!   reads to resolve device references; never mounts.
//! * `session` — owns a private namespace + ordered list of mounts. Reverses
//!   on failure, reports residual mounts.
//!
//! Phase 2 supports ONLY read-only mounts. There is no `rw` flag in any
//! public API of this module. Adding one requires a phase-3 design review.

pub mod namespace;
pub mod plan;
pub mod session;
pub mod syscall;
