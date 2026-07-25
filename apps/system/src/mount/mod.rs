//! Mount layer (phase 2). State-changing: actual mount/umount syscalls.
//!
//! Strict layering rule enforced by code review:
//! * `syscall` — thin FFI wrappers. errno classified into MountError.
//! * `namespace` — unshare + private propagation. fail-closed when unavailable.
//! * `plan` — build a MountPlan from fstab + device hints. Pure-ish: only
//!   reads to resolve device references; never mounts.
//! * `session` — owns a private namespace + ordered list of mounts. Reverses
//!   on failure, reports residual mounts.
//! * `secure_dir` — shared runtime-session-directory primitives used by
//!   phase 2 (read-only mounts) and phase 3 (read-write recovery
//!   transactions). Both phases MUST apply identical security semantics
//!   for the `/run/catos-system/sessions/` parent; centralising the
//!   rules here prevents phase 3 from shipping a weaker local copy.
//!
//! Phase 2 supports ONLY read-only mounts. The shared `secure_dir`
//! primitives are agnostic of the mount mode: they only build and
//! tear down the trusted session directory. Phase 3 mounts the
//! btrfs top-level read-write on top of a `secure_dir`-created
//! path; phase 2 mounts a read-only target on top of a different
//! `secure_dir`-created path. The two callers never share a path.

pub mod namespace;
pub mod plan;
pub mod probe;
pub mod secure_dir;
pub mod session;
pub mod syscall;
