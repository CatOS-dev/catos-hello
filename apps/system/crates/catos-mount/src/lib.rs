//! Mount capability: fstab/mountinfo parsing, mount layout diagnosis,
//! read-only and read-write mount session planning + execution, and
//! mount verification.
//!
//! Dependency rule: this crate depends only on `catos-target`,
//! `catos-process`, and external crates. It MUST NOT depend on the
//! `fs`, `snapshot`, `boot`, or `chroot` capability modules, nor on the
//! `doctor`, `repair`, `recovery`, `system`, `update`, or `entry`
//! application modules.

pub mod diagnose;
pub mod execute;
pub mod model;
pub mod plan;
pub mod session;
pub mod verify;
