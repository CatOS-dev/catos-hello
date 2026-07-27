//! `target` capability module — phase 1.
//!
//! Owns the target-domain model, the read-only diagnose layer, the
//! mount-free target plan, the rooted-filesystem execution primitives,
//! the LUKS open/close entry points, and the post-action verify hook.
//!
//! Dependency direction: `target` depends only on `shared::error`,
//! `shared::evidence`, `shared::process`, `shared::cli`, and external
//! crates. It MUST NOT depend on `mount`, `fs`, `snapshot`, `boot`,
//! `chroot`, `doctor`, `repair`, `recovery`, `system`, `update`, or
//! `entry`.

pub mod diagnose;
pub mod execute;
pub mod fingerprint;
pub mod model;
pub mod path;
pub mod plan;
pub mod verify;
pub mod view;
