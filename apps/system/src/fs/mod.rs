//! Filesystem capability: read-only diagnosis, pure repair planning,
//! explicit execution, target safety, and independent verification.
//!
//! Dependency rule: this module may depend on `target`, `mount`, and
//! cross-cutting `shared` infrastructure. It must not depend on `doctor`,
//! `repair`, `recovery`, `system`, `update`, `boot`, `snapshot`, or `chroot`.

pub mod command;
pub mod diagnose;
pub mod execute;
pub mod model;
pub mod plan;
pub mod safety;
pub mod verify;
