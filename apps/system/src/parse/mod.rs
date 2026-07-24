//! Parse layer. Pure functions: bytes/string in, model out. No I/O.
//!
//! These parsers are split from `probe/` so they can be tested against
//! fixtures without touching the filesystem, and so future probes can
//! reuse the same parsers (e.g. reading /etc/fstab from the running host
//! vs. from a mounted target root).

pub mod blkid;
pub mod fstab;
pub mod mountinfo;
