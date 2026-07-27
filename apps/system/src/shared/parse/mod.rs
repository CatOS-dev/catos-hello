//! Parse layer. Pure functions: bytes/string in, model out. No I/O.
//!
//! The fstab and mountinfo parsers migrated into the `mount` capability
//! ([`crate::mount::diagnose::fstab`] and [`crate::mount::diagnose::mountinfo`]).
//! This module is now empty; it remains declared until a later phase
//! removes the `shared::parse` path entirely.
