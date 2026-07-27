//! Read-only diagnose layer: device discovery, candidate identification,
//! filesystem probe abstraction, runtime detection, system-root resolution.
//!
//! All functions are read-only and accept `&dyn FilesystemProbe` (or its
//! concrete `RealFilesystem`). No function here acquires a write lock or
//! mutates the target.

pub mod block;
pub mod candidate;
pub mod filesystem;
pub mod runtime;
pub mod system_root;
