//! System capability and runtime-mode probes.

pub mod capability;
pub mod runtime;

pub use capability::detect_capabilities;
pub use runtime::detect_runtime;
