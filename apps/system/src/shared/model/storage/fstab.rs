//! Fstab data model: thin re-exports of [`crate::shared::parse::fstab`] types so
//! consumers can import from `model::` uniformly. The actual parsing
//! lives in `parse::fstab` (no I/O) so the model layer stays pure-data.

pub use crate::shared::parse::fstab::{
    FstabDiagnostic, FstabEntry, FstabEntryKind, FstabParseError, FstabSource,
};
