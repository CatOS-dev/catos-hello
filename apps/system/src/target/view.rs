//! `TargetView`: a snapshot of the resolved target root + ESP paths.
//!
//! Does NOT own mount lifecycle.

use std::path::{Path, PathBuf};

use crate::target::model::TargetIdentity;

/// Lightweight view over a selected target. Holds the offline root path
/// (or `/` for the running root) and, when known, the ESP device path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetView {
    pub root: PathBuf,
    pub identity: TargetIdentity,
}

impl TargetView {
    /// Build a minimal view for an offline root directory with no further
    /// device facts. Used by Doctor's running-root path and by tests.
    pub fn for_root(root: &Path) -> Self {
        TargetView {
            root: root.to_path_buf(),
            identity: TargetIdentity {
                root: root.to_path_buf(),
                ..TargetIdentity::default()
            },
        }
    }
}
