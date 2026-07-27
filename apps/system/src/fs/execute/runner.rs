//! Write-capable repair runner marker.
//!
//! The process transport itself is neutral and lives in `fs::command`; this
//! wrapper is used by the repair application so read-only callers do not need
//! to import the execution module.

use crate::fs::command::{
    FsCommandInvocation, FsCommandRunner, FsRunnerError, ToolResult, TrustedRunner,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct RepairRunner {
    inner: TrustedRunner,
}

impl RepairRunner {
    pub fn new() -> Self {
        Self {
            inner: TrustedRunner::new(),
        }
    }
}

impl FsCommandRunner for RepairRunner {
    fn invoke(&self, invocation: &FsCommandInvocation) -> Result<ToolResult, FsRunnerError> {
        self.inner.invoke(invocation)
    }
}
