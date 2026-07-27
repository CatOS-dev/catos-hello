//! Write-capable filesystem repair execution. Every entry point requires a
//! typed `FsRepairPlan`; callers cannot pass a diagnosis and ask the executor
//! to invent operations.

pub mod btrfs;
pub mod ext;
pub mod f2fs;
pub mod fat;
pub mod runner;
pub mod xfs;

use crate::fs::command::{FsCommandRunner, FsRunnerError};
use crate::fs::model::RepairAttempt;
use crate::fs::plan::FsRepairPlan;
use crate::fs::safety::FsRepairAuthorization;

pub use runner::RepairRunner;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowOutcome {
    Clean,
    Repaired,
    RepairedViaHighRiskFallback,
    ToolMissing,
    Unrepaired,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowResult {
    pub attempts: Vec<RepairAttempt>,
    pub outcome: FlowOutcome,
}

pub fn execute_repair_plan<R: FsCommandRunner + ?Sized>(
    runner: &R,
    plan: &FsRepairPlan,
    authorization: &FsRepairAuthorization,
) -> Result<FlowResult, FsRunnerError> {
    if !authorization.permits(plan) {
        return Err(FsRunnerError {
            message: "filesystem repair authorization does not match the plan".to_string(),
        });
    }
    match plan {
        FsRepairPlan::Ext(plan) => ext::execute(runner, plan),
        FsRepairPlan::Fat(plan) => fat::execute(runner, plan),
        FsRepairPlan::F2fs(plan) => f2fs::execute(runner, plan),
        FsRepairPlan::Xfs(plan) => xfs::execute(runner, plan),
        FsRepairPlan::Btrfs(plan) => btrfs::execute(runner, plan),
    }
}
