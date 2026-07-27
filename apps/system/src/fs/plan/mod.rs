//! Pure filesystem repair planning. This module performs no I/O and does not
//! accept a command runner or an execution context.

pub mod btrfs;
pub mod ext;
pub mod f2fs;
pub mod fat;
pub mod xfs;

use serde::Serialize;

use crate::fs::diagnose::BtrfsTopology;
use crate::fs::model::RepairTool;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FsRepairPlan {
    Ext(ext::ExtRepairPlan),
    Fat(fat::FatRepairPlan),
    F2fs(f2fs::F2fsRepairPlan),
    Xfs(xfs::XfsRepairPlan),
    Btrfs(btrfs::BtrfsRepairPlan),
}

impl FsRepairPlan {
    pub fn tool(&self) -> RepairTool {
        match self {
            Self::Ext(_) => RepairTool::E2fsck,
            Self::Fat(_) => RepairTool::FsckFat,
            Self::F2fs(_) => RepairTool::FsckF2fs,
            Self::Xfs(_) => RepairTool::XfsRepair,
            Self::Btrfs(_) => RepairTool::BtrfsCheck,
        }
    }

    pub fn device(&self) -> &str {
        match self {
            Self::Ext(plan) => &plan.device,
            Self::Fat(plan) => &plan.device,
            Self::F2fs(plan) => &plan.device,
            Self::Xfs(plan) => &plan.device,
            Self::Btrfs(plan) => &plan.device,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsPlanError {
    pub message: String,
}

impl std::fmt::Display for FsPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "filesystem plan error: {}", self.message)
    }
}
impl std::error::Error for FsPlanError {}

pub fn supports_filesystem(fstype: &str) -> Option<RepairTool> {
    match fstype {
        "ext2" | "ext3" | "ext4" => Some(RepairTool::E2fsck),
        "vfat" | "fat" | "fat32" | "fat16" | "fat12" | "msdos" => Some(RepairTool::FsckFat),
        "f2fs" => Some(RepairTool::FsckF2fs),
        "xfs" => Some(RepairTool::XfsRepair),
        "btrfs" => Some(RepairTool::BtrfsCheck),
        _ => None,
    }
}

pub fn build_repair_plan(
    fstype: &str,
    device: &str,
    btrfs_topology: Option<BtrfsTopology>,
) -> Result<Option<FsRepairPlan>, FsPlanError> {
    let plan = match supports_filesystem(fstype) {
        Some(RepairTool::E2fsck) => FsRepairPlan::Ext(ext::build(device)),
        Some(RepairTool::FsckFat) => FsRepairPlan::Fat(fat::build(device)),
        Some(RepairTool::FsckF2fs) => FsRepairPlan::F2fs(f2fs::build(device)),
        Some(RepairTool::XfsRepair) => FsRepairPlan::Xfs(xfs::build(device)),
        Some(RepairTool::BtrfsCheck) => {
            let topology = btrfs_topology.ok_or_else(|| FsPlanError {
                message: "Btrfs repair planning requires an explicit topology diagnosis"
                    .to_string(),
            })?;
            FsRepairPlan::Btrfs(
                btrfs::build(device, topology).map_err(|message| FsPlanError { message })?,
            )
        }
        None => return Ok(None),
    };
    Ok(Some(plan))
}
