use serde::Serialize;

use crate::fs::diagnose::BtrfsTopology;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BtrfsRepairPlan {
    pub(crate) device: String,
    pub(crate) topology: BtrfsTopology,
    pub(crate) allow_repair_fallback: bool,
    pub(crate) verify_after_repair: bool,
}

pub fn build(device: &str, topology: BtrfsTopology) -> Result<BtrfsRepairPlan, String> {
    match topology {
        BtrfsTopology::SingleDevice => Ok(BtrfsRepairPlan {
            device: device.to_string(),
            topology,
            allow_repair_fallback: true,
            verify_after_repair: true,
        }),
        BtrfsTopology::MultiDevice => {
            Err("multi-device Btrfs repair requires manual intervention".to_string())
        }
        BtrfsTopology::Unknown => {
            Err("Btrfs topology is unknown; refusing a write-capable repair plan".to_string())
        }
    }
}
