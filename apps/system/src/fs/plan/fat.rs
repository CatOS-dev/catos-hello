use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FatRepairPlan {
    pub(crate) device: String,
}

pub fn build(device: &str) -> FatRepairPlan {
    FatRepairPlan {
        device: device.to_string(),
    }
}
