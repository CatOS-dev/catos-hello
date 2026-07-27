use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtRepairPlan {
    pub(crate) device: String,
}

pub fn build(device: &str) -> ExtRepairPlan {
    ExtRepairPlan {
        device: device.to_string(),
    }
}
