use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct F2fsRepairPlan {
    pub(crate) device: String,
}

pub fn build(device: &str) -> F2fsRepairPlan {
    F2fsRepairPlan {
        device: device.to_string(),
    }
}
