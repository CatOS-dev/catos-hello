use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XfsRepairPlan {
    pub(crate) device: String,
    pub(crate) allow_log_zero_fallback: bool,
}

pub fn build(device: &str) -> XfsRepairPlan {
    XfsRepairPlan {
        device: device.to_string(),
        allow_log_zero_fallback: true,
    }
}
