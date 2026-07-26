//! Output layer. Renders the same structured model as either human-readable
//! text or stable JSON. Never mutates the model.

pub mod boot_repair;
pub mod doctor;
pub mod human;
pub mod json;
pub mod mount_repair;
pub mod phase2;
pub mod recovery;
pub mod repair;

pub use boot_repair::{render_boot_repair_human, render_boot_repair_json};
pub use doctor::{exit_code_for as doctor_exit_code_for, render_doctor_human, render_doctor_json};
pub use human::render_human;
pub use json::render_json;
pub use mount_repair::{render_mount_repair_human, render_mount_repair_json};
pub use phase2::{render_phase2_error_json, render_phase2_human, render_phase2_json};
pub use recovery::{render_phase3_human, render_phase3_json};
pub use repair::{render_repair_human, render_repair_json};
