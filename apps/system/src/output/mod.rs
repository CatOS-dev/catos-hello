//! Output layer. Renders the same structured model as either human-readable
//! text or stable JSON. Never mutates the model.

pub mod human;
pub mod json;
pub mod phase2;

pub use human::render_human;
pub use json::render_json;
pub use phase2::{render_phase2_human, render_phase2_json};
