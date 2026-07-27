//! Output layer. Renders the same structured model as either human-readable
//! text or stable JSON. Never mutates the model.

pub mod doctor;
pub mod human;
pub mod json;
pub mod repair;
pub mod system;

pub use doctor::*;
pub use doctor::exit_code_for as doctor_exit_code_for;
pub use human::*;
pub use json::*;
pub use repair::*;
pub use system::*;
