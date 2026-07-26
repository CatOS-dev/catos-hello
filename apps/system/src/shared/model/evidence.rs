//! Evidence: every important judgement keeps a trace of why it was made.

use serde::{Deserialize, Serialize};

/// A single piece of evidence supporting a detection or capability.
///
/// Serialised to JSON with stable English keys. `value` is optional and
/// omitted entirely when absent (not serialised as `null`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    /// Stable machine code, e.g. `INITRD_RELEASE_PRESENT`.
    pub code: String,
    /// Where the evidence came from, e.g. a path or syscall name.
    pub source: String,
    /// Human-readable explanation (English, no colour escapes).
    pub message: String,
    /// Optional captured value, e.g. file content snippet or path compared.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub value: Option<String>,
}

impl Evidence {
    pub fn new(
        code: impl Into<String>,
        source: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            source: source.into(),
            message: message.into(),
            value: None,
        }
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }
}
