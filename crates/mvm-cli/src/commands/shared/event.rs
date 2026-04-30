//! Structured JSON event output for `--json` mode.

use serde::Serialize;

/// Structured event emitted during sync/build operations in --json mode.
#[derive(Debug, Serialize)]
pub struct PhaseEvent {
    timestamp: String,
    command: &'static str,
    phase: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl PhaseEvent {
    pub fn new(command: &'static str, phase: &str, status: &'static str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            command,
            phase: phase.to_string(),
            status,
            message: None,
            error: None,
        }
    }

    pub fn with_message(mut self, msg: &str) -> Self {
        self.message = Some(msg.to_string());
        self
    }

    pub fn with_error(mut self, err: &str) -> Self {
        self.error = Some(err.to_string());
        self
    }

    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{}", json);
        }
    }
}
