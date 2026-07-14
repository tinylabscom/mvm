//! Shared state cucumber threads through the steps of one scenario.

use std::process::Output;

/// Constructed fresh for every scenario. Holds the result of the most
/// recent CLI invocation so later `Then` steps can assert on it.
#[derive(Debug, Default, cucumber::World)]
pub struct CliWorld {
    pub last_run: Option<Output>,
}

impl CliWorld {
    /// The `Output` of the most recent CLI invocation, or a failed
    /// assertion naming the step that forgot to run one first.
    pub fn last_output(&self) -> &Output {
        self.last_run
            .as_ref()
            .expect("no CLI invocation recorded yet — a prior `When` step must run one")
    }
}
