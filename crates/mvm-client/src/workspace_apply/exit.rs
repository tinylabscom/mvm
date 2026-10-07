//! What happens to a workspace's changes when a foreground run ends.
//!
//! Three outcomes, and the caller's flags and surroundings pick one. Nothing
//! is ever applied unless the caller asked for it up front or an operator
//! answered yes; every other case leaves the host tree alone and names the
//! command that would apply it later.

/// How a foreground run's workspace changes are handled at exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitApply {
    /// Show the diff and ask the operator on the controlling terminal.
    Prompt,
    /// Apply without asking; the caller asked for it up front.
    Apply,
    /// Apply nothing and print the command that would.
    Pointer,
}

/// The facts the exit decision depends on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExitApplyRequest {
    /// The caller passed `--apply`.
    pub apply: bool,
    /// Output is machine-readable, so nothing may be asked.
    pub json: bool,
    /// An operator is at a controlling terminal this process can ask on.
    pub operator_at_terminal: bool,
}

impl ExitApplyRequest {
    /// An explicit `--apply` always applies. Otherwise a prompt needs both a
    /// terminal and human-readable output; anything else gets the pointer.
    #[must_use]
    pub fn decide(self) -> ExitApply {
        if self.apply {
            ExitApply::Apply
        } else if self.json || !self.operator_at_terminal {
            ExitApply::Pointer
        } else {
            ExitApply::Prompt
        }
    }
}

/// The exact command that applies `vm`'s workspace later. `volume` is named
/// when the machine has more than one, because `machine apply` then requires
/// it.
#[must_use]
pub fn apply_command(vm: &str, volume: Option<&str>) -> String {
    match volume {
        Some(volume) => format!("mvmctl machine apply {vm} --volume {volume}"),
        None => format!("mvmctl machine apply {vm}"),
    }
}

/// Whether an answer to `Apply to working tree? [y/N]` is a yes. Only `y` and
/// `yes` count, in any case; an empty line, anything else, and no answer at
/// all are a no.
#[must_use]
pub fn is_affirmative(answer: Option<&str>) -> bool {
    answer.is_some_and(|answer| {
        let answer = answer.trim();
        answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
    })
}
