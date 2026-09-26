//! The backend trait and the backends that need no I/O of their own.

use mvm_contract::policy::approval::ApprovalOutcome;
use mvm_contract::policy::approval_prompt::{ApprovalAnswer, ApprovalPrompt, ApprovalScope};

/// Answers one approval prompt. Blocking: the broker calls it on its own
/// thread, one prompt at a time.
///
/// Must fail closed — any failure is a denial with a fixed reason label.
pub trait ApprovalBackend: Send + Sync {
    fn decide(&self, prompt: &ApprovalPrompt) -> ApprovalAnswer;
}

/// Refuses every prompt.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyBackend;

impl ApprovalBackend for DenyBackend {
    fn decide(&self, prompt: &ApprovalPrompt) -> ApprovalAnswer {
        ApprovalAnswer::denied(prompt.request_id.clone(), "approval_policy_deny")
    }
}

/// How a [`ChainBackend`] combines its members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainMode {
    /// Every member must approve. Asked in order; the first denial stops.
    /// The approval reaches only as far as the narrowest member allowed.
    All,
    /// One member approving is enough. Asked in order; the first approval
    /// stops.
    Any,
}

/// Several backends combined.
pub struct ChainBackend {
    mode: ChainMode,
    members: Vec<Box<dyn ApprovalBackend>>,
}

impl ChainBackend {
    /// Combine `members` under `mode`. An empty chain denies.
    #[must_use]
    pub fn new(mode: ChainMode, members: Vec<Box<dyn ApprovalBackend>>) -> Self {
        Self { mode, members }
    }
}

impl ApprovalBackend for ChainBackend {
    fn decide(&self, prompt: &ApprovalPrompt) -> ApprovalAnswer {
        let id = || prompt.request_id.clone();
        if self.members.is_empty() {
            return ApprovalAnswer::denied(id(), "chain_empty");
        }
        match self.mode {
            ChainMode::All => {
                let mut scope = ApprovalScope::Session;
                for member in &self.members {
                    let answer = member.decide(prompt);
                    if answer.outcome != ApprovalOutcome::Approved {
                        return ApprovalAnswer::denied(id(), answer.reason_label());
                    }
                    if answer.scope == ApprovalScope::Once {
                        scope = ApprovalScope::Once;
                    }
                }
                ApprovalAnswer::approved(id(), scope, "chain_all")
            }
            ChainMode::Any => {
                for member in &self.members {
                    let answer = member.decide(prompt);
                    if answer.outcome == ApprovalOutcome::Approved {
                        return ApprovalAnswer::approved(id(), answer.scope, answer.reason_label());
                    }
                }
                ApprovalAnswer::denied(id(), "chain_any_denied")
            }
        }
    }
}

/// A function as a backend: the shape an SDK callback takes once the host
/// library hands its embedder the broker.
pub struct CallbackBackend {
    callback: Box<dyn Fn(&ApprovalPrompt) -> ApprovalAnswer + Send + Sync>,
}

impl CallbackBackend {
    #[must_use]
    pub fn new(
        callback: impl Fn(&ApprovalPrompt) -> ApprovalAnswer + Send + Sync + 'static,
    ) -> Self {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl ApprovalBackend for CallbackBackend {
    fn decide(&self, prompt: &ApprovalPrompt) -> ApprovalAnswer {
        let mut answer = (self.callback)(prompt);
        // The callback answers this prompt, whatever id it echoed.
        answer.request_id = prompt.request_id.clone();
        answer
    }
}

/// A short human label for what a prompt asks, for a one-line summary.
#[must_use]
pub fn approval_label(prompt: &ApprovalPrompt) -> &'static str {
    prompt.subject.kind_label()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::policy::approval::ApprovalRequestId;
    use mvm_contract::policy::approval_prompt::ApprovalSubject;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn prompt() -> ApprovalPrompt {
        ApprovalPrompt {
            request_id: ApprovalRequestId::parse("appr-1").unwrap(),
            subject: ApprovalSubject::ToolCall { tool: "t".into() },
            expires_in_ms: 1000,
        }
    }

    struct Counted {
        answer: fn(&ApprovalPrompt) -> ApprovalAnswer,
        calls: Arc<AtomicUsize>,
    }

    impl ApprovalBackend for Counted {
        fn decide(&self, prompt: &ApprovalPrompt) -> ApprovalAnswer {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.answer)(prompt)
        }
    }

    fn yes_once(p: &ApprovalPrompt) -> ApprovalAnswer {
        ApprovalAnswer::approved(p.request_id.clone(), ApprovalScope::Once, "a")
    }
    fn yes_session(p: &ApprovalPrompt) -> ApprovalAnswer {
        ApprovalAnswer::approved(p.request_id.clone(), ApprovalScope::Session, "b")
    }
    fn no(p: &ApprovalPrompt) -> ApprovalAnswer {
        ApprovalAnswer::denied(p.request_id.clone(), "said_no")
    }

    fn member(
        answer: fn(&ApprovalPrompt) -> ApprovalAnswer,
    ) -> (Box<dyn ApprovalBackend>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Box::new(Counted {
                answer,
                calls: calls.clone(),
            }),
            calls,
        )
    }

    #[test]
    fn all_needs_every_member_and_stops_at_the_first_no() {
        let (a, a_calls) = member(yes_session);
        let (b, _) = member(yes_once);
        let answer = ChainBackend::new(ChainMode::All, vec![a, b]).decide(&prompt());
        assert_eq!(answer.outcome, ApprovalOutcome::Approved);
        assert_eq!(
            answer.scope,
            ApprovalScope::Once,
            "the narrowest scope wins"
        );
        assert_eq!(a_calls.load(Ordering::SeqCst), 1);

        let (a, _) = member(no);
        let (b, b_calls) = member(yes_session);
        let answer = ChainBackend::new(ChainMode::All, vec![a, b]).decide(&prompt());
        assert_eq!(answer.outcome, ApprovalOutcome::Denied);
        assert_eq!(answer.reason_label(), "said_no");
        assert_eq!(b_calls.load(Ordering::SeqCst), 0, "not asked after a no");
    }

    #[test]
    fn any_needs_one_member_and_stops_at_the_first_yes() {
        let (a, _) = member(no);
        let (b, _) = member(yes_session);
        let (c, c_calls) = member(yes_once);
        let answer = ChainBackend::new(ChainMode::Any, vec![a, b, c]).decide(&prompt());
        assert_eq!(answer.outcome, ApprovalOutcome::Approved);
        assert_eq!(answer.scope, ApprovalScope::Session);
        assert_eq!(c_calls.load(Ordering::SeqCst), 0);

        let (a, _) = member(no);
        let (b, _) = member(no);
        let answer = ChainBackend::new(ChainMode::Any, vec![a, b]).decide(&prompt());
        assert_eq!(answer.outcome, ApprovalOutcome::Denied);
    }

    #[test]
    fn an_empty_chain_and_the_deny_backend_deny() {
        for mode in [ChainMode::All, ChainMode::Any] {
            assert_eq!(
                ChainBackend::new(mode, Vec::new())
                    .decide(&prompt())
                    .outcome,
                ApprovalOutcome::Denied
            );
        }
        assert_eq!(
            DenyBackend.decide(&prompt()).outcome,
            ApprovalOutcome::Denied
        );
    }

    #[test]
    fn a_callback_answers_for_the_prompt_it_was_given() {
        let backend = CallbackBackend::new(|_| {
            ApprovalAnswer::approved(
                ApprovalRequestId::parse("appr-other").unwrap(),
                ApprovalScope::Once,
                "sdk",
            )
        });
        let answer = backend.decide(&prompt());
        assert_eq!(answer.request_id.as_str(), "appr-1");
        assert_eq!(answer.outcome, ApprovalOutcome::Approved);
    }
}
