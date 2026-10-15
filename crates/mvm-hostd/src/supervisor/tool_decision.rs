//! Per-VM decisions for declared tool invocations.
//!
//! The endpoint receives resolved rules from the admitted plan. Only hashes
//! of the tool name and command line reach the audit chain; either input may
//! contain user data or a credential. A failed audit write refuses the call.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use mvm_contract::policy::approval_prompt::ApprovalSubject;
use mvm_contract::policy::tool_rules::{ToolDecision, ToolRules};
use mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding;
use mvm_contract::protocol::network_flow::tool::{ToolCheckRequest, ToolOrigin};
use rand::Rng;
use sha2::{Digest, Sha256};

use super::audit_recorder::{EventCategory, Recorder, RecorderError};
use super::runtime_approval::{ApprovalVerdict, RuntimeApprover};

/// Final decision after the signed rules and any operator answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolVerdict {
    /// The invocation may proceed.
    Allow,
    /// The invocation must be refused for this fixed, safe reason.
    Deny(&'static str),
}

/// A decision for a host-started invocation, carrying its lifecycle binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationVerdict {
    /// The invocation may proceed. The binding correlates its telemetry span;
    /// endpoint scope enforcement also consumes it when the tool owns routes
    /// or secrets.
    Allow {
        binding: Option<ToolInvocationBinding>,
    },
    /// The invocation must be refused for this fixed, safe reason.
    Deny(&'static str),
}

/// How many bound invocations one VM keeps live. A binding is released when
/// its command finishes; past this many, the oldest is retired, so a caller
/// that never released cannot exhaust the table.
pub const MAX_LIVE_INVOCATIONS: usize = 256;

trait ActiveToolTrace: Send {
    fn finish(self: Box<Self>, outcome: &'static str);
}

trait ToolTelemetry: Send + Sync {
    fn start(
        &self,
        binding: &ToolInvocationBinding,
        tool: &str,
        origin: ToolOrigin,
    ) -> Box<dyn ActiveToolTrace>;
}

struct TracingToolTelemetry;

struct TracingToolInvocation {
    span: tracing::Span,
    started: Instant,
}

impl ActiveToolTrace for TracingToolInvocation {
    fn finish(self: Box<Self>, outcome: &'static str) {
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.span.in_scope(|| {
            tracing::info!(
                target: "mvm.tool",
                phase = "finish",
                outcome,
                duration_ms,
                "tool invocation finished"
            );
        });
    }
}

impl ToolTelemetry for TracingToolTelemetry {
    fn start(
        &self,
        binding: &ToolInvocationBinding,
        tool: &str,
        origin: ToolOrigin,
    ) -> Box<dyn ActiveToolTrace> {
        let binding_id = binding.audit_id();
        let tool_sha256 = hex::encode(Sha256::digest(tool.as_bytes()));
        let span = tracing::info_span!(
            target: "mvm.tool",
            "mvm.tool.invocation",
            binding_id = %binding_id,
            tool_sha256 = %tool_sha256,
            origin = origin.audit_label(),
        );
        span.in_scope(|| {
            tracing::info!(
                target: "mvm.tool",
                phase = "start",
                "tool invocation started"
            );
        });
        Box::new(TracingToolInvocation {
            span,
            started: Instant::now(),
        })
    }
}

struct LiveInvocation {
    binding: ToolInvocationBinding,
    tool: String,
    trace: Option<Box<dyn ActiveToolTrace>>,
}

impl LiveInvocation {
    fn finish(mut self, outcome: &'static str) {
        if let Some(trace) = self.trace.take() {
            trace.finish(outcome);
        }
    }
}

impl Drop for LiveInvocation {
    fn drop(&mut self) {
        // Taking the trace makes explicit retirement and shutdown mutually
        // exclusive. Telemetry must not turn resource teardown into a panic,
        // including when a subscriber panics during an existing unwind.
        if let Some(trace) = self.trace.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                trace.finish("shutdown");
            }));
        }
    }
}

/// Rules, approver and chain recorder for one VM. Constructed only from the
/// endpoint's admitted plan projection.
pub struct ToolDecisionGate {
    rules: ToolRules,
    approver: Arc<dyn RuntimeApprover>,
    recorder: Arc<Recorder>,
    telemetry: Arc<dyn ToolTelemetry>,
    /// Live invocation traces, oldest first.
    invocations: Mutex<VecDeque<LiveInvocation>>,
}

impl ToolDecisionGate {
    /// Bind one admitted rule set to the endpoint's approval and audit path.
    #[must_use]
    pub fn new(
        rules: ToolRules,
        approver: Arc<dyn RuntimeApprover>,
        recorder: Arc<Recorder>,
    ) -> Self {
        Self::with_telemetry(rules, approver, recorder, Arc::new(TracingToolTelemetry))
    }

    fn with_telemetry(
        rules: ToolRules,
        approver: Arc<dyn RuntimeApprover>,
        recorder: Arc<Recorder>,
        telemetry: Arc<dyn ToolTelemetry>,
    ) -> Self {
        Self {
            rules,
            approver,
            recorder,
            telemetry,
            invocations: Mutex::new(VecDeque::new()),
        }
    }

    /// The admitted rules this gate decides.
    #[must_use]
    pub fn rules(&self) -> &ToolRules {
        &self.rules
    }

    /// Decide and record one invocation. A recorder failure is an error, so
    /// the caller cannot mistake an unaudited decision for an allow.
    pub async fn decide(
        &self,
        request: &ToolCheckRequest,
        origin: ToolOrigin,
    ) -> Result<ToolVerdict, RecorderError> {
        let verdict = self.verdict(request).await;
        self.record(request, verdict, None, origin).await?;
        Ok(verdict)
    }

    /// Decide and record one invocation. Every allow gets a fresh binding and
    /// a telemetry span that ends on release, eviction, or gate shutdown. Tools with
    /// endpoint scopes use the same binding for route and secret enforcement.
    pub async fn decide_invocation(
        &self,
        request: &ToolCheckRequest,
        origin: ToolOrigin,
    ) -> Result<InvocationVerdict, RecorderError> {
        let verdict = self.verdict(request).await;
        let binding = match verdict {
            ToolVerdict::Allow => Some(self.fresh_binding()),
            _ => None,
        };
        self.record(request, verdict, binding.as_ref(), origin)
            .await?;
        if let Some(binding) = &binding {
            self.start_trace(binding.clone(), &request.tool, origin);
        }
        Ok(match verdict {
            ToolVerdict::Allow => InvocationVerdict::Allow { binding },
            ToolVerdict::Deny(reason) => InvocationVerdict::Deny(reason),
        })
    }

    /// Retire a binding. Flows naming it afterwards belong to no tool.
    pub fn release(&self, binding: &ToolInvocationBinding) {
        let invocation = {
            let mut live = self.live();
            live.iter()
                .position(|invocation| &invocation.binding == binding)
                .and_then(|index| live.remove(index))
        };
        if let Some(invocation) = invocation {
            invocation.finish("completed");
        }
    }

    /// The tool a live binding was minted for.
    #[must_use]
    pub fn tool_for(&self, binding: &ToolInvocationBinding) -> Option<String> {
        self.live()
            .iter()
            .find(|invocation| &invocation.binding == binding)
            .map(|invocation| invocation.tool.clone())
    }

    fn live(&self) -> std::sync::MutexGuard<'_, VecDeque<LiveInvocation>> {
        self.invocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn fresh_binding(&self) -> ToolInvocationBinding {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        ToolInvocationBinding::from_random(bytes)
    }

    fn start_trace(&self, binding: ToolInvocationBinding, tool: &str, origin: ToolOrigin) {
        let trace = self.telemetry.start(&binding, tool, origin);
        let invocation = LiveInvocation {
            binding,
            tool: tool.to_string(),
            trace: Some(trace),
        };
        let mut live = self.live();
        if live.len() >= MAX_LIVE_INVOCATIONS
            && let Some(retired) = live.pop_front()
        {
            retired.finish("evicted");
        }
        live.push_back(invocation);
    }

    async fn verdict(&self, request: &ToolCheckRequest) -> ToolVerdict {
        let decision = match request.executable.as_deref() {
            Some(executable) => self
                .rules
                .decide_command(&request.tool, executable, &request.argv),
            None => ToolDecision::Deny("the invocation did not report an executable"),
        };
        match decision {
            ToolDecision::Allow => ToolVerdict::Allow,
            ToolDecision::Deny(reason) => ToolVerdict::Deny(reason),
            ToolDecision::Ask => {
                let subject = ApprovalSubject::ToolCall {
                    tool: request.tool.clone(),
                };
                match self.approver.decide(&subject).await {
                    ApprovalVerdict::Approved => ToolVerdict::Allow,
                    ApprovalVerdict::Denied { reason } => ToolVerdict::Deny(reason),
                }
            }
        }
    }

    async fn record(
        &self,
        request: &ToolCheckRequest,
        verdict: ToolVerdict,
        binding: Option<&ToolInvocationBinding>,
        origin: ToolOrigin,
    ) -> Result<(), RecorderError> {
        let (outcome, reason) = match verdict {
            ToolVerdict::Allow => ("allow", "allowed"),
            ToolVerdict::Deny(reason) => ("deny", reason),
        };
        let mut labels = vec![
            ("origin".to_string(), origin.audit_label().to_string()),
            (
                "tool_sha256".to_string(),
                hex::encode(Sha256::digest(request.tool.as_bytes())),
            ),
            (
                "argv_sha256".to_string(),
                hex::encode(Sha256::digest(request.argv.as_bytes())),
            ),
            ("outcome".to_string(), outcome.to_string()),
            ("reason".to_string(), reason.to_string()),
        ];
        if let Some(executable) = &request.executable {
            labels.push((
                "executable_sha256".to_string(),
                hex::encode(Sha256::digest(executable.as_bytes())),
            ));
        }
        if let Some(binding) = binding {
            labels.push(("binding_id".to_string(), binding.audit_id()));
        }
        self.recorder
            .record_unbound(EventCategory::Host, "host.tool.decision", labels)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use mvm_core::plan::TenantId;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    use super::*;
    use crate::supervisor::audit::{CapturingAuditSigner, NoopAuditSigner};

    #[derive(Default)]
    struct FieldCapture(std::collections::BTreeMap<String, String>);

    impl Visit for FieldCapture {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
    }

    #[derive(Default)]
    struct TraceCapture {
        spans: Vec<(u64, FieldCapture)>,
        events: Vec<(u64, FieldCapture)>,
    }

    struct CaptureLayer(Arc<Mutex<TraceCapture>>);

    impl<S> Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            _ctx: Context<'_, S>,
        ) {
            if attrs.metadata().target() == "mvm.tool" {
                assert_eq!(attrs.metadata().name(), "mvm.tool.invocation");
                let mut fields = FieldCapture::default();
                attrs.record(&mut fields);
                self.0.lock().unwrap().spans.push((id.into_u64(), fields));
            }
        }

        fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
            if event.metadata().target() == "mvm.tool" {
                let mut fields = FieldCapture::default();
                event.record(&mut fields);
                let id = ctx
                    .event_span(event)
                    .expect("tool event belongs to invocation")
                    .id();
                self.0.lock().unwrap().events.push((id.into_u64(), fields));
            }
        }
    }

    #[test]
    fn real_trace_fields_are_safe_and_finish_in_the_original_span() {
        let capture = Arc::new(Mutex::new(TraceCapture::default()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer(capture.clone()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let tool = "tool-secret-marker";
        let argv = "argv-secret-marker";
        let executable = "/bin/executable-secret-marker";
        let mut bindings = Vec::new();
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            runtime.block_on(async {
                let rules = ToolRules {
                    allow: vec![tool.into()],
                    detail: [(
                        tool.into(),
                        mvm_contract::policy::tool_rules::ToolRuleDetail {
                            executable: Some(executable.into()),
                            ..Default::default()
                        },
                    )]
                    .into(),
                    ..Default::default()
                };
                let (gate, _) = gate(rules, approving());
                for origin in [ToolOrigin::Host, ToolOrigin::GuestBroker] {
                    let InvocationVerdict::Allow {
                        binding: Some(binding),
                    } = gate
                        .decide_invocation(
                            &ToolCheckRequest {
                                tool: tool.into(),
                                executable: Some(executable.into()),
                                argv: argv.into(),
                            },
                            origin,
                        )
                        .await
                        .expect("audit before trace")
                    else {
                        panic!("allowed invocation must be bound");
                    };
                    bindings.push(binding);
                }
                gate.release(&bindings[0]);
                gate.release(&bindings[0]);
                drop(gate);
            });
        });
        let capture = capture.lock().unwrap();
        assert_eq!(capture.spans.len(), 2);
        assert_eq!(capture.events.len(), 4);
        for (index, (id, fields)) in capture.spans.iter().enumerate() {
            assert_eq!(fields.0.len(), 3);
            assert_eq!(fields.0["binding_id"], bindings[index].audit_id());
            assert_eq!(fields.0["tool_sha256"], hex::encode(Sha256::digest(tool)));
            let origin = [ToolOrigin::Host, ToolOrigin::GuestBroker][index];
            assert_eq!(fields.0["origin"], format!("{:?}", origin.audit_label()));
            let events: Vec<_> = capture
                .events
                .iter()
                .filter(|(event_id, _)| event_id == id)
                .collect();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].1.0["phase"], "\"start\"");
            assert_eq!(events[0].1.0.len(), 2);
            assert_eq!(events[1].1.0["phase"], "\"finish\"");
            assert_eq!(
                events[1].1.0["outcome"],
                if index == 0 {
                    "\"completed\""
                } else {
                    "\"shutdown\""
                }
            );
            assert_eq!(events[1].1.0.len(), 4);
            assert!(events[1].1.0["duration_ms"].parse::<u64>().is_ok());
        }
        for (_, fields) in capture.spans.iter().chain(capture.events.iter()) {
            for value in fields.0.values() {
                assert!(!value.contains(tool));
                assert!(!value.contains(argv));
                assert!(!value.contains(executable));
                assert!(
                    bindings
                        .iter()
                        .all(|binding| !value.contains(binding.as_str()))
                );
            }
        }
    }

    struct ScriptedApprover {
        calls: AtomicUsize,
        verdict: ApprovalVerdict,
    }

    #[async_trait]
    impl RuntimeApprover for ScriptedApprover {
        async fn decide(&self, subject: &ApprovalSubject) -> ApprovalVerdict {
            assert!(matches!(subject, ApprovalSubject::ToolCall { .. }));
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.verdict
        }
    }

    fn gate(
        rules: ToolRules,
        approver: Arc<ScriptedApprover>,
    ) -> (ToolDecisionGate, Arc<CapturingAuditSigner>) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Arc::new(Recorder::new(signer.clone(), TenantId("local".into())));
        (ToolDecisionGate::new(rules, approver, recorder), signer)
    }

    fn request(tool: &str, argv: &str) -> ToolCheckRequest {
        ToolCheckRequest {
            tool: tool.into(),
            executable: Some(format!("/bin/{tool}")),
            argv: argv.into(),
        }
    }

    #[tokio::test]
    async fn deny_and_unlisted_refusals_never_prompt() {
        let approver = Arc::new(ScriptedApprover {
            calls: AtomicUsize::new(0),
            verdict: ApprovalVerdict::Approved,
        });
        let (gate, signer) = gate(
            ToolRules {
                allow: vec!["read".into()],
                deny: vec!["write".into()],
                ..ToolRules::default()
            },
            Arc::clone(&approver),
        );
        assert!(matches!(
            gate.decide(&request("write", "write x"), ToolOrigin::Host)
                .await,
            Ok(ToolVerdict::Deny(_))
        ));
        assert!(matches!(
            gate.decide(&request("other", "other"), ToolOrigin::Host)
                .await,
            Ok(ToolVerdict::Deny(_))
        ));
        assert_eq!(approver.calls.load(Ordering::Relaxed), 0);
        assert_eq!(signer.entries().len(), 2);
    }

    #[tokio::test]
    async fn ask_uses_runtime_approver_and_records_the_result() {
        let approver = Arc::new(ScriptedApprover {
            calls: AtomicUsize::new(0),
            verdict: ApprovalVerdict::Approved,
        });
        let (gate, signer) = gate(
            ToolRules {
                ask: vec!["shell".into()],
                detail: [(
                    "shell".into(),
                    mvm_contract::policy::tool_rules::ToolRuleDetail {
                        executable: Some("/bin/shell".into()),
                        ..Default::default()
                    },
                )]
                .into(),
                ..ToolRules::default()
            },
            Arc::clone(&approver),
        );
        assert_eq!(
            gate.decide(&request("shell", "echo ok"), ToolOrigin::Host)
                .await
                .expect("audit"),
            ToolVerdict::Allow
        );
        assert_eq!(approver.calls.load(Ordering::Relaxed), 1);
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        let recorded = serde_json::to_string(&entries).expect("serialize audit entries");
        assert!(!recorded.contains("echo ok"));
    }

    #[tokio::test]
    async fn spoofed_or_unreported_executable_is_audited_and_never_prompts() {
        let approver = approving();
        let mut rules = ToolRules {
            ask: vec!["gh".into()],
            ..ToolRules::default()
        };
        rules.detail.insert(
            "gh".into(),
            mvm_contract::policy::tool_rules::ToolRuleDetail {
                executable: Some("/usr/bin/gh".into()),
                ..Default::default()
            },
        );
        let (gate, signer) = gate(rules, Arc::clone(&approver));
        let mut spoof = request("gh", "gh api");
        assert!(matches!(
            gate.decide(&spoof, ToolOrigin::Host).await,
            Ok(ToolVerdict::Deny(_))
        ));
        spoof.executable = None;
        assert!(matches!(
            gate.decide(&spoof, ToolOrigin::Host).await,
            Ok(ToolVerdict::Deny(_))
        ));
        assert_eq!(approver.calls.load(Ordering::Relaxed), 0);
        assert_eq!(signer.entries().len(), 2);
    }

    fn scoped_rules() -> ToolRules {
        let mut rules = ToolRules {
            allow: vec!["gh".into(), "plain".into()],
            ..ToolRules::default()
        };
        rules.detail.insert(
            "gh".into(),
            mvm_contract::policy::tool_rules::ToolRuleDetail {
                executable: Some("/bin/gh".into()),
                routes: vec!["api.github.com:443".into()],
                ..Default::default()
            },
        );
        rules.detail.insert(
            "plain".into(),
            mvm_contract::policy::tool_rules::ToolRuleDetail {
                executable: Some("/bin/plain".into()),
                ..Default::default()
            },
        );
        rules
    }

    fn approving() -> Arc<ScriptedApprover> {
        Arc::new(ScriptedApprover {
            calls: AtomicUsize::new(0),
            verdict: ApprovalVerdict::Approved,
        })
    }

    #[derive(Clone, Default)]
    struct FakeTelemetry {
        starts: Arc<AtomicUsize>,
        finishes: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ToolTelemetry for FakeTelemetry {
        fn start(
            &self,
            _binding: &ToolInvocationBinding,
            _tool: &str,
            _origin: ToolOrigin,
        ) -> Box<dyn ActiveToolTrace> {
            self.starts.fetch_add(1, Ordering::Relaxed);
            Box::new(FakeActiveTrace {
                finishes: Arc::clone(&self.finishes),
            })
        }
    }

    struct FakeActiveTrace {
        finishes: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ActiveToolTrace for FakeActiveTrace {
        fn finish(self: Box<Self>, outcome: &'static str) {
            self.finishes.lock().unwrap().push(outcome);
        }
    }

    #[tokio::test]
    async fn an_allowed_scoped_invocation_gets_a_recorded_binding_until_released() {
        let (gate, signer) = gate(scoped_rules(), approving());
        let InvocationVerdict::Allow {
            binding: Some(binding),
        } = gate
            .decide_invocation(&request("gh", "gh api"), ToolOrigin::Host)
            .await
            .expect("audit")
        else {
            panic!("a scoped tool's allowed invocation is bound");
        };
        assert_eq!(gate.tool_for(&binding).as_deref(), Some("gh"));
        let recorded = serde_json::to_string(&signer.entries()).expect("entries");
        assert!(recorded.contains(&binding.audit_id()), "{recorded}");
        assert!(
            !recorded.contains(binding.as_str()),
            "the audit log must not carry a usable binding: {recorded}"
        );
        gate.release(&binding);
        assert_eq!(gate.tool_for(&binding), None);
    }

    #[tokio::test]
    async fn an_allowed_tool_has_one_telemetry_span_from_allow_through_release() {
        let telemetry = Arc::new(FakeTelemetry::default());
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Arc::new(Recorder::new(signer, TenantId("local".into())));
        let gate = ToolDecisionGate::with_telemetry(
            scoped_rules(),
            approving(),
            recorder,
            telemetry.clone(),
        );
        let InvocationVerdict::Allow {
            binding: Some(binding),
        } = gate
            .decide_invocation(&request("plain", "plain x"), ToolOrigin::GuestBroker)
            .await
            .expect("audit")
        else {
            panic!("allowed tool use must carry its trace binding");
        };

        assert_eq!(telemetry.starts.load(Ordering::Relaxed), 1);
        assert!(telemetry.finishes.lock().unwrap().is_empty());

        gate.release(&binding);
        gate.release(&binding);
        drop(gate);
        assert_eq!(telemetry.finishes.lock().unwrap().as_slice(), ["completed"]);
    }

    #[tokio::test]
    async fn host_release_and_shutdown_finish_each_trace_once_even_with_poison() {
        let telemetry = Arc::new(FakeTelemetry::default());
        let recorder = Arc::new(Recorder::new(
            Arc::new(CapturingAuditSigner::new()),
            TenantId("local".into()),
        ));
        let gate = ToolDecisionGate::with_telemetry(
            scoped_rules(),
            approving(),
            recorder,
            telemetry.clone(),
        );
        let mut bindings = Vec::new();
        for origin in [ToolOrigin::Host, ToolOrigin::Host, ToolOrigin::GuestBroker] {
            let InvocationVerdict::Allow {
                binding: Some(binding),
            } = gate
                .decide_invocation(&request("plain", "plain x"), origin)
                .await
                .expect("audit")
            else {
                panic!("allowed invocation must be bound");
            };
            bindings.push(binding);
        }
        gate.release(&bindings[0]);
        gate.release(&bindings[0]);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _live = gate.live();
            panic!("poison the invocation mutex");
        }));
        assert!(poisoned.is_err());
        drop(gate);
        assert_eq!(telemetry.starts.load(Ordering::Relaxed), 3);
        assert_eq!(
            telemetry.finishes.lock().unwrap().as_slice(),
            ["completed", "shutdown", "shutdown"]
        );
    }

    #[test]
    fn shutdown_contains_telemetry_panics_and_continues_finishing() {
        struct PanickingTrace(Arc<AtomicUsize>);
        impl ActiveToolTrace for PanickingTrace {
            fn finish(self: Box<Self>, outcome: &'static str) {
                assert_eq!(outcome, "shutdown");
                self.0.fetch_add(1, Ordering::Relaxed);
                panic!("trace implementation failed");
            }
        }
        for already_unwinding in [false, true] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let invocations: Vec<_> = (0..2)
                    .map(|_| LiveInvocation {
                        binding: ToolInvocationBinding::from_random([1; 16]),
                        tool: "plain".into(),
                        trace: Some(
                            Box::new(PanickingTrace(attempts.clone())) as Box<dyn ActiveToolTrace>
                        ),
                    })
                    .collect();
                if already_unwinding {
                    panic!("outer failure");
                }
                drop(invocations);
            }));
            assert_eq!(result.is_err(), already_unwinding);
            if let Err(payload) = result {
                assert_eq!(payload.downcast_ref::<&str>(), Some(&"outer failure"));
            }
            assert_eq!(attempts.load(Ordering::Relaxed), 2);
        }
    }

    #[tokio::test]
    async fn every_allowed_invocation_is_traced_but_refusals_get_no_binding() {
        let (gate, _signer) = gate(scoped_rules(), approving());
        let InvocationVerdict::Allow {
            binding: Some(binding),
        } = gate
            .decide_invocation(&request("plain", "plain x"), ToolOrigin::Host)
            .await
            .expect("audit")
        else {
            panic!("every allowed tool use gets a lifecycle trace binding");
        };
        assert_eq!(gate.tool_for(&binding).as_deref(), Some("plain"));
        assert!(matches!(
            gate.decide_invocation(&request("other", "other"), ToolOrigin::Host)
                .await
                .expect("audit"),
            InvocationVerdict::Deny(_)
        ));
        assert_eq!(gate.live().len(), 1);
        gate.release(&binding);
        assert!(gate.live().is_empty());
    }

    #[tokio::test]
    async fn an_unaudited_scoped_allow_leaves_no_live_binding() {
        let telemetry = Arc::new(FakeTelemetry::default());
        let recorder = Arc::new(Recorder::new(
            Arc::new(NoopAuditSigner),
            TenantId("local".into()),
        ));
        let gate = ToolDecisionGate::with_telemetry(
            scoped_rules(),
            approving(),
            recorder,
            telemetry.clone(),
        );
        for origin in [ToolOrigin::Host, ToolOrigin::GuestBroker] {
            assert!(
                gate.decide_invocation(&request("gh", "gh api"), origin)
                    .await
                    .is_err()
            );
        }
        assert!(gate.live().is_empty());
        drop(gate);
        assert_eq!(telemetry.starts.load(Ordering::Relaxed), 0);
        assert!(telemetry.finishes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn past_the_bound_the_oldest_binding_is_retired() {
        let telemetry = Arc::new(FakeTelemetry::default());
        let recorder = Arc::new(Recorder::new(
            Arc::new(CapturingAuditSigner::new()),
            TenantId("local".into()),
        ));
        let gate = ToolDecisionGate::with_telemetry(
            scoped_rules(),
            approving(),
            recorder,
            telemetry.clone(),
        );
        let mut minted = Vec::new();
        for _ in 0..=MAX_LIVE_INVOCATIONS {
            match gate
                .decide_invocation(&request("gh", "gh api"), ToolOrigin::Host)
                .await
                .expect("audit")
            {
                InvocationVerdict::Allow {
                    binding: Some(binding),
                } => minted.push(binding),
                other => panic!("expected a bound allow, got {other:?}"),
            }
        }
        assert_eq!(gate.live().len(), MAX_LIVE_INVOCATIONS);
        assert_eq!(gate.tool_for(&minted[0]), None);
        assert_eq!(gate.tool_for(&minted[1]).as_deref(), Some("gh"));
        gate.release(&minted[0]);
        assert_eq!(telemetry.finishes.lock().unwrap().as_slice(), ["evicted"]);
        drop(gate);
        let finishes = telemetry.finishes.lock().unwrap();
        assert_eq!(finishes.len(), MAX_LIVE_INVOCATIONS + 1);
        assert!(finishes[1..].iter().all(|outcome| *outcome == "shutdown"));
    }

    #[tokio::test]
    async fn audit_failure_refuses_an_otherwise_allowed_call() {
        let approver = Arc::new(ScriptedApprover {
            calls: AtomicUsize::new(0),
            verdict: ApprovalVerdict::Approved,
        });
        let recorder = Arc::new(Recorder::new(
            Arc::new(NoopAuditSigner),
            TenantId("local".into()),
        ));
        let gate = ToolDecisionGate::new(
            ToolRules {
                allow: vec!["shell".into()],
                detail: [(
                    "shell".into(),
                    mvm_contract::policy::tool_rules::ToolRuleDetail {
                        executable: Some("/bin/shell".into()),
                        ..Default::default()
                    },
                )]
                .into(),
                ..ToolRules::default()
            },
            approver,
            recorder,
        );
        assert!(
            gate.decide(&request("shell", "echo ok"), ToolOrigin::Host)
                .await
                .is_err()
        );
    }
}
