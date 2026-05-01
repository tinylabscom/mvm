//! Inspector trait + InspectorChain — the L7 egress security backbone.
//!
//! Plan 37 §15 (CORNERSTONE / DIFFERENTIATOR). Every outbound HTTP
//! request the workload makes is mediated by the supervisor's
//! `EgressProxy` (Wave 2.6 wires the real impl). The proxy threads
//! the request through an ordered chain of `Inspector`s, each of
//! which can:
//!   - allow the request through (default verdict)
//!   - deny it with a reason that's surfaced to the workload + audit
//!   - rewrite the request (PiiRedactor in Wave 2.5)
//!
//! The chain short-circuits on the first `Deny` — subsequent
//! inspectors don't run. This matches the threat model: each
//! inspector defends against one threat, and a single block is a
//! definitive answer; nothing downstream can override it.
//!
//! Wave 2.1 ships the trait surface + chain runner + the simplest
//! concrete inspector (`DestinationPolicy`, an explicit
//! (host, port) allowlist). Subsequent waves layer on:
//!   - 2.2 SecretsScanner (regex on outbound bodies)
//!   - 2.3 SsrfGuard (block private IP ranges + cloud metadata IPs)
//!   - 2.4 InjectionGuard (model-output → tool-arg untainting)
//!   - 2.5 AiProviderRouter + PiiRedactor (detect-only first)
//!   - 2.6 Wire `L7EgressProxy` into the supervisor (replaces
//!     `NoopEgressProxy` default)

use std::fmt;
use std::net::IpAddr;

use async_trait::async_trait;

/// Mutable inspection context threaded through the chain. Wave 2.1
/// carries host/port/path; Wave 2.2 adds `body` so `SecretsScanner`
/// can scan outbound payloads. Later waves extend with `headers`,
/// `payload_classification`, etc. — the chain continues to
/// short-circuit on the first deny regardless of what fields are
/// populated. `body` is `Vec<u8>` (not `&[u8]`) so `Transform`
/// inspectors (e.g., PiiRedactor in 2.5) can mutate it in place.
#[derive(Debug, Clone)]
pub struct RequestCtx {
    pub host: String,
    pub port: u16,
    pub path: String,
    /// Outbound body bytes. Empty for GET/HEAD/DELETE; populated for
    /// methods that carry payloads. Bytes (not `String`) because
    /// bodies may be binary (protobuf, multipart, etc.).
    pub body: Vec<u8>,
    /// Resolved destination IP, populated by the proxy after DNS
    /// lookup but before opening the connection. `SsrfGuard` (Wave
    /// 2.3) inspects this to refuse private/internal/metadata IPs.
    /// `None` when the host is an IP literal (the proxy uses
    /// `host` directly) or before the proxy has resolved DNS — the
    /// guard handles both cases. The proxy must pin the IP it
    /// resolves here for the actual connect() call to defend
    /// against DNS rebinding.
    pub resolved_ip: Option<IpAddr>,
}

impl RequestCtx {
    pub fn new(host: impl Into<String>, port: u16, path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            path: path.into(),
            body: Vec::new(),
            resolved_ip: None,
        }
    }

    /// Builder-style: attach a body to a context. Useful in tests and
    /// at the proxy callsite when the body is read upfront.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Builder-style: pin the resolved IP. The proxy calls this once
    /// DNS resolution succeeds; tests use it to drive `SsrfGuard`
    /// directly.
    pub fn with_resolved_ip(mut self, ip: IpAddr) -> Self {
        self.resolved_ip = Some(ip);
        self
    }
}

/// One inspector's verdict. `Allow` falls through to the next
/// inspector; `Deny` short-circuits the chain. `Transform` is the
/// in-band mutation hook (PiiRedactor mutates `RequestCtx` and
/// returns `Allow` after; explicit `Transform` is reserved for
/// inspectors that need to signal "I changed the request" to the
/// audit stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectorVerdict {
    Allow,
    Deny {
        reason: String,
    },
    /// Request was mutated in `RequestCtx`. Inspectors should also
    /// emit an audit signal so the operator can answer "what was
    /// changed?" after the fact.
    Transform {
        note: String,
    },
}

impl InspectorVerdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, InspectorVerdict::Allow)
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, InspectorVerdict::Deny { .. })
    }
}

#[async_trait]
pub trait Inspector: Send + Sync {
    /// Stable name shown in audit entries when this inspector
    /// returns `Deny` or `Transform`. Should be a short snake_case
    /// identifier (`secrets_scanner`, `destination_policy`, etc.).
    fn name(&self) -> &'static str;

    /// Inspect (and potentially mutate) the request context.
    async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict;
}

/// Ordered chain of inspectors. The order matters — earlier
/// inspectors see unmutated requests and can deny before later
/// inspectors do their (potentially expensive) work. Plan 37 §15's
/// recommended order: `DestinationPolicy` → `SsrfGuard` →
/// `SecretsScanner` → `InjectionGuard` → `PiiRedactor`.
pub struct InspectorChain {
    inspectors: Vec<Box<dyn Inspector>>,
}

impl InspectorChain {
    pub fn new() -> Self {
        Self {
            inspectors: Vec::new(),
        }
    }

    pub fn with(mut self, inspector: Box<dyn Inspector>) -> Self {
        self.inspectors.push(inspector);
        self
    }

    pub fn push(&mut self, inspector: Box<dyn Inspector>) {
        self.inspectors.push(inspector);
    }

    /// Run the chain. Short-circuits on the first `Deny`. Returns
    /// the (final_verdict, inspector_name_that_produced_it). The
    /// name lets the egress-proxy callsite write an audit entry
    /// like "request denied by `destination_policy`: host not in
    /// allowlist".
    pub async fn run(&self, ctx: &mut RequestCtx) -> (InspectorVerdict, &'static str) {
        let mut last_name: &'static str = "<empty_chain>";
        for inspector in &self.inspectors {
            let verdict = inspector.inspect(ctx).await;
            last_name = inspector.name();
            if verdict.is_deny() {
                return (verdict, last_name);
            }
            // Allow + Transform both fall through; Transform's
            // mutation persists in `ctx` for downstream inspectors.
        }
        (InspectorVerdict::Allow, last_name)
    }

    pub fn len(&self) -> usize {
        self.inspectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inspectors.is_empty()
    }
}

impl Default for InspectorChain {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for InspectorChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&'static str> = self.inspectors.iter().map(|i| i.name()).collect();
        f.debug_struct("InspectorChain")
            .field("inspectors", &names)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test inspector that always returns the configured verdict.
    struct FixedVerdict {
        name: &'static str,
        verdict: InspectorVerdict,
    }

    #[async_trait]
    impl Inspector for FixedVerdict {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn inspect(&self, _ctx: &mut RequestCtx) -> InspectorVerdict {
            self.verdict.clone()
        }
    }

    /// Test inspector that mutates the path then allows.
    struct PathMutator;

    #[async_trait]
    impl Inspector for PathMutator {
        fn name(&self) -> &'static str {
            "path_mutator"
        }
        async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict {
            ctx.path = format!("{}?mutated=1", ctx.path);
            InspectorVerdict::Transform {
                note: "appended mutated=1".to_string(),
            }
        }
    }

    fn ctx() -> RequestCtx {
        RequestCtx::new("example.com", 443, "/v1/foo")
    }

    #[tokio::test]
    async fn empty_chain_allows() {
        let chain = InspectorChain::new();
        let (verdict, name) = chain.run(&mut ctx()).await;
        assert_eq!(verdict, InspectorVerdict::Allow);
        assert_eq!(name, "<empty_chain>");
    }

    #[tokio::test]
    async fn allow_chain_falls_through_to_allow() {
        let chain = InspectorChain::new()
            .with(Box::new(FixedVerdict {
                name: "first",
                verdict: InspectorVerdict::Allow,
            }))
            .with(Box::new(FixedVerdict {
                name: "second",
                verdict: InspectorVerdict::Allow,
            }));
        let (verdict, name) = chain.run(&mut ctx()).await;
        assert_eq!(verdict, InspectorVerdict::Allow);
        assert_eq!(name, "second");
    }

    #[tokio::test]
    async fn first_deny_short_circuits() {
        let chain = InspectorChain::new()
            .with(Box::new(FixedVerdict {
                name: "first",
                verdict: InspectorVerdict::Deny {
                    reason: "block".to_string(),
                },
            }))
            .with(Box::new(FixedVerdict {
                name: "should_not_run",
                verdict: InspectorVerdict::Allow,
            }));
        let (verdict, name) = chain.run(&mut ctx()).await;
        assert_eq!(
            verdict,
            InspectorVerdict::Deny {
                reason: "block".to_string()
            }
        );
        // Short-circuit: name must be the denying inspector, not
        // any inspector after it.
        assert_eq!(name, "first");
    }

    #[tokio::test]
    async fn transform_falls_through_with_mutation_visible_to_next() {
        // The mutation a Transform inspector makes must be visible
        // to subsequent inspectors via the shared RequestCtx.
        struct PathSnapshot {
            captured: std::sync::Mutex<Option<String>>,
        }
        #[async_trait]
        impl Inspector for PathSnapshot {
            fn name(&self) -> &'static str {
                "path_snapshot"
            }
            async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict {
                *self.captured.lock().expect("PathSnapshot mutex poisoned") =
                    Some(ctx.path.clone());
                InspectorVerdict::Allow
            }
        }
        let snapshot = std::sync::Arc::new(PathSnapshot {
            captured: std::sync::Mutex::new(None),
        });
        // Re-use the same Arc for the chain by cloning into a Box.
        // Box<dyn Inspector> needs ownership; PathSnapshot needs
        // Arc to share state with the test. Wrap both: Box owns an
        // adapter that holds the Arc.
        struct ArcAdapter(std::sync::Arc<PathSnapshot>);
        #[async_trait]
        impl Inspector for ArcAdapter {
            fn name(&self) -> &'static str {
                self.0.name()
            }
            async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict {
                self.0.inspect(ctx).await
            }
        }
        let chain = InspectorChain::new()
            .with(Box::new(PathMutator))
            .with(Box::new(ArcAdapter(snapshot.clone())));
        let mut c = ctx();
        chain.run(&mut c).await;
        let captured = snapshot
            .captured
            .lock()
            .expect("PathSnapshot mutex poisoned")
            .clone();
        assert_eq!(captured, Some("/v1/foo?mutated=1".to_string()));
        // The chain's run also leaves the mutation in the original ctx.
        assert_eq!(c.path, "/v1/foo?mutated=1");
    }

    #[test]
    fn chain_debug_shows_inspector_names() {
        let chain = InspectorChain::new()
            .with(Box::new(FixedVerdict {
                name: "alpha",
                verdict: InspectorVerdict::Allow,
            }))
            .with(Box::new(FixedVerdict {
                name: "beta",
                verdict: InspectorVerdict::Allow,
            }));
        let s = format!("{chain:?}");
        assert!(s.contains("alpha"));
        assert!(s.contains("beta"));
    }
}
