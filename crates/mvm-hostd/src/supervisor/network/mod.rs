//! Plan 113 / ADR-064 — Observer trait + Pipeline builder for the gateway
//! audit substrate.
//!
//! Observers consume `&crate::supervisor::gateway_bridge::FlowEvent` references inside
//! `signer_task` (fan-out before chain signing). Observers run under
//! `catch_unwind`: a panic in observer N surfaces a tracing warn and does
//! not break observer N+1 or the chain-signing path itself.
//!
//! Observers are **host-allowlisted**, not tenant-shipped. The allowlist
//! file at `~/.mvm/observers/allowlist.toml` is parsed at supervisor
//! startup; tenant policy bundles reference observer names by string and
//! the resolver refuses unknown names with `BuildError::NotAllowlisted`.
//!
//! Per ADR-064 §Decision 7.
//!
//! Task 1 lands the trait + builder + allowlist scaffolding in
//! isolation; Task 3 wires `Observer` into `BridgeConfig.observers` +
//! `signer_task`, at which point the module-level `#[allow(dead_code)]`
//! drops (the Observer trait + Pipeline + ObserverAllowlist + MAX_OBSERVERS
//! become reachable through `BridgeConfig`). Task 4 will wire
//! `Pipeline::from_admitted` from `run_with_bridge`.
//!
//! ## Visibility
//!
//! Observer + the capability + builder types are `pub` (not `pub(crate)`)
//! because Task 3 exposes them through `BridgeConfig.observers`, which is
//! itself a `pub` field on a `pub` struct — the supervisor binary
//! (`mvm-libkrun-supervisor`) constructs the literal with an empty
//! `observers: vec![]` until Task 4 wires real resolution.
//!
//! `FlowEvent` in `gateway_bridge` is similarly `pub` (was `pub(crate)`
//! in Plan 102 W6.A's original commit) so external observer impls can
//! receive `&FlowEvent` references through the Observer trait.

use crate::supervisor::gateway_bridge::FlowEvent;
use std::collections::HashMap;
use std::sync::Arc;

pub mod flow_count;

/// Maximum number of observers per VM. ADR-064 §Decision: hard cap of 8
/// (each observer is a synchronous callback in the signer task's hot path;
/// per-VM bound keeps the hot path predictable).
pub const MAX_OBSERVERS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub flow_events: bool,
    pub payload_tap: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequiredCapabilities {
    pub flow_events: bool,
    pub payload_tap: bool,
}

impl ProviderCapabilities {
    pub fn satisfies(&self, req: &RequiredCapabilities) -> bool {
        (!req.flow_events || self.flow_events) && (!req.payload_tap || self.payload_tap)
    }

    pub fn missing_for(&self, req: &RequiredCapabilities) -> Vec<&'static str> {
        let mut out = Vec::new();
        if req.flow_events && !self.flow_events {
            out.push("flow_events");
        }
        if req.payload_tap && !self.payload_tap {
            out.push("payload_tap");
        }
        out
    }
}

/// Synchronous observer callback. Implementations MUST NOT panic in hot
/// path (the signer task wraps each call in `catch_unwind`, but a panic
/// per event is wasteful). Implementations MUST be cheap (microseconds);
/// expensive work should buffer + defer to a background task the observer
/// owns.
///
/// Visibility is `pub` because Task 3 exposes observer references through
/// `BridgeConfig.observers` (a `pub` field on a `pub` struct), and
/// external supervisor binaries (`mvm-libkrun-supervisor`) construct the
/// literal at startup. `FlowEvent` is also `pub` in `gateway_bridge` for
/// the same reason.
pub trait Observer: Send + Sync {
    fn name(&self) -> &'static str;
    fn required_capabilities(&self) -> RequiredCapabilities;
    fn on_flow_event(&self, event: &FlowEvent);
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("observer chain too deep (max {max}); requested {requested}")]
    TooManyObservers { max: usize, requested: usize },

    #[error("observer {observer:?} requires {missing:?}; leaf does not provide them")]
    CapabilityMismatch {
        observer: &'static str,
        missing: Vec<&'static str>,
    },

    #[error("observer name {0:?} is not in ~/.mvm/observers/allowlist.toml")]
    NotAllowlisted(String),

    #[error("allowlist {path}: {detail}")]
    AllowlistRead { path: String, detail: String },
}

/// Pipeline builder. `observe()` is capability-gated + depth-capped;
/// `build_observers()` returns the `Vec<Arc<dyn Observer>>` the caller
/// hands to `BridgeConfig.observers`.
///
/// AuditEmit is NOT injected by this builder. The existing
/// `signer_task` (in `mvm-supervisor::gateway_bridge`) already calls
/// `signer.sign_and_emit(&entry)` after the fan-out — chain signing
/// is structural, runs after every observer, and cannot be displaced
/// by tenant policy.
pub struct Pipeline {
    observers: Vec<Arc<dyn Observer>>,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field(
                "observers",
                &self.observers.iter().map(|o| o.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            observers: Vec::new(),
        }
    }

    pub fn observe(
        mut self,
        observer: Arc<dyn Observer>,
        leaf_caps: ProviderCapabilities,
    ) -> Result<Self, BuildError> {
        if self.observers.len() >= MAX_OBSERVERS {
            return Err(BuildError::TooManyObservers {
                max: MAX_OBSERVERS,
                requested: self.observers.len() + 1,
            });
        }
        let req = observer.required_capabilities();
        if !leaf_caps.satisfies(&req) {
            return Err(BuildError::CapabilityMismatch {
                observer: observer.name(),
                missing: leaf_caps.missing_for(&req),
            });
        }
        self.observers.push(observer);
        Ok(self)
    }

    pub fn build_observers(self) -> Vec<Arc<dyn Observer>> {
        self.observers
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Host-allowlisted observer registry. Loaded from
/// `~/.mvm/observers/allowlist.toml` (mode 0600) at supervisor startup.
/// Tenant policy bundles reference observer names; `resolve()` returns
/// the typed `Arc<dyn Observer>` or `BuildError::NotAllowlisted`.
pub struct ObserverAllowlist {
    entries: HashMap<String, ObserverConstructor>,
}

impl std::fmt::Debug for ObserverAllowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObserverAllowlist")
            .field("entries", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

type ObserverConstructor = Box<dyn Fn() -> Arc<dyn Observer> + Send + Sync>;

#[derive(serde::Deserialize)]
struct AllowlistFile {
    schema_version: u32,
    #[serde(default)]
    observer: Vec<AllowlistEntry>,
}

#[derive(serde::Deserialize)]
struct AllowlistEntry {
    name: String,
}

impl ObserverAllowlist {
    /// Load from the canonical locations. Per-user `~/.mvm/observers/allowlist.toml`
    /// wins over system-wide `/etc/mvm/observers/allowlist.toml`. Missing both
    /// surfaces a `BuildError::AllowlistRead` error explaining what the operator
    /// must create.
    ///
    /// HOME must be set for the per-user path to be considered. If HOME is
    /// unset we refuse outright — we don't fall back to `/tmp` or any other
    /// default, because a writable-by-anyone fallback directory would let a
    /// local user place a malicious allowlist that any process running with
    /// HOME unset (e.g. a misconfigured systemd unit or chroot) would trust.
    /// Operator action in that case is "set HOME" or "place
    /// /etc/mvm/observers/allowlist.toml" — both are explicit.
    pub fn load_from_host_config() -> Result<Self, BuildError> {
        let home = std::env::var("HOME").map_err(|_| BuildError::AllowlistRead {
            path: "$HOME unset".to_string(),
            detail: "HOME environment variable is not set; cannot resolve user allowlist path. \
                     Either set HOME or run with /etc/mvm/observers/allowlist.toml present."
                .into(),
        })?;
        let user_path = std::path::PathBuf::from(home).join(".mvm/observers/allowlist.toml");
        if user_path.exists() {
            return Self::load_from_path(&user_path);
        }
        let system_path = std::path::PathBuf::from("/etc/mvm/observers/allowlist.toml");
        if system_path.exists() {
            return Self::load_from_path(&system_path);
        }
        Err(BuildError::AllowlistRead {
            path: user_path.display().to_string(),
            detail: "operator must create ~/.mvm/observers/allowlist.toml (mode 0600) \
                     with at least: schema_version = 1"
                .into(),
        })
    }

    /// Load and parse a single allowlist file.
    ///
    /// Hardened against TOCTOU + symlink races: the file is opened ONCE with
    /// `O_NOFOLLOW` (so a symlink at `path` is rejected at open time with
    /// `ELOOP`), then both the permission check and the content read use
    /// that single file descriptor. This eliminates the window where an
    /// attacker could swap the file between a `fs::metadata(path)` check
    /// and a later `fs::read_to_string(path)`.
    ///
    /// Additionally verifies the file's UID matches the effective UID — a
    /// config file owned by another user is not operator-trusted input,
    /// even if its mode bits look correct.
    pub fn load_from_path(path: &std::path::Path) -> Result<Self, BuildError> {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| BuildError::AllowlistRead {
                path: path.display().to_string(),
                detail: e.to_string(),
            })?;
        let meta = f.metadata().map_err(|e| BuildError::AllowlistRead {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(BuildError::AllowlistRead {
                path: path.display().to_string(),
                detail: format!("mode {mode:o}; expected 0600 (host-operator-trusted input)"),
            });
        }
        let file_uid = meta.uid();
        // SAFETY: `geteuid` is always safe — POSIX guarantees it cannot fail
        // and has no side effects.
        let effective_uid = unsafe { libc::geteuid() };
        if file_uid != effective_uid {
            return Err(BuildError::AllowlistRead {
                path: path.display().to_string(),
                detail: format!(
                    "file uid {file_uid} does not match effective uid {effective_uid}; refusing"
                ),
            });
        }
        let mut body = String::new();
        f.read_to_string(&mut body)
            .map_err(|e| BuildError::AllowlistRead {
                path: path.display().to_string(),
                detail: e.to_string(),
            })?;
        let parsed: AllowlistFile =
            toml::from_str(&body).map_err(|e| BuildError::AllowlistRead {
                path: path.display().to_string(),
                detail: format!("toml parse: {e}"),
            })?;
        if parsed.schema_version != 1 {
            return Err(BuildError::AllowlistRead {
                path: path.display().to_string(),
                detail: format!(
                    "schema_version = {}; this build only understands version 1",
                    parsed.schema_version
                ),
            });
        }
        let mut entries: HashMap<String, ObserverConstructor> = HashMap::new();
        for e in parsed.observer {
            match e.name.as_str() {
                "flow-count-metrics" => {
                    entries.insert(
                        e.name,
                        Box::new(flow_count::FlowCountMetrics::into_arc) as ObserverConstructor,
                    );
                }
                other => {
                    return Err(BuildError::AllowlistRead {
                        path: path.display().to_string(),
                        detail: format!(
                            "observer {other:?} is not known to this build; \
                             this version only ships `flow-count-metrics`. \
                             Remove the entry or upgrade mvm."
                        ),
                    });
                }
            }
        }
        Ok(Self { entries })
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub fn resolve(&self, name: &str) -> Result<Arc<dyn Observer>, BuildError> {
        match self.entries.get(name) {
            Some(ctor) => Ok(ctor()),
            None => Err(BuildError::NotAllowlisted(name.to_string())),
        }
    }
}

/// Production entry — resolves the admitted plan's `network_policy` ref
/// through the existing policy bundle convention (`<tenant>:<workload>`
/// at `~/.mvm/policies/<tenant>/<workload>.toml`), reads the bundle's
/// `network.observers` list, resolves each name through the
/// `ObserverAllowlist`, capability-gates against the leaf, and returns
/// the `Vec<Arc<dyn Observer>>` for `BridgeConfig.observers`.
///
/// The leaf capability is fixed at construction-time per backend:
/// libkrun + Firecracker leaves report `payload_tap: true`; Vz drainer
/// reports `payload_tap: false` (ADR-064 §Decision 8 / §Out of scope).
///
/// `local-default` plan refs short-circuit to empty observers without
/// consulting the allowlist, so callers can use `resolve_observer_chain_from_plan`
/// first to decide whether to load the allowlist at all.
pub fn from_admitted(
    plan: &mvm_core::plan::ExecutionPlan,
    leaf_caps: ProviderCapabilities,
    allowlist: &ObserverAllowlist,
) -> Result<Vec<Arc<dyn Observer>>, BuildError> {
    let observer_names = resolve_observer_chain_from_plan(plan)?;
    if observer_names.is_empty() {
        return Ok(Vec::new());
    }
    let mut pipe = Pipeline::new();
    for name in observer_names {
        let obs = allowlist.resolve(&name)?;
        pipe = pipe.observe(obs, leaf_caps)?;
    }
    Ok(pipe.build_observers())
}

/// Plan 113 Task 4 (security follow-up) — validate that a policy-bundle
/// path segment is safe to use as a filesystem component.
/// Allows only [A-Za-z0-9_-]+ (DNS-label-shape). Rejects empty,
/// `.`, `..`, any non-ASCII, any path separator or shell meta.
fn validate_policy_path_segment(segment: &str, kind: &str) -> Result<(), BuildError> {
    if segment.is_empty() {
        return Err(BuildError::AllowlistRead {
            path: segment.to_string(),
            detail: format!("{kind} segment must not be empty"),
        });
    }
    if segment.len() > 63 {
        return Err(BuildError::AllowlistRead {
            path: segment.to_string(),
            detail: format!("{kind} segment must be 1..=63 chars; got {}", segment.len()),
        });
    }
    for c in segment.chars() {
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(BuildError::AllowlistRead {
                path: segment.to_string(),
                detail: format!("{kind} segment may only contain [A-Za-z0-9_-]; got {c:?}"),
            });
        }
    }
    Ok(())
}

/// Reads the policy bundle referenced by `plan.network_policy` and
/// returns its `network.observers` list.
///
/// For the `local-default` plan ref (used by Stage 0 / dev mode), the
/// observer chain is empty — and the allowlist is not consulted.
///
/// `mvm-supervisor` cannot depend on `mvm-cli` (would close a cycle:
/// `mvm-cli → mvm-supervisor → mvm-cli`). Inline the same parse logic
/// here: `"<tenant>:<workload>"` → `~/.mvm/policies/<tenant>/<workload>.toml`.
/// Task 5 of Plan 113 adds `observers: Vec<String>` to
/// `mvm_core::policy::NetworkPolicy`; this `BundleShim` reads the same field
/// without requiring Task 5 to be done first. The shim stays private
/// to this function so Task 5 can refactor cleanly to the real type.
///
/// `pub` (not `pub(crate)`) because `run_with_bridge` in the leaf bin
/// crate `mvm-libkrun-supervisor` calls this to decide whether to
/// load the allowlist at all — preserving the local-default
/// short-circuit at the bin boundary.
pub fn resolve_observer_chain_from_plan(
    plan: &mvm_core::plan::ExecutionPlan,
) -> Result<Vec<String>, BuildError> {
    const LOCAL_DEFAULT: &str = "local-default";
    let policy_ref = &plan.network_policy.0;
    if policy_ref == LOCAL_DEFAULT {
        return Ok(Vec::new());
    }

    let (tenant, workload) = match policy_ref.split_once(':') {
        Some((t, w)) => (t, w),
        None => {
            return Err(BuildError::AllowlistRead {
                path: policy_ref.clone(),
                detail: format!("network_policy ref {policy_ref:?} is not in tenant:workload form"),
            });
        }
    };

    validate_policy_path_segment(tenant, "tenant")?;
    validate_policy_path_segment(workload, "workload")?;

    // Plan 113 Task 4 (security follow-up) — refuse cross-tenant policy
    // bundle access. The plan envelope was already verified upstream;
    // its declared tenant is authoritative. The ref's tenant segment
    // must agree.
    if tenant != plan.tenant.0 {
        return Err(BuildError::AllowlistRead {
            path: policy_ref.clone(),
            detail: format!(
                "policy ref tenant {tenant:?} does not match plan tenant {:?}; \
                 cross-tenant policy access refused",
                plan.tenant.0
            ),
        });
    }

    let home = std::env::var("HOME").map_err(|_| BuildError::AllowlistRead {
        path: "$HOME unset".to_string(),
        detail: "HOME is unset; cannot resolve policy bundle path".to_string(),
    })?;
    let policies_root = std::path::PathBuf::from(&home).join(".mvm/policies");
    let path = policies_root.join(tenant).join(format!("{workload}.toml"));

    if !path.exists() {
        return Err(BuildError::AllowlistRead {
            path: path.display().to_string(),
            detail: format!("policy bundle for {tenant}:{workload} not found at the expected path"),
        });
    }

    // After confirming the file exists, canonicalize and assert the
    // result is still beneath ~/.mvm/policies/. Defends against
    // intermediate-directory symlink redirection that O_NOFOLLOW
    // doesn't catch.
    let canonical_path = path.canonicalize().map_err(|e| BuildError::AllowlistRead {
        path: path.display().to_string(),
        detail: format!("canonicalize: {e}"),
    })?;
    let canonical_root = policies_root
        .canonicalize()
        .map_err(|e| BuildError::AllowlistRead {
            path: policies_root.display().to_string(),
            detail: format!("canonicalize policies root: {e}"),
        })?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(BuildError::AllowlistRead {
            path: canonical_path.display().to_string(),
            detail: format!(
                "policy bundle path escapes {} after canonicalization; refusing",
                canonical_root.display()
            ),
        });
    }

    let body = std::fs::read_to_string(&canonical_path).map_err(|e| BuildError::AllowlistRead {
        path: canonical_path.display().to_string(),
        detail: e.to_string(),
    })?;

    #[derive(serde::Deserialize)]
    struct BundleShim {
        #[serde(default)]
        network: NetworkShim,
    }
    #[derive(serde::Deserialize, Default)]
    struct NetworkShim {
        #[serde(default)]
        observers: Vec<String>,
    }

    let shim: BundleShim = match toml::from_str(&body) {
        Ok(s) => s,
        Err(e) => {
            // Plan 113 Task 4 (security follow-up) — do NOT echo the
            // parser error into BuildError; the parser's Display impl
            // can include the offending line content, which leaks
            // bundle bytes. Log internally for debugging.
            tracing::warn!(
                path = %canonical_path.display(),
                error = ?e,
                "policy bundle toml parse failed"
            );
            return Err(BuildError::AllowlistRead {
                path: canonical_path.display().to_string(),
                detail: "policy bundle toml parse failed (see supervisor log for details)"
                    .to_string(),
            });
        }
    };

    Ok(shim.network.observers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::gateway_bridge::FlowEvent;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::NamedTempFile;

    struct CountingObserver {
        n: AtomicU32,
        req: RequiredCapabilities,
    }
    impl Observer for CountingObserver {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn required_capabilities(&self) -> RequiredCapabilities {
            self.req
        }
        fn on_flow_event(&self, _: &FlowEvent) {
            self.n.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn caps_flow_only() -> ProviderCapabilities {
        ProviderCapabilities {
            flow_events: true,
            payload_tap: false,
        }
    }

    fn caps_full() -> ProviderCapabilities {
        ProviderCapabilities {
            flow_events: true,
            payload_tap: true,
        }
    }

    #[test]
    fn capabilities_satisfies() {
        assert!(caps_full().satisfies(&RequiredCapabilities {
            flow_events: true,
            payload_tap: true,
        }));
        assert!(caps_flow_only().satisfies(&RequiredCapabilities {
            flow_events: true,
            payload_tap: false,
        }));
        assert!(!caps_flow_only().satisfies(&RequiredCapabilities {
            flow_events: true,
            payload_tap: true,
        }));
    }

    #[test]
    fn pipeline_capability_gate() {
        let needs_tap = Arc::new(CountingObserver {
            n: AtomicU32::new(0),
            req: RequiredCapabilities {
                flow_events: true,
                payload_tap: true,
            },
        });
        let err = Pipeline::new()
            .observe(needs_tap, caps_flow_only())
            .expect_err("must refuse capability mismatch");
        assert!(matches!(
            err,
            BuildError::CapabilityMismatch {
                observer: "counting",
                ..
            }
        ));
    }

    #[test]
    fn pipeline_depth_cap() {
        let mut pipe = Pipeline::new();
        for _ in 0..MAX_OBSERVERS {
            let obs = Arc::new(CountingObserver {
                n: AtomicU32::new(0),
                req: RequiredCapabilities {
                    flow_events: true,
                    payload_tap: false,
                },
            });
            pipe = pipe.observe(obs, caps_flow_only()).expect("slot available");
        }
        let one_too_many = Arc::new(CountingObserver {
            n: AtomicU32::new(0),
            req: RequiredCapabilities {
                flow_events: true,
                payload_tap: false,
            },
        });
        let err = pipe
            .observe(one_too_many, caps_flow_only())
            .expect_err("over cap");
        assert!(matches!(
            err,
            BuildError::TooManyObservers {
                max: MAX_OBSERVERS,
                ..
            }
        ));
    }

    fn write_allowlist(body: &str, mode: u32) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), body).unwrap();
        let mut perm = std::fs::metadata(f.path()).unwrap().permissions();
        perm.set_mode(mode);
        std::fs::set_permissions(f.path(), perm).unwrap();
        f
    }

    #[test]
    fn allowlist_loads_known_name() {
        let f = write_allowlist(
            "schema_version = 1\n[[observer]]\nname = \"flow-count-metrics\"\n",
            0o600,
        );
        let alw = ObserverAllowlist::load_from_path(f.path()).expect("load");
        assert!(alw.contains("flow-count-metrics"));
        assert!(!alw.contains("hostname-filter"));
        // `Arc<dyn Observer>` is not `Debug`, so use `is_ok` / `is_err`
        // instead of `expect`/`expect_err`.
        assert!(alw.resolve("flow-count-metrics").is_ok(), "resolve known");
        match alw.resolve("hostname-filter") {
            Ok(_) => panic!("unknown name must not resolve"),
            Err(BuildError::NotAllowlisted(s)) => assert_eq!(s, "hostname-filter"),
            Err(other) => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn allowlist_refuses_loose_perms() {
        let f = write_allowlist("schema_version = 1\n", 0o644);
        let err = ObserverAllowlist::load_from_path(f.path()).expect_err("must refuse 0644");
        if let BuildError::AllowlistRead { detail, .. } = err {
            assert!(detail.contains("0600"), "detail was: {detail}");
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    #[test]
    fn allowlist_refuses_unknown_schema_version() {
        let f = write_allowlist("schema_version = 99\n", 0o600);
        let err = ObserverAllowlist::load_from_path(f.path()).expect_err("must refuse v99");
        if let BuildError::AllowlistRead { detail, .. } = err {
            assert!(detail.contains("schema_version"), "detail was: {detail}");
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    #[test]
    fn allowlist_refuses_unknown_observer_name() {
        let f = write_allowlist(
            "schema_version = 1\n[[observer]]\nname = \"egress-redactor\"\n",
            0o600,
        );
        let err = ObserverAllowlist::load_from_path(f.path()).expect_err("must refuse unknown");
        if let BuildError::AllowlistRead { detail, .. } = err {
            assert!(detail.contains("egress-redactor"), "detail was: {detail}");
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    /// Security regression: `load_from_path` must refuse to follow a symlink.
    /// An attacker who can drop a symlink at the well-known allowlist path
    /// (e.g. via a parent-directory race) could otherwise redirect us to a
    /// file they control. `O_NOFOLLOW` causes the open call itself to fail
    /// with `ELOOP` before we ever read metadata or content.
    #[test]
    fn allowlist_refuses_symlink_via_nofollow() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.toml");
        std::fs::write(&target, "schema_version = 1\n").unwrap();
        let mut perm = std::fs::metadata(&target).unwrap().permissions();
        perm.set_mode(0o600);
        std::fs::set_permissions(&target, perm).unwrap();

        let link = dir.path().join("allowlist.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err =
            ObserverAllowlist::load_from_path(&link).expect_err("symlink must be refused at open");
        if let BuildError::AllowlistRead { detail, .. } = err {
            // The OS-level error string varies (Linux: "Too many levels of
            // symbolic links", macOS: "Too many levels of symbolic links" or
            // similar). Asserting the variant + that we never reached the
            // schema-parse stage is the contract.
            assert!(
                !detail.contains("schema_version"),
                "must not have parsed content; detail was: {detail}"
            );
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    /// Security regression: `load_from_path` must refuse a file whose UID
    /// differs from the effective UID. A config file owned by another user
    /// is not operator-trusted input even if its mode bits look correct.
    ///
    /// Skipped when not running as root because changing a file's owner to
    /// a different UID requires `CAP_CHOWN`.
    #[test]
    fn allowlist_refuses_wrong_uid() {
        // SAFETY: `geteuid` is always safe (see `load_from_path`).
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let f = write_allowlist("schema_version = 1\n", 0o600);
        // SAFETY: `chown` is safe to call with a valid CString path; we
        // change to uid 1 (typically "daemon" or "bin"), gid -1 (no change).
        let c_path = std::ffi::CString::new(f.path().to_str().unwrap()).unwrap();
        let rc = unsafe { libc::chown(c_path.as_ptr(), 1, u32::MAX) };
        assert_eq!(rc, 0, "chown to uid 1 must succeed when running as root");

        let err = ObserverAllowlist::load_from_path(f.path())
            .expect_err("file owned by other uid must be refused");
        if let BuildError::AllowlistRead { detail, .. } = err {
            assert!(
                detail.contains("uid") && detail.contains("refusing"),
                "detail was: {detail}"
            );
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    // Plan 113 §Task 4 — `from_admitted` + `resolve_observer_chain_from_plan`.

    fn test_execution_plan_with_policy(policy_ref: &str) -> mvm_core::plan::ExecutionPlan {
        test_execution_plan_with_policy_and_tenant(policy_ref, "test")
    }

    fn test_execution_plan_with_policy_and_tenant(
        policy_ref: &str,
        tenant: &str,
    ) -> mvm_core::plan::ExecutionPlan {
        use chrono::TimeZone;
        use mvm_core::plan::{
            AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement,
            ExecutionPlan, FsPolicyRef, KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef,
            PostRunLifecycle, Resources, RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef,
            TenantId, TimeoutSpec, WorkloadId,
        };
        ExecutionPlan {
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId("test-plan".into()),
            plan_version: 1,
            tenant: TenantId(tenant.into()),
            workload: WorkloadId("test-workload".into()),
            runtime_profile: RuntimeProfileRef("firecracker".into()),
            image: SignedImageRef {
                name: "img".into(),
                sha256: "0".repeat(64),
                cosign_bundle: None,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 256,
                disk_mib: 1024,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 60,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef(policy_ref.into()),
            fs_policy: FsPolicyRef("local-default".into()),
            secrets: Vec::new(),
            egress_policy: PolicyRef("local-default".into()),
            tool_policy: PolicyRef("local-default".into()),
            artifact_policy: ArtifactPolicy {
                capture_paths: vec![],
                retention_days: 0,
            },
            audit_labels: std::collections::BTreeMap::new(),
            key_rotation: KeyRotationSpec { interval_days: 0 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: chrono::Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            valid_until: chrono::Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
            nonce: Nonce::from_bytes([0xab; 16]),
            bundle: None,
            deps_volume: None,
        }
    }

    #[test]
    fn resolve_observer_chain_local_default_returns_empty() {
        let plan = test_execution_plan_with_policy("local-default");
        let names = resolve_observer_chain_from_plan(&plan).expect("local-default ok");
        assert!(names.is_empty());
    }

    #[test]
    fn resolve_observer_chain_malformed_ref_errors() {
        let plan = test_execution_plan_with_policy("not-a-policy-ref");
        let err = resolve_observer_chain_from_plan(&plan).expect_err("must refuse malformed");
        if let BuildError::AllowlistRead { detail, .. } = err {
            assert!(detail.contains("tenant:workload"), "got: {detail}");
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    // Plan 113 Task 4 (security follow-up) — three rejection tests
    // backing the path-traversal, cross-tenant, and charset hardening.

    #[test]
    fn resolve_observer_chain_dotdot_in_segment_refused() {
        let plan = test_execution_plan_with_policy("..:..");
        let err = resolve_observer_chain_from_plan(&plan).expect_err("must refuse ..");
        if let BuildError::AllowlistRead { detail, .. } = err {
            assert!(
                detail.contains("[A-Za-z0-9_-]") || detail.contains("segment"),
                "got: {detail}"
            );
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    #[test]
    fn resolve_observer_chain_cross_tenant_refused() {
        let plan = test_execution_plan_with_policy_and_tenant("globex:workload", "acme");
        let err = resolve_observer_chain_from_plan(&plan).expect_err("must refuse cross-tenant");
        if let BuildError::AllowlistRead { detail, .. } = err {
            assert!(
                detail.contains("cross-tenant") || detail.contains("does not match plan tenant"),
                "got: {detail}"
            );
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    #[test]
    fn resolve_observer_chain_invalid_charset_refused() {
        let plan = test_execution_plan_with_policy("with space:workload");
        let err =
            resolve_observer_chain_from_plan(&plan).expect_err("must refuse non-ASCII charset");
        if let BuildError::AllowlistRead { detail, .. } = err {
            assert!(detail.contains("[A-Za-z0-9_-]"), "got: {detail}");
        } else {
            panic!("wrong error: {err:?}");
        }
    }

    #[test]
    fn from_admitted_local_default_returns_empty_observer_vec() {
        // The local-default plan ref short-circuits BEFORE the allowlist is
        // consulted; we still pass a valid allowlist so the call type-checks.
        let f = write_allowlist(
            "schema_version = 1\n[[observer]]\nname = \"flow-count-metrics\"\n",
            0o600,
        );
        let alw = ObserverAllowlist::load_from_path(f.path()).expect("allowlist");

        let plan = test_execution_plan_with_policy("local-default");
        let caps = ProviderCapabilities {
            flow_events: true,
            payload_tap: true,
        };
        let observers = from_admitted(&plan, caps, &alw).expect("from_admitted");
        assert!(observers.is_empty());
    }
}
