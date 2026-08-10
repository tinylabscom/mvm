//! Host-side plan-admission pipeline (claim 8).
//!
//! Lives in `mvm-hostd` beside the host signing key it uses, so every driver
//! reaches one admission contract: `mvmctl up`/`run` today, and the
//! `mvm-client` local backend once the boot seam wires local `run`.
//!
//! Threads `synthesize_plan` + the host keypair into the
//! supervisor-equivalent admission flow:
//!
//! ```text
//! cmd_run(args)
//!   ↓ synthesize_plan(args)
//!   ↓ load_or_init_host_signer()
//!   ↓ sign_plan(plan, signer)
//!   ↓ verify_plan(signed, trusted) — catches signing-time bugs
//!   ↓ check_window(plan, now)      — G4 validity window
//!   ↓ nonce_store.check_and_insert  — G4 replay protection
//!   ↓ return AdmittedPlan { plan, plan_id, signer_id, signed }
//!   ↓ caller invokes backend.start() as before
//! ```
//!
//! What this module does NOT do (intentional scope reduction):
//!
//! - **Drive `Supervisor::launch`.** The supervisor's backend
//!   dispatch slot expects a `BackendLauncher` trait impl that
//!   wraps today's `AnyBackend::start()`; landing that wrapper
//!   means refactoring three call sites in 1084 lines of `up.rs`
//!   (the main path, the MVM_DIRECT_BOOT branch, and the `--watch`
//!   path). That refactor lands in a follow-up. **This module is
//!   the substrate that makes the eventual supervisor refactor a
//!   one-line change** — `admit_for_run` produces the
//!   `SignedExecutionPlan` the supervisor needs.
//!
//! - **Emit audit lines.** A later step wires `FileAuditSigner` onto
//!   the `AdmittedPlan`'s `plan_id`; this module is silent on audit.
//!
//! - **Resolve component slots.** A later step maps `PolicyRef →
//!   concrete SupervisorEgressProxy/ToolGate/...`. This module returns the
//!   plan with refs unresolved.
//!
//! ## Test seam
//!
//! `admit_for_run` takes a `Clock` and a `NonceLedger` so tests can
//! drive the validity window + replay protection deterministically.
//! Production callers use `SystemClock` + the host's nonce store.

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_core::plan::bundle::{BundleResolver, TrustStore};
use mvm_core::plan::{
    ExecutionPlan, NonceStore, PlanId, PlanValidityError, SignedExecutionPlan, check_window,
    sign_plan, verify_plan, verify_plan_bundle, verify_plan_id,
};
use mvm_core::policy::PolicyBundle;
use std::sync::Mutex;

use crate::audit::host_keypair::host_signer_id;
use mvm_core::plan::{SynthesisInput, synthesize_plan};
use mvm_core::vm_backend::{VmId, VmStartConfig};
use mvm_runtime::AnyBackend;

pub use mvm_core::time::{Clock, SystemClock};

/// Production nonce ledger. Holds a `NonceStore` behind a mutex so
/// it's `Send + Sync`. In v0 we instantiate one per `mvmctl up` —
/// later when the supervisor is in-process, the ledger spans every
/// up call for the lifetime of the supervisor.
pub struct InMemoryNonceLedger {
    inner: Mutex<NonceStore>,
}

impl InMemoryNonceLedger {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NonceStore::default()),
        }
    }
}

impl Default for InMemoryNonceLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a successful admission. Carries everything the caller
/// needs to hand to the backend (the plan + its id), to the audit
/// chain (the plan again, for `AuditEntry::for_plan`), and — for the
/// bridge audit substrate and any cross-process consumer — the canonical
/// `SignedExecutionPlan` envelope, which [`populate_audit_substrate`]
/// serializes verbatim onto `VmStartConfig.plan_json`.
///
/// **The fields are private, and that is the type's whole point.** Consumers
/// downstream of admission — the egress gate, the share enforcer, the workload
/// input gate — decide what a workload may do by reading this plan, so a value
/// of this type has to be a claim that the plan *was* signed, verified,
/// window-checked and replay-checked, not merely a struct shaped like one. Both
/// halves of that are enforced by privacy: [`admit_for_run`] is the only
/// non-test code that can build one (a struct literal needs every field named,
/// and there is no `Default` to spread from), and no accessor hands out a `&mut`
/// or an owned field, so a caller that legitimately holds one cannot afterwards
/// push a grant into `plan.services` that admission never saw.
#[derive(Debug)]
pub struct AdmittedPlan {
    plan: ExecutionPlan,
    plan_id: PlanId,
    signer_id: String,
    signed: SignedExecutionPlan,
}

impl AdmittedPlan {
    /// The verified plan body — what every downstream authorization decision
    /// reads.
    #[must_use]
    pub fn plan(&self) -> &ExecutionPlan {
        &self.plan
    }

    /// The plan's content-address, re-derived and checked during admission.
    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    /// The host signer whose key the plan verified under.
    #[must_use]
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// The canonical signed envelope, for a consumer that re-verifies rather
    /// than trusting this process.
    #[must_use]
    pub fn signed(&self) -> &SignedExecutionPlan {
        &self.signed
    }

    /// Mint one without admitting it — **tests only**, and unreachable from a
    /// production build because the whole `impl` is `#[cfg(test)]`.
    ///
    /// A test that exercises a downstream consumer needs a plan of its own
    /// choosing; going through [`admit_for_run`] for each would drag the
    /// keystore and the nonce ledger into tests about something else. That
    /// convenience is exactly the forgery this type exists to prevent, so it is
    /// compiled out of every artifact anyone ships.
    #[cfg(test)]
    pub(crate) fn for_test(
        plan: ExecutionPlan,
        signer_id: String,
        signed: SignedExecutionPlan,
    ) -> Self {
        Self {
            plan_id: plan.plan_id.clone(),
            signer_id,
            plan,
            signed,
        }
    }
}

/// Optional bundle-admission context for plans pinned to a
/// `.mvmpkg`. Carries the resolver (where to find the archive
/// bytes by sha256) and the trust store (which publisher pubkeys
/// to accept). `admit_for_run` ignores it when the plan has no
/// pin; rejects when the plan has a pin but the context is
/// `None` (operator misconfiguration); runs full re-verify when
/// both are present.
pub struct BundleAdmissionContext<'a> {
    pub resolver: &'a dyn BundleResolver,
    pub trust: &'a dyn TrustStore,
}

/// Run the full admission pipeline for an `mvmctl up` invocation.
///
/// On success, the caller proceeds to `backend.start()` knowing the
/// plan was signed under the host signer, verified with the host's
/// own public key, satisfies its own validity window, hasn't been
/// admitted before (replay protection), and — when the plan pins a
/// `.mvmpkg` bundle — the on-disk archive matches the pin
/// byte-for-byte and verifies under the trust store.
///
/// On failure, the user gets a clear error per failure class:
///   - `tenant must not be empty` / `vm_name must not be empty` —
///     synthesis-time guard
///   - `host signer at {path} has mode {found}; expected 0600` —
///     keystore guard
///   - `plan validity window violated: {detail}` — G4 window check
///   - `plan replay detected for signer {id}; nonce {hex}` — G4 nonce
///   - `bundle re-verify failed: {detail}` — pinned bundle missing,
///     unknown publisher, tampered, or sha256/sig/key_id mismatch
pub fn admit_for_run(
    input: &SynthesisInput<'_>,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
    host_signer_keys_dir: Option<&std::path::Path>,
    bundle_ctx: Option<&BundleAdmissionContext<'_>>,
) -> Result<AdmittedPlan> {
    // Build the unsigned plan first. Synthesis failures are caught
    // before we touch the keystore — keeps "signed bad plan" from
    // being an outcome.
    let plan = synthesize_plan(input).context("synthesizing plan")?;

    // Load or generate the host signer. load_or_init refuses
    // loose perms; that error propagates verbatim.
    let signer = match host_signer_keys_dir {
        Some(dir) => crate::audit::host_keypair::load_or_init_at(dir)?,
        None => crate::audit::host_keypair::load_or_init()?,
    };
    let signer_id = host_signer_id();

    // Sign + verify roundtrip. Verifying our own signature catches
    // wire-format bugs that would otherwise surface at a real
    // verifier (mvmd's supervisor, an upstream consumer's mvm).
    let signed = sign_plan(&plan, &signer.signing, &signer_id);
    let trusted: [(&str, &VerifyingKey); 1] = [(&signer_id, &signer.verifying)];
    let verified = verify_plan(&signed, &trusted).context("verifying just-signed plan")?;

    // The plan_id is the content-address of the plan body — recompute it and
    // refuse a plan whose stored id doesn't match, so a run is only ever
    // admitted under an id that genuinely addresses its content.
    verify_plan_id(&verified).context("plan_id content-address check")?;

    // Validity window — refuses plans whose now() is outside
    // [valid_from, valid_until). For freshly-synthesized plans this
    // can only fire if the host's clock changed during signing or if
    // someone overrode the validity window in synthesis defaults.
    let now = clock.now();
    check_window(&verified, now).map_err(|e| match e {
        PlanValidityError::NotYetValid { .. } | PlanValidityError::Expired { .. } => {
            anyhow::anyhow!("plan validity window violated: {e}")
        }
        other => anyhow::anyhow!("plan validity error: {other}"),
    })?;

    // Replay protection: insert (signer_id, nonce). A second admit_for_run
    // call within the validity window with the same nonce gets refused.
    // Synthesis generates fresh nonces, so this only fires on the
    // pathological "same plan submitted twice" case.
    {
        let mut store = ledger.inner.lock().expect("nonce store mutex poisoned");
        store
            .check_and_insert(&signer_id, &verified)
            .context("replay protection check")?;
    }

    // Claim 9 — bundle re-verify at admit time. Only fires
    // when the plan pinned a bundle; missing context with a pinned
    // plan is operator misconfiguration (mvmctl up wasn't wired
    // with a resolver/trust store), so we refuse rather than skip
    // silently.
    if let Some(pin) = verified.bundle.as_ref() {
        let ctx = bundle_ctx.ok_or_else(|| {
            anyhow::anyhow!(
                "plan pins bundle {bundle} but no BundleAdmissionContext was provided — refuse",
                bundle = pin.bundle_sha256
            )
        })?;
        verify_plan_bundle(pin, ctx.resolver, ctx.trust)
            .with_context(|| format!("bundle re-verify for pin {}", pin.bundle_sha256))?;
    }

    Ok(AdmittedPlan {
        plan_id: verified.plan_id.clone(),
        signer_id,
        plan: verified,
        signed,
    })
}

/// Soft caps on the JSON envelope sizes flowing through
/// `VmStartConfig` → `SupervisorConfig` over the supervisor's
/// stdin pipe. Adversarial envelopes are a DoS vector (memory pressure
/// on the supervisor + pipe-buffer pressure on the producer). 1 MiB /
/// 4 MiB are generous for legitimate plans / bundles and tight enough
/// to refuse pathological inputs.
const PLAN_JSON_MAX_BYTES: usize = 1024 * 1024;
const BUNDLE_JSON_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Refuse an envelope over its byte cap.
///
/// A one-line comparison inlined at each call site is not reachable by a
/// test at its boundary: the only way to exercise it is to serialize a
/// real plan of exactly the cap, which is impractical to construct. So the
/// comparison lives here, where `cap - 1`, `cap` and `cap + 1` are three
/// cheap assertions.
///
/// The direction matters. Loosening `>` to `>=` refuses at exactly the cap
/// — stricter, and merely wrong. Tightening it to `==` refuses *only* at
/// exactly the cap and admits everything larger, which turns the cap into
/// no cap at all and reopens the memory-pressure vector it exists to
/// close.
fn enforce_size_cap(what: &str, len: usize, cap: usize) -> Result<()> {
    if len > cap {
        anyhow::bail!("{what} exceeds {cap} byte cap (got {len}); refusing");
    }
    Ok(())
}

/// Populate the three `VmStartConfig` audit-substrate fields
/// (`tenant_id`, `plan_json`, `bundle_json`) from the admitted
/// plan. Call after the `VmStartConfig` is built and before
/// `backend.start()`; the libkrun/HVF backends read these to wire
/// `SupervisorConfig.{tenant_id, audit_dir, gateway_audit_socket,
/// gateway_events_socket, signing_key_path}` and activate the
/// bridge-factory path.
///
/// JSON-encoded so the `VmStartConfig` wire type stays a serde seam
/// with no typed coupling to `mvm_core::plan` at the backend boundary. The
/// supervisor re-verifies the `SignedExecutionPlan` envelope before
/// trusting any decoded field — see
/// `mvm_hostd::supervisor::supervisor::SupervisorAdmission::admit`.
///
/// **Do not log the resulting `plan_json` / `bundle_json` values.**
/// The signed envelope may contain secret bindings, environment
/// variables, or policy refs that resolve to credentials. Treat as
/// opaque transport bytes.
/// Thread *only* the admitted tenant label onto the `VmStartConfig`.
///
/// The per-VM host-services broker (`host.audit.v1` / `host.time.v1` /
/// `host.cost.v1`) keys its spawn off `config.tenant_id`, so any admitted
/// workload must carry it — `host.audit.v1` is implicitly available to any
/// admitted workload. This is decoupled from
/// [`populate_audit_substrate`]: the broker needs the tenant string, **not**
/// the signed `plan_json`, whose presence flips libkrun/HVF workload boots onto
/// the claim-10 gateway-bridge supervisor path. Call this unconditionally; call
/// `populate_audit_substrate` when a backend has a signed-plan consumer.
pub fn thread_tenant_id(cfg: &mut mvm_core::vm_backend::VmStartConfig, admitted: &AdmittedPlan) {
    cfg.tenant_id = Some(admitted.plan().tenant.0.clone());
}

pub fn populate_audit_substrate(
    cfg: &mut mvm_core::vm_backend::VmStartConfig,
    admitted: &AdmittedPlan,
    policy_bundle: Option<&PolicyBundle>,
) -> Result<()> {
    thread_tenant_id(cfg, admitted);

    let plan_json = serde_json::to_string(admitted.signed())
        .context("serializing SignedExecutionPlan for VmStartConfig.plan_json")?;
    enforce_size_cap("plan_json", plan_json.len(), PLAN_JSON_MAX_BYTES)?;
    cfg.plan_json = Some(plan_json);

    // `bundle_json` carries the resolved tenant **PolicyBundle** (network /
    // egress / tool policy) that the supervisor's L4 gate + observers consume.
    // It is NOT the ExecutionPlan's `.mvmpkg` artifact pin
    // (`admitted.plan().bundle`, a `PlanArtifact` — content-addressed
    // kernel/rootfs, verified separately at admit time via `verify_plan_bundle`).
    // Feeding the pin here was a conflation the supervisor's PolicyBundle decode
    // would reject. `None` until a policy-bundle source is wired.
    cfg.bundle_json = match policy_bundle {
        Some(bundle) => {
            let bj = serde_json::to_string(bundle)
                .context("serializing PolicyBundle for VmStartConfig.bundle_json")?;
            enforce_size_cap("bundle_json", bj.len(), BUNDLE_JSON_MAX_BYTES)?;
            Some(bj)
        }
        None => None,
    };
    Ok(())
}

/// Atomically write `body` to `path` at mode 0600 on Unix hosts.
///
/// The Firecracker bridge sidecar reads `plan.json` + `bundle.json` from
/// the per-VM state dir at spawn time. Those files carry the signed
/// `ExecutionPlan` envelope and the (optional) bundle pin, which may
/// resolve through `secrets` / policy refs to credentials. They sit at
/// the same trust tier as the host signer key
/// (mode 0600); `std::fs::write` would default to 0644 minus umask which
/// on most contributor hosts is 0644 or 0664 — world-readable. Use
/// `OpenOptionsExt::mode(0o600)` + tmp-and-rename so a concurrent
/// bridge reader never sees a partial file.
///
/// Parent dir is assumed pre-created by the caller (the producer sites
/// in `up.rs` ensure `mvm_home/vms/<name>/` exists with the same
/// `0700` umbrella as `~/.mvm`).
#[cfg(unix)]
pub(crate) fn write_secret_file(path: &std::path::Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("write_secret_file: path has no parent: {}", path.display())
    })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create parent dir {}", parent.display()))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open tmp file {}", tmp.display()))?;
        f.write_all(body)
            .with_context(|| format!("write secret bytes to {}", tmp.display()))?;
        // Best-effort fsync; on tmpfs this is a no-op and on a flaky
        // FS we'd rather succeed-and-warn than fail-and-abort.
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Stash the signed plan envelope + (optional) bundle pin in the
/// per-VM state dir so the Firecracker bridge sidecar can read them
/// at spawn time.
///
/// Called from every `up.rs` producer site immediately after
/// `populate_audit_substrate`, before `backend.start()`. No-op when
/// `cfg.plan_json` is `None` (legacy / no-admission path). Files land
/// at mode 0600 via [`write_secret_file`] — see that helper's doc for
/// why `std::fs::write` is insufficient.
///
/// Lives in the producer (mvm-cli) rather than `microvm::run_from_build`
/// because the producer is the only place that has the signed envelope
/// in scope; `microvm` reads it back from disk inside the
/// `target_os = "linux"` bridge-spawn block.
pub fn stash_plan_for_bridge(cfg: &mvm_core::vm_backend::VmStartConfig) -> Result<()> {
    stash_plan_and_mint_verb_grant(cfg).map(|_| ())
}

/// Persist a VM's admitted plan material and mint its optional signed agent
/// verb grant, returning the exact envelope written to disk. Warm-restore
/// callers use the returned value in the post-restore handshake because there
/// is no new kernel boot at which to consume the sidecar.
pub fn stash_plan_and_mint_verb_grant(
    cfg: &mvm_core::vm_backend::VmStartConfig,
) -> Result<Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>> {
    let Some(plan_json) = cfg.plan_json.as_deref() else {
        return Ok(None);
    };
    let state_dir = mvm_core::config::vm_state_dir(&cfg.name);
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("create per-VM state dir {}", state_dir.display()))?;
    write_secret_file(&state_dir.join("plan.json"), plan_json.as_bytes())?;
    if let Some(bundle_json) = cfg.bundle_json.as_deref() {
        write_secret_file(&state_dir.join("bundle.json"), bundle_json.as_bytes())?;
    }
    mint_verb_grant_sidecar(plan_json, &cfg.name, &state_dir)
}

/// If the plan carries `agent_verbs`, mint a signed `VerbGrantEnvelope` and
/// write it to `<state_dir>/verb-grant.json` (mode 0600). Absent verbs ⇒ no
/// file written (grant-less boot). Best-effort key load — the key is created
/// on first use by `load_or_init_at` against the default keys dir.
///
/// The sidecar is consumed by the backend's `verb_grant_cmdline_token` at
/// launch time and carried to the guest on the kernel cmdline.
fn mint_verb_grant_sidecar(
    plan_json: &str,
    vm_name: &str,
    state_dir: &std::path::Path,
) -> Result<Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>> {
    use mvm_core::plan::SignedExecutionPlan;
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;

    // Remove any pre-existing sidecar so that a grant-less re-run of a
    // reused VM name does not inherit the previous boot's grant.
    let sidecar_path = state_dir.join("verb-grant.json");
    match std::fs::remove_file(&sidecar_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::Error::from(e)).with_context(|| {
                format!("remove stale verb-grant sidecar {}", sidecar_path.display())
            });
        }
    }

    // Best-effort parse: a missing or malformed plan_json skips the
    // sidecar (grant-less boot), matching the fail-open posture of the
    // other cmdline token producers.
    let Ok(signed) = serde_json::from_str::<SignedExecutionPlan>(plan_json) else {
        return Ok(None);
    };
    let Ok(plan) = serde_json::from_slice::<ExecutionPlan>(&signed.0.payload) else {
        return Ok(None);
    };

    let Some(verbs) = plan.agent_verbs else {
        // No verb grant requested — grant-less boot, sidecar already removed.
        return Ok(None);
    };

    let keys_dir = mvm_core::config::mvm_keys_dir();
    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir)
        .context("load host signer for verb-grant mint")?;
    let keystore = crate::host_signer::keystore::Keystore::load_from_file(&signer.secret_path)
        .context("load Keystore from host-signer key file")?;

    let grant = crate::host_signer::mint_verb_grant(
        &keystore,
        vm_name,
        &plan.nonce,
        plan.valid_until,
        verbs,
    )
    .context("mint verb grant")?;

    let pubkey_hex: String = keystore
        .pub_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let plan_nonce_hex = plan.nonce.as_hex().to_string();

    let envelope = VerbGrantEnvelope {
        pubkey_hex,
        plan_nonce_hex,
        predecessor_session_id: None,
        predecessor_plan_nonce_hex: None,
        grant,
    };
    let envelope_json = serde_json::to_vec(&envelope).context("serialize VerbGrantEnvelope")?;
    write_secret_file(&state_dir.join("verb-grant.json"), &envelope_json)?;
    Ok(Some(envelope))
}

/// Admission enforcement: every volume about to be attached must be
/// named in the verified `ExecutionPlan.shares`, with matching
/// host path, guest path, kind, ro/rw, and encryption.
///
/// On the local `mvmctl up`/`dev` path the CLI builds both the signed
/// plan and the launch config from one source, so this is self-consistent
/// by construction — but it **fails closed** if they ever diverge (a CLI
/// bug, or a future caller that hands a config the plan didn't authorize).
/// It's the trust-boundary hook: no host-fs grant reaches a guest unless
/// the signed plan admitted it (claim 1 / claim 8). The supervisor +
/// mvmd enforcement mirror this check against the same `plan.shares`.
pub fn enforce_admitted_shares(
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan: &ExecutionPlan,
) -> Result<()> {
    use mvm_core::vm_backend::VmVolumeKind;
    for v in volumes {
        let want_kind = match v.kind {
            VmVolumeKind::DirShare => mvm_core::plan::ShareKind::DirShare,
            VmVolumeKind::Disk => mvm_core::plan::ShareKind::Disk,
        };
        let admitted = plan.shares.iter().any(|g| {
            g.host_path == v.host
                && g.guest_path == v.guest
                && g.kind == want_kind
                && g.read_only == v.read_only
                && g.encrypted == v.encrypted
        });
        if !admitted {
            anyhow::bail!(
                "refusing to attach volume '{}' -> '{}' ({}): it is not named in the signed \
                 ExecutionPlan's admitted shares — every host-fs grant must be admitted (claim 1).",
                v.host,
                v.guest,
                if v.read_only { "ro" } else { "rw" },
            );
        }
    }
    Ok(())
}

/// Admission enforcement for the optional glibc SDK sidecar.
///
/// The sidecar carries the host-services cdylib the language SDKs `dlopen`. It
/// is not in the base rootfs or the static-musl runtime overlay, so it has to be
/// attached per-workload — and the attachment is authorized by the plan's
/// host-service bindings, never by an environment variable or a guess about
/// application content.
///
/// Both directions fail closed, and both are checked on the one admission path
/// every backend reaches — including the mock and dev-tier backends, so a
/// dev/test launch can't quietly acquire a posture production wouldn't:
///
/// - The plan binds an SDK-served host service, but no read-only sidecar
///   attachment is present → refuse. Booting anyway strands the workload with a
///   `dlopen` failure it cannot act on.
/// - The plan binds none, but something attached a volume at the sidecar mount
///   point anyway → refuse. That would smuggle the glibc closure (and a
///   host-services transport) into a workload the plan never authorized.
///
/// A sidecar attachment must additionally be read-only and a disk image: the
/// guest never writes to it, and a writable or directory-share attachment is a
/// different, unadmitted shape.
pub fn enforce_sdk_sidecar_attachment(
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan: &ExecutionPlan,
) -> Result<()> {
    use mvm_core::plan::{SDK_SIDECAR_GUEST_PATH, sdk_host_services_in, sdk_sidecar_required};
    use mvm_core::vm_backend::VmVolumeKind;

    let attached: Vec<_> = volumes
        .iter()
        .filter(|v| v.guest == SDK_SIDECAR_GUEST_PATH)
        .collect();
    let required = sdk_sidecar_required(plan);

    if !required {
        if let Some(stray) = attached.first() {
            anyhow::bail!(
                "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH}: the signed ExecutionPlan \
                 binds no SDK host service, so this workload must not carry the SDK sidecar",
                stray.host,
            );
        }
        return Ok(());
    }

    let bound: Vec<&str> = sdk_host_services_in(&plan.services)
        .iter()
        .map(|s| s.as_str())
        .collect();

    let Some(sidecar) = attached.first() else {
        anyhow::bail!(
            "refusing to launch: the signed ExecutionPlan binds SDK host service(s) [{}], which \
             need the SDK sidecar mounted read-only at {SDK_SIDECAR_GUEST_PATH}, and no such \
             attachment is present. The launch path resolves the sidecar from the version-keyed \
             cache under the mvm cache dir; build it with \
             `nix build ./nix/images/runtime-overlay#sdk-sidecar-image` and retry.",
            bound.join(", "),
        );
    };
    if attached.len() > 1 {
        anyhow::bail!(
            "refusing to launch: {} attachments target {SDK_SIDECAR_GUEST_PATH}; exactly one \
             read-only SDK sidecar is admissible",
            attached.len(),
        );
    }
    if !sidecar.read_only {
        anyhow::bail!(
            "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH} read-write: the SDK sidecar is \
             read-only by contract",
            sidecar.host,
        );
    }
    if !matches!(sidecar.kind, VmVolumeKind::Disk) {
        anyhow::bail!(
            "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH}: the SDK sidecar is a read-only \
             disk image, not a host-directory share",
            sidecar.host,
        );
    }
    Ok(())
}

/// Inputs for [`admit_and_start`]. The `synthesis` describes the plan to admit
/// (the signed authority) and `config` is the launch shape to boot; they come
/// from one source in a well-formed caller, and [`enforce_admitted_shares`]
/// fails closed if they ever disagree on volumes.
pub struct AdmitAndStartParams<'a> {
    pub synthesis: &'a SynthesisInput<'a>,
    pub config: VmStartConfig,
    pub clock: &'a dyn Clock,
    pub ledger: &'a InMemoryNonceLedger,
    pub host_signer_keys_dir: Option<&'a std::path::Path>,
    pub bundle_ctx: Option<&'a BundleAdmissionContext<'a>>,
    pub policy_bundle: Option<&'a PolicyBundle>,
    /// Optional chain-signed emitter: `plan.admitted` fires after admission
    /// succeeds, then `plan.launched` on a successful backend start or
    /// `plan.failed` on a start failure — the same event ordering the CLI's
    /// up path wires by hand.
    pub emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    /// Whether a failure to record `plan.admitted` refuses the boot.
    ///
    /// Only the admission is gated. `plan.launched` and `plan.failed` describe
    /// something that has already happened — refusing after the fact prevents
    /// nothing, and tearing down a running workload because a log write failed
    /// trades a missing record for a killed job. The admission is different:
    /// it is the record that the run was allowed, and it is written before the
    /// backend starts, so refusing on it actually stops the unaudited run.
    pub audit_durability: crate::audit::durability::AuditDurability,
}

/// Refuse a boot whose kernel is not the one the plan pinned.
///
/// The image digest says what the workload *is*; it says nothing about what
/// confines it. The same signed image on a kernel built for a different job has
/// a different security posture — a kernel with `CONFIG_USER_NS` enabled lets
/// the guest become uid 0 in a user namespace, which the workload kernel is
/// built to prevent. Before the kernel was pinned, that substitution was
/// invisible: identical plan, identical image digest, and confinement decided
/// by whichever kernel the host happened to have cached.
///
/// Fail-closed in both directions. A plan that pins a kernel and a launch
/// config that supplies none is a refusal, not a pass — otherwise dropping the
/// kernel path would be a way to skip the check.
fn enforce_admitted_environment(config: &VmStartConfig, plan: &ExecutionPlan) -> Result<()> {
    let Some(environment) = plan.environment.as_ref() else {
        // No environment pinned. Plans predating the field, and backends that
        // boot their own bundled kernel, land here.
        return Ok(());
    };
    let Some(kernel_path) = config.kernel_path.as_deref() else {
        anyhow::bail!(
            "plan pins kernel {} but the launch config supplies no kernel path",
            environment.kernel_sha256
        );
    };
    let actual = mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(kernel_path))
        .with_context(|| {
            format!("hashing kernel at {kernel_path} for admitted-environment check")
        })?;
    if actual != environment.kernel_sha256 {
        anyhow::bail!(
            "admitted-environment mismatch: plan pins kernel {} but {kernel_path} hashes to {actual}",
            environment.kernel_sha256
        );
    }
    Ok(())
}

/// Outcome of a successful admitted boot: the backend's VM id plus the
/// `AdmittedPlan` (for the caller's audit chain / typed result).
#[derive(Debug)]
pub struct StartedMachine {
    pub vm_id: VmId,
    pub admitted: AdmittedPlan,
}

/// The single admitted-boot entrypoint every driver shares — the CLI's
/// `mvmctl up`/`run` and the `mvm-client` local backend both reach it, so a
/// workload can never boot on a path that skipped admission.
///
/// Order matters and is fail-closed: synthesize + sign + verify + validity +
/// replay (+ bundle re-verify) run first; only then is the signed plan threaded
/// onto the launch config and every volume checked against the admitted shares
/// (claim 1); only then does the backend start the VM. Any earlier failure
/// returns with **no VM created** — admission is a gate, not a formality.
///
/// The caller resolves the image to a `config.rootfs_path` beforehand; this
/// function is backend-agnostic (it drives whatever `AnyBackend` it is handed,
/// including the in-memory mock in tests).
/// The four post-admission gates between `plan.admitted` and the backend
/// start, run in order. On refusal the failing stage's wire label is
/// returned alongside the error so the caller can emit a terminal
/// `plan.failed` entry naming the gate.
fn run_post_admission_gates(
    mut config: VmStartConfig,
    admitted: &AdmittedPlan,
    policy_bundle: Option<&PolicyBundle>,
) -> std::result::Result<VmStartConfig, (&'static str, anyhow::Error)> {
    if let Err(e) = populate_audit_substrate(&mut config, admitted, policy_bundle) {
        return Err(("audit-substrate", e));
    }
    if let Err(e) = enforce_admitted_shares(&config.volumes, admitted.plan()) {
        return Err(("admitted-shares", e));
    }
    if let Err(e) = enforce_admitted_environment(&config, admitted.plan()) {
        return Err(("admitted-environment", e));
    }
    if let Err(e) = enforce_sdk_sidecar_attachment(&config.volumes, admitted.plan()) {
        return Err(("sdk-sidecar", e));
    }
    Ok(config)
}

pub fn admit_and_start(
    backend: &AnyBackend,
    params: AdmitAndStartParams<'_>,
) -> Result<StartedMachine> {
    let admitted = admit_for_run(
        params.synthesis,
        params.clock,
        params.ledger,
        params.host_signer_keys_dir,
        params.bundle_ctx,
    )?;
    crate::audit::durability::record_admission(
        params.emitter,
        admitted.plan(),
        admitted.signer_id(),
        params.audit_durability,
    )?;

    // A refusal in any post-admission gate must still terminate the chain:
    // `plan.admitted` already fired, so a gate refusal emits `plan.failed`
    // carrying the refusing stage rather than leaving a dangling admission.
    let config = match run_post_admission_gates(params.config, &admitted, params.policy_bundle) {
        Ok(config) => config,
        Err((stage, err)) => {
            if let Some(emitter) = params.emitter
                && let Err(e) = emitter.emit_failed(admitted.plan(), stage, &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
            }
            return Err(err.context(format!("admission gate refused ({stage})")));
        }
    };

    let backend_name = backend.name().to_string();
    match backend
        .start(&config)
        .context("backend start after signed-plan admission")
    {
        Ok(vm_id) => {
            if let Some(emitter) = params.emitter
                && let Err(e) = emitter.emit_launched(admitted.plan(), &backend_name)
            {
                tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
            }
            Ok(StartedMachine { vm_id, admitted })
        }
        Err(err) => {
            if let Some(emitter) = params.emitter
                && let Err(e) =
                    emitter.emit_failed(admitted.plan(), "backend-start", &format!("{err:#}"))
            {
                tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
            }
            Err(err)
        }
    }
}

#[cfg(test)]
mod admitted_environment_tests {
    use super::*;

    fn plan_pinning(kernel_sha256: Option<&str>) -> ExecutionPlan {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.environment = kernel_sha256.map(|k| mvm_core::plan::EnvironmentRef {
            kernel_sha256: k.to_string(),
        });
        plan
    }

    fn config_with_kernel(kernel: Option<&std::path::Path>) -> VmStartConfig {
        VmStartConfig {
            kernel_path: kernel.map(|k| k.display().to_string()),
            ..VmStartConfig::default()
        }
    }

    fn write_kernel(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join("vmlinux");
        std::fs::write(&p, bytes).expect("write kernel fixture");
        p
    }

    /// The pinned kernel is the one on disk: the boot proceeds.
    #[test]
    fn matching_kernel_digest_is_admitted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let kernel = write_kernel(tmp.path(), b"workload-kernel");
        let sha = mvm_core::crypto::image_verify::sha256_file(&kernel).expect("hash");
        enforce_admitted_environment(
            &config_with_kernel(Some(&kernel)),
            &plan_pinning(Some(&sha)),
        )
        .expect("matching kernel must be admitted");
    }

    /// A different kernel than the plan pinned is refused: same plan, same
    /// image, a kernel swapped underneath — the substitution that used to be
    /// invisible because nothing in the plan described the environment.
    #[test]
    fn substituted_kernel_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let kernel = write_kernel(tmp.path(), b"workload-kernel");
        let sha = mvm_core::crypto::image_verify::sha256_file(&kernel).expect("hash");
        std::fs::write(&kernel, b"a-general-purpose-kernel").expect("swap kernel");

        let err = enforce_admitted_environment(
            &config_with_kernel(Some(&kernel)),
            &plan_pinning(Some(&sha)),
        )
        .expect_err("a substituted kernel must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("admitted-environment mismatch"),
            "error must name the mismatch, got: {msg}"
        );
    }

    /// Dropping the kernel path must not be a way around the pin.
    #[test]
    fn pinned_plan_with_no_kernel_path_is_refused() {
        let err = enforce_admitted_environment(
            &config_with_kernel(None),
            &plan_pinning(Some(&"a".repeat(64))),
        )
        .expect_err("a pinned plan with no kernel path must be refused");
        assert!(format!("{err:#}").contains("supplies no kernel path"));
    }

    /// Plans that pin nothing still boot — every plan written before the field
    /// existed, and backends that carry their own bundled kernel.
    #[test]
    fn unpinned_plan_is_unaffected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let kernel = write_kernel(tmp.path(), b"whatever");
        enforce_admitted_environment(&config_with_kernel(Some(&kernel)), &plan_pinning(None))
            .expect("an unpinned plan must be unaffected");
        enforce_admitted_environment(&config_with_kernel(None), &plan_pinning(None))
            .expect("an unpinned plan with no kernel must be unaffected");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy};

    const FIXTURE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// This module's own source, for the unforgeability check below.
    const SOURCE: &str = include_str!("plan_admission.rs");

    /// The production half of it — everything before this test module, so the
    /// checks below cannot be satisfied by a string literal written here.
    fn production_source() -> &'static str {
        SOURCE
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("this module keeps its tests at the end")
            .0
    }

    /// The body of the `AdmittedPlan` declaration, plus the derives above it.
    fn admitted_plan_declaration() -> (&'static str, &'static str) {
        let (before, after) = production_source()
            .split_once("pub struct AdmittedPlan {")
            .expect("the type is declared in this file");
        let derives = before
            .rfind("#[derive(")
            .map(|at| &before[at..])
            .unwrap_or_default();
        let body = after
            .split_once("\n}")
            .expect("the declaration is brace-terminated")
            .0;
        (derives, body)
    }

    /// Every `impl ... for AdmittedPlan` line, i.e. trait impls on the type.
    fn trait_impls_on_admitted_plan() -> Vec<&'static str> {
        production_source()
            .lines()
            .map(str::trim_start)
            .filter(|line| line.starts_with("impl") && line.contains("for AdmittedPlan"))
            .collect()
    }

    #[test]
    fn an_admitted_plan_cannot_be_fabricated_outside_this_module() {
        // Downstream consumers — the share enforcer, the workload input gate —
        // treat a value of this type as proof that admission ran, so a caller
        // able to mint one has the authority admission was supposed to hold.
        // What stops them is a set of *absences* in this declaration, and an
        // absence is exactly what no runtime assertion can observe: the honest
        // form is a compile-fail test, and this workspace has no harness for
        // one. So the source is the assertion, and each branch below names the
        // public path it keeps closed.
        let (derives, body) = admitted_plan_declaration();

        // 1. No `pub` field: a struct literal needs every field named, and a
        //    private one makes the literal unwritable outside this module.
        //    Privacy also means no `&mut` reaches a field, so a caller holding
        //    a legitimately-admitted plan cannot afterwards push a service
        //    grant into it that admission never saw.
        for field in ["plan", "plan_id", "signer_id", "signed"] {
            assert!(
                body.contains(&format!("\n    {field}: ")),
                "`AdmittedPlan.{field}` must stay private — a pub field is a forge"
            );
        }

        // 2. No derive that reconstitutes one: `Clone` would let a caller
        //    duplicate a legitimate plan (harmless alone, but it is the first
        //    half of clone-then-mutate), `Default` and `Deserialize` would
        //    each build one from nothing at all.
        for derive in ["Clone", "Default", "Deserialize", "Serialize"] {
            assert!(
                !derives.contains(derive),
                "`AdmittedPlan` must not derive {derive} — it is a second way to obtain one"
            );
        }

        // 3. No trait impl offering a conversion in: `From`/`TryFrom`, a
        //    hand-written `Default`, a `Deserialize` impl.
        assert!(
            trait_impls_on_admitted_plan().is_empty(),
            "no trait may be implemented for AdmittedPlan without re-checking \
             whether it hands out a construction path: {:?}",
            trait_impls_on_admitted_plan()
        );

        // 4. The one convenience constructor is compiled out of production.
        assert!(
            SOURCE.contains("#[cfg(test)]\n    pub(crate) fn for_test("),
            "the test constructor must stay `#[cfg(test)]` and crate-private"
        );

        // 5. And `admit_for_run` is the only place that writes the literal.
        let literals = production_source().matches("Ok(AdmittedPlan {").count();
        assert_eq!(
            literals, 1,
            "exactly one production construction site, inside admit_for_run"
        );
    }

    fn fixture_input(vm_name: &str) -> SynthesisInput<'_> {
        SynthesisInput {
            stream_edges: Vec::new(),
            kernel_sha256: None,
            network_mode: Default::default(),
            l3_network: None,
            vm_name,
            tenant: None,
            backend_name: "firecracker",
            image_name: "img",
            image_sha256: FIXTURE_SHA,
            image_cosign_bundle: None,
            intent: None,
            seccomp_tier: PlanSeccompTier::Standard,
            network_policy_ref: None,
            fs_policy_ref: None,
            egress_policy_ref: None,
            tool_policy_ref: None,
            secret_release: SecretReleasePolicy::None,
            secrets: Vec::new(),
            audit_event_prefix: None,
            cpus: 1,
            mem_mib: 256,
            disk_mib: 0,
            boot_timeout_secs: 30,
            exec_timeout_secs: 0,
            destroy_on_exit: true,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            audit_labels: Default::default(),
            agent_verbs: None,
            services: Vec::new(),
            stream_retention: Default::default(),
        }
    }

    fn sdk_sidecar_volume() -> mvm_core::vm_backend::VmVolume {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        VmVolume {
            host: "/cache/sdk-sidecar/1.2.3/aarch64/sdk.ext4".into(),
            guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
            read_only: true,
            kind: VmVolumeKind::Disk,
            ..Default::default()
        }
    }

    fn plan_binding(services: &[&str]) -> ExecutionPlan {
        let mut input = fixture_input("vm-sdk");
        input.services = services
            .iter()
            .map(|s| {
                mvm_contract::protocol::broker::ServiceId::parse(*s).expect("fixture service id")
            })
            .collect();
        synthesize_plan(&input).expect("fixture plan synthesizes")
    }

    struct FixedClock(DateTime<Utc>);

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// Claim 1: a volume that the signed plan didn't admit — or that
    /// mismatches the admitted ro/rw — is refused before launch.
    #[test]
    fn enforce_admitted_shares_refuses_unadmitted_or_mismatched() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let grant = mvm_core::plan::HostShareGrant {
            tag: "uvol0".into(),
            host_path: "/h/src".into(),
            guest_path: "/data".into(),
            kind: mvm_core::plan::ShareKind::DirShare,
            read_only: true,
            encrypted: false,
        };
        let mut input = fixture_input("vm-shares");
        input.shares = vec![grant];
        let plan = synthesize_plan(&input).unwrap();

        let admitted_vol = VmVolume {
            host: "/h/src".into(),
            guest: "/data".into(),
            read_only: true,
            kind: VmVolumeKind::DirShare,
            ..Default::default()
        };
        // The exact admitted volume passes.
        assert!(enforce_admitted_shares(std::slice::from_ref(&admitted_vol), &plan).is_ok());

        // A volume the plan never named is refused.
        let unadmitted = VmVolume {
            host: "/etc".into(),
            guest: "/data".into(),
            read_only: true,
            kind: VmVolumeKind::DirShare,
            ..Default::default()
        };
        assert!(enforce_admitted_shares(&[unadmitted], &plan).is_err());

        // Same path/kind, but read-WRITE when the plan admitted read-only:
        // an unauthorized escalation, refused.
        let escalated = VmVolume {
            read_only: false,
            ..admitted_vol
        };
        assert!(enforce_admitted_shares(&[escalated], &plan).is_err());
    }

    /// A workload that binds no SDK host service gets no sidecar, and nothing
    /// may attach one behind the plan's back.
    #[test]
    fn no_sdk_binding_means_no_sidecar_attachment() {
        let plan = plan_binding(&[]);
        assert!(enforce_sdk_sidecar_attachment(&[], &plan).is_ok());

        let err = enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan)
            .expect_err("an unauthorized sidecar must be refused");
        let msg = err.to_string();
        assert!(msg.contains("binds no SDK host service"), "{msg}");
    }

    /// An unrelated host-service binding is not an SDK binding: it must not pull
    /// the glibc sidecar into an ordinary workload.
    #[test]
    fn unrelated_service_binding_does_not_require_the_sidecar() {
        let plan = plan_binding(&["broker.v1", "host.other.v1"]);
        assert!(enforce_sdk_sidecar_attachment(&[], &plan).is_ok());
        assert!(enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan).is_err());
    }

    /// A bound SDK host service with the sidecar attached read-only is admitted.
    #[test]
    fn sdk_binding_with_a_read_only_sidecar_is_admitted() {
        for service in mvm_core::plan::SDK_HOST_SERVICES {
            let plan = plan_binding(&[service]);
            assert!(
                enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan).is_ok(),
                "{service} bound + sidecar attached read-only must be admitted"
            );
        }
    }

    /// A bound SDK host service with no sidecar attachment fails closed, and the
    /// message names the binding that demanded it without leaking file bytes.
    #[test]
    fn sdk_binding_without_the_sidecar_fails_closed() {
        let plan = plan_binding(&["host.secrets.v1"]);
        let err = enforce_sdk_sidecar_attachment(&[], &plan)
            .expect_err("a required-but-absent sidecar must refuse the launch");
        let msg = err.to_string();
        assert!(msg.contains("host.secrets.v1"), "{msg}");
        assert!(
            msg.contains(mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
            "{msg}"
        );
    }

    /// The sidecar is read-only by contract: a writable or directory-share
    /// attachment at the sidecar mount point is a different, unadmitted shape.
    #[test]
    fn a_writable_or_dir_share_sidecar_fails_closed() {
        use mvm_core::vm_backend::VmVolumeKind;
        let plan = plan_binding(&["host.audit.v1"]);

        let writable = mvm_core::vm_backend::VmVolume {
            read_only: false,
            ..sdk_sidecar_volume()
        };
        let err = enforce_sdk_sidecar_attachment(&[writable], &plan).expect_err("rw refused");
        assert!(err.to_string().contains("read-only"), "{err}");

        let share = mvm_core::vm_backend::VmVolume {
            kind: VmVolumeKind::DirShare,
            ..sdk_sidecar_volume()
        };
        let err = enforce_sdk_sidecar_attachment(&[share], &plan).expect_err("share refused");
        assert!(err.to_string().contains("disk image"), "{err}");
    }

    /// Two attachments racing for the same mount point is ambiguous — refuse
    /// rather than let mount order decide which cdylib the workload loads.
    #[test]
    fn duplicate_sidecar_attachments_fail_closed() {
        let plan = plan_binding(&["host.time.v1"]);
        let dup = [sdk_sidecar_volume(), sdk_sidecar_volume()];
        let err = enforce_sdk_sidecar_attachment(&dup, &plan).expect_err("duplicates refused");
        assert!(err.to_string().contains("exactly one"), "{err}");
    }

    /// Unrelated volumes are untouched by the sidecar gate in either direction.
    #[test]
    fn unrelated_volumes_are_ignored_by_the_sidecar_gate() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let other = VmVolume {
            host: "/h/data.img".into(),
            guest: "/data".into(),
            read_only: false,
            kind: VmVolumeKind::Disk,
            ..Default::default()
        };
        assert!(
            enforce_sdk_sidecar_attachment(std::slice::from_ref(&other), &plan_binding(&[]))
                .is_ok()
        );
        let bound = plan_binding(&["host.cost.v1"]);
        assert!(
            enforce_sdk_sidecar_attachment(&[other.clone(), sdk_sidecar_volume()], &bound).is_ok()
        );
        assert!(
            enforce_sdk_sidecar_attachment(std::slice::from_ref(&other), &bound).is_err(),
            "an unrelated volume must not satisfy the sidecar requirement"
        );
    }

    /// The signed plan round-trips its service bindings, so the gate decides on
    /// the same bytes the signature covers.
    #[test]
    fn service_bindings_survive_plan_serialization() {
        let plan = plan_binding(&["host.audit.v1", "broker.v1"]);
        let json = serde_json::to_string(&plan).expect("plan serializes");
        let back: ExecutionPlan = serde_json::from_str(&json).expect("plan round-trips");
        assert_eq!(back.services, plan.services);
        assert!(mvm_core::plan::sdk_sidecar_required(&back));
        assert!(enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &back).is_ok());
    }

    #[test]
    fn happy_path_returns_admitted_plan_with_plan_id() {
        let dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let ledger = InMemoryNonceLedger::new();
        let admitted = admit_for_run(
            &fixture_input("vm1"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
        )
        .expect("happy path");
        assert!(!admitted.plan_id().0.is_empty());
        assert!(admitted.signer_id().starts_with("host:"));
        // The signed envelope must be re-verifiable with the public
        // half of the host signer.
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(admitted.signer_id(), &signer.verifying)];
        let recovered = mvm_core::plan::verify_plan(admitted.signed(), &trusted).unwrap();
        assert_eq!(&recovered.plan_id, admitted.plan_id());
    }

    #[test]
    fn admitted_plan_id_is_a_content_address() {
        let dir = tempfile::tempdir().unwrap();
        let admitted = admit_for_run(
            &fixture_input("vm1"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
        )
        .expect("happy path");
        assert!(
            admitted.plan_id().0.starts_with("sha256:"),
            "content-addressed, not a UUID: {}",
            admitted.plan_id().0
        );
        // The admission path enforces the content-address; the admitted plan
        // re-derives to exactly its stored id.
        assert_eq!(mvm_core::plan::verify_plan_id(admitted.plan()), Ok(()));
    }

    #[test]
    fn rejects_replay_within_validity_window() {
        let dir = tempfile::tempdir().unwrap();
        // We can't naturally replay because synthesize_plan generates a
        // fresh nonce each call — instead, build the plan once, sign,
        // then ask the ledger to admit twice. The second call must
        // refuse with nonce-replay.
        let plan = synthesize_plan(&fixture_input("vm1")).unwrap();
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let signer_id = host_signer_id();
        let signed = sign_plan(&plan, &signer.signing, &signer_id);
        let verified =
            mvm_core::plan::verify_plan(&signed, &[(&signer_id, &signer.verifying)]).unwrap();

        let ledger = InMemoryNonceLedger::new();
        {
            let mut store = ledger.inner.lock().unwrap();
            assert!(store.check_and_insert(&signer_id, &verified).is_ok());
            assert!(
                store.check_and_insert(&signer_id, &verified).is_err(),
                "second insert of same (signer, nonce) must fail"
            );
        }
    }

    #[test]
    fn rejects_plan_outside_validity_window() {
        // Construct a fixed clock 30 minutes in the future — past
        // the plan's 10-minute window from synthesis.
        let now_plus_30 = Utc.with_ymd_and_hms(2099, 1, 1, 12, 30, 0).unwrap();
        // Override time by constructing a plan with a known window
        // and a FixedClock outside it.
        let dir = tempfile::tempdir().unwrap();
        // To exercise the window check deterministically, we
        // pre-build a stale signed plan and feed it directly through
        // the check (synthesize_plan can't make a stale plan because
        // it uses Utc::now()).
        let mut plan = synthesize_plan(&fixture_input("vm1")).unwrap();
        plan.valid_from = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
        plan.valid_until = Utc.with_ymd_and_hms(2000, 1, 1, 0, 10, 0).unwrap();
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let signed = sign_plan(&plan, &signer.signing, &host_signer_id());
        let verified = verify_plan(&signed, &[(&host_signer_id(), &signer.verifying)]).unwrap();
        let _clock = FixedClock(now_plus_30);
        // Inline the window check (admit_for_run does it after
        // synthesis; we're proving the underlying assert).
        assert!(check_window(&verified, now_plus_30).is_err());
    }

    #[test]
    fn admitted_plan_signed_field_round_trips_through_verify() {
        let dir = tempfile::tempdir().unwrap();
        let admitted = admit_for_run(
            &fixture_input("vm1"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
        )
        .unwrap();
        // The signed field is what the audit signer will hash;
        // proving it round-trips here closes the contract.
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(admitted.signer_id(), &signer.verifying)];
        assert!(verify_plan(admitted.signed(), &trusted).is_ok());
    }

    #[test]
    fn propagates_synthesis_failures() {
        let dir = tempfile::tempdir().unwrap();
        let err = admit_for_run(
            &fixture_input(""), // empty vm_name fails synthesis
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
        )
        .expect_err("must refuse");
        assert!(
            err.to_string().contains("vm_name")
                || err.chain().any(|e| e.to_string().contains("vm_name"))
        );
    }

    #[test]
    fn two_distinct_admit_calls_produce_distinct_plan_ids_and_nonces() {
        let dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let ledger = InMemoryNonceLedger::new();
        let a1 = admit_for_run(
            &fixture_input("vm1"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
        )
        .unwrap();
        let a2 = admit_for_run(
            &fixture_input("vm1"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
        )
        .unwrap();
        assert_ne!(a1.plan_id, a2.plan_id);
        assert_ne!(a1.plan.nonce, a2.plan.nonce);
    }

    // ── Claim 9: admit-time bundle re-verify ─────────────────────
    //
    // Tests exercise the boundary between `synthesize_plan`'s
    // `bundle_pin` (the input) and `admit_for_run`'s
    // `BundleAdmissionContext` (the verifier seam). The mvm_plan
    // bundle module already tests every BundleVerifyError /
    // PlanBundleError variant in isolation; these tests prove the
    // wiring fires when admit_for_run sees a pinned plan.

    use mvm_core::plan::bundle::{
        BundleResolveError, BundleResolver, KeyId as BundleKeyId, PlanArtifact, TrustStore,
        bundle_sha256, key_id_from_pubkey, write_bundle,
    };
    use std::collections::HashMap;

    struct FixedResolver(Vec<u8>);
    impl BundleResolver for FixedResolver {
        fn resolve(&self, _bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError> {
            Ok(self.0.clone())
        }
    }

    struct MapTrust(HashMap<BundleKeyId, ed25519_dalek::VerifyingKey>);
    impl TrustStore for MapTrust {
        fn lookup(&self, key_id: &BundleKeyId) -> Option<ed25519_dalek::VerifyingKey> {
            self.0.get(key_id).copied()
        }
    }

    /// Build a minimal signed bundle around `(kernel, rootfs)` bytes.
    /// Returns the archive plus the matching `PlanArtifact` pin.
    fn make_test_bundle(
        sk: &ed25519_dalek::SigningKey,
        kernel: &[u8],
        rootfs: &[u8],
    ) -> (Vec<u8>, PlanArtifact) {
        use mvm_core::plan::bundle::{
            ARTIFACTS_DIR, ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest,
            sha256_hex,
        };
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        let make_art = |name: &str, role: ArtifactRole, bytes: &[u8]| BundleArtifact {
            name: name.to_string(),
            role,
            path: format!("{ARTIFACTS_DIR}/{name}"),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        };
        let manifest = BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            publisher: "test".to_string(),
            key_id: key_id.clone(),
            arch: "aarch64".to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-05-13T00:00:00Z".to_string(),
            labels: std::collections::BTreeMap::new(),
            artifacts: vec![
                make_art("vmlinux", ArtifactRole::Kernel, kernel),
                make_art("rootfs.ext4", ArtifactRole::Rootfs, rootfs),
            ],
            verity: None,
            resources: None,
        };
        let archive = write_bundle(
            &manifest,
            sk,
            vec![
                (format!("{ARTIFACTS_DIR}/vmlinux"), kernel.to_vec()),
                (format!("{ARTIFACTS_DIR}/rootfs.ext4"), rootfs.to_vec()),
            ],
        )
        .expect("write_bundle");

        // Recover the signature bytes from the archive for the pin.
        let mut sig_bytes: Vec<u8> = Vec::new();
        let mut a = tar::Archive::new(std::io::Cursor::new(&archive));
        for entry in a.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == "manifest.sig" {
                std::io::Read::read_to_end(&mut entry, &mut sig_bytes).unwrap();
                break;
            }
        }
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let pin = PlanArtifact::new(bundle_sha256(&archive), &sig_arr, key_id);
        (archive, pin)
    }

    fn input_with_pin<'a>(vm_name: &'a str, pin: &PlanArtifact) -> SynthesisInput<'a> {
        let mut input = fixture_input(vm_name);
        input.bundle_pin = Some(pin.clone());
        input
    }

    #[test]
    fn admit_with_clean_pinned_bundle_passes() {
        // Generate the publisher key out of band, build a bundle,
        // enrol the pubkey in the trust store, hand admit_for_run a
        // matching pin + context.
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (archive, pin) = make_test_bundle(&sk, b"kernel-bytes", b"rootfs-bytes");
        let mut map = HashMap::new();
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        map.insert(key_id, sk.verifying_key());
        let trust = MapTrust(map);
        let resolver = FixedResolver(archive);
        let ctx = BundleAdmissionContext {
            resolver: &resolver,
            trust: &trust,
        };
        let admitted = admit_for_run(
            &input_with_pin("vm-pinned", &pin),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
        )
        .expect("clean pin admits");
        assert!(admitted.plan().bundle.is_some());
    }

    #[test]
    fn admit_with_pin_but_no_context_refuses() {
        // Publisher misconfiguration: plan carries a pin but the
        // mvmctl up path didn't wire a BundleAdmissionContext. The
        // admit path refuses rather than silently skipping the
        // re-verify step (fail closed, not fail open).
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (_archive, pin) = make_test_bundle(&sk, b"k", b"r");
        let err = admit_for_run(
            &input_with_pin("vm-no-ctx", &pin),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
        )
        .expect_err("must refuse without context");
        let msg = format!("{err:#}");
        assert!(msg.contains("BundleAdmissionContext"), "got: {msg}");
    }

    #[test]
    fn admit_with_unknown_publisher_in_trust_store_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (archive, pin) = make_test_bundle(&sk, b"k", b"r");
        // Empty trust store — publisher's key_id is unknown locally.
        let trust = MapTrust(HashMap::new());
        let resolver = FixedResolver(archive);
        let ctx = BundleAdmissionContext {
            resolver: &resolver,
            trust: &trust,
        };
        let err = admit_for_run(
            &input_with_pin("vm-untrusted", &pin),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
        )
        .expect_err("must refuse unknown publisher");
        let msg = format!("{err:#}");
        // The error chain bubbles up the BundleVerifyError::UnknownKey
        // variant from the read_and_verify pass.
        assert!(
            err.chain().any(|e| e.to_string().contains("key_id")),
            "expected key_id mention; got: {msg}"
        );
    }

    #[test]
    fn admit_with_pin_mismatching_archive_refuses() {
        // Resolver returns a different archive than the pin describes.
        // The bundle_sha256 cross-check catches it before the
        // signature verify even runs.
        let dir = tempfile::tempdir().unwrap();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (_archive_a, pin_a) = make_test_bundle(&sk, b"kA", b"rA");
        let (archive_b, _pin_b) = make_test_bundle(&sk, b"kB", b"rB");
        let mut map = HashMap::new();
        map.insert(key_id_from_pubkey(&sk.verifying_key()), sk.verifying_key());
        let trust = MapTrust(map);
        let resolver = FixedResolver(archive_b);
        let ctx = BundleAdmissionContext {
            resolver: &resolver,
            trust: &trust,
        };
        let err = admit_for_run(
            &input_with_pin("vm-pin-drift", &pin_a),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            Some(&ctx),
        )
        .expect_err("must refuse pin drift");
        assert!(
            err.chain().any(|e| e.to_string().contains("sha256")),
            "expected sha256 mismatch chain; got {err:#}"
        );
    }

    #[test]
    fn thread_tenant_id_sets_only_tenant_label_not_the_bridge_plan() {
        use mvm_core::vm_backend::VmStartConfig;
        let dir = tempfile::tempdir().unwrap();
        let admitted = admit_for_run(
            &fixture_input("vm-tenant-only"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
        )
        .expect("happy admit");

        let mut cfg = VmStartConfig::default();
        thread_tenant_id(&mut cfg, &admitted);

        // The broker spawn keys off this label.
        assert_eq!(
            cfg.tenant_id.as_deref(),
            Some(admitted.plan().tenant.0.as_str())
        );
        // It must NOT thread the signed plan / policy bundle — that flips
        // libkrun/HVF onto the gateway-bridge supervisor (+ its ~/.mvm/keys
        // substrate validation), which is a separate opt-in concern.
        assert!(
            cfg.plan_json.is_none(),
            "thread_tenant_id must not set plan_json"
        );
        assert!(
            cfg.bundle_json.is_none(),
            "thread_tenant_id must not set bundle_json"
        );
    }

    #[test]
    fn populate_audit_substrate_threads_tenant_and_signed_envelope() {
        use mvm_core::vm_backend::VmStartConfig;
        let dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let ledger = InMemoryNonceLedger::new();
        let admitted = admit_for_run(
            &fixture_input("vm-substrate"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
        )
        .expect("happy admit");

        let mut cfg = VmStartConfig::default();
        populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
        assert_eq!(
            cfg.tenant_id.as_deref(),
            Some(admitted.plan().tenant.0.as_str())
        );
        let plan_json = cfg.plan_json.expect("plan_json populated");
        let roundtrip: mvm_core::plan::SignedExecutionPlan =
            serde_json::from_str(&plan_json).expect("roundtrip");
        // Re-verify the envelope to get the inner ExecutionPlan and
        // confirm the plan_id matches what the producer admitted.
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(admitted.signer_id(), &signer.verifying)];
        let recovered =
            mvm_core::plan::verify_plan(&roundtrip, &trusted).expect("envelope re-verifies");
        assert_eq!(&recovered.plan_id, admitted.plan_id());
        // fixture has no bundle pin, so bundle_json stays None
        assert!(cfg.bundle_json.is_none());
    }

    #[test]
    fn bundle_json_carries_a_policy_bundle_not_the_artifact_pin() {
        // De-conflation: bundle_json is the tenant PolicyBundle the
        // supervisor's L4 gate + observers consume — sourced from the
        // policy_bundle arg, NOT from `admitted.plan().bundle` (the .mvmpkg
        // PlanArtifact pin, a different bundle verified separately).
        use mvm_core::vm_backend::VmStartConfig;
        let dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let ledger = InMemoryNonceLedger::new();
        let admitted = admit_for_run(
            &fixture_input("vm-policy-bundle"),
            &clock,
            &ledger,
            Some(dir.path()),
            None,
        )
        .expect("happy admit");

        let bundle = mvm_core::policy::PolicyBundle {
            schema_version: mvm_core::policy::SCHEMA_VERSION,
            bundle_id: mvm_core::policy::PolicyId("test".into()),
            bundle_version: 1,
            network: Default::default(),
            egress: Default::default(),
            pii: Default::default(),
            tool: Default::default(),
            artifact: Default::default(),
            keys: Default::default(),
            audit: Default::default(),
            wasi: Default::default(),
            tenant_overlays: std::collections::BTreeMap::new(),
        };

        let mut cfg = VmStartConfig::default();
        populate_audit_substrate(&mut cfg, &admitted, Some(&bundle)).expect("populate");
        let bj = cfg.bundle_json.expect("bundle_json populated");
        let roundtrip: mvm_core::policy::PolicyBundle =
            serde_json::from_str(&bj).expect("bundle_json deserializes as a PolicyBundle");
        assert_eq!(roundtrip, bundle);

        // No policy bundle → None (the de-conflated default; a pinned artifact
        // no longer leaks into this field).
        let mut cfg2 = VmStartConfig::default();
        populate_audit_substrate(&mut cfg2, &admitted, None).expect("populate none");
        assert!(cfg2.bundle_json.is_none());
    }

    // ───────────────────────────────────────────────────────────────
    // write_secret_file + stash_plan_for_bridge
    // ───────────────────────────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn write_secret_file_creates_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.json");
        write_secret_file(&path, b"{\"hello\":\"world\"}").expect("write");
        let meta = std::fs::metadata(&path).expect("stat");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be mode 0600 (got {mode:o})");
        let body = std::fs::read(&path).expect("read");
        assert_eq!(body, b"{\"hello\":\"world\"}");
    }

    #[test]
    #[cfg(unix)]
    fn write_secret_file_atomic_via_rename() {
        // Two consecutive writes; the second must fully replace the
        // first and leave no `*.json.tmp` artifact behind. This proves
        // the tmp-and-rename happy path doesn't leak partial files.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.json");
        write_secret_file(&path, b"first body").expect("first write");
        write_secret_file(&path, b"second body wins").expect("second write");
        assert_eq!(std::fs::read(&path).unwrap(), b"second body wins");
        // The tmp file path is `plan.json.tmp`; it must not exist after
        // a clean write.
        assert!(
            !dir.path().join("plan.json.tmp").exists(),
            "tmp file should be renamed away"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_secret_file_creates_parent_dir() {
        // The bridge writes under `~/.mvm/vms/<vm>/`; that dir may not
        // exist on a first boot. The helper must create it (matching
        // the `stash_plan_for_bridge` callsite's invariant).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vms").join("foo").join("plan.json");
        write_secret_file(&path, b"body").expect("write with missing parent");
        assert!(path.exists());
    }

    #[test]
    fn stash_plan_for_bridge_skips_when_plan_json_none() {
        use mvm_core::vm_backend::VmStartConfig;
        // Legacy / no-admission path: cfg.plan_json is None.
        // `stash_plan_for_bridge` must succeed without touching disk
        // because there's nothing to stash.
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let cfg = VmStartConfig {
            name: "skip-me".into(),
            ..Default::default()
        };
        stash_plan_for_bridge(&cfg).expect("None plan_json is a no-op");
        assert!(
            !dir.path().join("vms/skip-me/plan.json").exists(),
            "no files when plan_json is None"
        );
    }

    #[test]
    #[cfg(unix)]
    fn stash_plan_for_bridge_writes_both_files_when_present() {
        use mvm_core::vm_backend::VmStartConfig;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let cfg = VmStartConfig {
            name: "with-plan".into(),
            plan_json: Some("{\"plan\":\"body\"}".into()),
            bundle_json: Some("{\"bundle\":\"pin\"}".into()),
            ..Default::default()
        };
        stash_plan_for_bridge(&cfg).expect("stash succeeds");

        let plan_path = dir.path().join("vms/with-plan/plan.json");
        let bundle_path = dir.path().join("vms/with-plan/bundle.json");
        assert!(plan_path.exists(), "plan.json must be written");
        assert!(bundle_path.exists(), "bundle.json must be written");
        assert_eq!(
            std::fs::metadata(&plan_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "plan.json must be mode 0600"
        );
        assert_eq!(
            std::fs::metadata(&bundle_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "bundle.json must be mode 0600"
        );
    }

    #[test]
    fn caller_audit_labels_flow_through_admission() {
        let dir = tempfile::tempdir().unwrap();
        let mut input = fixture_input("vm-label");
        input.audit_labels.insert(
            "origin.descriptor".to_string(),
            "blake3:testvalue".to_string(),
        );
        let admitted = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
        )
        .expect("happy path");
        assert_eq!(
            admitted.plan().audit_labels["origin.descriptor"],
            "blake3:testvalue"
        );
        // Profile-derived keys must still be present and authoritative.
        assert!(!admitted.plan().audit_labels["intent"].is_empty());
        assert!(!admitted.plan().audit_labels["admission_profile"].is_empty());
        assert_eq!(admitted.plan().audit_labels["seccomp_tier"], "standard");
    }

    // ───────────────────────────────────────────────────────────────
    // verb-grant sidecar: stash_plan_for_bridge mint path
    // ───────────────────────────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn stash_plan_for_bridge_writes_verb_grant_when_agent_verbs_present() {
        use ed25519_dalek::VerifyingKey;
        use mvm_core::plan::VerbId;
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
        use mvm_core::vm_backend::VmStartConfig;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys_dir = mvm_core::config::mvm_keys_dir();

        // Build an admitted plan that carries agent_verbs.
        let mut input = fixture_input("vm-verb-grant");
        input.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
        let admitted = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys_dir.as_path()),
            None,
        )
        .expect("admit with agent_verbs");

        let mut cfg = VmStartConfig {
            name: "vm-verb-grant".into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
        let issued = stash_plan_and_mint_verb_grant(&cfg)
            .expect("stash succeeds")
            .expect("agent verbs mint a grant");

        let grant_path = dir.path().join("vms/vm-verb-grant/verb-grant.json");
        assert!(grant_path.exists(), "verb-grant.json must be written");
        let mode = std::fs::metadata(&grant_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "verb-grant.json must be mode 0600");

        // Parse the envelope and verify the grant under the signer key.
        let raw = std::fs::read(&grant_path).unwrap();
        let envelope: VerbGrantEnvelope = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            serde_json::to_vec(&issued).unwrap(),
            serde_json::to_vec(&envelope).unwrap(),
            "the returned envelope is exactly the sidecar payload"
        );
        assert!(!envelope.pubkey_hex.is_empty(), "pubkey_hex must be set");
        assert_eq!(
            envelope.plan_nonce_hex,
            admitted.plan().nonce.as_hex(),
            "nonce hex must match plan"
        );
        let pub_arr: [u8; 32] = hex::decode(&envelope.pubkey_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = VerifyingKey::from_bytes(&pub_arr).unwrap();
        envelope
            .grant
            .verify(
                &vk,
                "vm-verb-grant",
                &admitted.plan().nonce,
                SystemClock.now(),
            )
            .expect("grant must verify under the signer key");
    }

    #[test]
    fn stash_plan_for_bridge_no_verb_grant_when_agent_verbs_absent() {
        use mvm_core::vm_backend::VmStartConfig;

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys_dir = mvm_core::config::mvm_keys_dir();

        // Plain plan with no agent_verbs — the fixture default.
        let admitted = admit_for_run(
            &fixture_input("vm-no-verbs"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys_dir.as_path()),
            None,
        )
        .expect("admit without agent_verbs");

        let mut cfg = VmStartConfig {
            name: "vm-no-verbs".into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
        stash_plan_for_bridge(&cfg).expect("stash succeeds");

        assert!(
            !dir.path().join("vms/vm-no-verbs/verb-grant.json").exists(),
            "verb-grant.json must NOT be written when agent_verbs is None"
        );
    }

    #[test]
    #[cfg(unix)]
    fn stash_plan_for_bridge_removes_stale_verb_grant_on_grant_less_restash() {
        use mvm_core::plan::VerbId;
        use mvm_core::vm_backend::VmStartConfig;

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys_dir = mvm_core::config::mvm_keys_dir();

        let vm_name = "vm-stale-grant";

        // First boot: plan with agent_verbs — sidecar must be written.
        let mut input_with = fixture_input(vm_name);
        input_with.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
        let admitted_with = admit_for_run(
            &input_with,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys_dir.as_path()),
            None,
        )
        .expect("admit with agent_verbs");
        let mut cfg_with = VmStartConfig {
            name: vm_name.into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg_with, &admitted_with, None).expect("populate");
        stash_plan_for_bridge(&cfg_with).expect("first stash succeeds");

        let grant_path = dir.path().join(format!("vms/{vm_name}/verb-grant.json"));
        assert!(
            grant_path.exists(),
            "verb-grant.json must be present after first stash"
        );

        // Second boot: same VM name, no agent_verbs — stale sidecar must be removed.
        let admitted_without = admit_for_run(
            &fixture_input(vm_name),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys_dir.as_path()),
            None,
        )
        .expect("admit without agent_verbs");
        let mut cfg_without = VmStartConfig {
            name: vm_name.into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg_without, &admitted_without, None).expect("populate");
        stash_plan_for_bridge(&cfg_without).expect("second stash succeeds");

        assert!(
            !grant_path.exists(),
            "stale verb-grant.json must be removed on a grant-less re-stash of the same VM name"
        );
    }

    // ───────────────────────────────────────────────────────────────
    // admit_and_start: the shared admitted-boot entrypoint
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn admit_and_start_admits_then_boots_on_mock() {
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-boot".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };
        let started = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-boot"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                policy_bundle: None,
                emitter: None,
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            },
        )
        .expect("admit + boot");

        // Admission ran (claim 8): a signed plan id under the host signer.
        assert!(!started.admitted.plan_id().0.is_empty());
        assert!(started.admitted.signer_id().starts_with("host:"));
        // The backend actually started the VM and reports it running.
        assert_eq!(started.vm_id.0, "vm-boot");
        assert!(matches!(
            backend.status(&started.vm_id).unwrap(),
            mvm_core::vm_backend::VmStatus::Running
        ));
    }

    /// The point of `AuditDurability::Required`: a run that cannot record its
    /// admission does not reach the backend at all.
    ///
    /// Asserting the error is not enough — what matters is that no VM booted,
    /// because the failure mode being closed is a workload that ran while
    /// leaving no evidence it was ever admitted.
    #[test]
    fn a_required_admission_record_that_cannot_be_written_stops_the_boot() {
        use crate::audit::durability::AuditDurability;

        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-unauditable".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };

        // A chain whose tenant file cannot be written: a directory sits where
        // the JSONL belongs.
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir(audit_dir.join("local.jsonl")).unwrap();
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let emitter = crate::audit::emitter::AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&seed),
            &audit_dir,
        )
        .expect("the emitter opens; writing the tenant file is what fails");

        let err = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-unauditable"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                policy_bundle: None,
                emitter: Some(&emitter),
                audit_durability: AuditDurability::Required,
            },
        )
        .expect_err("an unauditable sealed run must not boot");
        assert!(
            format!("{err:#}").contains("cannot be proven"),
            "the refusal must explain itself: {err:#}"
        );

        assert!(
            backend.list().expect("mock list").is_empty(),
            "no VM may exist for a run whose admission could not be recorded"
        );
    }

    /// The same broken chain under the dev tier boots and warns.
    #[test]
    fn a_best_effort_admission_record_does_not_stop_the_boot() {
        use crate::audit::durability::AuditDurability;

        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-dev-unauditable".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        };

        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::create_dir(audit_dir.join("local.jsonl")).unwrap();
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let emitter = crate::audit::emitter::AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&seed),
            &audit_dir,
        )
        .expect("emitter");

        let started = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-dev-unauditable"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                policy_bundle: None,
                emitter: Some(&emitter),
                audit_durability: AuditDurability::BestEffort,
            },
        )
        .expect("a dev run is not blocked by a broken audit chain");
        assert_eq!(started.vm_id.0, "vm-dev-unauditable");
    }

    #[test]
    fn admit_and_start_refuses_unadmitted_volume_before_boot() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let dir = tempfile::tempdir().unwrap();
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        // The synthesized plan admits no shares, but the launch config carries a
        // volume — claim 1 must refuse before the backend ever starts.
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-badvol".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            volumes: vec![VmVolume {
                host: "/etc".into(),
                guest: "/data".into(),
                read_only: true,
                kind: VmVolumeKind::DirShare,
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = admit_and_start(
            &backend,
            AdmitAndStartParams {
                synthesis: &fixture_input("vm-badvol"),
                config,
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: Some(dir.path()),
                bundle_ctx: None,
                policy_bundle: None,
                emitter: None,
                audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            },
        )
        .expect_err("unadmitted volume must refuse");
        assert!(
            err.chain()
                .any(|e| e.to_string().contains("not named in the signed")),
            "expected admitted-shares refusal; got: {err:#}"
        );
        // Crucially: no VM was started (the gate fired before backend.start).
        assert!(matches!(
            backend.status(&VmId("vm-badvol".into())),
            Ok(mvm_core::vm_backend::VmStatus::Stopped)
        ));
    }

    /// Three points around the cap. The `>` → `==` mutant admits
    /// everything above the cap, which is the whole vector the cap closes;
    /// `>` → `>=` refuses a payload exactly at it. Only a boundary test
    /// separates the two, and only an extracted comparison makes a
    /// boundary test cheap.
    #[test]
    fn the_size_cap_admits_up_to_the_cap_and_refuses_above_it() {
        assert!(enforce_size_cap("plan_json", 0, 16).is_ok());
        assert!(enforce_size_cap("plan_json", 15, 16).is_ok());
        assert!(
            enforce_size_cap("plan_json", 16, 16).is_ok(),
            "a payload exactly at the cap is within it"
        );
        assert!(
            enforce_size_cap("plan_json", 17, 16).is_err(),
            "a payload over the cap must be refused"
        );
        assert!(
            enforce_size_cap("plan_json", usize::MAX, 16).is_err(),
            "a cap that only refuses one exact size is not a cap"
        );
    }

    /// The stale-sidecar removal exists so a reused VM name cannot inherit
    /// the previous boot's grant. Swallowing a real removal failure leaves
    /// that grant in place while reporting success — the one outcome the
    /// removal is there to prevent.
    #[test]
    fn a_failed_stale_grant_removal_is_not_reported_as_success() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_dir = tmp.path().join("vm-state");
        std::fs::create_dir_all(&state_dir).unwrap();

        // A non-empty directory where the sidecar file belongs: remove_file
        // refuses it, and the refusal is not NotFound.
        let sidecar = state_dir.join("verb-grant.json");
        std::fs::create_dir_all(&sidecar).unwrap();
        std::fs::write(sidecar.join("occupant"), b"stale").unwrap();

        assert!(
            mint_verb_grant_sidecar("{}", "vm-reused", &state_dir).is_err(),
            "a stale grant that could not be removed must not read as removed"
        );

        // Absent is still the quiet, successful case.
        let clean = tmp.path().join("clean-state");
        std::fs::create_dir_all(&clean).unwrap();
        assert!(mint_verb_grant_sidecar("{}", "vm-fresh", &clean).is_ok());
    }
}
