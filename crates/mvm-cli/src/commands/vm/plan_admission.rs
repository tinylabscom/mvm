//! Plan-admission pipeline used by `mvmctl up`.
//!
//! Threads `synthesize_plan` + `host_signer` into the
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
    sign_plan, verify_plan, verify_plan_bundle,
};
use mvm_core::policy::PolicyBundle;
use std::sync::Mutex;

use super::host_signer::host_signer_id;
use super::plan_builder::{SynthesisInput, synthesize_plan};

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
/// chain (the plan again, for `AuditEntry::for_plan`), and — for
/// downstream consumers that want the canonical envelope — the
/// `SignedExecutionPlan` itself.
///
/// `signed` carries a `#[allow(dead_code)]` because the only current
/// consumer is in-module tests proving the envelope round-trips
/// through `verify_plan`. Cross-process consumers (a future
/// `mvm-hostd` lift, or `mvmctl plan show` once it lands) will read
/// the envelope verbatim. Keeping the field on the struct stabilises
/// the surface for those callers.
#[derive(Debug)]
pub struct AdmittedPlan {
    pub plan: ExecutionPlan,
    pub plan_id: PlanId,
    pub signer_id: String,
    #[allow(dead_code)]
    pub signed: SignedExecutionPlan,
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
        Some(dir) => super::host_signer::load_or_init_at(dir)?,
        None => super::host_signer::load_or_init()?,
    };
    let signer_id = host_signer_id();

    // Sign + verify roundtrip. Verifying our own signature catches
    // wire-format bugs that would otherwise surface at a real
    // verifier (mvmd's supervisor, an upstream consumer's mvm).
    let signed = sign_plan(&plan, &signer.signing, &signer_id);
    let trusted: [(&str, &VerifyingKey); 1] = [(&signer_id, &signer.verifying)];
    let verified = verify_plan(&signed, &trusted).context("verifying just-signed plan")?;

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

/// Populate the three `VmStartConfig` audit-substrate fields
/// (`tenant_id`, `plan_json`, `bundle_json`) from the admitted
/// plan. Call after the `VmStartConfig` is built and before
/// `backend.start()`; the libkrun/Vz backends read these to wire
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
/// the signed `plan_json`, whose presence flips libkrun/Vz workload boots onto
/// the claim-10 gateway-bridge supervisor path. Call this unconditionally; call
/// `populate_audit_substrate` when a backend has a signed-plan consumer.
pub fn thread_tenant_id(cfg: &mut mvm_core::vm_backend::VmStartConfig, admitted: &AdmittedPlan) {
    cfg.tenant_id = Some(admitted.plan.tenant.0.clone());
}

pub fn populate_audit_substrate(
    cfg: &mut mvm_core::vm_backend::VmStartConfig,
    admitted: &AdmittedPlan,
    policy_bundle: Option<&PolicyBundle>,
) -> Result<()> {
    thread_tenant_id(cfg, admitted);

    let plan_json = serde_json::to_string(&admitted.signed)
        .context("serializing SignedExecutionPlan for VmStartConfig.plan_json")?;
    if plan_json.len() > PLAN_JSON_MAX_BYTES {
        anyhow::bail!(
            "plan_json exceeds {} byte cap (got {}); refusing",
            PLAN_JSON_MAX_BYTES,
            plan_json.len()
        );
    }
    cfg.plan_json = Some(plan_json);

    // `bundle_json` carries the resolved tenant **PolicyBundle** (network /
    // egress / tool policy) that the supervisor's L4 gate + observers consume.
    // It is NOT the ExecutionPlan's `.mvmpkg` artifact pin
    // (`admitted.plan.bundle`, a `PlanArtifact` — content-addressed
    // kernel/rootfs, verified separately at admit time via `verify_plan_bundle`).
    // Feeding the pin here was a conflation the supervisor's PolicyBundle decode
    // would reject. `None` until a policy-bundle source is wired.
    cfg.bundle_json = match policy_bundle {
        Some(bundle) => {
            let bj = serde_json::to_string(bundle)
                .context("serializing PolicyBundle for VmStartConfig.bundle_json")?;
            if bj.len() > BUNDLE_JSON_MAX_BYTES {
                anyhow::bail!(
                    "bundle_json exceeds {} byte cap (got {}); refusing",
                    BUNDLE_JSON_MAX_BYTES,
                    bj.len()
                );
            }
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
/// in `up.rs` ensure `mvm_data_dir/vms/<name>/` exists with the same
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
pub(crate) fn stash_plan_for_bridge(cfg: &mvm_core::vm_backend::VmStartConfig) -> Result<()> {
    let Some(plan_json) = cfg.plan_json.as_deref() else {
        return Ok(());
    };
    let state_dir = std::path::PathBuf::from(mvm_core::config::mvm_data_dir())
        .join("vms")
        .join(&cfg.name);
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("create per-VM state dir {}", state_dir.display()))?;
    write_secret_file(&state_dir.join("plan.json"), plan_json.as_bytes())?;
    if let Some(bundle_json) = cfg.bundle_json.as_deref() {
        write_secret_file(&state_dir.join("bundle.json"), bundle_json.as_bytes())?;
    }
    mint_verb_grant_sidecar(plan_json, &cfg.name, &state_dir)?;
    Ok(())
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
) -> Result<()> {
    use mvm_core::plan::SignedExecutionPlan;
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;

    // Best-effort parse: a missing or malformed plan_json skips the
    // sidecar (grant-less boot), matching the fail-open posture of the
    // other cmdline token producers.
    let Ok(signed) = serde_json::from_str::<SignedExecutionPlan>(plan_json) else {
        return Ok(());
    };
    let Ok(plan) = serde_json::from_slice::<ExecutionPlan>(&signed.0.payload) else {
        return Ok(());
    };

    let Some(verbs) = plan.agent_verbs else {
        // No verb grant requested — grant-less boot.
        return Ok(());
    };

    let keys_dir = mvm_core::config::mvm_keys_dir();
    let signer = super::host_signer::load_or_init_at(&keys_dir)
        .context("load host signer for verb-grant mint")?;
    let keystore = mvm_hostd::host_signer::keystore::Keystore::load_from_file(&signer.secret_path)
        .context("load Keystore from host-signer key file")?;

    let grant = mvm_hostd::host_signer::mint_verb_grant(
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
        grant,
    };
    let envelope_json = serde_json::to_vec(&envelope).context("serialize VerbGrantEnvelope")?;
    write_secret_file(&state_dir.join("verb-grant.json"), &envelope_json)?;
    Ok(())
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
pub(crate) fn enforce_admitted_shares(
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use mvm_core::plan::{AuthPolicy, PlanSeccompTier, SecretReleasePolicy};

    const FIXTURE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn fixture_input(vm_name: &str) -> SynthesisInput<'_> {
        SynthesisInput {
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
            auth: AuthPolicy::none(),
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
            audit_labels: Default::default(),
            agent_verbs: None,
        }
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
        assert!(!admitted.plan_id.0.is_empty());
        assert!(admitted.signer_id.starts_with("host:"));
        // The signed envelope must be re-verifiable with the public
        // half of the host signer.
        let signer = super::super::host_signer::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(&admitted.signer_id, &signer.verifying)];
        let recovered = mvm_core::plan::verify_plan(&admitted.signed, &trusted).unwrap();
        assert_eq!(recovered.plan_id, admitted.plan_id);
    }

    #[test]
    fn rejects_replay_within_validity_window() {
        let dir = tempfile::tempdir().unwrap();
        // We can't naturally replay because synthesize_plan generates a
        // fresh nonce each call — instead, build the plan once, sign,
        // then ask the ledger to admit twice. The second call must
        // refuse with nonce-replay.
        let plan = synthesize_plan(&fixture_input("vm1")).unwrap();
        let signer = super::super::host_signer::load_or_init_at(dir.path()).unwrap();
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
        let signer = super::super::host_signer::load_or_init_at(dir.path()).unwrap();
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
        let signer = super::super::host_signer::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(&admitted.signer_id, &signer.verifying)];
        assert!(verify_plan(&admitted.signed, &trusted).is_ok());
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
        bundle_sha256, write_bundle,
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
        let key_id = BundleKeyId::from_pubkey(&sk.verifying_key());
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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let (archive, pin) = make_test_bundle(&sk, b"kernel-bytes", b"rootfs-bytes");
        let mut map = HashMap::new();
        let key_id = BundleKeyId::from_pubkey(&sk.verifying_key());
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
        assert!(admitted.plan.bundle.is_some());
    }

    #[test]
    fn admit_with_pin_but_no_context_refuses() {
        // Publisher misconfiguration: plan carries a pin but the
        // mvmctl up path didn't wire a BundleAdmissionContext. The
        // admit path refuses rather than silently skipping the
        // re-verify step (fail closed, not fail open).
        let dir = tempfile::tempdir().unwrap();
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let (_archive_a, pin_a) = make_test_bundle(&sk, b"kA", b"rA");
        let (archive_b, _pin_b) = make_test_bundle(&sk, b"kB", b"rB");
        let mut map = HashMap::new();
        map.insert(
            BundleKeyId::from_pubkey(&sk.verifying_key()),
            sk.verifying_key(),
        );
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
            Some(admitted.plan.tenant.0.as_str())
        );
        // It must NOT thread the signed plan / policy bundle — that flips
        // libkrun/Vz onto the gateway-bridge supervisor (+ its ~/.mvm/keys
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
            Some(admitted.plan.tenant.0.as_str())
        );
        let plan_json = cfg.plan_json.expect("plan_json populated");
        let roundtrip: mvm_core::plan::SignedExecutionPlan =
            serde_json::from_str(&plan_json).expect("roundtrip");
        // Re-verify the envelope to get the inner ExecutionPlan and
        // confirm the plan_id matches what the producer admitted.
        let signer = super::super::host_signer::load_or_init_at(dir.path()).unwrap();
        let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
            [(&admitted.signer_id, &signer.verifying)];
        let recovered =
            mvm_core::plan::verify_plan(&roundtrip, &trusted).expect("envelope re-verifies");
        assert_eq!(recovered.plan_id, admitted.plan_id);
        // fixture has no bundle pin, so bundle_json stays None
        assert!(cfg.bundle_json.is_none());
    }

    #[test]
    fn bundle_json_carries_a_policy_bundle_not_the_artifact_pin() {
        // De-conflation: bundle_json is the tenant PolicyBundle the
        // supervisor's L4 gate + observers consume — sourced from the
        // policy_bundle arg, NOT from `admitted.plan.bundle` (the .mvmpkg
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
        env.set("MVM_DATA_DIR", dir.path());

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
        env.set("MVM_DATA_DIR", dir.path());

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
            admitted.plan.audit_labels["origin.descriptor"],
            "blake3:testvalue"
        );
        // Profile-derived keys must still be present and authoritative.
        assert!(!admitted.plan.audit_labels["intent"].is_empty());
        assert!(!admitted.plan.audit_labels["admission_profile"].is_empty());
        assert_eq!(admitted.plan.audit_labels["seccomp_tier"], "standard");
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
        env.set("MVM_DATA_DIR", dir.path());

        // Build an admitted plan that carries agent_verbs.
        let mut input = fixture_input("vm-verb-grant");
        input.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
        let admitted = admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
        )
        .expect("admit with agent_verbs");

        let mut cfg = VmStartConfig {
            name: "vm-verb-grant".into(),
            ..Default::default()
        };
        populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
        stash_plan_for_bridge(&cfg).expect("stash succeeds");

        let grant_path = dir.path().join("vms/vm-verb-grant/verb-grant.json");
        assert!(grant_path.exists(), "verb-grant.json must be written");
        let mode = std::fs::metadata(&grant_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "verb-grant.json must be mode 0600");

        // Parse the envelope and verify the grant under the signer key.
        let raw = std::fs::read(&grant_path).unwrap();
        let envelope: VerbGrantEnvelope = serde_json::from_slice(&raw).unwrap();
        assert!(!envelope.pubkey_hex.is_empty(), "pubkey_hex must be set");
        assert_eq!(
            envelope.plan_nonce_hex,
            admitted.plan.nonce.as_hex(),
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
                &admitted.plan.nonce,
                SystemClock.now(),
            )
            .expect("grant must verify under the signer key");
    }

    #[test]
    fn stash_plan_for_bridge_no_verb_grant_when_agent_verbs_absent() {
        use mvm_core::vm_backend::VmStartConfig;

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_DATA_DIR", dir.path());

        // Plain plan with no agent_verbs — the fixture default.
        let admitted = admit_for_run(
            &fixture_input("vm-no-verbs"),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
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
}
