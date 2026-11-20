//! Threading an admitted plan onto the launch config and the per-VM state
//! directory the supervisor and bridge read.

use super::AdmittedPlan;
use super::verb_grant_sidecar::mint_verb_grant_sidecar;
use anyhow::{Context, Result};
use mvm_core::policy::PolicyBundle;

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
pub(super) fn enforce_size_cap(what: &str, len: usize, cap: usize) -> Result<()> {
    if len > cap {
        anyhow::bail!("{what} exceeds {cap} byte cap (got {len}); refusing");
    }
    Ok(())
}

/// Populate the `VmStartConfig` audit substrate (`tenant_id`, `plan_json`,
/// `bundle_json`, and `audit_context`) from the admitted plan.
/// Call after the `VmStartConfig` is built and before
/// `backend.start()`; the libkrun/HVF backends read these to wire
/// `SupervisorConfig.{tenant_id, audit_dir, gateway_audit_socket,
/// gateway_events_socket, signing_key_path}` and activate the
/// bridge-factory path.
///
/// The signed plan and policy bundle remain JSON envelopes; the endpoint's
/// typed audit context carries the admitted plan identity. The
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

/// Carry the admitted CPU bound and core placement onto the launch config, so
/// the backend can be born inside them rather than adjusted into them
/// afterwards.
///
/// Taken from the **admission** and nowhere else. A caller-supplied
/// `cfg.cpu_grant` or `cfg.allowed_cpus` would be a bound chosen outside the
/// admission that just checked it against the host, so whatever was there is
/// overwritten — including with `None`, which is what an uncapped or unplaced
/// launch means.
pub fn thread_cpu_grant(cfg: &mut mvm_core::vm_backend::VmStartConfig, admitted: &AdmittedPlan) {
    cfg.cpu_grant = admitted.plan().grants.as_ref().and_then(|g| g.cpu);
    cfg.allowed_cpus = admitted.allowed_cpus().cloned();
}

pub fn populate_audit_substrate(
    cfg: &mut mvm_core::vm_backend::VmStartConfig,
    admitted: &AdmittedPlan,
    policy_bundle: Option<&PolicyBundle>,
) -> Result<()> {
    thread_tenant_id(cfg, admitted);
    thread_cpu_grant(cfg, admitted);
    admitted.bind_canonical_kernel(cfg)?;

    let plan_json = serde_json::to_string(admitted.signed())
        .context("serializing SignedExecutionPlan for VmStartConfig.plan_json")?;
    enforce_size_cap("plan_json", plan_json.len(), PLAN_JSON_MAX_BYTES)?;
    cfg.plan_json = Some(plan_json);
    cfg.audit_context = Some(admitted.workload_audit_context());

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
///
/// Nothing is synced. Every file written here is a per-run copy of material
/// the admission record already holds durably, read by this run from the
/// page cache; a host crash that could lose it also ends the guest that would
/// read it, and a torn signed envelope fails verification rather than being
/// trusted. On a rotational disk the sync was most of a warm claim's time
/// between verifying its parent and forking its child.
///
/// The temporary has a fresh random name created exclusively, so nothing
/// planted beside `path` is written through, and the rename replaces whatever
/// sits at `path` itself, a link included, without following it.
#[cfg(unix)]
pub(crate) fn write_secret_file(path: &std::path::Path, body: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("write_secret_file: path has no parent: {}", path.display())
    })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create parent dir {}", parent.display()))?;
    mvm_core::atomic_io::write_private_ephemeral(path, body)
        .with_context(|| format!("write {}", path.display()))
}

/// Whether this backend consumes the persisted plan during endpoint setup.
///
/// QEMU reads the in-memory config instead; writing a bridge plan for it
/// would overwrite state it does not consume.
pub fn persists_plan_before_start(backend: &str) -> bool {
    matches!(
        backend,
        "firecracker" | "libkrun" | "hvf" | "apple-container"
    )
}

/// Stash the signed plan envelope + (optional) bundle pin in the
/// per-VM state dir so the Firecracker bridge sidecar can read them
/// at spawn time.
///
/// Runs at the admitted dispatch boundary (or at the legacy CLI producer
/// boundary for unmigrated launches), after audit-substrate population and
/// before the bridge spawn reads the signed envelope back from disk. No-op
/// without `cfg.plan_json`; files land at mode 0600 via [`write_secret_file`].
///
/// Preserve the admitted envelope bytes rather than reconstructing a plan from
/// persisted state. Bridge and mailbox helpers read this same per-run copy.
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
    // A new plan under this name is a new run, and a human credential entered
    // during the previous one is not in this guest.
    mvm_runtime::vm::human_credential::clear_for_new_run(&state_dir)?;
    if let Some(bundle_json) = cfg.bundle_json.as_deref() {
        write_secret_file(&state_dir.join("bundle.json"), bundle_json.as_bytes())?;
    }
    mint_verb_grant_sidecar(plan_json, &cfg.name, &state_dir)
}
