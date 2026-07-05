# ADR-108: Verb-grant measured trust policy and the key-separation ceiling

- Status: Proposed
- Date: 2026-07-04
- Owner: MVM Project
- Related: ADR-002 (microVM security posture — trusted-host and hardware-attestation out-of-scope; claim 3 verified boot, claim 4 `do_exec`, claim 15 sealed interactivity), ADR-103 (plan-bound agent verb capabilities — the `VerbGrant` this ADR anchors), ADR-041 (signed audited execution plans — claim 8), ADR-090 (resident daemon trust gradient)
- Sequenced by: [Plan 215](../plans/215-plan-bound-agent-verb-capabilities.md) follow-on

## Context

ADR-103 delivered plan-bound agent-verb capabilities: a per-workload `VerbGrant`,
minted host-side, delivered to the guest on the kernel cmdline
(`mvm.verb_grant=<hex(VerbGrantEnvelope)>`), decoded by `/init` into
`/run/mvm/verb-grant.json`, pinned by the agent at boot
(`load_pinned_verb_grant`, `crates/mvm-guest/src/vsock.rs`), and enforced
subtractively after the class gate.

The `VerbGrantEnvelope` carries the grant **and** the verifying key
(`pubkey_hex`) in one blob. So the guest verifies the grant against a key
delivered by the same launcher, over the same channel, as the grant itself. The
in-tree comment states the limitation plainly: *"the verifying key rides in the
same launcher-provisioned envelope as the grant … NOT proof of an independent
issuer … A build-time-provisioned anchor is tracked."* That tracked item
(issue #1381 item 3) asked for "real cryptographic key separation via a
build-time trust anchor."

This ADR records the outcome of designing that anchor: **within ADR-002's scope,
real cryptographic key separation for the verb grant is not achievable**, and
states precisely why, what *is* achievable and valuable instead (a measured
trust *policy*), and the exact future path that would make key separation real.

## The ceiling: why in-scope key separation is not achievable

ADR-002 fixes two scope boundaries that jointly foreclose key separation here:

1. **The host is trusted.** mvmctl trusts the host with the hypervisor and the
   private build/signing keys. A "malicious host" is explicitly out of scope.
2. **No hardware-backed key attestation.** Explicitly out of scope.

Given these, consider every anchor the guest could verify the grant against:

- **Kernel cmdline** (today): launcher-provisioned, unmeasured by anything.
- **The `mvm-config` drive** (per-launch, `crates/mvm-backend/src/microvm.rs`):
  assembled by the host each boot, **no dm-verity sidecar, no roothash** —
  plaintext and unmeasured. Moving the key here is the same launcher-controlled,
  unmeasured channel as the cmdline: no gain.
- **A dm-verity-sealed rootfs file** (claim 3): genuinely measured and
  tamper-evident — **but the roothash is computed at *image-build* time** in the
  Nix derivation (`nix/images/runtime-overlay/flake.nix`), and at launch
  `probe_verity_sidecar` only *reads* the pre-baked roothash onto the cmdline.
  There is no per-launch re-seal. The **host-signer key is per-host and
  runtime-generated** (`~/.mvm/keys/host-signer.ed25519`, created on first
  `mvmctl` run — `host_keypair::load_or_init_at`), so it **cannot** be baked into
  a build-time-generic verity image: the key does not exist when the image is
  built.
- **A build-time key baked into the verity rootfs** could be measured, but a
  per-host runtime key cannot be *certified* by it: the release/build
  infrastructure never sees the host key, so no certificate chain from the
  build-time anchor to the host-signer key can exist.

Every anchor is therefore either (a) provisioned by the same trusted launcher
that provisions the grant (cmdline, config drive — no independence), or (b)
measured but build-time-generic and unable to carry the per-host key (verity
rootfs). Nothing measures the cmdline itself. The one construction that would
give a genuinely independent anchor — a launch-time key measured/attested by a
root the launcher cannot forge — requires hardware attestation (a vTPM / measured
boot quoting the launch key), which ADR-002 places out of scope.

Note also that the in-scope guest adversary — a **compromised guest workload**
attempting to escalate its own agent verbs — is already fully addressed by
*pinning timing*: the agent pins the grant at boot **before** any untrusted
workload runs, and the pinned value is immutable thereafter. Key separation adds
no defense against that adversary. The only residual value of an independent
anchor is defense-in-depth against a **trusted-but-buggy launch path**.

**Conclusion.** "Real cryptographic key separation for the verb grant" is a
non-goal under ADR-002. The delivered ADR-103 mechanism is, and remains,
**trusted-channel provisioning**: integrity over a launcher-provisioned blob,
rooted in kernel-cmdline provenance. It must **not** be promoted to the ADR-002
numbered claim ledger. This is the honest ceiling.

## Decision

Ship the achievable, non-theater improvement: make the guest's grant-trust
*policy* — not the key — **measured**, and make grant enforcement survive
restore. Concretely:

### 1. A measured `VerbTrustPolicy` baked into the sealed rootfs

A policy is **generic** (identical for every launch of an image), so unlike the
per-host key it *can* be baked at Nix-build time into the dm-verity-covered
rootfs. Define `mvm_core::plan::VerbTrustPolicy`:

```
VerbTrustPolicy {
    version: u32,                 // 1
    require_grant: bool,          // guest fails closed if a grant is required but absent
    grant_key_source: GrantKeySource,  // LaunchProvisioned (today) | Attested (future seam)
}
```

`mkGuest` bakes `/etc/mvm/verb-trust.json` into the rootfs. For **sealed prod
images** (`withDevShell = false`): `{ version: 1, require_grant: <staged, see
Rollout>, grant_key_source: "launch_provisioned" }`. For **dev / OCI images**:
the file is absent (⇒ no requirement — the permissive default is preserved).

### 2. Policy-driven guest enforcement (fail-closed code, staged bit)

At boot the agent reads the verity-measured `/etc/mvm/verb-trust.json` and acts
on it with a single code path:

- **No policy file** (dev / OCI) ⇒ no requirement; serve (permissive default).
- **Policy present, valid grant pinned** ⇒ serve.
- **Policy present, grant absent / malformed / verification-failed** ⇒ emit an
  **audited observability signal** ("verb-trust policy present but no valid grant
  pinned") *regardless* of `require_grant`, then:
  - `require_grant: true` ⇒ **fail closed** — refuse to serve control RPCs.
  - `require_grant: false` ⇒ serve (observe mode; the audited signal is the only
    effect).

The fail-closed behavior is thus fully implemented in the guest from day one;
whether it *bites* is driven entirely by the measured `require_grant` bit. This
is the one genuinely valuable property: a sealed image's assertion *"I must run
under a grant"* is **dm-verity-measured** (claim 3), so a launch-path bug — or
tampering — that omits or corrupts the grant can no longer silently downgrade a
sealed workload to permissive class-gate-only operation. The *key* is still
launch-provisioned and honestly labeled `launch_provisioned`; only the *policy*
is measured.

An unexpected `grant_key_source: "attested"` (the future arm, not implemented
here) is treated as fail-closed, never a silent downgrade.

### Rollout (staged, to bound cross-repo risk)

`mkGuest` is shared: the sealed images it builds are also run by **mvmd** (the
separate fleet orchestrator), whose admission/launch/restore paths are not
verified by this work. Baking `require_grant: true` unconditionally could brick
an mvmd sealed workload whose launcher does not deliver a grant. Enforcement is
therefore rolled out in two stages, each a distinct PR:

- **Stage B (this ADR's implementation) — measure-now.** Ship the full mechanism
  with `require_grant: false` baked for sealed images: the policy type, the
  verity-measured file, the guest fail-closed **code path** (dormant at
  `false`), the audited observe signal, restore reconciliation, and the
  `grant_key_source` seam. Live-prove that every *mvmctl* sealed launch + restore
  flavor delivers a valid grant.
- **Stage A (fast-follow) — enforce.** Flip the baked bit to `require_grant:
  true` for sealed prod images. Gate the flip on a concrete criterion: every
  sealed-image launch + restore path in **both** mvmctl (verified in Stage B) and
  mvmd is confirmed to deliver a grant. This is a one-line policy-value change,
  not a mechanism change, tracked as an explicit follow-up so observe mode does
  not become permanent.

### 3. Restore reconciliation (grant survives every restore flavor)

`require_grant` must hold across snapshot restore, not only fresh boot:

- **Pause/resume + warm-restore** (guest RAM saved/restored): the agent's pinned
  grant survives in memory; `require_grant` is already satisfied. No change.
- **`fs_quick` fork** (rootfs-only; agent restarts): mint a fresh child grant at
  fork admission and deliver it on the child's cmdline — the restarting agent
  re-pins via the existing boot path.
- **`vm_full` fork** (memory cloned; agent survives with the *parent's* grant
  while a *fresh child plan* with a new session/nonce is admitted at
  `checkpoint.rs`): the surviving grant is stale. Mint a fresh child grant and
  deliver it over the **existing** `PostRestore` vsock frame, extended with an
  optional `#[serde(default)] grant_envelope: Option<VerbGrantEnvelope>` (no
  schema-version bump — consistent with the repo's no-ceremony rule and
  `PostRestore`'s existing `serde(default)` fields). The guest re-pins via a new
  `re_pin_verb_grant(envelope)` in the `PostRestore` handler.

This also closes the pre-existing "forked children run class-gate-only"
follow-up (`restrict_agent_verbs: false` at the fork sites): forked children of a
sealed image now carry a valid grant matching their own admitted plan.

### 4. The future attestation seam

`grant_key_source` is the forward hook. When measured boot / a vTPM lands (an
explicit ADR-002 scope expansion, out of scope here), sealed images bake
`grant_key_source: "attested"`, and the guest requires the grant's verifying key
to match an attested launch measurement rather than trusting the cmdline
`pubkey_hex`. No wire/protocol churn is needed to reach that state — only the
policy value and the guest's key-source branch. This ADR deliberately leaves the
`Attested` arm defined-but-unimplemented (the guest treats an unexpected
`Attested` policy as fail-closed, never as a silent downgrade).

## Consequences

**Positive**
- A sealed image's grant requirement is dm-verity-measured: no silent downgrade
  to class-gate-only from a buggy/omitting/tampering launch path.
- `require_grant` holds across all restore flavors; the "forked children run
  class-gate-only" gap is closed with a correct per-child grant.
- The honest limitation is documented in one place, and the future
  attestation upgrade has a defined, churn-free seam (`grant_key_source`).

**Negative / accepted**
- No real key separation is added (and, per the ceiling analysis, none is
  achievable in scope). This ADR does **not** move the verb-grant story onto the
  numbered claim ledger.
- New surface: one optional `PostRestore` field, a guest re-pin path, and
  mint-at-fork. All reuse existing frames/mechanisms.
- Once enforced (Stage A), `require_grant: true` makes a sealed image un-bootable
  if the launch path genuinely cannot deliver a grant — the intended fail-closed,
  but it raises the bar on the launch path's correctness for sealed images. The
  staged rollout (measure-now / enforce-fast-follow) bounds this to paths already
  confirmed to deliver a grant across both mvmctl and mvmd.

**Neutral**
- Dev / OCI images are unaffected (policy file absent ⇒ permissive default),
  consistent with the item-2 change that already mints the default grant only
  for sealed images (PR #1437).

## Alternatives considered

- **Bake the host-signer pubkey into the verity rootfs.** Infeasible: verity is
  build-time-generic; the per-host key does not exist at build time; no
  per-launch re-seal.
- **Per-launch full-rootfs re-seal** (recompute the roothash with the key baked
  in). Real "measured key," but heavyweight (per-launch verity over the whole
  rootfs) and of ~nil marginal value in the trusted-host model (the host controls
  key, roothash, and cmdline alike). Rejected.
- **Move the key onto the `mvm-config` drive.** The config drive is unmeasured;
  this is the same launcher-controlled channel as the cmdline. Security theater.
  Rejected.
- **Pull hardware attestation into scope.** The only construction that yields
  real key separation, but a deliberate ADR-002 scope expansion beyond this
  work; recorded as the future seam instead.

## Out of scope

- A malicious host (ADR-002).
- Hardware-backed key attestation / measured boot (ADR-002) — the future seam,
  not built here.
- Promotion of the verb-grant story to the ADR-002 numbered claim ledger.
