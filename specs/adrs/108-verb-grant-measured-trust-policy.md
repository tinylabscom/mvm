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
  pinned"), then fail closed **iff** enforcement is required. As shipped (see
  Rollout / Stage A), the enforcement trigger is `trust_decision(policy,
  grant_present, launch_requires_grant)`: fail closed when the launch asserts
  `mvm.require_grant=1` **OR** the baked `require_grant: true` **OR**
  `grant_key_source: attested`; otherwise serve (observe mode). Because Stage B/A
  bake `require_grant: false`, the enforcement in practice comes from the
  launch-asserted `mvm.require_grant=1` token (emitted only when the host
  delivered a grant), leaving mvmd / direct-launch instances in observe mode.

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
- **Stage A (shipped) — enforce, launcher-gated (Option A).** Investigating the
  Stage-A precondition established that **mvmd cannot be relied on to deliver a
  grant**: it boots instances through a *direct* Firecracker launch
  (`mvmd-runtime` `instance_start_inner`) that synthesizes no `ExecutionPlan`,
  mints no `VerbGrant`, and **bypasses mvm-backend's cmdline assembly entirely**.
  So flipping the *baked* bit to `require_grant: true` would fail-close every
  mvmd instance. Stage A therefore does **not** flip the baked bit (it stays
  `false`); instead enforcement is **launcher-gated**:
  - The host emits a `mvm.require_grant=1` kernel-cmdline token **only when it
    delivered a grant** (`require_grant_cmdline_token`, keyed on the
    `verb-grant.json` sidecar *existing* — so a corrupt sidecar still asserts
    enforcement and the guest fails closed rather than running grant-less),
    appended at the four mvm-backend cmdline builders
    (`microvm`/`qemu`/`libkrun`/`vz`) — all of which mvmd bypasses.
  - The guest reads it (`launch_requires_grant()` over `/proc/cmdline`) and
    `trust_decision(policy, grant_present, launch_requires_grant)` fails closed
    when enforcement is **launch-asserted OR baked-policy-required OR
    `grant_key_source: attested`**, and no grant is pinned.

  Net: mvmctl grant-delivering launches enforce; mvmd (and any direct-launch
  path) asserts nothing → always serves → **no brick, no mvmd change**. The
  measured `require_grant` field is retained for the observe signal and the
  `attested` seam; the enforcement *trigger* moved to the launch token. Trade-off
  vs. the original "flip the baked bit" plan: `require_grant` enforcement is now
  launcher-asserted rather than rootfs-measured — a slight weakening of the
  measured-policy property, accepted because a delivered grant is still
  pinned+enforced and the launcher emits the flag in the same routine that
  delivers the grant. A stale-sidecar guard unlinks a pre-existing
  `verb-grant.json` on re-stash so a reused persistent name cannot inherit a
  spurious enforcement assertion; an `xtask` gate machine-checks that
  `mvm.require_grant=1` appears only in the four allowlisted builders (guards the
  no-brick invariant).

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
- A grant-delivering launch enforces the grant end-to-end: a launch that mints a
  grant asserts `mvm.require_grant=1`, so a bug/corruption that drops or mangles
  the delivered grant fails closed rather than silently downgrading to
  class-gate-only. (The *policy* is dm-verity-measured; the enforcement *trigger*
  is the launch token — see Rollout / Stage A for why.)
- Enforcement holds across all restore flavors; the "forked children run
  class-gate-only" gap is closed with a correct per-child grant.
- The honest limitation is documented in one place, and the future
  attestation upgrade has a defined, churn-free seam (`grant_key_source`).

**Negative / accepted**
- No real key separation is added (and, per the ceiling analysis, none is
  achievable in scope). This ADR does **not** move the verb-grant story onto the
  numbered claim ledger.
- New surface: one optional `PostRestore` field, a guest re-pin path, and
  mint-at-fork. All reuse existing frames/mechanisms.
- Under Stage A, a grant-delivering launch that asserts `mvm.require_grant=1` but
  then cannot pin a valid grant fails closed — the intended catch, but it raises
  the bar on the correctness of the launch paths that deliver grants. The
  launcher-gated design (Option A) bounds this to exactly the mvmctl paths that
  emit the token; mvmd and other direct-launch paths never assert it, so they are
  never fail-closed.

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
- **Stage A as a baked `require_grant: true` flip** (the original Rollout plan).
  Superseded before implementation: mvmd boots sealed images through a direct
  Firecracker path that delivers no grant, so a baked flip would brick every
  mvmd instance. Replaced by the launcher-gated `mvm.require_grant=1` token
  (Option A, see Rollout / Stage A), which enforces only where a grant was
  delivered and leaves mvmd untouched with no mvmd-side change.

## Out of scope

- A malicious host (ADR-002).
- Hardware-backed key attestation / measured boot (ADR-002) — the future seam,
  not built here.
- Promotion of the verb-grant story to the ADR-002 numbered claim ledger.
