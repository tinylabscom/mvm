# Control/data-plane separation and provable chains of content & execution

Grounded research note. Answers two questions from `specs/scratch.md:15` and
`specs/scratch.md:19`:

1. Does mvm have a cleanly separated control plane and data plane?
2. Are merkle / mathematically-provable chains of content and execution already
   covered, and where would an explicit merkle structure add value the current
   mechanisms don't?

All claims cite real code (`file:line`). Reading was done against the main
checkout; nothing here proposes a specific patch, only maps what exists and
where a bounded, dependency-light gap remains.

---

## Q1 — Control plane vs data plane

### Verdict up front

mvm has a **clean conceptual separation that is enforced by verb class and a
disjoint vsock port map, not by physically distinct transports.** Both planes
funnel through host-mediated vsock chokepoints — that funnel, not wire
separation, is the actual security property (the "vsock-only auditable data
plane" invariant). There are exactly two places where control and data ride the
same channel; both are known, documented, and backstopped.

### The unifying fact: there is no guest-native NIC

Every guest I/O path — control RPC, workload egress, port-forward, console — is
a host-mediated vsock service. HVF is vsock-only; libkrun/Firecracker route
their virtio-net through a host gateway rather than giving the guest an
unmediated route. Consequently **every byte of both planes crosses a host
enforcement/substitution/audit seam.** The planes are separated by *port and
verb*, and made auditable by *transport*.

### Plane-boundary map

Fixed vsock port map (`crates/mvm-agentd/src/vsock/mod.rs:90-135`):

| Port / range | Channel | Plane | Enforcement seam | Cite |
|---|---|---|---|---|
| 5251 | workload exit-code report (`/init` → host) | control | one-shot i32, host binds listener | `vsock/mod.rs:96` |
| 5252 | guest-agent control RPC (`GuestRequest`/`GuestResponse`) | **control + data (mixed)** | verb-grant + profile gate | `vsock/mod.rs:90` |
| 5253 | host egress gateway (single egress chokepoint) | data | claim-10 allow/deny + claims-12/13 credential substitution | `vsock/mod.rs:98-106` |
| 5300 | host-services broker (`ServiceCall`/`ServiceResponse`) | control | binding-gated dispatch, server-minted correlation id | `vsock/mod.rs:108-122` |
| `NETWORK_TUNNEL_PORT` | guest-TUN ↔ host-worker packet tunnel | data | smoltcp L3 forward on host | `vsock/mod.rs:124-128` |
| 10000+ | TCP port-forward | data | host proxy allowlist | `vsock/mod.rs:130-132` |
| 20000+ | interactive console PTY | data (dev-only) | `interactive` feature + sealed-VM gate (claim 15) | `vsock/mod.rs:134-142` |

The port ranges are asserted disjoint so the host-side proxy allowlist keeps a
"disjoint-union" shape (`vsock/mod.rs:151-153`, test at `:217-229`).

### Control-plane inventory

- **ExecutionPlan admission.** `synthesize_plan` → `sign_plan` (Ed25519 over
  canonical-JSON plan, `crates/mvm-core/src/plan/signing.rs:58-66`) → verify →
  validity window + per-signer nonce replay store
  (`crates/mvm-core/src/plan/validity.rs:125-167`) → dispatch. This is the
  admission control plane (claim 8).
- **Chain-signed audit log.** `AuditEmitter`
  (`crates/mvm-hostd/src/audit/emitter.rs:61`) emits
  `plan.admitted`/`plan.launched`/`plan.failed`/`plan.oci_provenance`/
  `checkpoint.*`/`verb_denied`/`plan.grant_required` into per-tenant
  `~/.mvm/audit/<tenant>.jsonl` via `FileAuditSigner`
  (`crates/mvm-hostd/src/supervisor/audit_file.rs`). This is the tamper-evident
  spine of the control plane (detail in Q2).
- **Host-services broker.** UDS + vsock 5300; length-prefixed JSON
  `ServiceCall`, **cap-checked before parse**, correlation id **reassigned
  server-side at ingress** so a guest can't collide with the audit chain
  (`crates/mvm-hostd/src/broker/server.rs:78-141`). Binding-gated dispatch
  (claims 12/13); the guest-supplied id is never trusted.
- **Guest-agent RPC (5252).** `GuestRequest`/`GuestResponse` over
  authenticated frames, with a verb-grant layer and a
  `RequestClass::{ProdSafe,DevOnly,BuilderOnly}` profile gate
  (`crates/mvm-agentd/src/vsock/request_policy.rs:16-171`). `SealedProd` admits
  only `ProdSafe` verbs; the dev-only data verbs are refused before the handler
  runs, and additionally excluded at compile time (`do_exec`/`RunCode`/console
  gated by the `interactive` feature — claims 4/15).

### Data-plane inventory

- **Egress (5253).** The single host-mediated chokepoint. Default-deny is the
  type default: `NetworkPolicy::default() == deny_all()`
  (`crates/mvm-net/src/lib.rs:11-14`, `crates/mvm-net/src/enforcement.rs:8-9`),
  and an unwired enforcer **fails closed** — `EnforcementError::NotWired` rather
  than silent open egress (`crates/mvm-net/src/enforcement.rs:31-40`, `:60-74`).
  Firecracker self-enforces via nftables; libkrun goes through the
  gateway-bridge `PlanFlowPolicy` (ADR-001 tier matrix,
  `specs/adrs/001-microvm-security-posture.md:218-222`).
- **Packet tunnel / port-forward / console** carry user payload bytes and are
  data-plane by construction.
- **`TrafficPlane` verb classification.** The agent wire enum tags every verb
  `Control` or `Data`
  (`crates/mvm-agentd/src/vsock/response.rs:375-437`): `Exec`, `ExecBatch`,
  `RunEntrypoint`, `Fs{Read,Write,List}`, `FsDiff`, `ProcSendInput`,
  `ProcWait`, `RunCode` are `Data`; lifecycle/status/mount/console-setup are
  `Control`. The doc is explicit that this "drives dispatch capacity and audit
  handling; it is independent of the prod/dev profile gate"
  (`response.rs:372-379`).

### Where control and data mix (the two honest exceptions)

1. **The agent RPC channel (5252) is dual-plane on one socket.**
   `RunEntrypoint` (Data) and `Ping`/lifecycle (Control) share the same
   authenticated frame stream; `Exec`/`Fs*`/`Proc*`/`RunCode` (Data) also ride
   it in dev. The `TrafficPlane` enum exists precisely because these are not
   physically separated — it re-derives the plane from the verb. Mitigation:
   under `SealedProd` every Data verb except `RunEntrypoint` is profile-gated
   off (`request_policy.rs:96-152`, `:162-171`) and symbol-excluded from the
   sealed build, so a sealed workload's agent channel is control-plus-entrypoint
   only. **Separation here is enforced by profile + compile-time symbol
   absence, not by transport.**

2. **Broker / egress / DNS as covert-egress surface (the Cardoso / claim-10
   concern).** The broker channel (5300), the egress gateway (5253), and the
   deny-all control-plane carve-outs (DHCP/ARP/ND) are all host-mediated paths a
   hostile guest could try to abuse as a low-bandwidth exfil side channel.
   This is documented, not unmanaged:
   - ADR-020 states the broker channel "carries no per-frame cryptographic
     authentication; ... the identity guarantee ... rests entirely on
     process/socket topology, not on a signature"
     (`specs/adrs/020-host-services-broker.md:192`).
   - Claim 13 guarantees no raw secret value ever crosses the broker channel
     (`specs/adrs/001-microvm-security-posture.md:136`).
   - The default-deny proxy plus leak-scan is the named backstop against the
     "non-cooperative side channel"
     (`specs/adrs/023-secrets-subsystem-egress-substitution.md:134`).
   - Deny-all means deny-all even for control-plane link-bringup: DHCP is
     dropped with no carve-out; the guest self-assigns a static fallback
     (`specs/adrs/001-microvm-security-posture.md:224-236`).

### Q1 conclusion

The planes are cleanly *modeled* (explicit `TrafficPlane`, disjoint port map,
fail-closed egress seam) and cleanly *separated in the sealed-prod profile*. They
are **not** separated onto distinct transports — the agent socket is dual-plane,
and several host-mediated control/egress paths converge as a covert-egress
surface. That surface is a known, documented, leak-scanned concern rather than a
defect. **No restructuring is warranted;** the honest posture statement is
"one vsock transport family, plane-separated by verb class and port, made safe
by the host-mediated-only invariant + default-deny + leak-scan," not "two
physically isolated planes."

---

## Q2 — Provable chains of content and execution

### What provability already exists

Four independent cryptographic mechanisms already ship, each a real
merkle-or-hash-chain construction:

| Mechanism | Structure | Proves | Cite |
|---|---|---|---|
| dm-verity roothash | **Merkle tree** over rootfs data blocks, SHA-256, salted | any block tamper panics the kernel before userspace (claim 3); also the content-addressed image id | `crates/mvm-fs/src/ext4/verity.rs:26-58` (`root_hash`), `:73-131` (`format` emits full tree) |
| Chain-signed audit log | **hash-linked list** — each line commits `sha256(prev line)` + Ed25519 over `json(entry)‖prev_hash` | append-only tamper-evidence of the execution event history; reorder/edit/delete all break it | `crates/mvm-hostd/src/supervisor/audit_file.rs:31-44`, `verify_audit_chain:213-266` |
| Content-addressed signed bundle | manifest lists every artifact + SHA-256; detached Ed25519 sig; `key_id = sha256(pubkey)` looked up out-of-band | published workload artifacts are content-addressed, key-pinned, re-verified at fetch and admit (claim 9) | `crates/mvm-core/src/plan/bundle.rs:13-55`, `key_id_from_pubkey:83-87` |
| Signed ExecutionPlan | Ed25519 over canonical-JSON plan + validity window + per-signer nonce replay store | plan authenticity + freshness/replay resistance (claim 8) | `crates/mvm-core/src/plan/signing.rs:58-66`, `validity.rs:125-167` |

The audit verifier is even re-implemented byte-for-byte as `#![no_std]`/wasm so
anyone can verify a downloaded log in a browser with no host and no server trust
(`crates/mvm-contract/src/verify.rs:169-236`); a supervisor-side test pins the
two implementations equivalent (`audit_file.rs:366-400`).

So the primitives the scratch note asks about — merkle trees, hash chains,
content addressing — **are already in the codebase and already load-bearing.**
There is no need for a new merkle library, and no need for UOR / veilid
dependencies to obtain them (limit-dependencies, no-lock-in).

### The one real gap: the checkpoint lineage is not hash-linked

The scratch note's specific ask is narrower than "do we have merkle trees": it
wants **"checkpoints where we can rewind to previous sessions, microvms, and
revert with a single lookup"** — i.e. a content-addressed, provable *DAG of
checkpoints spanning multiple runs*. That is the one thing the four mechanisms
above do **not** provide.

`CheckpointMeta` (`crates/mvm-core/src/checkpoint.rs:52-68`) already carries the
skeleton of a DAG:

- `parent: Option<CheckpointId>` — a single-parent lineage pointer, so a tree
  already exists structurally (fork emits parent/child ids into the audit chain:
  `crates/mvm-hostd/src/audit/emitter.rs:290-306`).
- `content: Vec<ContentBlob>` where each blob is `{ name, sha256 }` — a
  per-artifact content manifest (`checkpoint.rs:40-46`).
- `supervisor_config_digest` and `audit_ref` — a config hash and a back-pointer
  into the chain-signed log.

But three properties are missing that keep it from being *mathematically
provable* the way the audit chain and dm-verity are:

1. **`parent` is an opaque id (a name), not a digest of the parent's meta.**
   The audit chain commits each entry to `sha256(prev line)`; the checkpoint
   lineage does not commit a child to its parent's content. Editing an
   ancestor's `content` manifest is invisible to descendants.
2. **`CheckpointMeta` itself is neither hashed nor signed.** `audit_ref` is
   explicitly "non-load-bearing" and integrity "relies on `content`, not on
   `audit_ref`" (`checkpoint.rs:48-51`) — but nothing rolls `content` up into a
   single commitment. There is no `meta_digest`, so no "single lookup" root to
   revert to.
3. **`plan_id` is a random UUID, not content-addressed** — `PlanId(uuid::new_v4)`
   (`crates/mvm-core/src/plan/synthesis.rs:180`). The plan is *signed* (which
   gives authenticity) but not *content-addressed*, so a plan cannot be
   referenced by, or chained to, a prior plan by hash.

Net: mvm has a merkle tree *inside* one image (dm-verity), a hash chain *of
events* (audit log), and content-addressing *of one artifact set* (bundle). It
does **not** have a content-addressed, hash-linked DAG *across* checkpoints/runs.
That DAG is exactly what "rewind and revert with a single lookup" needs.

### Recommendation

**Q1: no action beyond documentation.** Keep the current model. The one
improvement worth considering is surfacing `TrafficPlane` into the audit labels
on data-verb calls so an operator can attest which agent-channel calls carried
payload bytes vs control — the enum already exists (`response.rs:375-437`), so
this is a labeling change, not new machinery. The broker covert-egress surface
is already documented and leak-scanned; no code change is warranted there.

**Q2: mostly already covered; one bounded, dependency-free enhancement is
genuinely additive.** Content-address the checkpoint DAG by *reusing primitives
that already exist*:

- Compute a `meta_digest` = a merkle/hash root over the sorted `content` blobs
  (each `ContentBlob.sha256` is already a leaf; a rootfs blob's leaf can be its
  dm-verity `root_hash`, which `crates/mvm-fs/src/ext4/verity.rs:26` already
  produces — no new hashing of the rootfs).
- Make `parent` a `meta_digest` (or add `parent_digest` alongside the id) so the
  lineage becomes hash-linked, like the audit chain.
- Let the checkpoint id **be** its `meta_digest`, giving "revert with a single
  lookup" (address by content) and a provable ancestry (walk parent digests,
  compare one root).
- Bind each `meta_digest` into the existing chain-signed audit log via
  `emit_checkpoint_created`/`_forked` (already carry `content_sha256` — promote
  it to the full meta digest), so the DAG inherits the audit chain's Ed25519
  tamper-evidence for free.

This needs **no new crate, no merkle library, and no UOR/veilid dependency** —
SHA-256 (`sha2`), Ed25519 (`ed25519-dalek`), the dm-verity merkle root, and the
audit chain are all already in-tree and already the sanctioned primitives. It
honors limit-dependencies and no-lock-in, and it keeps the vsock-only /
host-mediated invariants untouched (this is host-side metadata, not a guest
channel).

**Honest bottom line:** for *content and execution integrity in a single run*,
already covered — no action. For the scratch note's *cross-run rewindable
checkpoint DAG*, there is a real, narrow gap, and closing it is a small
reuse-first change to `CheckpointMeta` + the checkpoint audit events, not a new
subsystem. If the UOR content-addressing exploration
(`specs/research/uor-addr-integration-assessment.md`) proceeds, the natural seam
is this `meta_digest`/content-address field — adopt the *addressing scheme*
there without pulling the *library* as a runtime dependency.
