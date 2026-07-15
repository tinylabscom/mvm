# ADR 069 - `wasm-sandbox` portable backend (non-microVM)

**Status**: Proposed
**Date**: 2026-06-03
**Cross-refs**: ADR-002 (security posture — wasm-sandbox is OUTSIDE its claim
set), ADR-066 (target architecture — `VmBackend` seam), Plan 144

## Context

mvm's real backends provide hardware-isolated microVMs (Firecracker/KVM,
Apple VZ, Cloud Hypervisor, libkrun). We also want a backend that runs in
browser/WASM and WASI-like environments for demos, docs playgrounds, and
deterministic repros. Browsers expose none of the primitives the security model
depends on: no KVM, no Apple VZ, no TAP, no virtio, no vsock, no privileged
mounts. A backend in that environment therefore cannot honestly claim microVM
isolation — but it can still be useful if it is explicit about what it is.

## Decision

### 1. Add a `wasm-sandbox` backend that reports its non-virtualization honestly

It implements the existing `VmBackend` seam and declares a `BackendCapabilities`
matrix with `hardware_virtualization=false`, `kvm=false`,
`real_linux_kernel=false`, `tap_networking=false`, `virtio=false`,
`vsock=false`, `virtual_filesystem=true`, `logical_snapshots=true`,
`browser_compatible=true`, `network_mode=ProxyOnly`. It is opt-in only
(`--hypervisor wasm-sandbox`/`browser`); `auto_select()` never returns it.

### 2. Fail closed on microVM-only requests

Kernel image, TAP networking, vsock, raw block passthrough, and host mounts each
return an explicit typed `WasmSandboxError` naming the supported alternative.
The artifact validator rejects any artifact whose `BackendCompat` row demands a
kernel format (wasm-sandbox accepts none).

### 3. It provides NONE of the ADR-002 numbered security claims

The wasm-sandbox is a portability/demo tier, not an isolation tier. ADR-002's
threat model and per-backend tier matrix do not extend to it, and this ADR does
not request claim-table promotion.

## Alternatives

- Emulate a Linux kernel in WASM to "be a real microVM" — rejected: enormous,
  and still not hardware isolation; dishonest framing.
- Silently degrade (accept a kernel arg and ignore it) — rejected: violates
  "do not silently degrade security semantics".

## Consequences

- Differs from Firecracker/Vz/Cloud Hypervisor: no hardware boundary, no real
  kernel, proxy-only networking, logical (not memory) snapshots.
- Intended uses: browser demos, docs playground, deterministic repros,
  lightweight plugin sandbox, offline-ish development.
- Not for: production tenant isolation, untrusted multi-tenant compute, real
  kernel testing, real network-device testing.
- Future work (Plan 144 deferred follow-ups): real WASI execution, live
  websocket/MessageChannel transports, a `wasm32` browser build target.


## Consolidated from ADR-069 — ADR-069 — Tier-0 wasm preview, ship-time promotion, and the capability-policy bridge

# ADR-069 — Tier-0 wasm preview, ship-time promotion, and the capability-policy bridge

**Status:** Proposed 2026-06-11. Adversarially reviewed 2026-06-11; this
revision folds in those findings.
**Extends** [ADR-069](069-wasm-sandbox-backend.md) (the `wasm-sandbox` backend —
the Tier-0 substrate this ADR promotes *from*) and
[ADR-041](041-signed-audited-execution-plans.md) (the product loop this preview
tier feeds). **Cross-refs:** ADR-002 (security posture — the claims the ship
side must keep), ADR-041 (signed/audited execution plans — the admission path
every promotion lands on), ADR-041 (app-deps audit — what re-validation means),
ADR-067 (secret substitution — why Tier 0 never holds a raw secret),
ADR-002 (mvm-primitive ↔ mvmd-product boundary, consolidated from ADR-070), Plan 129 (secrets), Plan 169
(agent-RPC transport, the vsock leg of the relay).

## Context

We want the fastest possible "wow" loop: a developer authors and *runs* a
workload live, in the browser or against a streamed host sandbox, with zero
infrastructure — then ships, and what they shipped is a real microVM carrying
every ADR-002 claim. ADR-069 gave us the honest substrate: a `wasm-sandbox`
`VmBackend` that declares `browser_compatible=true` and provides **none** of
the numbered claims. ADR-041 gave us the product loop around real microVMs.
What neither decides is the bridge: **how does work done in a no-claims tier
become a claims-bearing microVM without laundering anything past the claims?**

Two forces pull against each other. DX wants the preview to feel like
production and the promotion to be one click. Security wants nothing produced
in an untrusted tier to carry authority into the trusted one. This ADR
resolves the tension with one principle, applied everywhere:

> **The preview tier carries *intent*, never *authority*.** Identity, tenant
> policy, mandatory constraints, and artifact trust always come from the
> ship-side authoritative context. The preview only ever says "I want X";
> the ship side decides what X becomes.

A discipline note up front, because the first draft of this ADR violated it:
every protection this document names is either (a) existing, witnessed
machinery, cited as such, or (b) a **precondition** — required to exist, with
a named witness, before the Tier-0 promotion path is enabled. §8 is the
ledger. Until a precondition's witness lands, the path it protects fails
closed (promotion refused), the same way claims 4/15 are real only because
their symbol-grep gates exist.

## Decision

### 1. The trust boundary is *ship*, not preview

Tier 0 — the `wasm-sandbox` backend in a browser tab, or a host-side wasmtime
session streamed to a browser — asserts zero isolation claims (ADR-069 §3
already says so; this ADR adds it to ADR-002's threat-model notes rather than
the claim table). It is **single-principal for isolation purposes**: the
developer's own code, in their own session, so no *other tenant* is at risk
and no production claim is asserted or needed.

Single-principal does not mean harmless, and this ADR does not pretend it
does. The developer's own assets — the source being previewed, anything
pasted into the session — are exactly what a supply-chained preview
dependency or hostile previewed package would exfiltrate. Tier 0 therefore
has its own (claim-free, but real) posture:

- **Preview egress is mediated, not ambient.** The browser tier inherits
  ADR-069's `network_mode=ProxyOnly`; the preview surface ships a CSP that
  denies arbitrary outbound from the preview UI itself. Workload egress in
  preview flows through the decision-honest resolver (§3) — denied egress is
  *simulated as denied*, not silently allowed.
- **Secret-looking input is refused at paste time**, not only at ship
  (§5) — the input path runs the same detector the ship gate uses.

**Session binding on the relay.** The host-side relay's WebSocket leg is an
untrusted-client surface on a multi-tab machine: ADR-041's local ingress is
deliberately loopback-only/no-auth, so *any page in the developer's browser*
can attempt a WebSocket to it. "Single-session" is therefore an enforced
property, not a naming convention: the relay mints a short-lived random
session token at start, requires it on the WebSocket upgrade, refuses any
connection without it, and refuses a second concurrent client *without
terminating the first* (no takeover-by-race). Witness: tests asserting
wrong-token and second-client refusal (§8). Origin headers are checked as
defense-in-depth, not as the mechanism.

**Resource containment on host-side sessions.** In-browser execution is
bounded by the browser; host-side wasmtime is not, unless told. Host-side
Tier-0 sessions run under an explicit wasmtime `Config` with a fuel
(instruction-count) limit, a linear-memory cap, and a session wall-clock
timeout; `RuntimeRecording` carries a max-op guard. Dev defaults may be
permissive, but the caps exist from the first implementation — a single
authorized session must not be a local DoS.

**The moment host-side wasmtime serves more than one principal, it must run
inside a microVM** — a wasm-engine escape is contained by hardware isolation
exactly as any other workload escape is. This is a hard requirement, not an
optimization. mvm ships only a *single-session* relay primitive (one
wasmtime, one client, one policy); the second-client-refusal witness above is
also what keeps this premise from silently dissolving in a later PR. The
multi-tenant streaming service that composes wasmtime-in-microVM sessions is
mvmd's, per the ADR-002 split (consolidated from ADR-070).

### 2. Promotion is a trace, never a snapshot

Ship does not capture the preview's runtime state. It rebuilds from recorded
intent through the existing audited pipeline:

```
Tier-0 session ──records──▶ RuntimeRecording ──compile_recording()──▶ Workload IR
                                                            │
              nix build · deps seal (claim 11) · verity (claim 3) ·
              plan sign + admit (claim 8) · audit chain ◀───┘
```

The SDK's record mode (`mvm_sdk::runtime::RuntimeRecording` →
`compile_recording()`) is the promotion mechanism; Tier 0 extends it rather
than inventing a parallel path. Snapshot-style promotion (capture the mutated
sandbox filesystem and boot it) is rejected: it would carry un-audited bytes
past claim 11 and un-attested content past claim 3, making every downstream
claim unfalsifiable.

**What the trace can and cannot do — stated against the real lowering.** The
trace does *not* get to inject build-time execution: `before_build` is never
populated from a trace, and the IR→Nix lowering is fixed, trusted code in
this repo. But the existing lowering *does* emit in-guest boot-time steps
from trace content — non-final `CommandStart` ops become `before_start`
argv hooks. `FilesWrite` no longer touches a guest shell at all: it lowers
to the declarative `App.files` IR field, baked into the rootfs at build time
via `mkFunctionService` `extraFiles` (base64 decoded by the trusted build,
never interpolated into a guest command). So the honest statement is:
**a hostile trace can run code inside the guest it is itself defining — which
is what a workload is — and its safety rests on the guest confinement claims
(1, 2, 10) plus the fixed lowering, not on a pretense that no steps exist.**
What the constraints below guarantee is narrower and real: the trace cannot
execute anything on the *host* or at *build* time, and cannot widen the
guest's authority beyond what admission grants.

- **Closed vocabulary.** `RecordedOp` stays a closed enum of declarative
  actions. No host-exec or build-exec variant exists and none may be added.
- **Shrink the shell surface.** The `FilesWrite` shell-string lowering is
  gone (Plan 191): it lowers to the declarative `App.files` IR field, baked
  into the rootfs at build time via `mkFunctionService` `extraFiles` (bytes
  carried as data, base64 decoded by the trusted build, no shell
  interpolation). Reserved `/etc/mvm/*` paths take precedence over user files
  so a trace cannot clobber boot wiring. File content and paths never reach a
  guest shell context.
- **Untrusted input discipline.** The trace parser gets the claim-5
  treatment: `#[serde(deny_unknown_fields)]`, a fuzz target landing in
  `security.yml` beside `fuzz_supervisor_config` *in the same plan that
  builds the parser* (a ship criterion, not a follow-up), and rejection tests
  for oversize/duplicate/contradictory ops.
- **Trace integrity at rest.** A trace on disk is tamperable by ADR-002's
  same-host hostile process — and a swapped dep name inside a schema-valid
  trace steers the build while every schema check passes. Traces persist
  under the `mvm-core::config` state dir at mode 0600, and the recording is
  content-hashed at capture; `compile_recording()` verifies the hash on
  entry and refuses a mismatch. Sessions that never persist (in-memory
  record→ship) skip the window entirely.
- **Best-effort, reviewed — with teeth.** Trace→IR lowering is a scaffold,
  not a guaranteed reproduction. Actions that do not lower cleanly (an opaque
  downloaded binary, imperative state mutation) are surfaced as divergence
  findings — and **unacknowledged divergence blocks promotion**. The user
  explicitly acknowledges each divergence before the IR is admittable; a
  click-past warning is not a control.

**Re-validation runs on outputs, not claims** — CVE/SBOM gates evaluate the
sealed volume the build actually produced (`verify_sealed_volume`, the
claim-11 machinery), never what the trace says was installed; the promoted IR
must build deterministically (claim 7's witness applies unchanged). Two
honest limits on that sentence: claim 11 gates *known* high/critical CVEs and
SBOM/attestation presence — it does not detect typosquats or CVE-free
backdoors. A trace requesting `numpy-malware-fork` by name builds "clean."
The residual malicious-package risk is real and stated; what bounds it is
exact-name+version pinning of trace-sourced deps into the IR (the user
reviews the pinned list, not a fuzzy request), with registry allowlisting and
provenance checks as the existing ADR-041 trajectory hardens. Claim 11 is not
represented as malware protection.

### 3. One capability policy, two enforcement fidelities

Policy is expressed in object-capability terms — no ambient authority, every
grant explicit and attenuable. One **resolved** policy object then projects to
both enforcement points:

- **Fine projection (new):** the WASI context — preopens, outbound-host
  grants, env, stdio — built from the resolved policy behind a new enforcement
  trait (`resolved policy in, WasiCtx out`).
- **Coarse projection (existing, untouched):** nftables/passt egress rules,
  seccomp filters, verity sealing. These keep their current, independently
  audited machinery, fed by the same resolved policy through a translation
  seam. They are deliberately **not** re-homed behind the trait.

The heterogeneity is the point. Routing both layers through one capability
abstraction would correlate their failure modes — one misprojection bug
breaches both at once — and would insert new security-critical code under the
default-deny path that claim 10's witnesses already gate. Keeping the kernel
layer coarse and independent is what makes a wasm escape land in a boundary
that does not share the wasm layer's bugs.

**The two projections speak different namespaces, and the ADR closes that
gap rather than hand-waving it.** WASI grants are hostname-shaped; nftables
rules are CIDR-shaped. "The projections agree" and "intersection-only" have
no canonical meaning across namespaces, and DNS is the attacker's friend in
the gap (a granted hostname re-resolving to a metadata, loopback, or CGNAT address
widens effective reach past everything). Therefore:

- **One canonical address space at projection time.** Hostname grants are
  resolved and **IP-pinned when the policy is projected**; both projections
  are then compared and enforced over the same pinned set. The coarse layer
  enforces the pinned IPs, not live DNS.
- **Mandatory-deny is unconditional.** The existing `mandatory_deny_ranges`
  (cloud metadata + link-local, CGNAT, loopback — v4 and v6) are denied by
  the coarse projection regardless of any grant — a hostname grant that
  resolves into a mandatory-deny range yields a refusal, not a pin. Negative
  witness: a rebinding-shaped fixture (grant resolves into 169.254.0.0/16)
  must be denied by both projections. RFC1918 is deliberately not in the
  mandatory set (the const's rationale: legitimate VPN/cluster traffic, and
  the dev network itself is RFC1918) — a tenant that must not reach private
  ranges expresses that through its resolved policy, not the unconditional
  floor.
- **The consistency witness is property-based, not a fixture.** A single
  fixture proves one example; drift lives in wildcard semantics, v4/v6,
  ports, and resolution divergence. The witness generates grant sets over the
  canonical address space and asserts, for each, that the WASI grant and the
  nftables rules accept exactly the same set and deny everything else.

Two corollaries:

- **Prod wasm workloads run least-privilege at both layers.** "Open up wasm
  and lean on the microVM" is rejected: it discards the finer of the two
  layers. The double posture folds into the claim 1–3 and claim 10 narratives
  — no new claim number is requested now; promotion to the ADR-002 table can
  follow the same path the OCI-provenance claim took, once witnesses exist.
- **The preview is decision-honest from day 1.** Tier 0 runs the same pure
  policy resolver and *shows* the verdict ("this egress would be denied by
  default-deny") without claiming to enforce it. The UI labels the two modes
  distinctly: *policy preview (decisions shown, not enforced)* vs *policy
  enforced (prod)*. A preview that lets everything through would train users
  against the product's own posture and make every first ship a default-deny
  surprise.

Where Tier 0 cannot see the authoritative tenant policy (browser, offline), it
resolves against the local policy and flags that tenant policy may further
restrict at ship. At ship, resolution is authoritative and **intersection
only over the canonical (pinned) address space**: a trace-authored policy
request can attenuate the resolved grant, never widen it; mandatory-deny and
mvmd tenant policy always win. Witness: a clamp test (request wider than
allowed → admitted grant is the intersection).

### 4. Two fidelity regimes, named honestly

- **WASM-component workloads** (any WASI-targeting language): the
  **artifact** is byte-identical between preview and prod — the same
  content-addressed component bytes, digest-pinned in the IR (claim-9 shape),
  digest verified before boot, provenance recorded in the audit chain,
  mutable references refused under `--prod` before any fetch (mirroring the
  OCI path). The **engines** are not assumed identical: browser-side and
  embedded wasmtime can differ in version, enabled proposals, and WASI
  level, so this ADR pins a wasmtime/WASI baseline both ends must meet, and
  preview execution is still never an admission criterion. Anything the
  *preview itself* fetches (WASI adapters, registry components) is
  digest-pinned at fetch and the **digest, not the mutable reference, is
  what `compile_recording()` carries into the IR** — the same artifact the
  user previewed is the artifact admission verifies, or admission refuses.
- **Source-language workloads** (Python/TS): the preview is approximate (a
  wasm port of the interpreter is not the prod interpreter); ship rebuilds
  faithfully via the audited pipeline. The fidelity gap is disclosed in the
  UX and participates in §2's divergence-acknowledgement gate.

The component path is canonical — it is the one tier where "create a microVM
around what they did" is literal and correct, artifact-for-artifact.

### 5. Secrets never enter Tier 0

Plan 129's posture (raw secrets never reach the guest; the host proxy
substitutes on egress — claim 13) extends to the preview tier, which has no
host proxy at all. Tier 0 handles `SecretRef` placeholders only; substitution
is simulated as part of decision-honesty and only ever performed for real at
the prod egress proxy.

Stated plainly, because the first draft overclaimed here: the schemas do
**not** make raw secrets unrepresentable — `EnvValue::Literal` is a free
string and `FilesWrite` carries arbitrary bytes, so a pasted token *is*
representable. Containment is therefore a **gate, not a type**: a ship-time
admission scan over the trace and the lowered IR (the Plan 129 secret
detector — the enriched default secret list already in-tree, plus tenant
defs) refuses promotion when raw secret material is embedded, and the
Tier-0 input path runs the same detector at paste time so the refusal
arrives early instead of at ship. This scan is a §8 precondition: the
promotion path does not enable without it. The `run --mode plan` admission scan
has landed (Plan 187): `scan_recording_for_secrets` walks every env literal,
argv token, and decoded FilesWrite payload and `refuse_embedded_secrets`
hard-refuses admission on any match — not acknowledgeable. Paste-time detection
(the Tier-0 input path) remains deferred with the browser preview tier.
Developers who paste a real token into a recording get a refusal at
promote-time, not a silently-promoted leak.

### 6. New TCB surfaces, named

- **wasmtime/WASI** becomes a large parser of untrusted wasm bytes on the
  workload path. It gets the dependency treatment claims 5/7 prescribe: pinned
  version, `cargo deny`/`audit` coverage, upstream fuzzing relied upon and
  tracked (ADR-004 precedent), and at runtime it is confined exactly as any
  guest service — dedicated uid under setpriv, seccomp `standard`, no
  ambient fs (claims 1–2 narratives extend to it).
- **The projection seam** (resolved policy → WasiCtx, resolved policy →
  nftables input, hostname→IP pinning) is the one new security-critical code
  path this ADR accepts even under the heterogeneous design. It stays small
  and pure, with negative tests (a grant that must deny ⇒ both projections
  deny) plus the property-based consistency witness above.

### 7. `no_std` is a hardening track, not a gate

The browser tier rides on **wasm-clean** (compiles to `wasm32`, touches no
unsupported std surface on the hot path) — `mvm-verify` already proves the
pattern. Carving a `no_std` core out of the pure-logic crates remains
desirable (supply-chain shrink, compile-time portability guarantees) and is
pursued opportunistically per crate; nothing in this ADR blocks on it.

### 8. Preconditions — the promotion path fails closed until these witness

None of the following exist at proposal time. Each is REQUIRED before the
Tier-0 promotion path (record→ship) is enabled; until then `mvmctl` refuses
promotion with a message naming the missing gate. The claim catalog
discipline applies: when these land, their witnesses are named in
`specs/claims/catalog.md`-adjacent tooling so `xtask` lints can hold them.

| # | Control (section) | Witness required |
|---|---|---|
| P1 | Trace parser hardening (§2) | **DONE (Plan 186).** `fuzz_runtime_recording` in `security.yml` fuzz lane (`crates/mvm-sdk/fuzz`); `too_many_ops_refuses` + `files_write_oversize_refuses` + `duplicate_files_write_path_refuses` (mvm-sdk runtime). |
| P2 | Shell-surface shrink (§2) | **DONE (Plan 191):** `FilesWrite` lowers to the declarative `App.files` IR field, baked into the rootfs at build time via `mkFunctionService` `extraFiles` (base64 decoded at build, never in a guest shell) — the `before_start` shell hook is gone. Plan 186's interim base64-hardening superseded. |
| P3 | Trace integrity (§2) | **DONE (Plan 186).** `recording_sha256_hex` captured at read in `load_recording`/auto-exec; `verify_recording_digest` + `--recording-sha256` on `compile --from-recording`; 64 MiB byte cap before parse; `digest_verify_match_passes_mismatch_refuses` (mvm-sdk). |
| P4 | Divergence gate (§2) | **DONE (Plan 186).** `require_acknowledged` refuses unacknowledged findings on the `run --mode plan` admission path (`gate_passes_with_no_findings`, `gate_refuses_unacknowledged`, `gate_passes_when_all_kinds_acked`, `gate_refuses_partial_acks` — mvm-cli); `Divergence` vocabulary in `mvm_sdk::runtime`; `--ack-divergence <kind>` to acknowledge. Ship-verb wiring inherits this gate when it lands. |
| P5 | Projection consistency (§3) | `cross_projection_consistency_property` + `clamp_never_widens_property` + `rebinding_pin_into_metadata_range_refuses` (mvm-core `policy::projection`) — landed by Plan 188. Kernel close-out (Plan 190): `canonicalize_l4` (lenient — no mandatory-deny-overlap refusal at construction time; runtime `permits()` + `MandatoryDenyEgressScan` enforce it) feeds `L4PolicyScan` via `CanonicalEgress::permits`; `L4Policy`/`LiveL4Gate` duplicate deleted; claim-10 witnesses migrated, zero behaviour change; `kernel_egress_canonical_permits_agrees_with_hand_written_oracle` is the equivalence witness. Remaining for P5 close-out: WASI-context mapping (runner plan). |
| P6 | Component digest carry (§4) | preview-fetched artifacts enter the IR as digests; mutable ref under `--prod` refused before fetch (test) |
| P7 | Secret-scan admission (§5) | `scan_recording_for_secrets` (env literals + argv + decoded FilesWrite payloads, mvm-cli) + `refuse_embedded_secrets` hard-refuses `run --mode plan` (not acknowledgeable, no `--ack`); reuses the Plan 129 `SecretsScanner`; witnesses `create_env_literal_secret_is_flagged`, `files_write_decoded_secret_is_flagged`, `secret_ref_value_is_not_flagged`, `secret_gate_refuses_any_finding`, `scan_then_refuse_composition_rejects_embedded_secret` — landed by Plan 187. Paste-time detector deferred with the browser preview tier. |
| P8 | Relay session binding (§1) | wrong-token refusal + second-client refusal tests; fuel/memory/wall-clock caps present in the wasmtime `Config` |

## Alternatives considered

- **Snapshot promotion** ("docker-commit the sandbox, boot it") — rejected;
  see §2. It is the single fastest way to make claims 3/7/11 unfalsifiable.
- **Full policy re-expression** (one capability abstraction enforcing at both
  layers) — rejected; see §3. Uniform plumbing adds correlated failure and new
  code under default-deny while adding no enforcement the two-projection
  design lacks.
- **Kernel emulation in the browser** for native-deps fidelity — already
  rejected by ADR-069 as a framing for the backend itself; remains available
  later as an explicitly-labeled high-fidelity preview fallback if the
  source-language gap proves painful. Out of scope here.
- **Defer policy honesty** (preview runs open, policy appears at ship) —
  rejected; it trains users against default-deny and converts the product's
  central posture into a first-ship failure.

## Consequences

- The wow loop exists without a single claim bending: preview is fast, open,
  and honest about being claim-free; ship lands on the unchanged claim-8
  admission path with claim-11 re-validation of real outputs — and the
  promotion path is disabled until §8's witnesses exist, so the interim state
  is fail-closed rather than aspirational.
- WASM-component workloads get artifact-identical preview→prod; every
  WASI-targeting language becomes a supported workload via one component path.
- New surfaces to build, each owned by a plan and gated per §8: the trace
  vocabulary + fuzz target; the declarative file-materialization lowering;
  the projection trait + property witness + clamp test; the single-session
  relay (websocket leg client-facing with session-token binding, vsock leg
  unchanged, one framed protocol over a transport trait); the secret-scan
  admission hook.
- ADR-002 gains a Tier-0 threat-model note; claims 1–3/10 narratives grow the
  double-posture and wasmtime-confinement language. `xtask
  check-claim-catalog` keeps every named witness honest as they land.
- mvmd inherits clean primitives: the relay, the policy projection, and the
  promotion flow are mvm's; sessions, auth, tenancy, and the streaming service
  are mvmd's.
- Known residual risks, accepted and stated: typosquat/CVE-free malicious
  packages requested by name (bounded by pinning + review, not eliminated);
  engine-version skew between preview and prod wasmtime (bounded by the
  pinned baseline); Tier-0 exfiltration of the developer's own assets
  (bounded by ProxyOnly + CSP + paste-time refusal, claim-free by design).


## Consolidated from ADR-069 — ADR-069 — Production in-microVM wasm-component runner

# ADR-069 — Production in-microVM wasm-component runner

**Status:** Proposed 2026-06-12.
**Extends** [ADR-069](069-wasm-sandbox-backend.md) (§4 two
fidelity regimes — this ADR builds the prod-tier execution for the WASM-component
regime; §6 wasmtime as a new untrusted-input surface). **Builds on**
[ADR-069](069-wasm-sandbox-backend.md) (the off-isolation-scale wasm-sandbox
*preview* backend; this ADR is the *production microVM* path, not that backend).
**Cross-refs:** ADR-002 (claims 1–3 isolation, 5 untrusted parsers, 8 signed
plan, 10 egress, 11 sealed deps, 13 secrets), ADR-041 (app-deps audit — the
builder already compiles untrusted inputs), ADR-005 (symmetric builder VM — the
sandbox the AOT compile runs in), Plan 188 (the capability projection/clamp seam
this extends from network to fs/env).

## Context

ADR-069 §4 names two fidelity regimes for the Tier-0→ship promotion. The
**WASM-component** regime is the clean one: a workload that *is* a `.wasm`
runs on the same engine in preview and prod (wasmtime ≈ wasmtime), so the
microVM just wraps it. ADR-069 deferred building that prod runner to its own
design. This ADR is that design — the **production, in-microVM wasm-component
runner**: make "a `.wasm` is a workload" real, with the component executing on
**wasmtime inside the guest**, the microVM providing isolation.

The runtime mechanism is already scaffolded: `crates/mvm-guest/src/runner/`
has a `Wasm` runner variant whose interpreter is `wasmtime` and whose entry is
`wasmtime run dispatch.wasm`, using the stdin→stdout function-invoke contract —
handled exactly like the `python3`/`node` runners. So **wasmtime is a guest
binary** (Nix-baked into the rootfs), invoked as a subprocess. **mvm's host
code never links wasmtime.** The work is to wire the surrounding pieces:
admit the `.wasm` as an artifact, project policy into the guest's WASI config,
and bake the engine.

The browser / host-streamed *preview* execution of components (ADR-069's P8
relay) is a **separate** subsystem that consumes the same component artifact;
it is out of scope here.

## Decision

### 1. v1 targets WASI Preview 1 modules, with a P2-ready seam

v1 runs WASI Preview 1 modules via the existing `wasmtime run` + stdin→stdout
invoke contract — the most-scaffolded path. The artifact-admission, capability
projection, and IR shapes are kept **WASI-version-agnostic** so swapping to
WASI Preview 2 / the Component Model (WIT worlds, `wasi:sockets`,
`wasi:http`) is a runner-internal change, not a re-architecture. P1 has no
socket API, which is *why* network stays a microVM-layer concern in v1
(below).

### 2. The `.wasm` is an admitted, content-addressed artifact

v1 source is a **local `.wasm` file**: `mvmctl run ./component.wasm`
(auto-detected, or `--wasm`). The file is SHA-256'd and admitted through the
**existing claim-8/9 path** — a signed `ExecutionPlan` whose content-addressed
artifact is the `.wasm`, with provenance (digest, wasmtime version) recorded in
the chain-signed audit log. No parallel admission path.

- **Fast-follow (this ADR's P6 leg):** a registry reference
  (`--wasm <registry>@sha256:…`), reusing the OCI claim-14 path — mutable refs
  refused under `--prod`, cosign verification, provenance recorded.
- **Deferred:** SDK-compiled-from-user-code (author in any language → `.wasm`)
  — the byte-identical-preview dream lives there, but it needs per-language
  compile-to-wasm toolchains and is its own program.

### 3. WASI capabilities are clamp-authored — the Plan 188 seam extended network→fs/env

In WASI P1 the *fine* layer the component sees is **filesystem preopens + env
vars** (P1 has no sockets). These grants are governed by the **clamp model
from Plan 188**, now extended from network to fs/env: the workload **requests**
fs/env capabilities in its IR; the authoritative **tenant policy bounds** them;
the granted set is the **intersection** (a request can attenuate, never widen).
**Default-deny** on both sides — a component is denied every dir/var not
granted. This makes ADR-069 §3's "one capability policy, two enforcement
fidelities" literal:

- **fine:** the resolved capability policy → wasmtime fs preopens + env grants,
  in-guest (extends `mvm-core::policy::projection`).
- **coarse:** the microVM layer — nftables/passt egress (Plan 188/190, already
  built). In P1 this is the *only* network enforcement; the `WasiEgress`
  *network* grant shape (Plan 188) becomes live only at P2 sockets.

Env grants carry `SecretRef` placeholders, substituted host-side, never raw
(claim 13) — same as every other workload.

### 4. AOT-compile at build for prod; JIT only for preview

The dangerous step is turning attacker `.wasm` bytes into native code. For the
**production in-microVM path**, the component is **AOT-compiled in the builder
VM** (`wasmtime compile` → a `.cwasm`); the guest runs the **precompiled**
artifact. Consequences:

- **No JIT in the live guest** → the guest seccomp profile can **forbid**
  `mmap(PROT_EXEC)` / exec-`mprotect`, materially tightening the
  workload-bearing tier (the whole point of running in a locked-down microVM).
- The compiler runs on attacker bytes in the **builder**, which already
  executes attacker-influenced build logic (`nix build`, `uv pip install`) in
  its own sandbox (ADR-041/057) — no *new* privileged trust boundary, one more
  build step in a place designed for it.
- **Deterministic** (claim 7 double-build) given a pinned wasmtime version,
  which is recorded in provenance; the `.cwasm` is same-arch as the guest by
  construction; precompiling removes cold-start JIT latency.

The **preview tier keeps JIT** (`wasmtime run` the `.wasm`) — there the
browser / host sandbox contains the JIT and the fast author-loop matters.

**Fidelity note (honest):** prod runs the AOT `.cwasm`, preview JITs the same
source `.wasm` — *same source component, two compilations*, identical wasm
semantics but not literally the same machine code. A far tighter gap than the
source-language regime's Pyodide-vs-CPython; recorded, not hidden.

### 5. wasmtime is a guest binary, never a host dependency

wasmtime enters the rootfs via Nix for `Wasm`-kind workloads (like `python3`/
`node`), pinned and recorded in the build closure. The host crates do **not**
take a `wasmtime` Cargo dependency — keeping the host TCB unchanged and the new
untrusted-input surface *inside* the guest, behind the microVM.

## Security considerations (the threat-model delta)

The new surfaces beyond the existing claim set:

1. **wasmtime as a new untrusted-`.wasm` parser/compiler (claim 5 family).** A
   wasmtime validation/codegen bug → arbitrary code where it runs. Mitigated by
   defense-in-depth (Decision 4 puts the *compile* in the sandboxed builder and
   the *execution* of precompiled code in the sealed guest with no JIT), version
   pinning + `cargo deny`/audit, and confining the in-guest wasmtime as the
   uid-901 setpriv service (claims 1–2). **We do not fuzz wasmtime ourselves —
   we rely on its upstream OSS-Fuzz coverage** (the ADR-004 precedent for the
   virtio parsers) and record that as the posture.
2. **The WASI config generator is new security-critical code**, peer to the
   Plan 188 projection seam: it turns the resolved policy into the actual
   preopen/env grant set; a bug = over-grant. It carries the same discipline —
   **deny-by-default, the clamp invariant (a request never widens tenant
   policy), and negative tests** ("a denied dir is not preopened").
3. **Resource exhaustion.** The microVM cgroup/jailer caps bound the blast
   radius, with wasmtime **fuel/epoch + a wall-clock timeout** as the inner
   bound so one component cannot wedge its VM.
4. **WASI preopen enforcement is wasmtime's to get right** (path-traversal /
   symlink escape out of a preopen) — an explicit **trust assumption**, the way
   nftables is trusted for egress. Bounded by: the rootfs is verity/read-only
   except granted writable dirs, and an escape is still inside the sealed guest.
5. **Secrets-in-env are exfil-safe in v1, with a P2 caveat.** A substituted
   credential in env (claim 13) has no exfil path in P1 (no sockets; network
   blocked at the microVM). When P2 `wasi:sockets` lands, the Plan 129
   egress-substitution / host proxy MUST mediate the component's outbound or a
   network-granted component could leak it. Flagged now, enforced at P2.
6. **P2 imports/worlds are capabilities to clamp** (forward-looking): a
   component's imports (`wasi:http`, custom host functions) are ambient
   authority if auto-satisfied. The capability/clamp model must govern which
   imports are granted; the v1 seam anticipates this so P2 is not a
   re-architecture.

## Claim mapping

A wasm-component workload runs in a microVM, so it inherits claims 1–3
(isolation), 8 (signed plan), 10 (default-deny egress), 11 (sealed deps, if it
has any), 13 (secrets), 15 (no interactive sealed access). The new fine-grained
fs/env enforcement (Decision 3) is a *strengthening* within claims 1–2, not a
new numbered claim — promotion to the ADR-002 table can follow the OCI-provenance
precedent once witnesses exist. The AOT-no-JIT-in-guest posture (Decision 4)
strengthens the claim-1/2 seccomp story.

## Decomposition (an ADR + ~3 plans — for `writing-plans`)

| Piece | What | Reuses |
|---|---|---|
| **A1** | Capability-policy extension: the resolved policy + `mvm-core::policy::projection` carry fs/env capabilities (not just network); `clamp` from Plan 188 applies; the WASI-config generator (deny-by-default, clamp invariant, negative tests). **Foundation — A2/A3 consume it.** | Plan 188 projection/clamp |
| **A2** | `.wasm` artifact admission: `mvmctl run ./x.wasm` → SHA-256 → signed `ExecutionPlan` with the `.wasm` as the content-addressed artifact → provenance (digest + wasmtime version) in the audit chain. | claim 8/9 admission |
| **A3** | Guest runner + Nix bake + AOT: bake wasmtime into the rootfs for `Wasm` workloads; AOT-compile the `.wasm`→`.cwasm` in the builder; generate the `wasmtime run` invocation + WASI config (preopens/env, as data) from A1; tighten guest seccomp to forbid `PROT_EXEC`; run under the existing invoke contract. | the `Wasm` runner scaffold + the factory bake (Plan 191-style) |

**Sequencing:** A1 (foundation) → A2 + A3 (largely parallel; both consume A1).
v1 "done": `mvmctl run ./hello.wasm` boots a microVM, the AOT-compiled
component runs on wasmtime under clamped fs/env grants with a no-`PROT_EXEC`
guest seccomp, output returns, provenance recorded.

## Alternatives considered

- **JIT-in-guest** (compile at load): rejected for prod — forces the guest
  seccomp to permit executable-memory syscalls, loosening the workload-bearing
  tier. Kept for the preview tier where a sandbox already contains it.
- **Linking the `wasmtime` crate into the host** (e.g. a host-side WASI runner):
  rejected — grows the host TCB for no benefit; the component runs in the guest,
  so wasmtime belongs in the guest (subprocess), like python/node.
- **A new parallel admission path for `.wasm`**: rejected — reuse claim-8/9;
  a `.wasm` is just another content-addressed artifact.
- **WASI P2 / Component Model for v1**: deferred — the scaffold is P1 and P1
  modules cover the v1 target; Decision 1's seam keeps P2 a later swap.
- **A kernel-less, library-embedded Wasm VMM with snapshot-per-call** (prior
  art): a CNCF-sandbox embedded Virtual Machine Manager runs a purpose-built
  `no_std` Wasm guest — no guest kernel, no OS — linked *in-process* as a
  library, with typed function calls across the boundary and a clean snapshot
  restored before every guest invocation. Its existence is a useful
  existence-proof: a `no_std` Wasm guest with a hardware boundary boots in
  milliseconds, calls complete in microseconds, and snapshot-per-call is cheap
  enough to run on every step of an agent loop — concrete evidence for the
  dependency-budget review that gates pulling a Wasm engine in (Plan 144's
  `wasm-sandbox` follow-up) and for the preview tier's fast author-loop
  (ADR-069 P8). It is **rejected as the production shape here** for two
  reasons: (1) it collapses the VMM into the orchestrator's address space,
  abandoning the supervisor/jailer/broker **process moat** mvm relies on; and
  (2) a kernel-less guest forgoes the Linux microVM boundary that earns claims
  1–3, 10, 13, 15. The takeaway is the *guest model and snapshot cadence*, not
  the embedding: mvm keeps the full microVM and the moat, and runs wasmtime as
  an in-guest subprocess (Decisions 4–5), while the snapshot-per-call cadence
  is worth considering for the preview tier and for a per-invocation reset DX
  mode (evaluate against the Plan 159 checkpoint/fork primitive first — it may
  already provide a clean per-invoke baseline).

## Consequences

- A `.wasm` becomes a first-class, claim-bearing workload with no new host
  dependency and no new host trust surface; the new untrusted-input surface is
  in-guest, behind the microVM, and (for prod) is precompiled in the sandboxed
  builder rather than JIT'd in the live workload.
- The capability model graduates from network-only to network+fs/env, all
  through the one Plan 188 projection/clamp seam.
- New code/gates owned by plans A1–A3: the fs/env projection + WASI-config
  generator (with the clamp/deny-by-default witnesses), the `.wasm` admission,
  the AOT build step + the tightened guest seccomp, the Nix wasmtime bake.
- Out of scope: the preview/relay tier (ADR-069 P8), SDK-compile-to-wasm
  (Decision 2 deferred), and WASI P2 (Decision 1 seam).
