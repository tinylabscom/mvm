# ADR-080 — Tier-0 wasm preview, ship-time promotion, and the capability-policy bridge

**Status:** Proposed 2026-06-11. Adversarially reviewed 2026-06-11; this
revision folds in those findings.
**Extends** [ADR-069](069-wasm-sandbox-backend.md) (the `wasm-sandbox` backend —
the Tier-0 substrate this ADR promotes *from*) and
[ADR-079](079-app-builder-product-surface.md) (the product loop this preview
tier feeds). **Cross-refs:** ADR-002 (security posture — the claims the ship
side must keep), ADR-041 (signed/audited execution plans — the admission path
every promotion lands on), ADR-047 (app-deps audit — what re-validation means),
ADR-049/ADR-067 (secret substitution — why Tier 0 never holds a raw secret),
ADR-070 (mvm-primitive ↔ mvmd-product boundary), Plan 129 (secrets), Plan 169
(agent-RPC transport, the vsock leg of the relay).

## Context

We want the fastest possible "wow" loop: a developer authors and *runs* a
workload live, in the browser or against a streamed host sandbox, with zero
infrastructure — then ships, and what they shipped is a real microVM carrying
every ADR-002 claim. ADR-069 gave us the honest substrate: a `wasm-sandbox`
`VmBackend` that declares `browser_compatible=true` and provides **none** of
the numbered claims. ADR-079 gave us the product loop around real microVMs.
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
untrusted-client surface on a multi-tab machine: ADR-079's local ingress is
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
mvmd's, per the ADR-070 split.

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
argv hooks, and `FilesWrite` currently lowers to a constructed shell line
(`printf '%s' '<b64>' | base64 -d > <path>`). So the honest statement is:
**a hostile trace can run code inside the guest it is itself defining — which
is what a workload is — and its safety rests on the guest confinement claims
(1, 2, 10) plus the fixed lowering, not on a pretense that no steps exist.**
What the constraints below guarantee is narrower and real: the trace cannot
execute anything on the *host* or at *build* time, and cannot widen the
guest's authority beyond what admission grants.

- **Closed vocabulary.** `RecordedOp` stays a closed enum of declarative
  actions. No host-exec or build-exec variant exists and none may be added.
- **Shrink the shell surface.** The `FilesWrite` shell-string lowering is
  replaced by a declarative IR file-materialization field (bytes carried as
  data, written by the trusted init path, no shell interpolation). Until that
  lands, a regression test pins the b64 encoding to the `STANDARD` alphabet —
  the property that currently keeps the interpolation injection-free — so a
  decoder/alphabet change cannot silently reopen it.
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
provenance checks as the existing ADR-047 trajectory hardens. Claim 11 is not
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
promotion path does not enable without it. Developers who paste a real token
get a refusal, not a silently-promoted leak.

### 6. New TCB surfaces, named

- **wasmtime/WASI** becomes a large parser of untrusted wasm bytes on the
  workload path. It gets the dependency treatment claims 5/7 prescribe: pinned
  version, `cargo deny`/`audit` coverage, upstream fuzzing relied upon and
  tracked (ADR-055 precedent), and at runtime it is confined exactly as any
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
| P2 | Shell-surface shrink (§2) | **Interim pin DONE + HARDENED beyond plan (Plan 186); declarative-materialization OPEN (own plan).** The pin caught and fixed a live shell-injection in the FilesWrite lowering — the path is now base64-encoded into the hook (not single-quote-interpolated), verified injection-safe by executing generated hooks against /bin/sh. Witnesses: `files_write_b64_with_single_quote_refuses` + `files_write_b64_url_safe_alphabet_refuses` + `files_write_hostile_path_is_base64_encoded_in_hook` + `files_write_root_level_path_materializes` + `files_write_slashless_nested_path_materializes` (mvm-sdk runtime). The remaining P2 work (replace the shell hook with a declarative IR file-materialization field) is deferred to its own plan. |
| P3 | Trace integrity (§2) | **DONE (Plan 186).** `recording_sha256_hex` captured at read in `load_recording`/auto-exec; `verify_recording_digest` + `--recording-sha256` on `compile --from-recording`; 64 MiB byte cap before parse; `digest_verify_match_passes_mismatch_refuses` (mvm-sdk). |
| P4 | Divergence gate (§2) | **DONE (Plan 186).** `require_acknowledged` refuses unacknowledged findings on the `run --mode plan` admission path (`gate_passes_with_no_findings`, `gate_refuses_unacknowledged`, `gate_passes_when_all_kinds_acked`, `gate_refuses_partial_acks` — mvm-cli); `Divergence` vocabulary in `mvm_sdk::runtime`; `--ack-divergence <kind>` to acknowledge. Ship-verb wiring inherits this gate when it lands. |
| P5 | Projection consistency (§3) | `cross_projection_consistency_property` + `clamp_never_widens_property` + `rebinding_pin_into_metadata_range_refuses` (mvm-core `policy::projection`) — landed by Plan 184. Remaining for P5 close-out: wire `LiveL4Gate`/`PlanFlowPolicy` to consume `CanonicalEgress` (kernel-side), and the WASI-context mapping (runner plan). |
| P6 | Component digest carry (§4) | preview-fetched artifacts enter the IR as digests; mutable ref under `--prod` refused before fetch (test) |
| P7 | Secret-scan admission (§5) | trace+IR scan refuses embedded secrets (test); paste-time detector in the preview input path |
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
