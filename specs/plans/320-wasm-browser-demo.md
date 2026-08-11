# Plan 320: A live wasm sandbox demo on the website

## Status

DESIGN — approved in brainstorming, implementation not started.

Bound by [ADR-024](../adrs/024-wasm-sandbox-backend.md)'s three constraints.
Adds no numbered security claim, and does not request one.

Companion: [plan 321](321-wasm-in-microvm-workload-format.md) covers the
*other* half of "support wasm fully" — running a wasm workload inside a real
microVM (engine-in-guest), which is where the numbered claims actually come
from. 320 and 321 are independent; 320 ships first.

## Context

### What exists today

- `WasmBackend` is real: `crates/mvm-runtime/src/wasm_backend.rs` (1,706 lines),
  behind the off-by-default `wasm-backend` feature, on `wasmtime` 46. It runs a
  user-supplied WASI module and mediates the module's `mvm:egress` host-import
  through the same substitution endpoint the microVM backends use.
- `crates/mvm-hostd/tests/wasm_egress_witness.rs` drives that seam through the
  real `SubstitutionService` (real registry/resolver/encrypted secret store/
  claim-10 gate/chain-signed recorder), swapping only the outbound TCP dial.
- `mvm-contract` is `#![no_std] + alloc`, builds on `wasm32-unknown-unknown` in
  CI, and already carries `NetworkPolicy`, the audit DTOs,
  `verify_audit_chain_bytes`, `ed25519-dalek` v3 and `sha2`.
- `web/audit-verify/` is a `wasm_bindgen` shim + static page, excluded from the
  workspace so `wasm-bindgen` never enters `cargo build --workspace`.

### The premise this plan corrects

"We have a microVM that runs as a wasm container" is half true, and the half
that is false determines the whole design. `WasmBackend` runs **on the host**
under native `wasmtime`. `wasmtime` is a native embedding; it does not run in a
browser. Nothing in the tree can be dropped onto a web page as-is.

A browser demo therefore uses **the browser's own wasm engine** as the
execution substrate, with mvm's governance seam recompiled from `mvm-contract`.
The host `WasmBackend` is never exercised by the page. The page must say so.

## Scope (decided)

| Question | Decision |
|---|---|
| What the visitor sees | A live in-browser sandbox run — real WASI module, real policy gate, real chain-signed audit log, verified on screen |
| What runs | Curated modules picked from a list, shipped as fixtures |
| Egress on allow | A simulated destination, rendered on screen, labelled as simulated |
| Placement | A dedicated `/demo` route; a compact teaser card on the landing page links to it |
| Shared with the host | The egress decision, `${NAME}` substitution, and audit-entry construction + chain signing — all three relocated into `mvm-contract`, not reimplemented |

Rationale for the simulated destination: it is the only option that can
actually *show* the substitution. The demo's core assertion is that the
destination received the real secret while the module held only a placeholder.
A real remote destination cannot show you its own inbox, and there is no real
credential to substitute anyway.

## Architecture

Three layers.

**1. `mvm-contract` — the shared `no_std` core.** Gains three pure cores by
relocation. Nothing new enters the workspace dependency graph except `ipnet`
gaining a `no_std` configuration.

**2. `web/mvm-demo/` — a new crate, excluded from the workspace.** A
`wasm-bindgen` shim over `mvm-contract`, for the same reason `web/audit-verify/`
is excluded: `wasm-bindgen` and the `wasm32` target must never enter
`cargo build --workspace` or CI. It exposes `run(module_id, policy_json)` and
`verify(chain_bytes)`, and owns the `mvm:egress` host-call handler.

**3. `public/` — the existing Astro/Starlight + React site.** A `/demo` route, a
dedicated Web Worker owning both wasm instances, and a thin async proxy on the
main thread. No signing or verification on the main thread.

### Who instantiates the visitor's module

A wasm module cannot instantiate another wasm module; the host does. Here the
host is the Worker's JavaScript. The Worker holds two instances — the
`mvm-demo` core and the curated WASI module — and supplies the module's
`mvm:egress` import as a JS trampoline that calls into the core.

This is the honest structural difference from the host tier, and it is the
reason the page carries no claim: the isolation boundary is the browser's,
not mvm's.

## The extraction

Three pure cores move down into `mvm-contract`. Each is a relocation, following
the verbatim-relocation discipline of
[10-increment3-protocol-core-split.md](../refactor/10-increment3-protocol-core-split.md)
— leaf-first, green and wasm-clean after every step, no serde-shape change.

### E1 — the egress decision

`crates/mvm-core/src/policy/projection.rs` (1,456 lines) already contains
`Proto`, `CanonicalRule`, `CanonicalEgress`, `WasiEgress`, `to_wasi_grants()`
and `wasi_allows(egress, proto, ip, port)` — the last of which exists
specifically to project a `NetworkPolicy` onto a WASI grant set. That is the
demo's gate, already written and already tested.

Its dependencies are near-entirely portable:

| Dependency | Status |
|---|---|
| `crate::policy::{dns_pin, network_policy, resolver}` | already in `mvm-contract` |
| `thiserror` | already a `mvm-contract` `no_std` dep |
| `std::net::IpAddr` | → `core::net::IpAddr`, the swap Increment 3 already made |
| `ipnet` | supports `no_std` via `default-features = false` |

Every consumer imports through the `mvm_core::ln` alias — `EgressGate`,
`mvm-net`'s L3 admit, `mvm-hostd`'s proxy and DNS handler, `mvm-conformance` —
roughly twenty call sites. `mvm-core` re-exports the relocated module under the
same alias, so none of them change.

`projection_fs_env.rs` (567 lines, the fs/env analogue) stays in `mvm-core`.
The demo does not need it.

### E2 — `${NAME}` substitution

The pure resolution core teased out of
`crates/mvm-hostd/src/keyholder/substitution.rs` (509 lines). The boundary,
stated explicitly so the extraction is not a judgement call at implementation
time:

**Moves down** — locating `${NAME}` placeholders in a request, checking the
name against the destination binding, and producing the substituted result from
a supplied value. Pure functions over owned data.

**Stays in `mvm-hostd`** — key custody and the encrypted secret store, the
outbound forward leg, sockets and files, and anything async. The browser
supplies its own fixture values through the same function signature the host
supplies real ones through.

### E3 — audit-entry construction and chain signing

The pure core of `crates/mvm-hostd/src/supervisor/audit_file.rs` (1,400 lines):
building a `SignedEnvelope` (entry + canonical bytes + `prev_hash` + signature)
and `hash_line`. `FileAuditSigner`'s filesystem, mutex and async wrapper stay
in `mvm-hostd`.

This one is lower-risk than its line count suggests: `mvm-contract`'s
`verify.rs` already implements the exact inverse, and its `signed_bytes_for` is
documented as the byte-for-byte counterpart of `audit_file.rs`'s. The chain
semantics are already portable; only the writer half is not.

### Why relocate rather than reimplement

After E1–E3 the host and the browser run identical code for all three things
the page asserts on screen. A demo-local reimplementation would be a second
copy of claim-10 and claim-13 logic with nothing keeping it in sync; the page
would eventually market a behavior the product does not have, and we would find
out from a user rather than from a red test.

## The demo

### Three curated modules

Chosen to restate the existing host witness rather than invent new behavior.
`wasm_egress_witness.rs` already asserts the first two against the real
`SubstitutionService`.

| Module | Policy | What the visitor sees | Audit event |
|---|---|---|---|
| `allowed` | allow-list contains the destination | Destination receives the real secret; module memory holds only `${API_KEY}` | `secret.substituted` |
| `denied` | default-deny | Refused; destination never contacted | refusal entry |
| `unbound` | host admitted, secret not bound to it | Request forwarded **without** the secret; placeholder dropped | `secret.placeholder_dropped` |

The third is the claim-12 bind check, and it is the one most people do not
expect: the destination is reachable and the request still goes out stripped.

### Four panes at `/demo`

1. **Module + policy** — pick a module; edit the allow-list. The editor's
   output is a real `NetworkPolicy` deserialized by `mvm-contract`, not a
   demo-shaped struct.
2. **Module view** — what the guest holds. Shows the placeholder, never a value.
3. **Destination view** — the exact bytes a simulated destination received,
   labelled as simulated.
4. **Audit chain** — entries append live. **Verify** runs
   `verify_audit_chain_bytes`. **Tamper** flips one byte and re-verifies,
   surfacing the typed failure with its line index (`PrevHashMismatch { line }`
   or `SignatureInvalid { line }`, straight out of `AuditVerifyError`).

The tamper button is the demo's strongest moment: it is the one property a
visitor can falsify themselves, in their own browser, offline.

### One run, end to end

1. Main thread posts `{moduleId, policyJson}` to the Worker.
2. The Worker instantiates the curated module, supplying `mvm:egress` as a JS
   trampoline into the core.
3. On each host-call the core canonicalizes the policy via
   `canonicalize_network_policy`, decides via `wasi_allows`, resolves `${NAME}`
   on allow, constructs and chain-signs an audit entry, and returns the outcome.
4. On completion the Worker posts back the module view, the destination view and
   the raw chain bytes.

### Two stated simplifications

- **No resolver.** `wasi_allows` takes an `IpAddr` and a browser has no
  resolver, so the demo ships a fixed hostname→IP map as a fixture. DNS pinning
  is out of scope.
- **A fixed demo key, committed to the repo.** Reproducible, and it keeps a
  `getrandom` shim out of the bundle. It demonstrates chain integrity and
  tamper detection, not host key custody.

Both appear in the page's own copy, not only here.

## Error handling

ADR-024 §2 binds the demo core exactly as it binds the host tier. A curated
module that reaches for a capability the core does not provide receives a typed
error naming what *is* supported — never a silent no-op, never a degraded
approximation.

The Worker propagates every error to the UI; nothing is swallowed into a blank
pane. A failed run renders *why*, because a fail-closed refusal is the product
behavior on display, not an embarrassment to hide.

## Honesty guardrails

The failure mode ADR-024 warns about is a demo that overstates. Three
assertions, all in Rust, all in CI:

- [ ] The fixture secret value does **not** appear anywhere in the
      module-visible bytes, on any of the three modules. (claim-13 property,
      asserted the way `wasm_egress_witness.rs` asserts it)
- [ ] The secret **does** appear in the destination view on `allowed`, and
      **does not** on `unbound`. Positive and negative, so a broken
      substitution cannot pass by doing nothing.
- [ ] The tier's capability description renders from a Rust-owned constant, so
      the page's "what this does not prove" text cannot drift from the code.

No claim-catalog witness is added. `xtask check-claim-catalog` reads ADR-001's
table; this work touches no row. That is deliberate, and it is ADR-024 §3.

### What the page must state plainly

- The browser is the wasm engine. The host `WasmBackend` is not exercised.
- This is a portability and governance demo, not an isolation boundary.
- The claims-bearing way to run a wasm workload is plan 321's engine-in-guest
  path, and the page links to it.

## Testing

The regression oracle is `crates/mvm-hostd/tests/wasm_egress_witness.rs`. It
drives the real `SubstitutionService`, so if E2 or E3 changes behavior it goes
red. **It must stay green unmodified** — that is the condition for believing the
extraction was faithful. If it needs editing, the extraction was not a
relocation and the design is wrong.

- [ ] Full `cargo nextest run --workspace` for E1's ~20 call sites.
- [ ] The existing wasm lane (`scripts/ci-linux-coverage.sh:20,23`) already
      builds `mvm-contract` for `wasm32-unknown-unknown` and runs its tests
      under `wasm32-wasip1`. The relocated projection tests then run *under
      wasm* for free — closing plan 301 P1's "tests under wasm" gap for this
      module as a side effect.
- [ ] A fixture-parity test: the three browser fixtures produce the same
      outcomes the host witness asserts.
- [ ] `web/mvm-demo/` excluded from the workspace, as `web/audit-verify/` is.
- [ ] `wasm-opt -Oz` plus a gzipped-size budget in that same lane (plan 301 B4's
      discipline), failing the lane on regression.
- [ ] Built in the builder VM, never a host toolchain (ADR-004 / ADR-007).
- [ ] `cargo fmt --all -- --check` (nightly, per CI Lint),
      `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo test --workspace --doc`, xtask gates.

## Sequencing constraints

- **PR #2359 "Redesign the marketing site and docs chrome"** is open and
  rewrites all of `public/src/components/landing/` (54 files), plus
  `astro.config.mjs` and two new site gates
  (`check-no-hardcoded-hex.mjs`, `check-sample-provenance.mjs`). The landing
  teaser must be built against the redesigned page or it will be written and
  then deleted. The `/demo` route itself is independent. Check both new gates
  apply cleanly to the demo's rendered sample output.
- **`feat/301-b1-nostd-oci-decoders`** is in flight and is also extracting into
  `mvm-contract`, in a different module (OCI decoders vs. projection). Low
  semantic conflict, but expect `crates/mvm-contract/Cargo.toml` to conflict
  textually.
- **PR #2355 `feat/308-wasm-bounds`** touches the host wasm tier (fuel and
  epoch bounds). No overlap with this plan's files, but land order matters if
  both touch `wasm_backend.rs`.

## Non-goals

- Any numbered security claim for the browser tier. ADR-024 §3.
- Exercising the host `WasmBackend` or `wasmtime` from the page. Structurally
  impossible; the page says so.
- Merkle inclusion proofs. Plan 301 B5 retires `web/audit-verify/` only once its
  replacement covers chain verification **and** Merkle inclusion. This demo
  covers the former only, so `web/audit-verify/` stays and B5 remains plan
  301's.
- `mvmctl audit pubkey`. Not needed here — the demo uses a fixed key. Remains
  plan 301 B5's.
- Arbitrary user-uploaded modules. Curated fixtures only.
- Replacing JCS canonical JSON anywhere on the signed control plane.
