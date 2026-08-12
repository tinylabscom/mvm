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

Every consumer imports through the `mvm_core::policy::projection` path —
`EgressGate`, `mvm-net`'s L3 admit, `mvm-hostd`'s proxy and DNS handler,
`mvm-conformance` — roughly twenty call sites. `mvm-core` re-exports the
relocated module under that same path, so none of them change.

`projection_fs_env.rs` (567 lines, the fs/env analogue) stays in `mvm-core`.
The demo does not need it.

**Status: SHIPPED.** The relocation landed as a `git mv` plus a nine-line
diff (the `std::net` → `core::net` swap, the `alloc` prelude, and
`std::str::FromStr` → `core::str::FromStr`); no consumer moved.

- [x] `crates/mvm-core/src/policy/projection.rs` →
      `crates/mvm-contract/src/policy/projection.rs`, verbatim.
- [x] `ipnet = { version = "2", default-features = false }` added to
      `mvm-contract`. Under `no_std` its `AddrParseError` implements
      `core::error::Error`, which is what `ProjectionError`'s `thiserror`
      derive needs to carry it as a `source`.
- [x] `mvm-core`'s `policy/mod.rs` re-exports the module as
      `pub use mvm_contract::policy::projection`, alongside the existing
      DTO-leaf module aliases. Every `mvm_core::policy::projection::X`
      path resolves unchanged; zero call sites edited.
- [x] `projection_fs_env.rs` stayed in `mvm-core`.
- [x] `crates/mvm-hostd/tests/wasm_egress_witness.rs` green **unmodified**.

One dependency the table above missed, resolved the same way: projection
decides with `is_mandatory_deny` / `mandatory_deny_ranges`, which Increment
3 left in `mvm-core`'s `network_policy.rs` logic half because they are
`ipnet`/`std::net`-typed. Both are pure predicates over the already-relocated
`MANDATORY_DENY_RANGES` const, so they moved down with `unmap_v4_mapped` and
their ten tests, and `mvm-core` re-exports all three. The iptables script
generators — the genuinely host-only half — stayed put.

This supersedes
[10-increment3-protocol-core-split.md](../refactor/10-increment3-protocol-core-split.md)'s
`policy/` disposition table, which lists `projection.rs` as **core whole**.
That was correct for a DTO-only increment; E1 moves a decision core, not a
DTO, on the different rationale that the browser must run the host's gate
rather than a copy of it.

### E2 — placeholder substitution

**Status: NOT STARTED. Boundary mapped below; three corrections to the
paragraph this section used to contain.**

The original text read: "the pure resolution core teased out of
`crates/mvm-hostd/src/keyholder/substitution.rs` (509 lines) … locating
`${NAME}` placeholders in a request". Against the code, that sentence is
wrong three times over, and each error would have cost implementation time.

**Correction 1 — `${NAME}` is not the runtime wire form.** The token a guest
holds is `mvm-secret-<hex>`, minted per session by
`SubstitutionRegistry::mint` under the reserved `PLACEHOLDER_PREFIX =
"mvm-secret-"`. `${NAME}` is an *authoring* notation that appears in the
Workload IR and in `wasm_backend.rs`'s doc comment; nothing resolves it at
runtime. The oracle pins this — `wasm_egress_witness.rs` asserts the
destination sees neither the placeholder *nor* a literal `${`.

There is a third, unrelated prefix: `mvm-managed:` in
`mvm_contract::policy::secret_binding`. Three notations, none
interchangeable. Name the one you mean.

**This is a demo-honesty issue, not only a naming one.** Pane 2 ("Module
view — what the guest holds. Shows the placeholder, never a value") must
render the opaque minted token. If it renders `${API_KEY}` because that
reads better, the page is showing a form the runtime never produces, in the
one pane whose whole job is to be what the guest actually holds.

**Correction 2 — the core spans three files, not one.** The path from a
guest's header to a credential on the wire:

| Step | Location | Lines |
|---|---|---|
| Mint per-secret placeholders from the plan's bindings | `keyholder/admission.rs::assemble_registry` | 55–92 |
| Walk each header, find a token, branch inject-vs-sign | `supervisor/substitution_proxy.rs::prepare_request` | 118–192 |
| Resolve token → `SecretRef`, dispatch | `keyholder/substitution.rs` | whole file |
| Bind-check, decrypt, replace | `keyholder/injector.rs::inject_placeholder` | 53–75 |

The step the demo replays is `prepare_request` — the per-header walk.
`substitution.rs` alone gets you the registry and none of the walk.

**Correction 3 — `mint` cannot move as written.** It draws 24 bytes from
`rand::thread_rng()`. That is the same `getrandom`-in-the-bundle problem the
plan already decided against for the audit key. Split it: a pure
`insert(token, secret_ref)` moves, token generation stays host-side, and the
browser supplies a fixture token exactly as it supplies fixture values.

#### Moves / stays

| Item | Where | Disposition |
|---|---|---|
| `PLACEHOLDER_PREFIX`, `Placeholder`, `as_str` | substitution.rs 30–45 | **→P** — opaque newtype over `String` |
| `find_placeholder` | substitution.rs 52–63 | **→P** — pure `&str` scan |
| `SubstitutionRegistry` map + `resolve` + `host_is_bound` | substitution.rs 71–108 | **→P** — `host_matches` is already in `mvm_contract::ir` |
| `SubstitutionRegistry::mint` | substitution.rs 83–89 | **split** — `insert(token, ref)` →P; the RNG draw stays |
| The claim-12 bind check | injector.rs 68–70 **and** substitution.rs 191–199 | **→P once.** It is written twice today; move one copy, call it from both |
| `text.replace(placeholder, value)` | injector.rs 74 | **→P** as `substitute_into(text, placeholder, value) -> String` |
| `SubstituteError`, `SignDispatchError`, `InjectError` | 3 files | **split** — pure variants (`UnknownPlaceholder`, `DestinationNotBound`, `WrongAuthType`) →P; `Resolve(_)` stays |
| `SecretResolver`, `LocalResolver`, `FileSecretStore` | resolver.rs, mvm-core | **stays** — key custody |
| `Injector`'s resolve leg, `Zeroizing`/`secrecy` | injector.rs | **stays** — the browser has no value to zeroize |
| `Signer`, `sigv4.rs`, `SigningInput` | signer.rs, sigv4.rs | **stays** — no demo fixture signs |
| `assemble_registry` | admission.rs | **stays** — reads a `BindingStore` off the filesystem |
| `substitution_proxy.rs` transport | proxy | **stays** — UDS/TLS/async |
| `prepare_request`'s header walk | proxy 118–192 | **split** — pure over owned headers once the endpoint is a trait. The largest judgement call in E2; give it its own commit |

`Zeroizing<String>` is the host-side return type and is meaningless in a
browser (no `mmap`, no core dump, a GC'd heap). The moved `substitute_into`
returns a plain `String` and the host wraps it. Do **not** pull `zeroize`
into `mvm-contract` to preserve a signature.

#### Order

- [ ] E2.1 — `PLACEHOLDER_PREFIX` + `Placeholder` + `find_placeholder` →P.
      Leaf; nothing moves with it.
- [ ] E2.2 — de-duplicate the bind check into one fn, **in place, before it
      crosses a crate boundary**, so the claim-12 predicate has exactly one
      definition at the moment it moves.
- [ ] E2.3 — `SubstitutionRegistry` map/`resolve`/`host_is_bound` →P;
      `mint` splits.
- [ ] E2.4 — `substitute_into` →P; `Injector` calls it.
- [ ] E2.5 — decide `prepare_request`. Own commit, own review.

### E3 — audit-entry construction and chain signing

**Status: NOT STARTED. Boundary mapped. Lower-risk than E2 on the mechanics,
higher-risk on one decision that has to be made first.**

The writer core of `crates/mvm-hostd/src/supervisor/audit_file.rs` (1,401
lines): building a `SignedEnvelope` (entry + canonical bytes + `prev_hash` +
signature) and `hash_line`. `FileAuditSigner`'s filesystem, `flock`, mutexes
and async wrapper stay in `mvm-hostd`.

The old text said this is "lower-risk than its line count suggests" because
`mvm-contract`'s `verify.rs` "already implements the exact inverse". True,
and it is precisely why E3 cannot be done as a naive move.

#### The blocking decision: `mvm-contract` already has a `SignedEnvelope`

`mvm_contract::verify::SignedEnvelope` exists (verify.rs 88–102) and is
field-identical to hostd's. It carries a `MirrorEntry` — a hand-maintained
copy of hostd's `AuditEntry` with `DateTime<Utc>` flattened to `String` and
the newtype ids flattened to `String`, written that way because the real
entry was not reachable from `no_std`.

So E3 has three options, and picking one is the precondition for any code:

| Option | Consequence |
|---|---|
| **A. Move `AuditEntry` down, retire `MirrorEntry`, unify on one `SignedEnvelope`** | The prize. One definition, and the pre-`canonical` byte-exactness hazard stops being a cross-crate coupling. Largest diff |
| B. Move only the writer fns, keep both envelope types | Smallest diff. Leaves two structurally identical types in one crate, which is the drift the mirror's own doc comment warns about |
| C. Generic `SignedEnvelope<E>` over the entry type | Avoids the collision without deciding it. Adds a type parameter to a signed wire type — most churn per unit of value |

**Recommend A.** `AuditEntry`'s fields are `DateTime<Utc>`, `TenantId`,
`PlanId`, `Option<PolicyId>`, `String`, `BTreeMap<String, String>` — chrono
and all three id newtypes are already in `mvm-contract` from Increment 3, so
the type is portable *today*. `MirrorEntry` exists only because nobody
revisited it after those landed.

#### The name collision, to resolve before the move

Two unrelated types are already called `AuditEntry`:

- `mvm_contract::policy::audit::AuditEntry` — the mvmd
  tenant/pool/instance action record (`AuditAction`, `ThreatFinding`,
  `GateDecision`).
- `mvm_hostd::supervisor::audit::AuditEntry` — the chain-signed plan entry
  this section is about.

They share a name and nothing else. Both would sit in `mvm-contract` under
option A. Precedent is exact: Increment 3 hit this with two `NetworkPolicy`
types and resolved it by hard-renaming one to `BundleNetworkPolicy`, no
alias. Do the same, and do it **before** the move, so the rename and the
relocation are never in one diff.

#### Moves / stays

| Item | Where | Disposition |
|---|---|---|
| `SignedEnvelope` | audit_file.rs 52–71 | **→P** — unify with `verify.rs`'s under option A |
| `hash_line` | audit_file.rs 513–517 | **→P** — already duplicated in `verify.rs`; one definition after |
| `signed_bytes_for` | audit_file.rs 414–436 | **→P** — ditto; the writer and verifier halves become one fn |
| `AuditEntry` + `#[serde(deny_unknown_fields)]` | supervisor/audit.rs 33–61 | **→P** under option A, after the rename |
| `AuditEntry::for_plan` and the other constructors | supervisor/audit.rs 63+ | **stays** — `Utc::now()`. The standard orphan-rule rewrite: type moves, clock-reading constructor becomes a `mvm-core`/`mvm-hostd` free fn |
| Envelope construction (serialize → sign → b64 → hash) | audit_file.rs 304–318 | **→P** as a pure `seal(entry, prev_hash, &SigningKey) -> SignedEnvelope`. `ed25519_dalek::SigningKey` is already a `mvm-contract` dep |
| `VerifyError` | audit_file.rs 384–404 | **→P minus `Io`** — merge with `AuditVerifyError`, which is the same enum plus `KeyDecode` and minus `TruncatedTail` |
| `verify_audit_chain_entries` | audit_file.rs 450–511 | **stays** — takes a `&Path`. Its loop body is already `verify_audit_chain_bytes` in contract |
| `FileAuditSigner`, `open`, `restore_cursor`, cursors, `pending_sync` | audit_file.rs 76–264 | **stays** — fs, mutexes, `Drop` |
| `flock_exclusive` | audit_file.rs 378–382 | **stays** — `rustix` |
| `SyncPolicy`, `DEFERRABLE_EVENTS`, `sync_policy_for` | audit_file.rs 98–144 | **stays** — pure, but it is an fsync-scheduling policy. A browser has no fsync; moving it would be relocation for its own sake |
| `AuditSigner` trait | supervisor/audit.rs 286 | **stays** — `async_trait` |

`TruncatedTail` is the one verifier variant with no `mvm-contract`
counterpart, because it is a property of a file ending mid-record — the
browser verifies a `&[u8]` it already holds whole. It stays host-side; do not
add it to the merged enum.

#### The byte-identity gate

E3 touches signed bytes, which E1 did not. Increment 3's gate 6 is
mandatory here and was not needed for E1: **freeze a signed audit chain as a
fixture before the first commit, and assert byte-identical output after each
step.** `verify_audit_chain` on a pre-move chain must still pass after the
move — a chain written by yesterday's binary is evidence, and evidence that
stops verifying because a struct moved crates is the exact failure mode the
`canonical` field was introduced to prevent.

#### Order

- [ ] E3.0 — pick option A / B / C. Blocking.
- [ ] E3.1 — freeze the byte fixture (a signed multi-entry chain + its
      verifying key) and assert it verifies. Do this first, on `main`'s
      behaviour, so it is a real before-picture.
- [ ] E3.2 — hard-rename one of the two `AuditEntry`s. No alias.
- [ ] E3.3 — `hash_line` + `signed_bytes_for` de-duplicated to one
      definition each, `mvm-hostd` calling `mvm-contract`.
- [ ] E3.4 — `AuditEntry` →P (option A); `for_plan` becomes a free fn.
- [ ] E3.5 — unify `SignedEnvelope`, retire `MirrorEntry`.
- [ ] E3.6 — `seal()` →P; `FileAuditSigner::sign_and_emit` calls it.

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

- [x] Full `cargo nextest run --workspace` for E1's ~20 call sites.
      11064/11064 pass.
- [x] The existing wasm lane (`scripts/ci-linux-coverage.sh:20,23`) already
      builds `mvm-contract` for `wasm32-unknown-unknown` and runs its tests
      under `wasm32-wasip1`. The relocated projection tests then run *under
      wasm* for free — closing plan 301 P1's "tests under wasm" gap for this
      module as a side effect. **Holds:** `mvm-contract`'s wasip1 suite went
      from 651 to 715 tests — 54 relocated projection tests plus the 10
      mandatory-deny tests — and the pair that matters most, the
      cross-projection consistency property and `clamp_never_widens`, now
      decide under wasm. The same lane's `riscv32imac-unknown-none-elf`
      lib build also stayed green, so the decision core is bare-metal clean,
      not merely wasm clean.
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
