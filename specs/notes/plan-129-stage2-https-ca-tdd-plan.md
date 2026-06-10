# Plan 129 Stage 2 — name-constrained CA + `https` termination (TDD plan)

> **For agentic workers:** REQUIRED SUB-SKILL — use superpowers:subagent-driven-development or superpowers:test-driven-development to implement task-by-task. Steps use checkbox (`- [ ]`) syntax. Builds directly on Stage 1b (merged: terminator core #735, FC wiring #744).

**Goal:** Extend the transparent egress terminator from `http` to **`https`** so a generic guest client (`curl https://api…`, no SDK) gets its placeholder swapped for the real credential — by terminating TLS at the host with a **per-VM name-constrained CA the guest trusts**, substituting on the decrypted request, and re-originating real TLS upstream. Bound hosts only; unbound SNI is spliced through untouched.

**Architecture (delta over Stage 1b):**
- Stage 1b redirects guest `:80` to the terminator, which reads cleartext HTTP, substitutes via `handle_request`, and raw-splices to the origin (`forward_http_raw`).
- Stage 2 also redirects guest `:443`. The terminator peeks the TLS ClientHello SNI:
  - **bound SNI** → terminate TLS with an on-the-fly leaf signed by the per-VM name-constrained intermediate → decrypt → reuse `handle_request` to substitute → re-originate a real upstream TLS connection (validated against the system root store) → stream back.
  - **unbound SNI** → **splice passthrough** (no termination; end-to-end TLS preserved; zero added host visibility).
- The guest trusts only the **per-VM intermediate cert** (delivered per-run; never the host CA, never any key). The intermediate carries `nameConstraints permitted = the plan's bound hosts`.

**Why this is not the rejected blanket MITM (ADR-006 §rationale):** the host already sees bound-host plaintext via the injector (it must, to substitute). Scoped name-constrained termination of *only* bound hosts adds **zero** host visibility over what substitution already requires, and the CA is cryptographically constrained so it cannot vouch for any host outside the plan's allow-list. Unbound traffic is never decrypted.

**Honest caveat (defense-in-depth, state it in code + ADR):** Python `ssl` and older Node do **not** enforce X.509 `nameConstraints` client-side. So the in-guest cert constraint is a courtesy, not the boundary — **the host-side allow-list check in `prepare_request` (claim 12) remains the real egress boundary.** The CA constraint limits blast radius if the per-VM intermediate ever leaked; it is not the primary control.

**Tech stack additions:** `rcgen` (≥0.13, for `nameConstraints`) — new workspace dep; `rustls` as a **direct** dep for the terminator's TLS server (today it's only transitive via `reqwest`). Reuse: `prepare_request`/`SubstitutionEndpoint`/`handle_request`, `EgressRedirect`, `wire_egress_substitution`, `create_dev_secrets_drive`, mkGuest trust bundle.

**Scope:** Linux/Firecracker (the Stage 1b backend). macOS/gvproxy + libkrun-on-Linux remain out of scope. Box e2e is Firecracker (see the Stage 1b bringup prompt `specs/prompts/129-fc-bringup-debug.md` — the live FC e2e + local secret-launch glue (#745) are its prerequisites; Stage 2's box e2e (S2.7) is gated on Stage 1b's e2e first going green).

**Prereqs:** Stage 1b merged. `rcgen` version check (S2.1 step 0). Stage 1b live FC e2e green (for S2.7 only — the code tasks S2.1–S2.6 don't need the box and unit-test on macOS).

---

## Task S2.1 — per-VM name-constrained CA module ✅ DONE (commit e2ff6b02)

**Files:** Created `crates/mvm-core/src/crypto/egress_ca.rs` (+ feature-gated `pub mod egress_ca;` in `crypto/mod.rs`). Added `rcgen` (workspace + mvm-core, behind `egress-ca`). Tests in-file.

- [x] **Step 0:** `rcgen` pinned at **0.14** (not 0.13 — 0.13.2's `Issuer` is private; 0.14 exposes `Issuer::from_ca_cert_pem`, gated behind `pem`+`x509-parser`). `ring` backend, no aws-lc-rs/cmake. Gated behind mvm-core's new **`egress-ca`** feature so the runtime-free default build pulls no rcgen — `xtask check-core-runtime-free` still clean (verified).
- [x] **Step 1–4: Tests + impl (all green):**
  - `host_ca_is_self_signed_ca_true` ✓ (+ deterministic reload).
  - `ca_key_is_mode_0400` ✓.
  - `intermediate_is_name_constrained_to_bound_hosts` ✓ (nameConstraints permitted = exactly the bound host).
  - `intermediate_refuses_to_sign_a_leaf_for_an_unbound_host` ✓ — asserted via a **real rustls/webpki path verifier** (bad SNI rejected, bound SNI accepted), not field inspection.
  - `EgressCa { load_or_init_at, mint_vm_intermediate, cert_pem }` + `VmIntermediate { cert_pem, key_pem, mint_leaf }` + `Leaf`. Every key-carrying type has a **redacted `Debug`** (`check-no-display-on-secret-types` clean); only certs leave the host process.
  - **Deferred:** explicit zeroize-on-drop of the in-memory `KeyPair` — `rcgen::KeyPair` doesn't expose its key buffer for zeroization; redacted `Debug` covers the accidental-log risk. Note for hardening.
  - `load_or_init_at(dir)` takes the dir as a param (test-friendly); the `~/.mvm/egress/` config-helper wiring lands with the caller in S2.2.
- [x] **Step 5: Commit** — `feat(egress-ca): name-constrained per-VM CA (plan 129 stage 2)` (e2ff6b02).

## Task S2.2 — per-run cert delivery to the guest

**Files:** `crates/mvm-backend/src/microvm.rs` (thread the per-VM intermediate cert into the FC guest via the existing secrets-drive channel — `config.secret_files` / `create_dev_secrets_drive`); `crates/mvm-backend/src/substitution_spawn.rs` / `wire_egress_substitution` (mint the intermediate when the plan has secrets, hand the cert to the guest + the intermediate key to the terminator endpoint config).

- [ ] **Step 1: Failing test** — given a secret-bearing plan, `wire_egress_substitution` (unit-extractable helper) produces a `DriveFile` carrying the per-VM intermediate **cert** at a fixed guest path (e.g. `/etc/ssl/certs/mvm-egress-<vm>.crt`) and the endpoint config carries the intermediate **key** (terminator side) — assert the key is NOT in the guest-delivered set (only the cert reaches the guest). Reuse the claim-13-style "no key to guest" assertion shape.
- [ ] **Step 2: Run (fail). Step 3: Implement** — mint intermediate (S2.1), add its cert to `config.secret_files` (so `create_dev_secrets_drive` injects it), pass the key + cert to the `EndpointConfig` (new `tls_intermediate: Option<{cert_pem, key_pem}>` field, `#[serde(default)]`, redacted `Debug`). Gate on `!plan_secrets.is_empty()` (same gate as the redirect).
- [ ] **Step 4: pass. Step 5: Commit** — `feat(terminator): deliver per-VM egress cert to guest, key to endpoint (plan 129 stage 2)`.

## Task S2.3 — guest trust install

**Files:** `nix/lib/mk-guest.nix` (a boot step that appends any `/etc/ssl/certs/mvm-egress-*.crt` to the trust bundle before the entrypoint) + matching guest `/init` wiring. Honest caveat documented inline.

- [ ] **Step 1:** Decide the install mechanism (append to `ca-bundle.crt` at boot vs `update-ca-certificates`-style) — the secrets drive mounts the cert; the boot step concatenates it into the trusted bundle the guest's TLS stack reads (`/etc/ssl/certs/ca-bundle.crt`, baked by mkGuest at `mk-guest.nix:809`). Test: a mkGuest fixture / boot-script unit asserts the concat step runs before the entrypoint and only for present `mvm-egress-*.crt`.
- [ ] **Step 2–4:** Implement + the inline caveat comment (Python/older-Node don't enforce nameConstraints → host allow-list is the boundary). **Commit** — `feat(guest): trust per-VM egress cert at boot (plan 129 stage 2)`.

## Task S2.4 — TLS termination + SNI-gated splice in the terminator

**Files:** Create `crates/mvm-hostd/src/supervisor/terminator/tls.rs`; modify `listener.rs`/`serve_terminator` to branch http(:80)→Stage-1b path vs https(:443)→TLS path. Add `rustls` as a direct dep of `mvm-hostd`.

- [ ] **Step 1: Failing tests** (loopback, no VM):
  - `peek_sni_extracts_servername_from_clienthello` — a helper reads the SNI from the buffered ClientHello without consuming the stream (peek/replay).
  - `bound_sni_terminates_substitutes_and_reoriginates` — drive a loopback TLS client trusting a test intermediate at a bound SNI through the terminator with a mock upstream; assert the upstream saw the **real** credential (placeholder substituted) and the client got the response. Reuse `handle_request` for the substitution core (assert on the forwarded `PreparedRequest`).
  - `unbound_sni_is_spliced_without_termination` — an unbound SNI is byte-spliced both ways; assert the terminator never decrypts (no leaf minted, bytes pass through verbatim).
  - `upstream_tls_validates_against_system_roots` — re-origination rejects an upstream with an untrusted cert (no blind trust on the forward leg).
- [ ] **Step 2: Run (fail). Step 3: Implement** — `tls.rs`: buffer+peek ClientHello → SNI; if bound (per the endpoint's binding set), build a `rustls::ServerConfig` resolving a freshly-minted leaf (S2.1 `mint_leaf(sni)`) under the per-VM intermediate, accept, read the decrypted HTTP request (reuse `read::read_http_request` semantics over the TLS stream), `handle_request` to substitute, then forward over a **real** upstream TLS (rustls client w/ system roots; reuse the hardened-client posture from `ReqwestForwarder` where practical), stream the response back; if unbound, `splice_bidirectional` (the existing helper in `qemu.rs` — lift it to a shared util) with no decryption. Per-connection errors logged, fail-closed (a bound SNI whose substitution refuses → drop, never forward — same claim-12 invariant as Stage 1b).
- [ ] **Step 4: pass. Step 5: Commit** — `feat(terminator): SNI-gated TLS termination + substitution, splice unbound (plan 129 stage 2)`.

## Task S2.5 — extend the redirect to `:443`

**Files:** `crates/mvm-backend/src/egress_redirect.rs` (add a `:443` rule alongside `:80`; `nft_rule_argv` currently hardcodes `"80"` — parameterize the dport or emit both rules into the per-VM table); `wire_egress_substitution` unchanged except both ports now steer to the terminator.

- [ ] **Step 1: Failing test** — `EgressRedirect::install` emits redirect rules for **both** 80 and 443 to the terminator port (assert both `nft_rule_argv(..,80)` and `..443)` token vectors are produced). Keep the pure-function test shape from Stage 1b.
- [ ] **Step 2–4:** Implement (idempotent table holds both rules; Drop/teardown_by_name unchanged — whole-table delete already covers both). **Commit** — `feat(terminator): redirect guest :443 to the terminator (plan 129 stage 2)`.

## Task S2.6 — ADR updates

**Files:** `specs/adrs/006-name-constrained-egress-ca.md` (status Proposed → Accepted; record the implemented shape: per-VM intermediate, SNI-gated termination, unbound-splice, the zero-added-visibility argument, and the Python/Node nameConstraints caveat); `specs/adrs/067-secrets-subsystem-egress-substitution.md` (make **proxy-native primary / SDK optional**).

- [ ] Amend both ADRs; cross-link to this plan + #735/#744. Note that scoped name-constrained termination ≠ the rejected blanket MITM. **Commit** — `docs(adr): accept ADR-006; ADR-067 proxy-native primary (plan 129 stage 2)`.

## Task S2.7 — box e2e (`https`, SDK-free) — the headline acceptance

**Gated on Stage 1b's live FC e2e first being green** (`specs/prompts/129-fc-bringup-debug.md`) and #745 (local secret-launch glue). Validation only; append results here.

- [ ] Store+bind a secret to a **real https** bound host; boot the secret-egress workload on FC; the guest entrypoint runs a generic `curl -s https://<bound-host>/ -H "Authorization: Bearer $TOKEN"` ($TOKEN = placeholder, no SDK).
- [ ] Assert: the destination received the **real** credential over TLS; the guest holds only `mvm-secret-…` and the per-VM cert (never the host CA/key); `secret.substituted` audited (no secret bytes); an **unbound** https host is spliced (works, not terminated, not substituted) and a placeholder sent to an unbound host is refused (claim 12); the host's own egress is untouched.
- [ ] Record PASS/FAIL + log paths.

---

## Self-review / risks

- **Spec coverage:** name-constrained CA (S2.1) ✓; cert-to-guest / key-to-host split (S2.2) ✓; guest trust (S2.3) ✓; SNI-gated terminate-vs-splice + upstream-TLS-validate (S2.4) ✓; :443 redirect (S2.5) ✓; ADR-006/067 (S2.6) ✓; e2e (S2.7) ✓.
- **Reuse verified:** `handle_request` (`terminator/handler.rs:18`), `EgressRedirect`/`nft_rule_argv` (hardcoded `"80"` → parameterize), `create_dev_secrets_drive`/`secret_files` (`microvm.rs:1611/577`), mkGuest trust bundle (`mk-guest.nix:809-812`), `splice_bidirectional` (lift from `qemu.rs`). ADR-006/067 exist (006 status Proposed).
- **New deps:** `rcgen` (≥0.13, nameConstraints) + direct `rustls` for the terminator server — both must respect mvm-core's runtime-free invariant (egress_ca in mvm-core stays sync; rustls lives in mvm-hostd, already async). Re-check `xtask check-core-runtime-free`.
- **Honest boundary:** client-side nameConstraints is defense-in-depth, NOT the egress control — `prepare_request`'s host allow-list (claim 12) is. Stated in S2.3 + S2.6.
- **Fail-closed parity:** the TLS path must preserve Stage 1b's invariant — a bound-host request whose placeholder is unknown / dest unbound never reaches `forward`. The unbound-SNI splice must never decrypt.
