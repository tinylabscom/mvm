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

## Task S2.2 — per-run cert delivery to the guest ✅ DONE

**Implemented shape (differs slightly from the original sketch — boot ordering forced the split across crates):** the FC secrets drive is sealed *before* `wire_egress_substitution` runs, so the mint+cert-push happens in `mvmctl up` (`mvm-cli`, where `secret_files` is assembled), not in `wire_egress_substitution`. The key flows forward to the endpoint via a host-only sidecar.

- [x] **Bound-host provenance (resolved, no fork):** `SecretBinding` is only `{name, source}`; the egress allow-list (`allowed_hosts`) lives in the host **binding store** (`mvm_hostd::keyholder::FileBindingStore`). `stage_egress_tls_delivery` resolves the name-constraint set as the **union of every plan secret's `allowed_hosts`** — the SAME claim-12 allow-list, so the intermediate's `nameConstraints` can never exceed it. Reuse, not a new traversal.
- [x] **`build_egress_tls_delivery(bound_hosts, ca_dir)`** (`mvm-backend::substitution_spawn`, re-exported): mints under the host CA (`mvm_core::config::egress_ca_dir()`), returns `EgressTlsDelivery { guest_cert: DriveFile, endpoint_cert_pem, endpoint_key_pem }` (redacted `Debug`). Tests: cert-to-guest/key-to-endpoint split + no key in the guest file + redacted Debug.
- [x] **`mvmctl up` → `stage_egress_tls_delivery`** (both the main + watch-rebuild `secret_files` paths): pushes the cert (`mvm-egress.crt`, mode 0444) onto the guest secrets drive and persists the cert+key to host-only `<vm_state_dir>/egress-intermediate.json` (mode 0600, atomic tmp+rename). No-op without secrets/bindings. Test asserts the cert lands in `secret_files` (no key) and the 0600 sidecar holds the key.
- [x] **`EndpointConfig.tls_intermediate: Option<TlsIntermediate{cert_pem,key_pem}>`** (`#[serde(default)]`, redacted `Debug`); `spawn_substitution_endpoint` gained a `tls_intermediate` arg → cfg JSON; `wire_egress_substitution` reads the sidecar (`read_egress_intermediate`, Linux) and hands the **key** to the endpoint — never the guest. Tests: serde roundtrip + default-None + Debug-redacts-key.
- [x] Gates clean: clippy, fmt, `check-core-runtime-free`, `check-no-display-on-secret-types`; 2911 + egress tests green.
- [x] **Commit** — `feat(terminator): deliver per-VM egress cert to guest, key to endpoint (plan 129 stage 2)`.

## Task S2.3 — guest trust install

> **⚠️ BLOCKED — channel assumption is wrong (found while scoping S2.3, 2026-06-10).**
> The original sketch ("the secrets drive mounts the cert; the boot step concats
> it") does **not** hold for the sealed-FC workload path:
> - `nix/lib/mk-guest.nix`'s `/init` mounts **neither** the `mvm-secrets` nor the
>   `mvm-config` drive — `grep -ni secret nix/lib/mk-guest.nix` is empty; the only
>   per-VM mounts are `mvm.uvols` user volumes (kernel cmdline).
> - The per-VM **runtime overlay** (`/mvm/runtime`, ADR-051) is **verity-sealed**
>   (build-time roothash via `mvm-verity-init`), so a boot-minted cert can't ride
>   it either.
> - The proven per-VM placeholder-env channel is **`invoke.rs`** (the invoke
>   dispatch injects `HTTP_PROXY` + placeholder vars into the agent-run call) —
>   **not** the sealed *entrypoint* path that S2.7's generic `curl https://` uses.
>   No entrypoint-env injection of placeholders for the FC sealed path exists yet
>   (`rg` for it is empty).
>
> **Implication:** S2.2's cert-via-`secret_files` (secrets drive) is **inert on
> sealed FC** until a real per-VM guest channel exists. The host-side split
> (key→endpoint) S2.2 landed is still correct; only the guest-delivery leg is
> affected.
>
> **Recommended S2.3 redesign (sealed-rootfs-safe):** deliver the per-VM cert
> over the **same per-VM channel that carries the entrypoint placeholder env**
> (to be established — likely a small `/init` step that reads a per-VM mutable
> source the host writes: kernel cmdline blob, an `/init`-mounted config drive,
> or an agent/vsock fetch), then write it to a **tmpfs** path (`/run/mvm/
> egress-ca.crt`) and export `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` /
> `NODE_EXTRA_CA_CERTS` pointing at `cat ca-bundle.crt egress-ca.crt`. Tmpfs keeps
> it writable under dm-verity. **Decide the channel before coding S2.3/S2.7.**

**Files (original sketch — revisit per the block above):** `nix/lib/mk-guest.nix` (a boot step that appends any `/etc/ssl/certs/mvm-egress-*.crt` to the trust bundle before the entrypoint) + matching guest `/init` wiring. Honest caveat documented inline.

- [ ] **Step 1:** Decide the install mechanism (append to `ca-bundle.crt` at boot vs `update-ca-certificates`-style) — the secrets drive mounts the cert; the boot step concatenates it into the trusted bundle the guest's TLS stack reads (`/etc/ssl/certs/ca-bundle.crt`, baked by mkGuest at `mk-guest.nix:809`). Test: a mkGuest fixture / boot-script unit asserts the concat step runs before the entrypoint and only for present `mvm-egress-*.crt`.
- [ ] **Step 2–4:** Implement + the inline caveat comment (Python/older-Node don't enforce nameConstraints → host allow-list is the boundary). **Commit** — `feat(guest): trust per-VM egress cert at boot (plan 129 stage 2)`.

## Task S2.4 — TLS termination + SNI-gated splice in the terminator ✅ DONE (4 slices)

**Files:** `crates/mvm-hostd/src/supervisor/terminator/tls.rs` (new); `substitution_proxy.rs` accept loop branches `:80`→Stage-1b vs `:443`→`handle_https_terminator`. `rustls` + `rustls-pemfile` added as direct mvm-hostd deps.

Landed in four committed slices, each TDD'd:
- [x] **S2.4a** (`76344771`) — `parse_sni`/`peek_sni`: pure, total ClientHello SNI parser (bounds-checked, never panics on hostile/truncated input). Tested vs real rustls ClientHellos + every truncation prefix + garbage.
- [x] **S2.4b** (`b7b1791a`) — `server_config_for_sni` (mint leaf under intermediate, present `[leaf, intermediate]`) + `terminate_and_substitute` (rustls handshake → decrypt → `prepare_request` substitute, claim-12 fail-closed → forward closure → write back). `VmIntermediate::from_pem` reconstructor; `read_http_request` generic over `Read`; `proxy_request_from_origin_form_https`. **Headline test `bound_sni_terminates_substitutes_and_reoriginates`**: real rustls client trusting the intermediate completes the handshake against the minted leaf; mock upstream sees the **real** credential over `https://`.
- [x] **S2.4c** (`4f9deaf5`) — `splice_unbound` + `unbound_sni_is_spliced_without_termination`: unbound SNI byte-spliced both ways, never decrypted, no leaf minted.
- [x] **S2.4d** (`8e442395`) — accept-loop wiring: branch on `orig_dst.port()`; `handle_https_terminator` peeks SNI → `host_is_bound` gate → terminate (reqwest upstream, audited) or splice. Threads `tls_intermediate` through `assemble`→`from_plan`→service. Verified host (1994 tests) + Linux cross-build (`cargo-zigbuild aarch64-unknown-linux-gnu`).
- [x] **`upstream_tls_validates_against_system_roots`** — satisfied **by reuse**, not a new test: the upstream re-origination leg is the existing hardened `ReqwestForwarder` (`hardened_client_builder_no_dns`, TLS 1.3 min, **no** `accept_invalid_certs` anywhere), which validates against the default root store by construction (covered by `hardened_client_builds_successfully` / `w7_min_tls_version_is_pinned_at_1_3` + the box e2e). A loopback negative test is precluded — the forwarder's own SSRF filter blocks loopback *before* the TLS leg — and a badssl.com test would be non-hermetic/flaky.

## Task S2.5 — extend the redirect to `:443`

**Files:** `crates/mvm-backend/src/egress_redirect.rs` (add a `:443` rule alongside `:80`; `nft_rule_argv` currently hardcodes `"80"` — parameterize the dport or emit both rules into the per-VM table); `wire_egress_substitution` unchanged except both ports now steer to the terminator.

- [x] **DONE** (`1e50e4b1`) — `nft_rule_argv` gains a `dport` param; `REDIRECTED_DPORTS = [80, 443]`; `install` emits one rule per port into the per-VM table (terminator demuxes via `SO_ORIGINAL_DST`). Drop/teardown unchanged. Test `install_redirects_both_80_and_443_to_the_terminator`.

## Task S2.6 — ADR updates

**Files:** `specs/adrs/006-name-constrained-egress-ca.md` (status Proposed → Accepted; record the implemented shape: per-VM intermediate, SNI-gated termination, unbound-splice, the zero-added-visibility argument, and the Python/Node nameConstraints caveat); `specs/adrs/067-secrets-subsystem-egress-substitution.md` (make **proxy-native primary / SDK optional**).

- [x] **DONE** — ADR-006 status Proposed → **Accepted** with an as-implemented section (per-VM intermediate, SNI-gated termination, unbound-splice, zero-added-visibility argument, Python/Node nameConstraints caveat) cross-linking plan 129 + ADR-067. ADR-067 §1 retitled "proxy-native transparent substitution (SDK optional)" with an update block flipping primary↔SDK and superseding the coverage caveat for bound hosts; the "TLS MITM of all egress" rejected-alternative now distinguishes the scoped name-constrained terminator. **Commit** — `docs(adr): accept ADR-006; ADR-067 proxy-native primary (plan 129 stage 2)`.

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
