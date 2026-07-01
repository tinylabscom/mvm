# Plan-bound Agent Verb Grant: Out-of-Band Delivery + End-to-End Wiring

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Tracking:** issue #1381. **Stacks on:** the staged-core PR #1380 (Plan 215 Tasks 1–5a: `VerbId`, `ExecutionPlan.agent_verbs`, `VerbGrant` + mint, guest `enforce_verb_grant` wired after the class gate, `pin_verb_grant` / `load_host_signer_verifying_key` / `HOST_SIGNER_PUBKEY_PATH` verify-core). Sequences ADR-103. This plan is the **follow-on** that makes the (currently inert) guest enforcement live.

**Goal:** Provision the host-signer verifying key + the admitted plan nonce into a sealed guest per launch, deliver the minted `VerbGrant` to the agent, verify + pin it at handshake, and audit denials — so `AgentBootState.verb_grant` stops being always-`None` and the plan-bound verb check actually attenuates a real boot.

**Architecture:** The staged core proved the *types and the guest verify seam* with unit tests, but left three things unwired: (1) the guest has no host-signer pubkey to verify against (the placeholder `HOST_SIGNER_PUBKEY_PATH` sits on the read-only rootfs and is never populated); (2) the guest has no way to learn the admitted plan's `nonce`; (3) nobody mints the grant on the launch path or hands it to the agent. This plan closes all three by reusing the **existing per-launch out-of-band channel to a sealed guest**: the kernel cmdline hex-token mechanism (`mvm.egress_ca=`, `mvm.secret_env=`) that `/init` already decodes into `/run/mvm/`. The grant and pubkey are small, host-signer-controlled, and pre-computed before boot — exactly the shape that channel carries. The grant rides the same channel (not the ProtocolHello wire), so it reaches the agent before it binds vsock, and no host↔guest wire type changes.

**Tech stack:** Rust, `ed25519-dalek`, `serde`/`serde_json`, `chrono`. Nix (`nix/lib/mk-guest.nix` `/init`). Tests via `cargo nextest`; the mount + end-to-end delivery are **live-boot-validated** (marked per step).

---

## Resolved design decisions (the four forks)

### Fork 1 — plan_nonce provisioning: **(A) provision the nonce out-of-band, bound alongside the pubkey.**

`VerbGrant::verify` requires the guest to pass the *expected* `plan_nonce`; the guest doesn't know it today. Decision **(A)**: provision the admitted plan's `nonce` to the guest out-of-band on the same cmdline token that carries the pubkey and the grant (one `mvm.verb_grant=<hex(JSON)>` blob: `{ pubkey_hex, plan_nonce_hex, grant }`). The guest passes that `plan_nonce_hex` into `pin_verb_grant`, and `verify`'s `NonceMismatch` arm then actually binds the grant to *this* plan.

*Why not (B) session-id-only?* The workload readiness path's `ProtocolHello` (`negotiate_protocol`, `crates/mvm-guest/src/vsock.rs:2703`) is **unauthenticated and carries no `session_id`** — there is no per-VM handshake session id in scope on this path (the `AuthenticatedFrame`/`handshake_as_host` session id at `vsock.rs:2321` is a *different*, unused-on-this-path leg). So "bind to session_id only" would require inventing a session id and provisioning it out-of-band anyway — the same cost as provisioning the nonce, but weaker: the plan nonce is the claim-8 replay-ledger identity, so binding to it ties the grant to the exact admitted plan and defeats replay of a *broader* grant captured from an earlier plan for the same VM name. Provisioning the nonce is therefore both cheaper (it already exists in the stashed `plan.json`) and stronger. We still generate and bind a `session_id` field (the grant's `session_id` = the VM name + nonce-derived tag) so the signed payload keeps the ADR-103 shape and `SessionMismatch` stays a live check; the nonce is the load-bearing freshness bind.

### Fork 2 — delivery vehicle: **kernel cmdline hex token, NOT extending `ProtocolHello`.**

The workload boot path (Firecracker / libkrun / vz / qemu) attaches **no config drive** and uses **no authenticated `ProtocolHello`**; every per-launch, host-signer-controlled blob a sealed guest receives today rides the kernel cmdline as a hex token that `/init` decodes into `/run/mvm/` (`mvm.egress_ca`, `mvm.secret_env`, `mvm.uvols` — `crates/mvm-core/src/protocol/vm_backend.rs:234/252`, decoded in `nix/lib/mk-guest.nix` stages 2.46/2.47). The grant is pre-signed offline, tiny, and must reach the agent *before* it accepts the first vsock connection — the cmdline lands it in `/run/mvm/` in `/init` before the agent forks (stage 2.5), so it is pinned by the time `wait_for_guest_agent` probes. Extending `ProtocolHello` was rejected: it would require adding an `Option<VerbGrant>` to a `deny_unknown_fields` wire type, re-plumbing the unauthenticated readiness probe to carry a per-workload token, and threading the plan+keystore into `wait_for_guest_agent` (a readiness poller with neither) — all to duplicate a channel that already exists and already reaches a sealed guest. A dedicated post-handshake RPC verb is worse still (a new wire verb + a second round trip, and the agent would answer verbs before it's pinned). This *supersedes* the prompt's config-drive framing: the config drive (`mvm-config`, `create_dev_config_drive`) exists only on the legacy dev/default-image path and is not attached on any workload backend, so it is the wrong surface.

### Fork 3 — Gap 1 (guest provisioning + `HOST_SIGNER_PUBKEY_PATH` reconciliation): **decode the cmdline token into `/run/mvm/host-signer.pub` (tmpfs), repoint `HOST_SIGNER_PUBKEY_PATH` there.**

`HOST_SIGNER_PUBKEY_PATH = /etc/mvm/host-signer.pub` cannot stay on the dm-verity-sealed read-only rootfs — `/etc/mvm` is baked at build time and is identical for every launch, so it cannot carry a per-launch key. `/init` already writes per-launch material to `/run/mvm/` (tmpfs, writable under the sealed rootfs: `egress-ca.crt`, `secret-env`). Decision: `/init` decodes the `mvm.verb_grant=` token, writes the pubkey to `/run/mvm/host-signer.pub` and the grant to `/run/mvm/verb-grant.json`, both before the agent forks (stage 2.5). Repoint the constant to `/run/mvm/host-signer.pub`. This keeps `load_host_signer_verifying_key`'s fail-closed contract (absent file → `Ok(None)` → grant-less boot; present-but-malformed → `Err`). *No config drive, no new mount* — this is the correct reconciliation given the workload path never mounts one.

### Fork 4 — Gap 2 (supervisor→caller threading): **mint at the backend cmdline-token site from the stashed `plan.json` + host-signer keystore; the caller/ProtocolHello sender is untouched.**

Because delivery is the cmdline (Fork 2), the grant is minted where the *other* cmdline tokens are built — `crates/mvm-backend/src/microvm.rs:2260/2269` (`egress_ca_cmdline_token` / `secret_env_cmdline_token`), which read per-VM sidecars from the state dir. The admitted plan is **already stashed** at `~/.mvm/vms/<name>/plan.json` (mode 0600) by `stash_plan_for_bridge` (`crates/mvm-cli/src/commands/vm/plan_admission.rs:348`), so the parsed `nonce` + `agent_verbs` are recoverable there (same file `spawn_fc_bridge` reads at `:2952`); the host-signer keystore loads via `mvm-cli`'s `host_signer::load_or_init`. The `ProtocolHello` sender (`wait_for_guest_agent`, `crates/mvm-cli/src/commands/shared/vsock.rs:22`) — which has neither the plan nor the keystore — **needs no change at all**, resolving the "threading" problem by not threading through it. The mint site consumes `plan.agent_verbs`; if it is `None` the token is absent and the boot is byte-identical to today (grant-less). The host-signer keystore lives in `mvm-hostd`; `mint_verb_grant` already exists there (`crates/mvm-hostd/src/host_signer/verb_grant_mint.rs`). Since `mvm-backend` sits below `mvm-hostd` in the dep graph, the mint happens in **`mvm-cli` at stash time** (a new `~/.mvm/vms/<name>/verb-grant.json` sidecar), and the backend token builder only *reads + hex-encodes* that sidecar — mirroring `secret_env_cmdline_token` reading the substitution-endpoint sidecar. This keeps the dependency direction clean (mint stays high, backend stays a reader).

---

## Global Constraints

- **Reuse first.** Delivery reuses the cmdline-token pattern (`encode_secret_env_cmdline` shape) and the `/init` hex-decode idiom verbatim. Mint reuses `mint_verb_grant` (already landed). Verify reuses `pin_verb_grant` + `load_host_signer_verifying_key` (already landed). Do NOT add a config drive, a new wire type, or a canonicalizer.
- **No schema-bump ceremony.** No `ExecutionPlan` field changes here; `agent_verbs` already landed. The cmdline token is additive; absent ⇒ no-op.
- **Strictly subtractive + key separation are already enforced in the landed core** (`enforce_verb_grant` after `allowed_in`; `pin_verb_grant` fails closed when a grant arrives with no key). This plan only *feeds* those seams real data.
- **Placeholders/values never confused.** Unlike `mvm.secret_env` (placeholders only, claim 13), the verb-grant token carries a *public* key + a signed grant — no secret. It is safe on `/proc/cmdline`.
- **Fail-open on absence, fail-closed on tampering.** A malformed/missing token ⇒ grant-less boot (class gate only), mirroring the best-effort egress-ca/secret-env decoders. A *present* grant that fails verify ⇒ `pin_verb_grant` errors and the agent boots with no grant pinned (the landed core already refuses to silently pass an unverifiable grant).
- **No spec/PR/ADR citations in code comments** (repo rule). Reasoning stays here.
- **Docs upkeep:** on completion, tick Plan 216 in `specs/REFACTOR-STATUS.md` and reflect status in `specs/SPRINT.md` in the same change; flip ADR-103 `Status: Proposed → Accepted` if the maintainer approves.

---

### Task 5b: Encode/decode the `mvm.verb_grant=` cmdline token (host encoder + guest decoder contract)

**Files:**
- Modify: `crates/mvm-core/src/protocol/vm_backend.rs` (add `encode_verb_grant_cmdline` beside `encode_secret_env_cmdline` at `:252`; add a matching decode helper the guest test can drive)
- Test: inline `#[cfg(test)]` in `vm_backend.rs` (sibling to `encode_secret_env_cmdline_round_trips_pairs_as_single_token` at `:1755`)

**Interfaces:**
- Consumes: `mvm_core::plan::{VerbGrant, Nonce}` (already in `mvm-core`), an Ed25519 pubkey `[u8;32]`.
- Produces:
  - `VerbGrantEnvelope { pubkey_hex: String, plan_nonce_hex: String, grant: VerbGrant }` (`#[serde(deny_unknown_fields)]`, in `mvm-core`).
  - `encode_verb_grant_cmdline(env: &VerbGrantEnvelope) -> Option<String>` → `Some("mvm.verb_grant=<hex(JSON)>")`; `None` if the grant has no verbs and is baseline-only *and* the plan opted out (caller decides — encoder just hex-encodes what it's given, returning `None` only on serialize failure, matching the other encoders' "empty ⇒ None" shape by returning `None` for an empty pubkey).
  - `decode_verb_grant_cmdline(token_value_hex: &str) -> Result<VerbGrantEnvelope>` (the guest-side inverse; unit-tested here, called from the agent in 5c).

- [ ] **Step 1: Write the failing roundtrip test** (mirror `encode_secret_env_cmdline_round_trips_pairs_as_single_token`): build a signed `VerbGrant` (reuse the `verb_grant` test helpers' pattern — `SigningKey::from_bytes`, `Signer`), wrap in `VerbGrantEnvelope`, `encode_verb_grant_cmdline` → assert single space-free token starting `mvm.verb_grant=`, strip prefix, `decode_verb_grant_cmdline` → assert the envelope (pubkey_hex, nonce_hex, grant fields) round-trips. Add a `decode_rejects_malformed_hex` and `decode_rejects_unknown_field` negative test.
- [ ] **Step 2: Run** `cargo nextest run -p mvm-core verb_grant_cmdline` — expect FAIL (helpers absent).
- [ ] **Step 3: Implement** `VerbGrantEnvelope`, `encode_verb_grant_cmdline` (hex the `serde_json::to_vec`), `decode_verb_grant_cmdline` (un-hex → `serde_json::from_slice`). Keep byte-determinism (fixed-field-order struct, no maps — same rule the landed `VerbGrant::signing_bytes` follows).
- [ ] **Step 4: Run** `cargo nextest run -p mvm-core verb_grant_cmdline` — expect PASS. **Unit-testable in full** (pure encode/decode).
- [ ] **Step 5: Commit** `feat(core): mvm.verb_grant cmdline token encode/decode for out-of-band grant delivery`.

---

### Task 5c: Guest `/init` decodes the token + agent reads the pinned grant

**Files:**
- Modify: `nix/lib/mk-guest.nix` `/init` — add a stage (after 2.47 secret-env, before 2.5 agent fork, around `:562`) that `sed`-extracts `mvm.verb_grant=` from `/proc/cmdline`, hex-decodes it (same `printf '%b' | sed 's/../\\x&/g'` idiom as stages 2.46/2.47), writes the raw JSON to `/run/mvm/verb-grant.json` (mode 0644) and — parsing just the `pubkey_hex` field out — writes `/run/mvm/host-signer.pub` (mode 0644). Absent token ⇒ whole block is a no-op (byte-identical boot).
- Modify: `crates/mvm-guest/src/vsock.rs:1395` — repoint `HOST_SIGNER_PUBKEY_PATH` from `/etc/mvm/host-signer.pub` to `/run/mvm/host-signer.pub`; update its doc-comment.
- Modify: `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — at startup (before the accept loop at `:3086`, i.e. right after `AgentBootState::new` at `:2987`), read `/run/mvm/verb-grant.json` if present, `decode`/deserialize the envelope, call `load_host_signer_verifying_key(HOST_SIGNER_PUBKEY_PATH)` + `pin_verb_grant(...)` with the envelope's `plan_nonce` (Fork 1) and store the result into `boot_state.verb_grant` (the slot already exists, `mvm-guest-agent.rs:308`, currently hardcoded `None` at `:341`).

**Interfaces:**
- Consumes: `decode_verb_grant_cmdline`/`VerbGrantEnvelope` (5b), `pin_verb_grant` + `load_host_signer_verifying_key` (landed core).
- Produces: `boot_state.verb_grant: Some(grant)` on a verified grant; `None` otherwise. A helper `fn load_pinned_verb_grant(grant_path: &Path, pubkey_path: &Path, now) -> Option<VerbGrant>` in the agent (or `vsock.rs`) so the assembly is unit-testable off a tempdir.

- [ ] **Step 1: Write the failing agent test** for `load_pinned_verb_grant`: write a valid `verb-grant.json` + matching `host-signer.pub` to a tempdir, assert it returns `Some` with the expected verbs; write a grant signed by a different key, assert `None` (verify fails → not pinned); omit the pubkey file, assert `None` (fail-closed since the landed `pin_verb_grant` errors → caller maps to `None` and logs). This is the **AgentBootState population from files** — unit-testable.
- [ ] **Step 2: Run** `cargo nextest run -p mvm-guest load_pinned_verb_grant` — expect FAIL.
- [ ] **Step 3: Implement** `load_pinned_verb_grant` (read files → `decode` → `load_host_signer_verifying_key` → `pin_verb_grant` → `Ok(Some)`/log+`None`) and call it into `boot_state.verb_grant`. Repoint the const.
- [ ] **Step 4: Run** `cargo nextest run -p mvm-guest load_pinned_verb_grant verb_grant` — expect PASS.
- [ ] **Step 5 (live-boot validation — NOT unit-tested):** the `/init` cmdline-decode stage and the ordering guarantee (files present in `/run/mvm/` *before* the agent forks and *before* `wait_for_guest_agent` probes) can only be confirmed on a real boot. Add a note: validate on macOS Vz + Linux Firecracker that a booted guest has `/run/mvm/host-signer.pub` + `/run/mvm/verb-grant.json` (inspect via `machine run … --attach` / console on a dev image, or a `ReadinessStatus` field echo). The Nix `/init` shell is not exercised by `cargo nextest`.
- [ ] **Step 6: Commit** `feat(guest): decode verb-grant cmdline token in /init and pin it in the agent`.

---

### Task 5d: Mint the grant sidecar (mvm-cli) + build the cmdline token (backend)

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/plan_admission.rs:348` (`stash_plan_for_bridge`) — after writing `plan.json`, if the parsed plan has `agent_verbs.is_some()`, mint via `mvm_hostd::host_signer::mint_verb_grant` (keystore from `host_signer::load_or_init`), wrap in `VerbGrantEnvelope { pubkey_hex = signer.pub_key hex, plan_nonce_hex = plan.nonce.as_hex(), grant }`, and `write_secret_file` it to `~/.mvm/vms/<name>/verb-grant.json` (mode 0600). `not_after` = `plan.valid_until` (clamped). `session_id` = the ADR-shape tag (Fork 1). Absent `agent_verbs` ⇒ no sidecar (grant-less).
- Modify: `crates/mvm-backend/src/microvm.rs` — add `verb_grant_cmdline_token(vm_name)` (sibling to `secret_env_cmdline_token` at `:2904`) that reads `verb-grant.json`, `encode_verb_grant_cmdline`s it, returns the token; append it to `boot_args` at `:2272` (right after the `secret_env` append) via the same `match … { Some(token) => format!("{boot_args} {token}"), None => boot_args }` shape. Repeat the append in the libkrun (`:289`) / vz (`:1857`) / qemu (`:144`) cmdline builders where `mvm.uvols` is appended, so the token reaches every workload backend.

**Interfaces:**
- Consumes: `mint_verb_grant`, `load_or_init` (keystore + `pub_key()`), `plan.nonce`/`plan.valid_until`/`plan.agent_verbs`, `encode_verb_grant_cmdline` (5b).
- Produces: `~/.mvm/vms/<name>/verb-grant.json` (mint); `mvm.verb_grant=<hex>` on the cmdline (backend).

- [ ] **Step 1: Write the failing mint-sidecar test** in `plan_admission.rs` (sibling to `stash_plan_for_bridge_writes_both_files_when_present` at `:1032`): a `VmStartConfig` whose `plan_json` decodes to a plan with `agent_verbs = Some([...])` ⇒ `verb-grant.json` written and its envelope verifies under the loaded signer key + the plan nonce; a plan with `agent_verbs = None` ⇒ **no** sidecar. This is the **mint/provision assembly** — unit-testable.
- [ ] **Step 2: Write the failing token-builder test** in `microvm.rs` (sibling to the existing cmdline-token tests): given a `verb-grant.json` in a tempdir state dir, `verb_grant_cmdline_token` returns `Some("mvm.verb_grant=…")`; absent ⇒ `None`. Unit-testable.
- [ ] **Step 3: Run both** — expect FAIL.
- [ ] **Step 4: Implement** the mint-at-stash and the backend token builder + the four append sites.
- [ ] **Step 5: Run** `cargo nextest run -p mvm-cli stash_plan verb_grant && cargo nextest run -p mvm-backend verb_grant_cmdline_token && cargo build -p mvm-cli -p mvm-backend` — expect PASS + builds.
- [ ] **Step 6 (live-boot validation — NOT unit-tested):** that the appended token actually rides each backend's real cmdline and is decoded by the guest (5c) end-to-end — i.e. a plan with `agent_verbs` produces a booted agent whose `boot_state.verb_grant` is `Some` and which returns `VerbNotAuthorized` for an unlisted `ProdSafe` verb — is a **full end-to-end boot** check. Unit tests cover encode+mint+read in isolation; only a live boot exercises cmdline-assembly → kernel → `/proc/cmdline` → `/init` decode → agent pin → refusal. Validate on Vz (macOS) and Firecracker (Linux).
- [ ] **Step 7: Commit** `feat: mint verb-grant sidecar and carry it on every workload backend's cmdline`.

---

### Task 6: Audit denials to the chain-signed log

**Files:**
- Modify: the audit emitter (grep `emit_oci_provenance` — `crates/mvm-hostd/src/audit/emitter.rs` per Plan 215 Task 6 file map, or its real home `crates/mvm-cli/src/commands/vm/audit_chain.rs` where `emit_oci_provenance` lives per CLAUDE.md claim 14) — add `emit_verb_denied(&self, plan: &ExecutionPlan, verb: &str)` reusing the same append+chain helper `emit_oci_provenance` uses. Category `"verb_denied"`, labels `{ verb }`, no payload bytes.
- Modify: the host caller that receives `GuestResponse::VerbNotAuthorized { verb }` (the invoke/exec agent client — `crates/mvm-cli/src/commands/vm/invoke.rs` dispatch, and any `send_request` caller that can now see this response) to call `emit_verb_denied` before surfacing the error.

**Interfaces:**
- Consumes: the existing `AuditEmitter` + chain helper + `verify_audit_chain`.
- Produces: `emit_verb_denied` emitting a chained `"verb_denied"` entry.

- [ ] **Step 1: Read** `emit_oci_provenance` (`:206`-ish) to find the exact private append/chain helper + the emitter's test helpers (`test_signing_key`, `sample_plan`, verify/chain-path helpers). Match them; don't invent.
- [ ] **Step 2: Write the failing test** `verb_denied_entry_is_chained_and_verifies` (mirror the `emit_oci_provenance` test): `emit_admitted` then `emit_verb_denied(&plan, "update-idle-timeout")`; assert the chain still verifies, the log contains `verb_denied` + the verb, and a byte-flip breaks `verify_audit_chain`. Unit-testable.
- [ ] **Step 3: Run** — expect FAIL.
- [ ] **Step 4: Implement** `emit_verb_denied` + wire the caller.
- [ ] **Step 5: Run** `cargo nextest run -p <emitter-crate> verb_denied verify_audit_chain` — expect PASS.
- [ ] **Step 6 (partial live-boot note):** the *emitter + chain* is unit-tested; that a **real** refusal from a booted sealed agent triggers the caller's `emit_verb_denied` is covered by the Task 5d end-to-end boot check (the caller wiring itself is unit-testable with a mocked `VerbNotAuthorized` response).
- [ ] **Step 7: Commit** `feat(audit): chain-signed verb_denied entries on grant refusal`.

---

## Live-boot validation checklist (single end-to-end proof, after 5d + Task 6)

The unit tests prove every seam in isolation; this is the one thing they cannot: the whole chain on real hardware. Run on **Vz (macOS 26 AS)** and **Firecracker (Linux KVM)**:

1. Synthesize + admit a plan with `agent_verbs = Some(["run-entrypoint","ping"])` (a `machine run`/`up` path that populates `SynthesisInput.agent_verbs`).
2. Boot; confirm `/run/mvm/host-signer.pub` + `/run/mvm/verb-grant.json` exist in the guest and that the agent logged a pinned grant (add a one-line `eprintln!` on pin for the validation build).
3. Invoke a *listed* verb (`RunEntrypoint`) ⇒ succeeds. Invoke an *unlisted* `ProdSafe` verb (`UpdateIdleTimeout`) ⇒ `VerbNotAuthorized`; a `DevOnly` verb on a sealed agent ⇒ still `UnsupportedInProfile` (class gate wins — subtractive invariant holds live).
4. Confirm an `agent.verb_denied` / `verb_denied` entry landed in `~/.mvm/audit/<tenant>.jsonl` and `mvmctl trust audit verify` passes.
5. Boot a plan with `agent_verbs = None` ⇒ no token, no sidecar, `boot_state.verb_grant == None`, behavior byte-identical to today (grant-less regression guard).

> Echo log paths up front when running: driver, per-step, and the guest console (`console.log` / firecracker.log) so the operator can `tail -f`.

---

## Full-suite gate (after the last task)

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo nextest run --workspace`
- [ ] `cargo test --workspace --doc`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `just check-linux` (the cmdline append touches `cfg(linux)` FC + qemu paths)
- [ ] Update `specs/REFACTOR-STATUS.md` (tick Plan 216) + `specs/SPRINT.md` same commit.
- [ ] Flip ADR-103 `Status: Proposed → Accepted` if the maintainer approves; update its `Sequenced by:` to reference Plan 216 for the delivery leg.

## Self-Review

- **Fork resolutions are code-grounded:** delivery = cmdline token because the workload path attaches no config drive and uses no authed ProtocolHello (`microvm.rs:2260/2269`, `mk-guest.nix` 2.46/2.47, `vsock.rs:2703` unauth negotiate); nonce provisioning = out-of-band because there is no per-VM handshake session id on this path; threading avoids `wait_for_guest_agent` (which lacks plan+keystore) by minting at `stash_plan_for_bridge` where the plan is in scope and the keystore loads, and reading it back at the existing sidecar→cmdline-token site.
- **Unit-testable vs live-boot-only, explicitly split:** 5b (encode/decode), 5c Step 1–4 (`load_pinned_verb_grant` file assembly), 5d Step 1–5 (mint sidecar + token builder), Task 6 Step 1–5 (emitter + chain) are unit-testable. 5c Step 5 (`/init` decode + pre-agent ordering), 5d Step 6 (cmdline → kernel → decode → pin → refuse), and the end-to-end checklist are live-boot-only — the Nix `/init` shell and the real cmdline round-trip are outside `cargo nextest`.
- **Zero-behavior-change guard:** `agent_verbs == None` ⇒ no sidecar, no token, no pin — asserted in 5d Step 1 and checklist item 5.
- **Reuse:** no new wire type, no config drive, no canonicalizer; every new piece mirrors an existing one (`encode_secret_env_cmdline`, `secret_env_cmdline_token`, `emit_oci_provenance`).
