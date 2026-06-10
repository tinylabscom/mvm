# Plan 179 — Replace macOS/libkrun gvproxy with rvproxy (Implementation Plan)

> **Numbering:** 179 is the next free plan number after 178. Confirm still free
> at merge.
>
> **Decision source:** [ADR-078](../adrs/078-rvproxy-gateway-ownership.md).

**Goal:** Replace upstream `gvproxy` with `rvproxy` on the macOS/libkrun
gateway seam so `mvm` owns the guest egress plane on that path without
rewriting the surrounding supervisor, builder, or policy architecture.

**Architecture:** The load-bearing production seam is the per-VM gateway spawn
in `crates/deps/libkrun-sys/src/gvproxy.rs`, the shared builder/runtime
gateway-selection flow in `crates/mvm-build/src/libkrun_builder.rs` and
`crates/mvm-backend/src/libkrun.rs`, and the claim-10 mediation bridge in
`crates/mvm-hostd/src/supervisor/gateway_bridge.rs`. `rvproxy` is adopted as a
gvproxy-compatible binary behind that seam, not as a new control-plane owner.

**Tech Stack:** Rust, libkrun supervisor path, `rvproxy` gvproxy-compat CLI,
Unix datagram vfkit transport, existing bridge/audit pipeline.

---

## Guardrails (every task)

- Do not weaken the claim-10 no-bypass posture. The bridge remains the
  mandatory mediation seam.
- No SSH-in-guest regressions. `rvproxy` may tolerate `-ssh-port`; `mvm` must
  not start depending on SSH forwarding.
- Keep Linux `passt` behavior unchanged unless a later plan explicitly broadens
  scope.
- Treat the builder VM and workload VM as one rollout surface; do not make them
  diverge on gateway selection semantics.
- Prefer an explicit binary-override seam over symlink/path hacks.
- Production rollout requires end-to-end proof, not just the existing DHCP test.

## File Structure

New / modified likely:

- `crates/deps/libkrun-sys/src/gvproxy.rs`
- `crates/mvm-build/src/libkrun_builder.rs`
- `crates/mvm-backend/src/libkrun.rs`
- `crates/mvm-hostd/src/supervisor/gateway_bridge.rs`
- `crates/mvm-cli/src/doctor.rs`
- `public/src/content/docs/guides/networking.md`
- `CLAUDE.md`
- new docs for operator selection / install guidance if needed

---

## Phase 1 — Make the production seam configurable

### Task 1: Add a real gateway-binary override for the gvproxy path
**Files:** `crates/deps/libkrun-sys/src/gvproxy.rs`

- [ ] Add an explicit binary-resolution path for the macOS/libkrun gvproxy
      launcher, e.g. `MVM_GVPROXY_BIN`, before fallback to `which("gvproxy")`.
- [ ] Preserve existing error messaging and install hints when no override is
      set.
- [ ] Cover override resolution with unit tests so the production path, not
      just the bridge test, can target `rvproxy`.
- [ ] Commit: `feat(network): allow overriding gvproxy-compatible gateway binary`

### Task 2: Keep the semantic mode name stable
**Files:** `crates/mvm-build/src/libkrun_builder.rs`,
`crates/mvm-backend/src/libkrun.rs`

- [ ] Confirm `NetworkingPreference::Gvproxy` remains the correct semantic name
      for "vfkit/unixgram gvproxy-shaped gateway mode", even when the binary is
      `rvproxy`.
- [ ] Do **not** introduce a parallel `Rvproxy` networking mode yet unless a
      hard production reason appears; prefer binary selection over mode
      duplication.
- [ ] Add comments clarifying that the mode name describes the transport
      contract, not necessarily the upstream implementation.
- [ ] Commit: `docs(network): clarify gvproxy mode is a contract, not a vendor`

### Task 3: Extend doctor/install messaging
**Files:** `crates/mvm-cli/src/doctor.rs`, docs

- [ ] Update doctor output to distinguish:
      - active gateway contract (`gvproxy`-compatible unixgram path)
      - selected binary (upstream `gvproxy` or overridden `rvproxy`)
- [ ] Make install guidance truthful for both the default upstream path and the
      first-party `rvproxy` path.
- [ ] Commit: `feat(doctor): report gvproxy-compatible gateway selection`

---

## Phase 2 — Prove rvproxy at the existing compatibility gate

### Task 4: Make the existing acceptance gate exercise the production override
**Files:** tests/docs only if needed

- [ ] Keep the authoritative acceptance test unchanged in substance:
      `gvproxy_dhcp_offer_roundtrips_through_bridge`.
- [ ] Add a repo-managed command path that runs the same gate against the
      production override, not only `MVM_GATEWAY_BIN` in test code.
- [ ] Record the control case against upstream `gvproxy` and the pass case
      against `rvproxy`.
- [ ] Commit: `test(network): exercise gvproxy bridge gate through production override`

### Task 5: Validate daemon lifecycle parity
**Files:** `crates/deps/libkrun-sys/src/gvproxy.rs`, test coverage

- [ ] Prove the per-VM lifecycle assumptions still hold when the binary is
      `rvproxy`:
      - socket appears within the existing wait window
      - stale socket cleanup still works
      - SIGTERM/SIGKILL shutdown behavior remains valid
      - orphan reaping behavior remains acceptable
- [ ] Encode any missing lifecycle assertions in tests or smoke scripts.
- [ ] Commit: `test(network): verify rvproxy lifecycle on gvproxy seam`

---

## Phase 3 — End-to-end builder and workload proof

### Task 6: Builder VM proof on macOS/libkrun with rvproxy
**Files:** builder docs/tests/scripts as needed

- [ ] Run the real builder path on macOS with the gateway override pointed at
      `rvproxy`.
- [ ] Prove the builder can:
      - acquire DHCP
      - resolve DNS
      - fetch from the network
      - complete a representative build or image bootstrap path
- [ ] Capture operator-facing evidence and document the exact invocation.
- [ ] Commit: `docs(network): record rvproxy-backed builder proof`

### Task 7: Workload VM proof on macOS/libkrun with rvproxy
**Files:** workload smoke tests/docs as needed

- [ ] Run the real workload libkrun path with the same override.
- [ ] Prove guest egress beyond DHCP:
      - DNS
      - TCP/UDP forwarding
      - policy/audit bridge still emits expected events
- [ ] Confirm no guest-control-plane regressions from the gateway swap.
- [ ] Commit: `docs(network): record rvproxy-backed workload proof`

---

## Phase 4 — Productize the first-party gateway path

### Task 8: Decide defaulting policy
**Files:** launch path + docs

- [ ] Decide whether first release behavior is:
      - explicit opt-in override only, or
      - default-to-`rvproxy` on supported macOS/libkrun hosts
- [ ] Prefer opt-in first if production evidence is still thin; flip default
      only after builder + workload proof is routine.
- [ ] Commit: `feat(network): default macOS libkrun gateway to rvproxy`
      or document why the default stays deferred.

### Task 9: Fix stale networking documentation
**Files:** `public/src/content/docs/guides/networking.md`, `CLAUDE.md`

- [ ] Remove stale references that still describe libkrun macOS networking as
      TSI/host-loopback.
- [ ] Replace them with the current truth:
      - Linux libkrun path uses `passt`
      - macOS libkrun path uses a `gvproxy`-compatible vfkit/unixgram gateway
      - `rvproxy` is the first-party implementation when selected
- [ ] Commit: `docs(network): align macOS libkrun networking docs with rvproxy path`

---

## Phase 5 — Close the ownership claim honestly

### Task 10: Restate the product claim precisely
**Files:** docs/specs as needed

- [ ] Update product/spec language so the claim is precise:
      - after this plan, `mvm` owns the macOS/libkrun guest egress gateway
        implementation
      - Linux `passt` remains a separate external dependency unless and until a
        later plan replaces it
- [ ] Cross-link ADR-078 from the relevant runtime/network architecture docs.
- [ ] Commit: `docs(architecture): state first-party network-plane ownership precisely`

### Task 11: Follow-on decision point for Linux
- [ ] After macOS/libkrun is stable on `rvproxy`, write the follow-on decision:
      keep Linux `passt` as an intentional exception, or start a separate plan
      to replace it.
- [ ] Do not let that decision silently ride inside this plan.

---

## Self-review / success criteria

- [ ] `mvm` can point its production macOS/libkrun gvproxy seam at `rvproxy`
      without code-path hacks.
- [ ] The unchanged bridge DHCP compatibility gate passes against `rvproxy`.
- [ ] Builder VM networking works end-to-end on the `rvproxy` path.
- [ ] Workload VM networking works end-to-end on the `rvproxy` path.
- [ ] Claim-10 bridge mediation remains intact; no TSI/no-bypass regression.
- [ ] The docs no longer claim stale TSI behavior on macOS/libkrun.
- [ ] The product claim is tighter and more truthful: `mvm` owns the macOS
      libkrun guest egress gateway implementation.
