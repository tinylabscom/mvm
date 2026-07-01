# mvm-client — unified local/remote client facade

**Status:** Design (pre-ADR, pre-plan)
**Date:** 2026-07-01
**Spawns:** ADR-104 (control-plane trust boundary) · Plan 216 (implementation)

## Problem

`mvmctl` and `mvm-studio` both need to drive microVM operations that may run
in two places:

- **Local** — single-machine microVMs on this host.
- **Fleet** — a multi-tenant fleet managed by `mvmd` over its REST API.

Today the two surfaces are reached in incompatible ways. Studio spawns an
`mvmd-gateway` sidecar and speaks HTTP to it (even locally); `mvmctl` drives the
local path through clap command handlers that are not cleanly callable as a
library. There is no single interface a caller programs against to say "run this
machine" without first deciding *where* and *how*.

We want one facade — a trait — with a local (in-process) impl and a remote
(REST) impl, so the CLI and studio can target local microVMs **or** the mvmd
fleet through the same calls. Deploy-from-CLI and deploy-from-studio become the
same code path with a different backend selected.

## Non-goals

- **No REST *server* in `mvmctl`.** `mvmd-gateway` remains the sole HTTP server.
  This adds a *client-side* facade only.
- No change to guest/workload isolation. Claims 1–15 are enforced by the
  supervisor/hostd at launch and are unaffected by which client initiated.
- No new orchestration in `mvmctl`. Tenant/pool/deploy authority stays in mvmd.

## Decision

Introduce a client facade trait with **two implementations** (option "C" from
the brainstorm):

- `LocalBackend` — calls mvmctl's Rust libraries in-process. Same code and same
  `~/.mvm` on-disk state that the CLI drives today; identical trust.
- `GatewayBackend` — a REST client speaking HTTP(S) to an `mvmd-gateway`. Serves
  both the local sidecar (loopback) and a remote fleet — the only difference is
  the URL and the transport hardening.

Because `mvmd-gateway` already links mvmctl as a library, the in-process path and
the sidecar path run the **same mvmctl code over the same state**. "C" therefore
does not create two divergent local behaviors — it is one behavior reachable by
two transports.

### Where it lives (dependency direction)

`mvmd` depends on `mvm`, never the reverse. A REST client is defined by the
**wire protocol**, not by a Rust dependency — a client doing `GET /sandboxes`
needs the HTTP contract, not mvmd's crate. So the entire facade lives in the
**mvm** repo without importing anything from mvmd:

```
crates/mvm-client/                (new; tokio allowed — NOT mvm-core)
  trait MvmClient                 the async facade
  LocalBackend                    in-process mvmctl library calls
  GatewayBackend                  reqwest -> mvmd-gateway, zero mvmd imports
  dto::*                          shared, typed wire contract
```

- **`mvm-client` is a new crate, not `mvm-core`.** The trait is async and pulls
  `reqwest`/`tokio`; `mvm-core` must stay runtime-free (the
  `check-core-runtime-free` gate). Only the serde DTO *structs* may live in
  `mvm-core` if reused there — they carry no runtime deps.
- **`mvmctl`** depends on `mvm-client` → gets local + remote for free.
- **`mvm-studio`** depends on `mvm-client` → same dual mode; retires its bespoke
  `mvmd-client` usage.
- **`mvmd-gateway`** depends on the same `dto::*` for its handlers, replacing
  today's stringly `Result<Value>` with one typed contract shared by client and
  server. The existing `mvmd-client` crate is superseded (or becomes a thin
  re-export of `GatewayBackend`).

### Selection

```
mvmctl machine list                 -> LocalBackend
mvmctl --remote <url> machine list  -> GatewayBackend(url)
studio (local view)                 -> GatewayBackend(loopback sidecar)
studio (fleet view)                 -> GatewayBackend(remote)
```

## Trait shape (sketch)

Async trait; domain-typed in/out (not `Value`). Scoped to machine lifecycle for
v1; grows by operation, not by transport.

```rust
#[async_trait]
pub trait MvmClient {
    async fn list_machines(&self, f: MachineFilter) -> Result<Vec<MachineState>>;
    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineHandle>;
    async fn stop_machine(&self, id: &MachineId) -> Result<()>;
    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<LogStream>;
    // ... intent-shaped operations only
}
```

`MachineSpec`/`MachineState`/`MachineId` reuse `mvm-core` domain types where they
exist. The DTOs are **intent-shaped**: they carry *what to do*, never local host
artifacts (signing keys, host paths) — see key-domain separation below.

## Security & Trust Boundary

This is a first-class part of the design, not an afterthought. The remote
endpoint (`mvmd-gateway`) is already a hardened control plane — scoped bearer
keys (`Authorization: Bearer mvmd_<org>_<hex>`, HMAC-hashed, expiry-warned),
mTLS (`require_client_cert`), RBAC, per-key rate limiting, quota enforcement,
audit, and `X-API-Version` skew detection. The facade's job is to **consume that
enforcement correctly**, adding no trust of its own.

### Governing principle: the remote client is a dumb courier with zero authority

Every security decision lives on the enforcing side. On the local path the
authority is the local host (signed `ExecutionPlan`, broker, audit chain — as
today). On the remote path the authority is `mvmd-gateway` (RBAC, quota, audit,
its own admission + signing). `GatewayBackend` holds **no enforcement logic** —
it presents credentials and ships intent; the server treats it as untrusted
input regardless. Security is never a property of the transport the caller
picked; it is enforced identically at whichever authority owns that path. **The
trait unifies the call, never the trust.**

### Key-domain separation (the subtle trap)

Local signing keys (`~/.mvm/keys/host-signer`) are the *local host's* authority
and must never be trusted by the fleet. The facade must never ship a
locally-signed plan and have the gateway honor that local signature —
that is key-trust confusion. Remote DTOs carry **intent**; the gateway
re-admits and re-signs under its own fleet key. The wire contract must not leak
local signing material or host paths across the boundary. This is a design
constraint on the DTOs, not merely a runtime check.

### Client-side rules (fail-closed)

1. **Ride the gateway auth model exactly** — `Bearer mvmd_<org>_<hex>`, honor
   `X-Key-Expires-Soon`, hard-fail on `X-API-Version` mismatch. No bespoke auth.
2. **Prefer mTLS; require TLS.** HTTPS + cert validation by default; support the
   gateway's `require_client_cert` mode; **refuse plaintext to any non-loopback
   host** (loopback sidecar is the only cleartext exception).
3. **Credential storage** — OS keychain (studio), env var or mode-0600 file
   (CLI). Never a `--token` flag (leaks to `ps`/shell history), never logged,
   `zeroize` on drop, routed through the `check-no-display-on-secret-types`
   discipline.
4. **Endpoint-bound tokens** — a token is bound to its configured endpoint and
   never sent to a different `--remote` URL. Kills token exfil via URL confusion.
5. **Fail closed** — TLS failure, version skew, expired/revoked key → hard error,
   never a silent degrade to a weaker mode.

### Untrusted-input hardening on the shared DTOs

The gateway deserializes client DTOs from anyone with network reach.
`#[serde(deny_unknown_fields)]` on every wire type, plus size/depth limits and
the gateway's existing `validation.rs`. Typed DTOs are a security win over
today's `Value` soup — they fail closed. The `LocalBackend` path carries no new
surface: it is the same in-process code and state as running `mvmctl` today.

### Trust-model expansion → ADR-104

`mvmd`-over-network is a **new actor** relative to ADR-002, which scopes the
threat model to a single trusted local host. This is the only place the threat
model actually expands, and it must be written down. **ADR-104 is a prerequisite
deliverable** for the remote path: it defines the control-plane trust boundary,
the dumb-courier principle, key-domain separation, and the client-side fail-closed
rules as posture, and states plainly that local and remote guarantees are
enforced by *different authorities* (never silently uniform).

## Scope / sequencing

- **v1 (Plan 216, Phase 1):** `mvm-client` crate + `MvmClient` trait +
  `LocalBackend` + the full typed `dto::*` contract + `mvmctl` wired to
  `LocalBackend`. Authors **ADR-104**. No remote wire yet — this de-risks the
  interface and the DTO shapes against the local path first.
- **v1.1 (Plan 216, Phase 2), gated on ADR-104 accepted:** `GatewayBackend` +
  `mvmctl --remote` + TLS/mTLS enforcement + gateway adopts `dto::*` + studio
  migrates off bespoke `mvmd-client`. This is the security-critical phase and
  ships only behind the accepted ADR.

Rationale: the remote goal is firmly in the plan (CLI *and* studio deploy to the
fleet), but the transport that expands the threat model lands behind its ADR
rather than racing ahead of it.

## Testing

- Trait: `LocalBackend` against a temp `MVM_DATA_DIR`; roundtrip machine
  lifecycle.
- DTOs: serde roundtrip, `deny_unknown_fields` rejection, defaults.
- `GatewayBackend` (Phase 2): mock HTTP server; assert `Bearer` header, TLS-refuse
  on non-loopback plaintext, version-skew hard-fail, endpoint-bound token,
  no-secret-in-logs.
- Contract: a shared-DTO conformance test both `mvm-client` and `mvmd-gateway`
  compile against, so the wire contract can't drift silently.

## Open questions

- DTO home: `mvm-core` (reused by mvmd already) vs `mvm-client` only. Leaning
  `mvm-core` for the pure structs so the gateway shares them without depending on
  `mvm-client`'s runtime.
- Log/exec streaming shape over REST (SSE — the gateway already has
  `sse_helpers.rs`) vs the local in-process stream; the trait must express both
  without leaking transport.
- Whether `mvmd-client` is deleted or kept as a thin re-export during migration.
