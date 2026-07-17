# Increment 3 — the `mvm-core` → `mvm-protocol` wire/policy split (DESIGN)

> **Status: COMPLETE.** Executed in 13 subagent-driven batches on branch
> `plan/mvm-simplification` (Tier 0 `6577d06ba` → final `51471dd7`). Every
> `plan/`+`policy/`+`protocol/` wire/policy DTO — leaves, the two biggest
> single-file splits (`bundle.rs` 2360, `vm_backend.rs` 2693), and the
> claim-8 signed `ExecutionPlan` itself — now lives in `#![no_std]+alloc`
> `mvm-protocol`, which builds on `wasm32`; all signing/verify/synthesis/
> resolution/fs/net/tar logic stays in `mvm-core` on top. Each batch was
> byte-identity `git show`-verified and left the workspace green (nextest
> ~6596/0, clippy `-D`, wasm build, xtask gates). Per-batch detail is in the
> Tier-2/3 checklist of `specs/SPRINT.md`. This document is the design of
> record; the prose below is the plan as authored.

This is the design of record for the long pole of Phase 1a: pulling the pure
wire/policy **DTOs** out of `mvm-core`'s `plan/` + `policy/` + `protocol/`
down into the `#![no_std] + alloc` `mvm-protocol` crate, and leaving every
piece of **logic** (signing, verification, hashing, resolution, fs/net/io,
synthesis) in `mvm-core` on top of it. It exists so the eventual execution is
mechanical and de-risked — it does not touch code.

Increments 1–2 already landed (`mvm-protocol` = audit verifier + Workload IR
+ entrypoint, wasm-clean). Increment 3 is the third and largest: it inverts a
meaningful fraction of `mvm-core`'s foundation. Read
[07-progress-and-decisions.md](07-progress-and-decisions.md) for why 1a-protocol
and 1b are one designed pass, and [02-architecture.md](02-architecture.md)
§Crate map for the target dependency direction (`mvm-protocol` sits *under*
`mvm-core`).

## The one principle

**A DTO describes what a thing *is*; logic operates *on* it.** If a type is a
serde struct/enum that names the fields of a plan / policy / frame /
host-service message, it moves to `mvm-protocol`. If a function signs, verifies,
hashes, resolves, reads the clock, touches the filesystem, opens a socket, or
generates a script, it stays in `mvm-core`. `mvm-core` gains a `mvm-protocol`
dependency and its logic now operates on the relocated types.

Corollary — the execution rule that makes this safe:

> **Relocate DTOs verbatim. Never change a serde-visible shape during the
> move.** Field names, declaration order, every `#[serde(...)]` attribute,
> `#[serde(deny_unknown_fields)]`, skip/default rules, and the concrete field
> *types* stay byte-for-byte identical. The only edits permitted to a moving
> type are its `use` paths (`std::` → `core::`/`alloc::`) and the crate its
> `impl`s live in.

## The load-bearing invariant: byte-identical serde

The signed `ExecutionPlan`, the chain-signed audit entries, `SignedControl`'s
`ControlRequest`, and every policy embedded in a signed plan are signed and
verified over their **serialized bytes**. Two independent reasons the bytes
must not drift across the move:

1. **Cross-repo contract.** `mvmd` (separate repo) signs plans and control
   requests that *this* repo's `mvm-hostd` verifies. If a field type or serde
   attribute changes on the move, mvmd's signature stops verifying — a silent,
   fail-closed break we would only catch at integration.
2. **In-repo round-trip + frozen fixtures.** Sign-then-verify and the
   claim-8/claim-9 rejection-ladder tests assert exact bytes.

The verbatim-relocation rule above *is* the guarantee. Two mechanical
consequences the analysis surfaced, both resolved in favour of no churn:

### chrono — keep `DateTime<Utc>`, do NOT convert to `String`

`DateTime<Utc>`'s `Serialize`/`Deserialize` emit/parse an RFC-3339 string and
are identical under `std` and `no_std` — chrono's `clock` feature only gates
`Utc::now()` (wall-clock reads), never serialization. So a moved type keeps its
`DateTime<Utc>` fields and `mvm-protocol` gets a scoped, no_std chrono:

```toml
# mvm-protocol/Cargo.toml — pinned directly (workspace entry carries std+clock)
chrono = { version = "0.4", default-features = false, features = ["serde", "alloc"] }
```

This keeps `ExecutionPlan.valid_from/valid_until`, `VerbGrant.not_after`, and
`policy::resolver::EmergencyDeny.expires_at` byte-identical. Converting them to
`String` (as one analysis pass proposed) would change the signed bytes and
break the mvmd contract — **rejected.** Types whose timestamps are *already*
`String` (e.g. `DnsPin.resolved_at/expires_at`, `LocalAuditEvent.timestamp`)
stay `String` — also no churn. `Utc::now()` call sites (`synthesize_plan`,
`DnsPin::new`, `LocalAuditEvent::now`) are *logic* and stay in `mvm-core`
regardless.

### std::net — swap `std::net` → `core::net`, do NOT convert to `String`

`core::net::{IpAddr, Ipv4Addr, Ipv6Addr}` is stable since Rust 1.77; the
workspace MSRV is 1.85. Every `std::net` IP type in a moving DTO
(`network_tunnel.rs`'s handshake fields, `policy::dns_pin::DnsPin.ips:
Vec<IpAddr>`) becomes a `core::net::` path swap — byte-identical serde, no new
dependency. `ipnet::IpNet` is *not* pulled into `mvm-protocol`: it appears only
in `policy::projection.rs` logic (`std::net`/`ipnet` free functions taking a
caller-supplied address), which stays in `mvm-core`.

### thiserror — scoped no_std, or hand-roll

`thiserror = "2"` supports `#![no_std]` via `core::error::Error` (stable since
1.81) behind its default `std` feature. `mvm-protocol` pins it directly:

```toml
thiserror = { version = "2", default-features = false }
```

For the handful of moved error enums with trivial `Display` this is a one-line
add; the existing `ir/error_codes.rs` hand-rolled `core::fmt` pattern is the
fallback if any derive resists.

### The orphan-rule rewrite (the recurring mechanical shape)

When a type moves to `mvm-protocol` but one of its inherent methods needs
crypto/std (`.verify()`, `.sign()`, `.content_hash()`, `.key_id_for()`,
`.resolve_value()`, `.checked()`), that method **cannot** stay an inherent
`impl` — `mvm-core` may not add inherent methods to a foreign type. It becomes
a free function in `mvm-core`:

```
// before (in mvm-core, type + method together)
impl VerbGrant { pub fn verify(&self, key: &VerifyingKey, ...) -> Result<...> }

// after — type in mvm-protocol, verify() a free fn in mvm-core
mvm_core::plan::verb_grant::verify(&grant, &key, ...) -> Result<...>
```

Pure predicate methods (no crypto/std — `VerbGrant::permits`,
`ReversibleReplacementPolicy::handles_class`, `NetworkPolicy::allows_egress`,
`BundleManifest::find_by_role`) move *with* the type. `Display`/`FromStr`/
`core::error::Error` impls on a moved type move *wholesale* with it (orphan rule
again — there is no "leave the trait impl behind" option); any that today
return `anyhow::Error` get rewritten to a local no_std error first. Every
free-function conversion changes call sites (`Type::method(x)` →
`module::method(&x)`) across `mvm-hostd`/`mvm-runtime`/`mvm-cli` — mechanical
but wide; grep each converted method before moving on.

## What moves / what stays

Condensed from the three per-folder analyses. "→P" = moves to `mvm-protocol`;
"core" = stays in `mvm-core`; "split" = file physically divides into a DTO half
(→P) and a logic half (core).

### `plan/`

| Module | LOC | Disposition |
|---|---|---|
| `types.rs` | 823 | **→P whole** (pure-DTO leaf, zero intra-`plan/` deps) |
| `verb.rs` | 83 | **→P whole** (`VerbId`, `VerbIdError`) |
| `verb_trust.rs` | 70 | **→P whole** (simplest file; zero cross-refs) |
| `bundle.rs` | 2360 | **split** — DTOs (`KeyId`+`is_well_formed`, `ArtifactRole`, `BundleArtifact`, `BundleResources`, `VerityInfo`, `BundleManifest`+`find_by_*`, `PlanArtifact`+`new`/`signature_bytes`, `signature_{to,from}_base64`) →P; all resolver/registry/truststore/verify/tar/fs/sha logic + `PathBuf`-bearing types stay core (`key_id_from_pubkey`/`from_identity`, `canonical_manifest_bytes`, `sha256_hex` become free fns) |
| `verb_grant.rs` | 199 | **split** — `VerbGrant`, `VerbGrantError`, `VERB_GRANT_BASELINE`, `permits()` →P; `signing_bytes()`/`verify()` → core free fns |
| `validity.rs` | 317 | **split** — only `FreshnessClaims`+`new()` →P; `Freshness` trait, `CheckedFreshness`, `PlanValidityError`, `check_window`, `NonceStore`, `checked()` stay core |
| `execution_plan.rs` | 234 | **→P**, last, gated on companion moves (below) — `ExecutionPlan`, `SCHEMA_VERSION` |
| `test_support.rs` | 194 | →P with `ExecutionPlan` under a `test-support` feature (`Utc::now()` in test/feature-gated code is fine) |
| `signing.rs` | 621 | **core** — `sign_plan`/`verify_plan`/`secrets_from_signed_json`/… all stay; `SignedExecutionPlan` newtype stays too (wraps out-of-scope `protocol::signing::SignedPayload`) |
| `synthesis.rs` | 679 | **core whole** — `synthesize_plan` + `SynthesisInput` (clock/RNG; not serde) |
| `mod.rs` | 68 | **core glue** — rewritten so `pub use` re-exports the →P types at their current paths (`crate::plan::ExecutionPlan`, …) so ~58 external `ExecutionPlan` + ~20 `sha256_hex` call sites don't churn |

### `policy/`

| Module | LOC | Disposition |
|---|---|---|
| `bundle.rs` | 67 | **→P whole** (`PolicyId`, `PolicyBundle`, `TenantOverlay`, `SCHEMA_VERSION`) — needs `plan::TenantId` (companion) |
| `policies.rs` | 313 | **→P whole** (`NetworkPolicy`[bundle], `EgressPolicy`, `PiiPolicy`, `ToolPolicy`, `AuditPolicy`, …) |
| `redaction.rs` | 123 | **→P whole** — **signed** (embedded in `ExecutionPlan.redaction`) |
| `reversible_replacement.rs` | 187 | **→P whole**, incl. pure `handles_class`/`replaces_on`/`reinjects_on` — **signed** (`ExecutionPlan.reversible_replacement`) |
| `security.rs` | 934 | **→P whole** (`AuthenticatedFrame`, `SessionHello`, `AgentProfile`, `SecurityPolicy`, `PostureReport`, threat/blocklist types, protocol version consts) — pairs with `protocol::signing::SignedPayload` |
| `network_policy.rs` | 1449 | **split** — DTOs (`HostPort`, `NetworkPreset`, `EgressMode`, `NetworkPolicy`, `BANNED_SSH_PORT`, `MANDATORY_DENY_RANGES`) + pure accessors →P; `iptables_*` script-gen + `is_mandatory_deny(IpAddr)` free fns stay core. **DTO fields carry no `std::net`** — the `std::net`/`ipnet` use is all in the logic half |
| `dns_pin.rs` | 502 | **split** — `DnsPin` (`ips: Vec<core::net::IpAddr>`), `DnsPinRegistry` + pure CRUD →P; chrono validity/TTL/prune + `ToSocketAddrs` resolution → core free fns |
| `resolver.rs` | 471 | **split** — `EffectivePolicy`, `EmergencyDeny` (keep `Option<DateTime<Utc>>`) →P; `resolve`/`pick`/`is_active` stay core |
| `secret_binding.rs` | 241 | **split** — `SecretBinding`, `PLACEHOLDER_PREFIX` + builders + `FromStr`/`Display` (rewrite off `anyhow`) →P; `resolve_value()` (`std::env`) → core free fn |
| `audit.rs` | 1564 | **split** — `LocalAuditKind`, `LocalAuditEvent`, `AuditAction`, `AuditEntry` →P; `LocalAuditLog`/`audit_emit!`/emit/read (`std::fs`) stay core |
| `signing.rs` | 241 | **core whole** — ed25519 `sign_bundle`/`verify_bundle` |
| `toml_loader.rs` | 448 | **core whole** — `std::fs`/toml |
| `projection.rs` | 1456 | **core whole** — no serde types; decision logic over `IpNet` |
| `projection_fs_env.rs` | 567 | **core whole** — mirrors `projection.rs` |
| `security_profile.rs` | 189 | **DEFER** — `SecurityProfile` isn't even `Serialize` (runtime value), and it reaches into `crypto::seccomp::SeccompTier` (out of scope) |

### `protocol/`

| Module | LOC | Disposition |
|---|---|---|
| `signing.rs` | 29 | **→P whole** — `SignedPayload` (the base envelope many others wrap) |
| `host_cost.rs` / `host_time.rs` | 54 / 56 | **→P whole** |
| `host_signer.rs` | 223 | **→P whole** (request/response DTOs; actual signing is in a hostd subprocess) |
| `audit_signer.rs` | 526 | **→P whole** (`PathBuf`→`String` on helper paths) |
| `routing.rs` | 276 | **→P whole** (`RoutingTable`/`Route`/… + `validate()`; `HashSet`→`BTreeSet`, `anyhow`→typed) |
| `broker.rs` | 413 | **→P whole** (`ServiceId`, `ServiceCall`, `ServiceResponse`, …) |
| `host_audit.rs` | 235 | **→P whole** |
| `network_tunnel.rs` | 1026 | **→P whole** — the flagship no_std codec: `PacketFrameHeader::encode/decode`, `Borrowed`/`OwnedTunnelFrame`, `TunnelHello`/`Ack`/config frames + their `validate()`. Only edit: `std::net`→`core::net` |
| `handler.rs` | 213 | **split** — `ServiceError` →P; `ServiceHandler` trait (async dispatch) stays core; `ServiceCallCtx` stays core for now (holds `AgentProfile`) |
| `signed_config.rs` | 351 | **split** — `SignedConfigEnvelope` →P; `key_id_for`/`encode`/`verify_envelope` → core free fns |
| `broker_control.rs` | 292 | **split** — `RegisterVm`/`DeregisterVm`/`ControlRequest`/`ControlResponse`/`SignedControl` →P (`PathBuf`→`String`); `sign`/`verify` → core free fns. **`ControlRequest` is JCS-signed — freeze a byte fixture before/after** |
| `protocol.rs` | 674 | **DEFER (DTO half)** — `HostdRequest`/`HostdResponse` embed `domain::instance::VolumeAttach` + `domain::tenant::TenantNet` (out of scope); the tokio frame I/O (`hostd-transport`) stays core regardless |
| `vm_backend.rs` | 2693 | **split (large, own PR)** — ~1327 lines of DTOs (`VmPortMapping`, `VmVolume`, `VmStatus`, `VmCapabilities`, `SnapshotCapability`, `StandbySpec/Handle/State`, `BackendKind`, cmdline encode/decode fns, …) →P; `VmBackend` trait stays core; `VmStartConfig`/`StandbyClaim` (embed `policy::NetworkPolicy`) and `VerbGrantEnvelope` (embeds `plan::VerbGrant`) stay core composites |
| `mod.rs` | 20 | **core glue** — re-export shim |

## Cross-folder entanglement — the companion moves

The three folders are not independent: three signed aggregates reach across
folder (and crate-module) boundaries. Increment 3's real scope therefore
includes a small set of **companion moves** so the entangled aggregates can
land, plus two explicit *deferrals* where the companion is too heavy.

Move as companions (all already pure/no_std-clean, cheap):

- **`lifecycle::SnapshotAt`** → P (small pure enum; `ExecutionPlan.snapshot_at`).
- **`policy::RedactionPolicy` + `policy::ReversibleReplacementPolicy`** → P — required anyway by the `policy/` cut, and they are `ExecutionPlan` fields, so their move unblocks `ExecutionPlan`.
- **`plan::{TenantId, PlanId, WorkloadId}`** → P — trivial `#[serde(transparent)]` String newtypes that `policy::bundle`/`resolver` key on. Move the three together as a one-off.

Stay as core composites (the aggregate references one heavy out-of-scope type):

- **`VmStartConfig` / `StandbyClaim`** — embed `policy::network_policy::NetworkPolicy`. Correct outcome: a `mvm-core` struct composed of `mvm-protocol` sub-DTOs + the policy type. Not every aggregate must move.
- **`VerbGrantEnvelope`** — embeds `plan::VerbGrant`; moves once `VerbGrant` (Tier 2) has landed, so sequence it after.
- **`protocol::HostdRequest/HostdResponse`** — deferred with `protocol.rs` (domain deps), OR pulled in with a `VolumeAttach`+`VolumeMode`+`TenantNet` adjunct if we choose to widen scope; default is defer.

## Naming collision — resolve before the move

Two unrelated types named `NetworkPolicy` exist, disambiguated today only by
module depth: `policy::policies::NetworkPolicy` (bundle/L4-rule shape) and
`policy::network_policy::NetworkPolicy` (preset/allow-list, CLI-facing). Both
move to `mvm-protocol`. Rename the `policies.rs` one to **`BundleNetworkPolicy`**
(hard rename, no alias — consistent with the no-back-compat norm) before or
during the move so a flatter DTO namespace doesn't collide.

## Intentionally stays in `mvm-core` (not gaps)

On execution, two candidates the draft flagged as "deferred pending a move"
resolved to **permanent `mvm-core` residents** — moving them would be wrong,
not merely postponed:

- `policy::security_profile.rs` — **stays.** `SecurityProfile` is not a serde
  wire type at all (a `Copy` runtime value with a `&'static str` field) and it
  depends on `crypto::seccomp::SeccompTier`. It is core logic, not a DTO.
- `protocol::protocol.rs` `HostdRequest`/`HostdResponse` (+ `PROTOCOL_VERSION`,
  `HOSTD_SOCKET_PATH`) — **stays.** It is the mvmd↔hostd *host-side* IPC control
  protocol: it embeds `domain::{instance::VolumeAttach, tenant::TenantNet}` —
  and per the architecture, mvmd-orchestration `domain/` types deliberately
  stay in `mvm-core` — and its transport is the `hostd-transport`-gated tokio
  framing (`read_frame`/`write_frame`/…). Nothing here runs in a guest or the
  browser, so it belongs with the host-side std/tokio logic, not in the
  no_std/edge crate. This draws the clean line for the whole increment:
  **`mvm-protocol` holds the DTOs a no_std/edge/guest/browser consumer needs
  (signed plans, audit, guest wire protocol, policy); the host-only mvmd↔hostd
  IPC and orchestration domain types stay in `mvm-core`.**

The composites the draft listed as staying (`vm_backend::VmStartConfig`/
`StandbyClaim`/`VerbGrantEnvelope`) did stay — as `mvm-core` composites over
`mvm-protocol` sub-DTOs, alongside the `VmBackend` trait (Batch K). And all
signing/verification/synthesis/resolution/projection **logic** stays in
`mvm-core` by design — this increment was DTO-only.

## Global extraction order (leaf-first; green after every step)

Each step ends green (`cargo check --workspace --all-targets` + the wasm32
build of `mvm-protocol`). Steps within a tier are independent.

**Tier 0 — prove the config.** Add the scoped `chrono`/`thiserror` deps to
`mvm-protocol` and spike-move `plan::verb_trust.rs` (zero cross-refs) end to
end. Confirms the no_std chrono + thiserror + wasm build before committing to
the big files. Abort/rethink here if `DateTime<Utc>` doesn't serialize
byte-identically under the scoped chrono.

**Tier 1 — pure leaves (parallel).** `plan::{types, verb, verb_trust}`;
`policy::{redaction, reversible_replacement, policies, security}` (bring
`protocol::signing::SignedPayload` first or with `security`);
`protocol::{signing, host_cost, host_time, routing, broker, host_audit,
network_tunnel}`. The `{TenantId,PlanId,WorkloadId}` newtype adjunct lands here.

**Tier 2 — depend only on Tier 1.** `plan::{verb_grant, validity}` (DTO
subsets); `plan::bundle.rs` split (own PR — 2360 lines);
`policy::{network_policy, dns_pin, secret_binding, bundle}` splits;
`protocol::{host_signer, audit_signer, handler(ServiceError), signed_config,
broker_control}` (broker_control with its JCS byte fixture).

**Tier 3 — the big/gated ones (each its own PR).** `protocol::vm_backend.rs`
split; `policy::{resolver, audit}` splits; then `plan::execution_plan.rs` +
`test_support.rs` **last**, after `SnapshotAt` + the two policy types are in P.

**Tier 4 — logic rewire.** Update `signing.rs`/`toml_loader.rs`/`projection*`/
the logic halves to import from `mvm-protocol`; convert every orphaned method to
a free fn and fix call sites; rewrite each `mod.rs` as a re-export shim so
downstream `crate::{plan,policy,protocol}::X` paths never churn.

## Green-keeping gates

Per step and at close:

1. `PATH="$HOME/.cargo/bin:$PATH" cargo build -p mvm-protocol --target wasm32-unknown-unknown` → 0 (the no_std proof).
2. `MVM_SKIP_EMBED_BINARIES=1 cargo check --workspace --all-targets` → 0.
3. `MVM_SKIP_EMBED_BINARIES=1 cargo clippy --workspace --all-targets -- -D warnings` → 0, **no new `#[allow]`**.
4. `MVM_SKIP_EMBED_BINARIES=1 cargo nextest run --workspace --no-fail-fast -E 'not package(mvm-runtime) and not package(mvm-conformance)'` + `-p mvm-runtime` separately (codesign SIGKILL) → 0 failed. The signed-plan / bundle / audit / substitution rejection ladders must stay green — they *are* the byte-identity regression net.
5. `cargo run -q -p xtask -- check-claim-catalog` + `check-core-runtime-free` → clean. `mvm-core` must stay tokio-free (the no_std pressure only tightens this).
6. Byte fixtures: freeze a signed `ExecutionPlan` and a `SignedControl.ControlRequest` before Tier 1; assert identical bytes after each tier.

## Risk register

1. **Byte-identity drift on a signed type** — the whole increment's failure
   mode. Mitigation: verbatim relocation + frozen fixtures (gate 6) + the
   existing rejection-ladder suites. The chrono/core::net "keep the type"
   decisions exist precisely to avoid drift.
2. **`bundle.rs` (2360) + `vm_backend.rs` (2693) partial splits** — per-`impl`
   surgery, not whole-file moves; the most error-prone diffs. Each gets its own
   PR.
3. **Orphan-rule rewrite is repo-wide** — every crypto inherent method → free
   fn changes call sites in 4+ crates; easy to miss one. Grep each method name
   across the workspace before declaring a split done.
4. **`ControlRequest` JCS signing** — field-order drift could make a
   differently-encoded request verify. The before/after byte fixture is
   mandatory, not optional.
5. **Facade discipline is the safety net** — the ~58 `ExecutionPlan` + ~20
   `sha256_hex` external call sites survive untouched *only if* each `mod.rs`
   re-export block stays 1:1. Keep the public paths stable; churn only the
   internal file boundaries and the Cargo graph.
