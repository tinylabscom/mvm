# ADR-022: Target architecture — crate graph, trait seams, process model

## Status

Accepted.

## Context

mvm holds a CI-enforced security posture (ADR-001) that every structural
choice has to preserve. Two constraints frame every decision below:
every claim in that posture stays true and stays CI-gated — a
simplification that would weaken a claim or remove its gate is rejected,
not silently accepted; and runtime process isolation is not the same
thing as build-time crate count — crates may merge, but the separate
address-space *processes* that back the signing, audit, and admission
claims may not. "The trust boundary lives below the workload" is
verified as a contract, not left as an emergent property of how the
code happens to be organized.

## Decision

### 1. Crate graph — one crate per role, fronted by a trait

Every crate is named for the capability or role it provides, never for a
specific implementation backing that role. Adding a new backend,
network provider, storage provider, or mount source is a new `impl`
behind an existing trait, not a new architectural crate wired everywhere.
A crate earns separate existence through a trait seam an external
consumer extends, a separate runtime process, a proc-macro boundary, or a
genuinely distinct dependency closure or OS gate — everything else is a
module inside an existing crate.

The current architectural crates:

| Crate | Role |
|---|---|
| `mvm-volume-contract` | Dependency-light external storage seam: validated relative paths, portable entry/error types, the object-safe async `VolumeBackend` trait, its reusable conformance fixture, and a feature-gated canonical host-directory implementation. Its default closure deliberately carries no async runtime, VMM, signing, guest-agent, or cloud-provider graph, so a fleet orchestrator can implement the mvm-owned contract without linking the host runtime. `mvm-core` and `mvm-runtime` re-export these exact items; downstream backend crates may depend on the leaf directly. No layer defines a mirror. |
| `mvm-core` | Foundation types: IDs, config, protocol, signing, routing. Absorbs the execution-plan types, policy (including session security policy), and the crypto substrate (attestation, keystore, secret store, snapshot crypto). Runtime-free by default — `tokio` is gated behind the opt-in `hostd-transport` and `manifest-verify` features, and a workspace lint asserts the default dependency tree carries no async runtime. |
| `mvm-sdk` | The build-time derivation engine: the canonical Workload IR (`ir/`), the decorator SDK (`decorator/`, parses source statically via AST — never runs user code on the host), the runtime/record-mode SDK (`runtime.rs`), and the compile/builder/addon pipeline that lowers every authoring surface to one IR and one builder-VM Nix build. |
| `mvm-runtime` | Runtime: shell execution, VM lifecycle, UI, templates; the `VmBackend` trait and every backend implementation (Firecracker, libkrun, HVF, QEMU, Mock), plus backend selection and dispatch. Its `storage::volume` module re-exports the mvm-owned volume contract and local implementation from `mvm-volume-contract`; object-store construction and encrypted remote implementations live outside this repo, in the fleet orchestrator that consumes the leaf seam. Folds together the former `mvm`, `mvm-backend`, and `mvm-storage` crates. |
| `mvm-build` | The Nix builder pipeline; also hosts the builder-VM-only binaries (the resident builder daemon and its supporting init/egress/patch tools), cross-compiled and embedded into the CLI at build time, inert on non-Linux hosts. |
| `mvm-agentd` | The vsock protocol, console, in-guest integrations, and guest agent; the in-guest function-workload runner; small in-guest helper binaries (loopback DNS resolution, a loopback-TCP-to-vsock bridge) baked into the runtime overlay. Folds together the former `mvm-guest` and `mvm-guest-helpers` crates. |
| `mvm-cli` | The Clap CLI, bootstrap, update, doctor, and template commands — a thin shell with no business logic of its own. |
| `mvm-hostd` | Host-side daemon roles: the broker and its per-tenant successor, the signing-key holders, the secret-substitution endpoint, and the per-VM packet-tunnel worker — each its own `[[bin]]` target so each role is its own process. Also hosts the per-VM host processes absorbed from the former `mvm-vm-host` crate, one per guest VM: the libkrun and HVF supervisors, and the shared external-VMM gateway/audit bridge Firecracker uses. |
| `mvm-net` | The `NetworkProvider` trait: provisioning, ingress/egress policy, DNS, and audit as a seam; the TAP/bridge/gateway implementation itself lives in `mvm-runtime`, which owns the in-VM shell it runs from. (Renamed from `mvm-network`.) |
| `mvm-fs` | OCI image distribution: registry resolution, manifest fetch, digest verification, layer fetch with streaming and size caps; the OCI-to-rootfs materialization pipeline; and a minimal, `#![forbid(unsafe_code)]`, deterministic ext4 image writer for read-only rootfs materialization — no external `mkfs`, no builder VM, no subprocess, zero `mvm-*` dependencies. Folds together the former `mvm-oci` and `mvm-ext4` crates. |
| `mvm-client` | The stable consumer-facing client trait and its DTOs (defined in `mvm-core` behind a feature flag to avoid a dependency cycle, re-exported here), with an in-process `LocalBackend` and an optional remote `GatewayBackend` behind a feature flag — one trait for every consumer regardless of whether the target is local or remote. |
| `mvm-host-services-ffi` | A C-ABI cdylib veneer over the in-guest host-services broker clients, so each language SDK binding loads one shared object instead of carrying its own Rust FFI surface. |

Two more workspace members sit outside this architectural count: `xtask`
(workspace tooling and the claim-gate lints) and `mvm-conformance` (a
dev-only BDD harness that drives the built `mvmctl` binary; never a
dependency of any shipped crate).

### 2. FFI bindings live under `crates/deps/*-sys`

Anything that binds, vendors, or compiles an external C/C++ library is a
minimal crate grouped under `crates/deps/`, holding only the binding
surface plus a thin safe wrapper — never selection, dispatch, or policy.
No architectural crate links a C library directly; it always goes
through a `crates/deps/*-sys` crate. Only `crates/deps/libkrun-sys` (the
libkrun C ABI, consumed by `mvm-runtime`) exists today. Adding a new
native dependency is a new `crates/deps/<name>-sys` crate plus a trait
impl in the consuming crate — nothing else moves.

### 3. Host process model — separate role binaries across three tiers

The host side runs as separate role binaries, isolated by tier, never as
one multicall binary re-execing into roles. Authority strictly decreases
down the tiers — the host tier alone may hold a signing key, admit a
plan, or write the audit chain — machine-checked by
`xtask check-trust-gradient` against the ledger in ADR-020.

- **Host tier.** `mvm-hostd` is one crate with several separate `[[bin]]`
  targets, each its own process: the roles that parse untrusted guest
  input hold no signing key, and the roles that hold a signing key never
  parse a guest frame directly — a compromise of the parser has nothing
  to steal, and a compromise of a signer never sees raw guest input. This
  parser/key-holder split is the moat (ADR-020).
- **Builder tier.** A resident builder daemon runs inside the builder VM
  as pid0's control-plane peer, listening on vsock and serving only a
  fixed, allowlisted build/eval protocol — no shell surface. It and its
  supporting init/egress binaries are cross-compiled static binaries
  embedded into the CLI, so a source checkout needs no separate
  toolchain step to produce them at normal build time.
  `xtask check-core-runtime-free` and its guest-agent-runtime-free
  counterpart guard the crates these binaries link against from
  regaining an async runtime dependency they don't need.
- **Per-VM tier.** `mvm-hostd`'s per-VM `[[bin]]` targets run one process
  per guest VM — a backend-specific supervisor (libkrun, HVF) or a shared
  external-VMM gateway/audit bridge (Firecracker) — confining a VMM-level
  compromise to that one VM.

### 4. Consumption topology — library, thin CLI, one client trait

`mvmctl`'s root crate is a facade: it re-exports the workspace's library
crates as `core`, `security` (an alias for the crypto module folded into
`mvm-core`), `runtime`, `backend`, `build`, and `guest`. `mvm-cli` is a
thin Clap shell over these libraries with no logic of its own. Any
consumer that wants a stable, backend-agnostic entry point — whether
in-process or over a remote gateway — uses `mvm-client`'s single trait
rather than reaching into the library crates directly; `LocalBackend` and
the optional remote `GatewayBackend` are two implementations of the same
contract, selected by how the caller connects, not by two different
consumer-facing APIs.

### 5. The SDK is the central derivation engine

Every path to a microVM workload derives through `mvm-sdk`: the
decorator surface (static AST parse, never executes user code on the
host), the runtime/record-mode surface, and any manifest- or
flake-driven authoring path all lower to the same canonical Workload IR
and the same builder-VM Nix build. There is one IR, one lowering path,
and one build path regardless of which authoring surface produced the
workload.

### 6. Encryption and key lifecycle are a separate, standing decision

The boundary-by-boundary encryption layering (which hop gets which
primitive, where key material lives) is ADR-008's decision, not
re-derived here; this ADR's job is the crate and process shape those
primitives live inside, not the primitives themselves.

## Consequences

**Positive.** One conceptual model — role-named crates, fronted by
traits, FFI bracketed under `crates/deps/` — that a newcomer can read in
an afternoon. Adding a backend, network, storage, or FFI binding is a
local change: a new `impl` and, if native code is involved, a new
`crates/deps/*-sys` crate — no architectural crate churn. The process
model gives the strongest available claim-8-class guarantee (separate
binaries, not runtime-only isolation) alongside a single operational
entry point per tier.

**Negative.** `mvm-core` dep-purity has to be actively guarded — nothing
folding into it may quietly reintroduce an async runtime dependency to
the default build. The Linux-only binaries in `mvm-build` and
`mvm-hostd` must stay inert, buildable stubs on non-Linux hosts so the
workspace build stays green for every contributor.

**Neutral.** Crate count is a consequence of the role/trait-seam
discipline above, not a target pursued for its own sake — it moves when
a role seam changes, not on a schedule.
