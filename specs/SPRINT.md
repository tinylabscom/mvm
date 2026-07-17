# Sprint: v1 Clean Restructure & Radical Simplification

**Status:** IN PROGRESS — Phase 0 executing
**Date opened:** 2026-07-14
**Branch:** `plan/mvm-simplification`
**Supersedes:** Plan 231 (radical-simplification, on hold) and the previous rolling `SPRINT.md` (archived in git history).

> The current tree is treated as a **disposable v1**. This sprint restructures it completely.
> **No legacy paths, no compatibility shims, no aliases.** Hard renames only.

---

## 1. Why

AI-driven development left the tree far larger and more tangled than the product warrants. Measured on `main` @ `6632527a8`:

| Symptom | Measured today | Target |
|---|---|---|
| Workspace crates | 19 members (+xtask, +root) | **~11**, named by domain area |
| Cargo.lock packages | **490** (~72 direct) | material cut (dedupe TLS/net/ext4/compression stacks; drop dead deps) |
| Cargo features | **28 names, 396 `#[cfg(feature)]` sites** | **2** (`user`, `host`) + the prod/dev guest-agent build split |
| Production binaries | **~29** (15 host, 13 guest, 1 CLI) | **1 host + 1 guest + 1 CLI** |
| Base directories | **6 roots** + stray `~/microvm/vms` | **1** (`~/.mvm`) |
| Files > 1500 lines | **39** (worst 7,997) | **0** non-test |
| Egress through the auditable vsock seam | **2 of 4 backends** (libkrun/HVF only) | **100%** of workload backends |
| specs/ | 512 files / 156k lines | ADRs only (consolidated) |
| Top-level directories | ~30 | **~8** (`crates` `features` `nix` `specs` `xtask` `examples` `public` `scripts`) |
| Open worktrees | 77 | the working set |

The bar: a codebase an **expert human can read and navigate**, fully tested, following the Rust guidelines in the referenced gist. **Non-negotiable:** security, auditability, attestation-via-nix, and data governance are preserved or strengthened, never traded away.

**Core goal — wasm containers from the same architecture.** The `VmBackend` seam + `Workload` IR + one host egress/audit boundary must also run a workload as a **wasm container** (a `WasmBackend`, WASI wasm module), not only a microVM — supporting more backends from one model and reaching hosts without KVM/HVF (CI, edge, the browser). This is enabled by, and makes non-optional, a **`no_std` core**: `mvm-protocol` builds `#![no_std] + alloc` on `wasm32` with tests, CI-gated. Full design in `specs/refactor/02-architecture.md` §Wasm-container; workstream is WS11 (promoted to core).

### Reference models (studied, not copied)
- **supermachine** (single crate, 4 bins, ~20 deps, **one** feature, bundled kernel, HVF via `applevisor-sys`, KVM via `kvm-ioctls`, `mio` event loop instead of a full async runtime, `mimalloc`, sub-100ms snapshot restore). North star for lean deps + low memory + external API shape (`Image`/`Vm`/`Pool`/`ExecBuilder`, warmup/snapshot/streaming-exec/`expose_tcp`/live host mounts).
- **microsandbox** crate naming: `agentd`, `cli`, `filesystem`, `image`, `network`, `protocol`, `runtime`, `utils`. Adopted (with `mvm-` prefix).
- **holospaces**: `default-features = false` no_std core with `std` as an opt-in feature; `unsafe_code = "forbid"` at the workspace; no_std OCI layer decoders → the wasm/browser path.
- **Rust guidelines** (gist `c3161f55…`): builder pattern over many-arg fns; traits over duplicated fns; newtypes over stringly-typed APIs; `thiserror` in libs; minimal deps; minimal default features; `mlock`/`zeroize`/`subtle` for secrets; small functions; `[lints]` with pedantic; release profile tuning.

---

## 2. Target architecture

### 2.1 Crate map (~19 → ~11, named by domain area)

| New crate | Absorbs | Role | `no_std`? |
|---|---|---|---|
| **mvm-protocol** | `mvm-sdk::ir` + protocol wire types + policy types + `mvm-verify` | Workload IR, wire protocol, policy/audit types, audit-log verifier. The wasm/browser-capable core. | **yes** (`no_std` + `alloc`) |
| **mvm-core** | `mvm-core` (std parts) | Single-dir config/paths, crypto (keystore/attestation/signing), catalog. | no (std) |
| **mvm-fs** | `mvm-ext4` + `mvm-oci` + build's rootfs/overlay/unpack | Turn any image (OCI **or** nix) into a mountable rootfs + `vmlinux`; ext4 writer/reader; runtime overlay; mount ordering/policy; OCI registry fetch + unpack. | no |
| **mvm-net** | `mvm-network` + hostd tunnel/smoltcp/gateway/dns + guest net/tun/netinit | vsock/UDS transport, smoltcp egress tunnel, DNS, network-policy enforcement, secret-substitution + PII-redaction seam. | no |
| **mvm-runtime** | `mvm` + `mvm-backend` | `VmBackend` trait + libkrun/hvf/firecracker impls (mock behind `test-support`); VM lifecycle, templates, pool, warm-start. | no |
| **mvm-build** | `mvm-build` | Nix builder-VM pipeline (the nix-execution engine). | no |
| **mvm-hostd** | `mvm-hostd` + `mvm-vm-host` + host-side builder bins | **The single host binary.** Resident single-process daemon; all host roles as in-process tasks. | no |
| **mvm-agentd** | `mvm-guest` + `mvm-guest-helpers` + `mvm-host-services-ffi` | **The single guest binary.** Shipped in the runtime-overlay volume. | no |
| **mvm-sdk** | `mvm-sdk` (minus `ir`) | Decorator + runtime authoring + the **tree-sitter → Workload IR → nix template** pipeline. | no |
| **mvm-client** | `mvm-client` | Facade (`MvmClient`). **Every CLI command routes through it.** The stable surface mvmd consumes. | no |
| **mvm-cli** | `mvm-cli` | `mvmctl`. Thin; delegates to `mvm-client`. | no |

Kept as-is: `crates/deps/libkrun-sys` (FFI), `xtask`. **Dropped/folded:** `mvm-ext4`, `mvm-network`, `mvm-verify`, `mvm-guest-helpers`, `mvm-vm-host`, `mvm-host-services-ffi`, `mvm-mcp` (folded into `mvmctl serve` behind an `AgentProtocol` trait — MCP now, ACP later, no per-protocol crate; see WS7), orphan Swift `mvm-vz-supervisor`, `qemu` backend, dead deps (`colored`, `names`, `hickory-server`, stale `mvm-egress-proxy` path).

Logging is **`mvm-core::log`** (a module, not a crate): structured `tracing` for operational logs (→ `~/.mvm/logs`) **and** the seam that emits chain-signed, tamper-evident entries to the audit log for every security-relevant action. Secrets/PII are redacted at the boundary — never logged. "Auditable everywhere" means every guest↔host RPC and every egress byte is traceable through the vsock seam and the chain-signed audit log.

**Dependency direction (high → low), acyclic:**
`mvm-cli → mvm-client → mvm-runtime → {mvm-build, mvm-net, mvm-fs} → mvm-core → mvm-protocol`, with `mvm-hostd`/`mvm-agentd` at the top (bin crates nothing depends on), and `libkrun-sys` a near-leaf pulled by runtime/build.

### 2.2 Binary model — 1 host + 1 guest, no subprocess forks

- `mvm-hostd` and `mvm-agentd` are each **one process**. Roles (supervisor, broker, signer, audit, substitution, tunnel, DNS; and in the guest: agent, runner, netinit, netd, oci-init, verity-init) are **in-process async tasks / threads**, never fork-`exec`'d helpers.
- **No `std::process::Command` / `tokio::process::Command` anywhere** in the host, runtime, or guest-agent paths. All former shell-outs become native Rust: ext4 (pure-Rust writer/reader), packet filtering (in userspace at the smoltcp seam / netlink where required), tar/gzip/zstd (Rust crates). CI lint enforces zero `Command` in these crates.
- **Two carved exemptions** (the process *is* the workload, not a helper we spawn for our own logic): (1) launching the **Firecracker** VMM process; (2) the **builder VM** invoking `nix` — the builder VM is a nix-execution engine and that is its sole purpose. Both are allow-listed explicitly in the lint.
- **Secrets isolation (Option A):** keys/secrets live in a dedicated module — `mlock`ed, `zeroize`-on-drop, constant-time compare (`subtle`), never logged; the whole daemon runs under seccomp + landlock; the vsock parsers stay fuzzed. This trades the previous address-space process-moat for in-process isolation + memory hygiene; the primary guarantee (*secrets never enter the guest*) is untouched.
- **Multi-role dispatch** is by subcommand/argv0 within the single binary (no fork). PID-1 variants (verity-init, oci-init) are selected by the overlay's init symlink.
- The **builder VM runs the same single guest binary** (`mvm-agentd` in a "builder" role: drive the nix build, report status/outcome, emit the artifact location) — one guest binary across workload *and* builder VMs, not a separate builder-VM binary set.
- **Host daemon state store = append-only, signed `jsonl`** (the tamper-evident shape the audit chain already uses), never an embedded SQL / `libSQL` database — fewer deps, smaller attack surface, and it doubles as an audit artifact.

### 2.3 Feature model — exactly two

Two workspace surfaces, enforced by `xtask check-two-surfaces`:
- **`user`** (default): CLI + SDK + build + run microVMs locally.
- **`host`**: library subset — everything to build and run a microVM, no authoring niceties.

The 28 member features collapse: `builder-vm`/`pure-mkfs`/`manifest-verify` become always-on (the default and only path); `schema` moves to build-time codegen in `xtask`; `s3`/`template-registry-s3`/`custom-dns`/`dev-watch`/`mcp`/`remote`/`attestation-*` are folded in or runtime-detected. The **one** remaining compile-time capability boundary is the **prod vs dev guest-agent build** (`dev-shell`) — a security boundary (no console / `do_exec` in prod), a separately compiled artifact, not a convenience flag.

### 2.4 Directory model — single `~/.mvm`

One base root, `~/.mvm` (override `MVM_HOME`; keep `MVM_DATA_DIR` as an alias only for the transition, then drop):

```
~/.mvm/
  state/     vms, machines, instances, pool
  cache/     builder-vm, stage0, images, packs, nix-store
  run/        per-VM UDS sockets (was scattered; closes #1654)
  keys/  audit/  volumes/  overlays/  images/  builder/  logs/  config.toml
```

Kill: `~/.cache/mvm`, `~/.config/mvm`, `~/.local/{state,share}/mvm`, `$XDG_RUNTIME_DIR/mvm`, and the hardcoded `~/microvm/vms` const. Every path flows through one `mvm-core::config` module; a CI lint bans inline `$HOME/.mvm` / `dirs::` / ad-hoc `.join(".cache")`. The only intentional out-of-tree path is the AF_UNIX 108-byte socket fallback, itself rooted under `~/.mvm/run` via a short hash.

### 2.5 Backend & egress model

- Backends: **libkrun** (macOS 13–25 + Linux), **HVF** (macOS 26+), **Firecracker** (Linux workload), and **wasm** (`WasmBackend` — WASI wasm-container; core goal, see §1 + WS11). QEMU **dropped**. `mock` behind `test-support`.
- Selected via the existing `BackendKind` enum + `backend_catalog!` registry — **never string-matched**. The ~6 remaining `backend.name() == "…"` sites in `mvm-cli` and the dead `"vz"` arms are removed.
- **One host-mediated, default-deny, audited egress boundary on every workload backend**, transport-abstracted via `VmDuplexTransport`: vsock/UDS for the microVM backends, WASI host-calls for the wasm backend (one auditable seam, many transports — vsock is the microVM transport, not the invariant). libkrun + HVF already comply; **Firecracker moves off TAP+iptables onto the smoltcp vsock tunnel** (folds PR #1717 / issue #1701). Any backend that cannot mediate egress through the host fails closed on `--network-allow`.
- Mount ordering is `rootfs → runtime-overlay → custom`, with an **explicit no-shadow rule**: a later mount may never shadow an earlier target; `/mvm` and `/mvm/runtime` join the deny-prefix set.

### 2.6 Security & data-governance model (preserved/strengthened)

- **Guest sees no secrets, emits no PII** becomes a *universal* invariant once all egress crosses the host seam: bidirectional secret **substitution** (user-named `${NAME}` placeholders in the guest, real secret injected host-side on egress only for the secret's bound destination) + bidirectional **PII redaction/masking**, both written to the chain-signed audit log. Backed by a CI witness across all workload backends. (Architecture guarantees the host inspects every byte; ruleset completeness is a policy concern.)
- Verified boot (dm-verity rootfs + sealed runtime overlay), signed `ExecutionPlan` admission, content-addressed bundles, and the chain-signed audit log are all retained. Attestation via nix templates and the machine-checked claims catalog stay.
- **Auditable logging everywhere:** `mvm-core::log` emits operational logs *and* chain-signed audit entries for every security-relevant action; secrets/PII redacted at the boundary; the audit chain stays verifiable via `mvmctl trust audit verify`.
- The guest binary ships **only** as the read-only, dm-verity-sealed **runtime-overlay volume** every microVM mounts — updating the overlay updates every microVM; it is never baked per-rootfs.

### 2.7 Testing model — BDD-first

Every user-facing behavior and every security claim begins as a Gherkin `.feature` scenario, becomes a green cucumber-rs test, then a parametric implementation. **Nothing is "done" until its scenario is green and CI-gated.**

- Top-level `features/suites/sN_<name>/*.feature`, numbered by area — e.g. `s0_cli`, `s1_build_run`, `s2_egress_vsock`, `s3_secrets_pii`, `s4_verified_boot`, `s5_lifecycle`, `s6_admission_audit`.
- A dev-only **cucumber-rs runner** (`crates/mvm-conformance`, *not* one of the ~11 product crates) wires step definitions to `mvm-client`, so scenarios drive the real facade rather than mocks.
- The **claims catalog becomes executable**: each numbered security claim maps to a scenario, complementing (not replacing) the existing machine-checked witnesses.
- `just bdd` runs the suite; folded into `just ci` / the full local gate.

### 2.8 Top-level layout (root ~30 dirs → ~8)

```
crates/    every crate, incl. the SDKs (Rust + language bindings): the old sdks/ folds in here
features/  BDD suites (cucumber-rs)
nix/       flakes / derivations (absorbs packaging/ + ops/ deploy bits)
specs/     ADRs only (post-sweep)
xtask/     Rust tooling + the BDD runner glue
examples/  example workloads
public/    the website (stray docs/ + web/ fold in); kept current
scripts/   the few remaining dev/CI shell scripts
```
Root files kept: `Cargo.*`, `Justfile`, `README`/`LICENSE`/`SECURITY`/`CHANGELOG`, `AGENTS.md`, `CLAUDE.md`, `deny.toml`, `rust-toolchain.toml`, `treefmt.toml`, `cliff.toml`, `install.sh`, `.github/`, `.githooks/`. Everything else is moved or deleted (WS0.3).

### 2.9 Consolidated vsock networking (one standardized protocol)

ALL guest ingress/egress rides vsock through a single authenticated, default-deny, auditable boundary — no NIC, no TAP, no bridge, ever. Data path:
```
guest app → guest Linux stack → guest TUN (mvm-net0) → mvm-agentd [net role]
  → framed vsock protocol → per-VM host UDS (~/.mvm/run) → mvm-hostd [net worker]
  → identity check + default-deny policy + DNS + audit → smoltcp userspace stack → approved endpoints
```
Two capabilities over that one seam:
- **Generic transparent L3 tunnel** — carries no secrets; guest uses ordinary sockets (no proxy-awareness); all protocols (TCP/UDP/DNS/ICMP) as raw IP over vsock; host terminates in **userspace smoltcp** (no host TUN/NAT, no shell-out, cross-platform).
- **Typed connectors** — secret-bearing requests; the host holds the credential and performs the request; secrets never enter the guest. Reuses the existing broker; replaces the global `HTTP_PROXY=:1080`.

**Standardized protocol** (wire types in `mvm-protocol`, no_std/fuzzable): length-prefixed frames `magic|version|type|flags|flow_id|len|seq`; strict max size; `HELLO/HELLO_ACK/CONFIG/PACKET/CREDIT/HEARTBEAT/ERROR/SHUTDOWN` + ext (`FLOW_OPEN/CLOSE/RESET`, `DNS_QUERY/RESPONSE`, `POLICY_UPDATE`, `STATS`, `AUDIT_EVENT`); credit backpressure; bounded queues; separate control + packet (+ audit) streams; session handshake `protocol_version/vm_id/boot_id/session_nonce/agent_version/features/max_frame` validated host-side, **fresh boot_id + nonce per boot and per snapshot-restore** (CID-reuse safe). Default-deny; block loopback/link-local/multicast/metadata/RFC1918/IPv6-local; DNS-rebinding protection; fail-closed everywhere. A `VmDuplexTransport` trait keeps protocol/policy/audit hypervisor-independent (Firecracker UDS · libkrun unixgram · HVF vsock · in-memory for tests). Host worker is one process (Option A) under cap-drop + seccomp + landlock. Identity is per-VM; mvmd layers tenant policy/quotas on the handshake fields.

---

## 3. Workstreams

Checkbox legend: `- [ ]` todo. Each WS lists its acceptance gate. Execution is subagent-driven (fresh task + two-stage review per WS), `cargo nextest run --workspace` + `cargo clippy --workspace -- -D warnings` + `cargo fmt --all --check` green before any WS is marked done.

### Phase 0 — Repo & spec hygiene (low-risk, unblocks a clean base)

**Done so far:** `specs/` sweep (`72a4214a7`) · claims/compliance/threat-models consolidated into their topic ADRs (`985225f4e`; `check-claim-catalog` verifies 16 claims / 38 witnesses from ADR-002) · dead workspace deps dropped (`dfc70f6a7`) · worktrees swept to the 2-tree working set.

**WS0.2 — ADR consolidation + renumber (~92 → ~15)**
- [ ] Merge the 13 clusters (Appendix A) into ~15 canonical ADRs; **renumber to a clean `0001..NN` sequence** (updating every cross-reference, the claim witnesses, and CLAUDE.md/AGENTS.md); delete merged files (no decision lost); fix the dup 008/010 titles + the 012 mismatch. Keep ADR-002's content as the security SoT; no mega-ADRs.
- Gate: ADR set ~15 files, cleanly numbered; `check-claim-catalog` + `check-adr-coverage` green.

**WS0.3 — top-level directory compression** (target layout in §2.8)
- [ ] `sdks/` — the SDK *layout* is **deferred to WS1g** (which creates `crates/mvm-sdk/languages/`, co-locates the Python/TS/… surfaces, and moves the `.argv` machine-fixtures → `tests/`). This WS does only the non-SDK moves below.
- [ ] Fold `ops/` + `packaging/` into `nix/` (+ `scripts/` for the shell bits); move `resources/` into the owning crate's `assets/` (or a shared top-level `assets/`); merge stray `docs/` + `web/` into `public/`.
- [ ] Delete `spikes/`, `web/audit-verify/` (superseded by wasm `mvm-protocol`), `schema/` (regenerated by xtask), `bin/`, `out/`, `.mvm-test/`, `.DS_Store` — each after confirming no CI gate depends on it.
- Gate: root matches §2.8; CI green; nothing a gate needs is lost.

**WS0.4 — dep-hygiene CI** (dead deps already dropped)
- [ ] Add a `cargo machete` (unused-dep) gate to CI so dead deps can't creep back.
- Gate: `cargo machete` clean in CI.

**WS0.6 — BDD conformance harness (cucumber-rs)** (see §2.7)
- [ ] Add `features/suites/sN_<name>/` + the `crates/mvm-conformance` cucumber-rs runner + a `just bdd` recipe (folded into `just ci`); seed scenarios for the current security claims and the top-level CLI verbs, wired through `mvm-client`.
- [ ] Standing rule for every later WS: land its Gherkin scenarios in the same change (feature-first — the scenario is written and red before the implementation).
- Gate: `just bdd` green in CI; each security claim has a scenario.

### Phase 1 — Foundations

**WS1 — crate restructure** (the spine; each sub-step keeps tests green)
- [ ] 1a `mvm-protocol`: extract `mvm-sdk::ir` + wire + policy + `mvm-verify`; make it `#![no_std]` + `alloc`; add a `wasm32-unknown-unknown` CI build; `unsafe_code = "forbid"`.
- [ ] 1b `mvm-core`: rebuild on `mvm-protocol`; own single-dir config, crypto, keystore, attestation, catalog, `log`.
- [ ] 1c `mvm-fs`: fold `mvm-ext4` + `mvm-oci` + rootfs/overlay/unpack; one ext4 writer + one reader; "image → rootfs + vmlinux" is its public surface. _(`mvm-ext4`+`mvm-oci` merged into `mvm-fs` with `ext4`/`oci` submodules; build's rootfs/overlay/unpack absorption pending)_ Prefer **virtiofs-root for OCI** (boot directly off the unpacked OCI dir, skipping ext4 materialize) where the backend supports it; keep materialize as the fallback.
- [ ] 1d `mvm-net`: fold `mvm-network` + host tunnel/gateway/dns + guest net; vsock/UDS transport + egress seam. _(crate rename `mvm-network`→`mvm-net` landed; tunnel/dns/guest-net absorption pending)_
- [x] 1e `mvm-runtime`: fold `mvm` + `mvm-backend`; `VmBackend` trait + libkrun/hvf/firecracker. _(merged flat, workspace green; `qemu.rs` KEPT — drop deferred/contested)_
- [ ] 1f `mvm-build`: slim the builder pipeline.
- [ ] 1g `mvm-sdk`: authoring + the tree-sitter → Workload IR → **nix-template** pipeline (IR from `mvm-protocol`); user-specified **base OCI image** as the template base.
  - **`PackageType` trait** under `crates/mvm-sdk/languages/` (moved off the root): each language detects its manifest and surfaces a **locked** dependency set — prefer `uv.lock`/`poetry.lock` over `requirements.txt`, the lockfile over `package.json`, `Cargo.lock`, `Package.resolved`; fall back to the loose manifest and flag it. Built-ins: Python / TypeScript / Rust / Swift; **users register their own**.
  - Custom package types run in the user's trust domain, but the deps they produce still flow through the sealed app-deps audit (claim 11) — extensibility never bypasses the hash-lock/CVE/SBOM seal. Polyglot repos use explicit or ordered detection (no silent first-wins). Co-locate `sdks/python` + fixtures here.
  - **Runtime SDK + decorator are first-class / enabled** (control a live microVM via `mvm-client`). Security boundary = **no shell in prod**: lifecycle + the declared entrypoint + audited output / `expose_tcp` / snapshot / fork are allowed; arbitrary interactive `exec` or console into a *sealed prod* VM stays dev-only (`dev-shell`; claims 4 + 15).
- [ ] 1h `mvm-client`: facade covering every runtime operation the CLI needs.
- [ ] 1i `mvm-cli`: delete direct reaches into runtime internals; route through `mvm-client`.
- Gate: `cargo build --workspace` for both `user` and `host` surfaces; full suite green; dependency graph acyclic and matches §2.1.

**WS1 execution progress (structure-first, single green branch — `cargo check --workspace --all-targets` green after each; crate count 20→15):**
- [x] `mvm-network`→`mvm-net` rename — `6ae57b438`
- [x] `mvm-ext4`+`mvm-oci`→`mvm-fs` (`ext4`/`oci` submodules) — `10977e915`
- [x] `mvm-vm-host`→`mvm-hostd` (flat; 3 supervisor bins) — `3fc1dae6d`
- [x] `mvm-mcp`→`mvm-cli` `crate::mcp` (behind `mcp` feature) — `42b432b89`
- [x] `mvm`+`mvm-backend`→`mvm-runtime` (flat, 96 files) — `764b7d897`
- [x] `mvm-guest`+`mvm-guest-helpers`→`mvm-agentd` (214 files) — `19f1830ba`. **`mvm-host-services-ffi` kept SEPARATE** — it is a `cdylib` (`mvm_host_services`) the SDK runtimes `dlopen` + nix bakes into the overlay; folding it would break that FFI/nix contract (deviation from §2.1).
- [~] `mvm-protocol` extraction (staged, `no_std`+wasm-clean each step): **Increment 1** — `mvm-verify` → `mvm_protocol::verify`; crate born `#![no_std]+alloc+forbid(unsafe)`, builds on `wasm32` (`13c2a46dd`). **Increment 2** — Workload IR (`mvm-sdk::ir`) → `mvm_protocol::ir` + `detect_shell_entrypoint_argv` down from `mvm-core`; 35 consumers rewired, `mvm-net`/`mvm-runtime`/`mvm-storage` dropped `mvm-sdk` for `mvm-protocol` (dep-graph tightened); schemars gated behind a `schema` feature so the default/wasm build stays truly `no_std` (`9aa8ba372`). **Increment 3 (DESIGNED — execution remaining, the hard one)**: pull the pure wire/policy DTOs out of `mvm-core`'s `plan/`+`policy/`+`protocol/` (~126 `crate::` refs into `config`/`crypto`/`security`/`instance`/`tenant`) down to `mvm-protocol`, logic stays in `mvm-core` on top. Full design of record in `specs/refactor/10-increment3-protocol-core-split.md`: per-module cut (moves/stays/split across all three folders), the byte-identity invariant guarding the mvm↔mvmd signed contract (relocate DTOs **verbatim** — no serde-shape change), four resolved mechanics (keep `DateTime<Utc>` via scoped no_std `chrono`; `std::net`→`core::net`; scoped `thiserror`; orphan-rule crypto-method→free-fn rewrite), companion moves (`lifecycle::SnapshotAt`, `RedactionPolicy`+`ReversibleReplacementPolicy`, `{TenantId,PlanId,WorkloadId}`) that unblock `ExecutionPlan`, the `BundleNetworkPolicy` rename, explicit deferrals (`security_profile`, `HostdRequest`, `VmStartConfig`/`VerbGrantEnvelope`), and the leaf-first Tier 0→4 extraction order (green + wasm-clean after every step).
  - [x] **Tier 0 — GO** (`6577d06ba`): moved `plan/{types,verb,verb_trust}.rs` whole + split `validity.rs` (`FreshnessClaims`→protocol, `checked()`→`mvm-core` free fn) down to `mvm-protocol::plan`; added scoped no_std `chrono`+`thiserror` + the FIRST `mvm-core`→`mvm-protocol` dep edge. **Proved all four mechanics**: `DateTime<Utc>` compiles no_std on wasm32 + serializes byte-identical RFC-3339 (`"2026-07-16T12:34:56Z"`), `thiserror 2` no_std works, orphan-rule rewrite works, facade re-export keeps every consumer path unchanged. Green (wasm build + nextest 6595/0 + clippy + xtask). Reviewed: spec ✅ / quality approved, byte-identity `git show`-verified pre/post.
  - [x] **Tier 1 — COMPLETE** (all pure/PathBuf leaves across plan/policy/protocol now in mvm-protocol; `{TenantId,PlanId,WorkloadId}` rode `types.rs` in Tier 0):
    - [x] **Batch A — protocol leaves** (`d157ff5ff`): `protocol/{signing[SignedPayload],host_cost,host_time,host_audit,broker,routing,network_tunnel}` → `mvm-protocol`. All 7 confirmed genuine leaves; verbatim serde; `anyhow`→`RoutingError`(thiserror), `HashSet`→`BTreeSet`, `std::net`→`core::net`, `std::time`→`core::time`. Facade re-exports keep `SignedPayload` + all paths resolving. Caught a stale hardcoded path in `mvm-hostd/net_l3.rs` guard test. Green (wasm + nextest 6595/0). Reviewed: spec ✅ / approved. Minor (deferred to final review): `RoutingError::InvalidJson` also names the to_json serialize-fail case (cosmetic). Stale ADR-020 broker.rs path fixed in the ledger commit.
    - [x] **Batch B1 — policy standalone leaves** (`0509e1403`): `policy/{security,reversible_replacement}` → `mvm-protocol` (security's `SignedPayload` import repointed to its mvm-protocol path; `std::fmt`→`core::fmt` on a redacted Debug). Verbatim serde (git-show byte-identity confirmed: only `alloc::`/`core::` import lines changed). Green (wasm + nextest 6595/0 + clippy + xtask). NOTE: implementer wedged on a phantom background clippy job pre-commit; controller verified the gate + committed.
    - [x] **Batch B2 — coupled leaves + rename** (`1c5785912`): hard-renamed `policies.rs` `NetworkPolicy`→`BundleNetworkPolicy` (10 files, compiler-guided, serde-invisible; `network_policy::NetworkPolicy` enum untouched, ~250 occ verified) + moved mutually-referential `redaction.rs`+`policies.rs` → `mvm-protocol`. `toml` added dev-only (test roundtrips; not in wasm lib build). Verbatim serde (byte-identity confirmed: only the rename line changed). Green (wasm + nextest 6595/0 + clippy + xtask + doctests).
    - [x] **Batch C** (`da40b772`): `protocol/{host_signer,audit_signer}` → `mvm-protocol`. host_signer whole; audit_signer's 2 `PathBuf` fields → wire `String` (IPC DTOs, not signed → serde-byte-identical). 2 `mvm-hostd` call sites got `Path::new`/`to_string_lossy` adapters bridging the untouched `broker_control::RegisterVm` (PathBuf) → moved `SignerHelperRegisterVm` (String). Green (wasm + nextest 6595/0). Byte-identity confirmed.
  - [~] **Tier 2** — the SPLITS (orphan-rule crypto-method→free-fn rewrites) + a few clean whole-moves that were mis-classified as splits:
    - [x] **Batch D** (`fc3a05bf3`): `plan/verb_grant.rs` + `policy/bundle.rs` → `mvm-protocol`, BOTH clean whole-moves (NOT splits). verb_grant moves whole incl. `verify()`/`signing_bytes()`/`permits()` — they use only chrono/ed25519/serde_json (all mvm-protocol deps; edge-consumer grant verification belongs beside the audit verifier, mirroring `mvm_protocol::verify`), zero call-site churn. policy/bundle pure DTO (TenantId down). Byte-identity clean; green (wasm + nextest 6595/0). Deviation: added `"chrono"` to schemars `schema`-feature (VerbGrant = first schemars+DateTime type; opt-in only, not in wasm build).
    - [ ] KNOWN COSMETIC (test-only, masked): `mvm-protocol/protocol/host_signer.rs` test mod uses `.to_string()` w/o `use alloc::string::ToString` — harmless (mvm-protocol tests only build under `schema`→std via workspace unification; standalone no_std test build isn't feasible since libtest needs std). Sweep opportunistically.
    - [x] **Batch E** (`2b5c87a7`): `protocol/{handler,signed_config}` splits. handler: `ServiceError`/`ServiceDispatchResult`→protocol, `ServiceHandler` trait + `ServiceCallCtx` stay. signed_config: `SignedConfigEnvelope`/`SignedConfigError`→protocol, `key_id_for()`→mvm-core free fn (orphan rule, 4 call sites), wrap/encode/decode/verify stay. Deviation: `SignedConfigError::BadEncoding` field `base64::DecodeError`→`String` (base64 err is std-only; enum is thiserror-only NOT serde → serde-safe). Byte-identity clean; green (wasm + nextest 6595/0).
    - [x] **Batch F** (`1b195c572`): `protocol/broker_control` split — DTOs (RegisterVm[4 PathBuf→String], DeregisterVm, ControlRequest, SignedControl, ControlResponse)→mvm-protocol; serde_jcs+ed25519 sign/sign_with_key_bytes/verify→mvm-core free fns (serde_jcs not in mvm-protocol); ControlError stayed. **Pinned JCS canonical-bytes fixture `control_request_canonical_bytes_are_pinned` PASSES** + full sign/verify rejection ladder green → JCS-signed contract byte-identical proven. Byte-identity full-field verified (all serde attrs/order preserved, sig was already String). Green (wasm + nextest 6596/0). NOTE: impl wedged on phantom background nextest → controller ran gate + committed (2nd wedge; briefs say run synchronous).
    - [x] **Batch G** (`1f227805`): `policy/{secret_binding,dns_pin}` splits. secret_binding: DTO+builders+`FromStr`/`Display`(anyhow→typed `SecretBindingParseError`)→P; `resolve_value()`(std::env)→core free fn. dns_pin: `DnsPin`(`ips`→`core::net::IpAddr`)+`DnsPinRegistry`+chrono-parse methods→P; `new_pin()`(Utc::now clock) + `resolve_network_policy_pins()`(ToSocketAddrs+NetworkPolicy) stay core free fns. Byte-identity clean; green (wasm + nextest 6596/0 + doctests). Impl actively polled (no wedge).
    - [x] **Batch H** (`ccbd926ea`): `policy/network_policy` (1449) split — DTOs (`HostPort`,`NetworkPreset`,`EgressMode`,`NetworkPolicy` + `BANNED_SSH_PORT`/`MANDATORY_DENY_RANGES` consts + `is_banned_ssh_port` + all pure ctors/accessors)→P; `FromStr`/`Display` anyhow→typed `NetworkPolicyParseError`; `iptables_script`/`iptables_cleanup_script` inherent methods→core free fns (1 call site `mvm-runtime/network.rs`); `mandatory_deny_*`/`is_mandatory_deny`(ipnet/std::net) STAY. Acyclic=0 crate:: refs. Byte-identity clean (tag/rename_all/default/skip_serializing_if/deny_unknown_fields all preserved). Green (wasm + nextest 6597/0).
    - [x] **Batch I** (`4813a6c2`): `plan/bundle.rs` (2360) split — DTOs (`KeyId`+`is_well_formed`, `ArtifactRole`, `BundleArtifact`, `BundleResources`, `VerityInfo`, `BundleManifest`+`find_by_*`, `PlanArtifact`+`new`/`signature_bytes`, schema/filename consts, base64 sig helpers)→P; `KeyId::from_pubkey`/`from_identity` + `BundleManifest::canonical_bytes`→core free fns (~45 call sites); `sha256_hex`/`bundle_sha256` + all tar/fs/registry/resolver/truststore/verify STAY. Acyclic clean. Byte-identity clean (all `transparent`/`deny_unknown_fields`/`default`/`skip_serializing_if` preserved — claim-9 contract intact). Green (wasm + nextest 6597/0).
  - [x] **Tier 2 COMPLETE** — every policy/protocol/plan DTO split done; the whole `protocol/` folder + all `plan/`+`policy/` DTOs now in `mvm-protocol`.
  - [~] **Tier 3** — the big/gated splits:
    - [x] **Batch J** (`4dfefed6`): `policy/{resolver,audit}` splits. resolver: `EmergencyDeny`(+`is_active`, keeps `Option<DateTime<Utc>>`)+`EffectivePolicy`→P; `resolve`/`pick` stay. audit: `LocalAuditKind`/`LocalAuditEvent`/`AuditAction`/`AuditEntry`→P; `LocalAuditEvent::now()`→core free fn `now_event` (Utc::now clock; 2 call sites); `LocalAuditLog`/`audit_emit!` macro/`event`/`emit`/`read_last_*`(std::fs) stay. Byte-identity clean; green (wasm + nextest 6597/0).
    - [ ] `protocol/vm_backend.rs` (2693, own PR — ~1327 DTO lines move [`VmPortMapping`/`VmVolume`/`VmStatus`/`VmCapabilities`/`SnapshotCapability`/`Standby*`/`BackendKind`/cmdline enc-dec fns]; `VmBackend` trait + `VmStartConfig`/`StandbyClaim` [embed NetworkPolicy] + `VerbGrantEnvelope` STAY as core composites).
    - [ ] `plan/execution_plan.rs` LAST (+ companion `lifecycle::SnapshotAt`; `RedactionPolicy`/`ReversibleReplacementPolicy`/id-newtypes already down).
  - [ ] **Tier 4** — logic rewire (imports→mvm_protocol) + `mod.rs` re-export shims; deferred items (`security_profile`, `protocol.rs` HostdRequest/domain).
- [ ] `mvm-storage` placement — no target crate in §2.1; fold into `mvm-core` or `mvm-runtime` (decide).
- [x] Full `nextest --workspace` ran — **6598 passed / 0 failed** (`176adc793`) after fixing a class the ident-rewrites missed: **stale crate-name STRING literals** (dir paths, `-p` pkgs, features, allowlist paths) in the builder-VM guest-build/libkrun-supervisor paths. Excl `mvm-runtime` (macOS codesign-SIGKILL) + `mvm-conformance` (cucumber `harness=false` → `just bdd`). Also unblocked **5 xtask claim gates that were failing-open** (paths pointed at renamed `crates/mvm-guest`) + a vacuous `no_backend_dep` cycle guard. Lesson: after crate renames, grep strings, not just idents; `nextest --no-fail-fast` catches runtime-wrong-but-compiling.
- [ ] **Follow-up (pre-PR):** `.github/workflows/{ci,ci-full,security,release,architecture}.yml` + `scripts/*.sh` still name old crate dirs/pkgs — same class; fail loud under CI (not running yet) but `security.yml`/`architecture.yml` path-filters risk fail-open; fix before PR.
- [ ] **Follow-up (WS2↔WS10):** `check-guest-agent-runtime-free` now FAILS — merging the tokio addon bins (`addon-dns`/`vsock-bridge`/`egress-client`) into the single guest binary drags tokio into the guest closure, against the tokio-free/~8 MB goal. Single guest binary requires de-tokio'ing the addons (WS10) or a per-binary check scope.

**WS4 — single `~/.mvm`** (can land alongside 1b)
- [ ] Reparent cache/state/share/runtime/config under `~/.mvm`; `MVM_HOME` override; delete the `~/microvm/vms` const; move per-VM UDS under `~/.mvm/run` (#1654).
- [ ] Route the ~10 known bypass sites through `mvm-core::config`; add the anti-bypass CI lint.
- Gate: fresh run creates exactly one root; lint green.

**WS5 — two features**
- [ ] Collapse the 28 member features to the `user`/`host` surfaces; make `builder-vm`/`pure-mkfs`/`manifest-verify` always-on; move `schema` to build-time; keep `dev-shell` as the prod/dev agent boundary.
- Gate: `xtask check-two-surfaces`; feature-powerset shrinks to the two surfaces.

**WS6 — trait dispatch + zero hardcoding**
- [x] Replace `backend.name() == "…"` sites with `BackendKind` matches; delete dead `"vz"` arms. `VmBackend::kind()` is now a required trait method (every backend implements it); `xtask check-no-string-backend-dispatch` guards the regression.
- [ ] Remove baked network literals (`172.16.x`, `127.0.0.1:1080`, `/tmp/firecracker.socket`); inject via config; name `DEFAULT_MEM_MIB`/`DEFAULT_CPUS`; add a CI lint for hardcoded IPs/ports.
- Gate: hardcoding lint green (pending); no string-typed backend dispatch remains (done).

### Phase 2 — Binaries, egress invariant, lifecycle

**WS2 — single host + single guest binary, no forks**
- [ ] `mvm-agentd`: merge `mvm-guest` + `mvm-guest-helpers` + `mvm-host-services-ffi` **and the builder-VM guest bins** (`mvm-host-vm-init`/`mvm-builderd`/`stage0-init`/`mvm-rootfs-patcher` → a "builder" role); one binary, subcommand/argv0 dispatch; ship via the runtime-overlay volume.
- [ ] `mvm-hostd`: fold `mvm-vm-host` + host-side builder bins; single-process resident daemon; roles as tasks; state in append-only signed `jsonl` (§2.2).
- [ ] Remove every `Command` shell-out (host/runtime/agent); native Rust replacements; the two carved exemptions (FC launch, builder-VM nix) allow-listed.
- [ ] Secrets module: `mlock` + `zeroize` + `subtle`; daemon-wide seccomp + landlock.
- [ ] CI lints: "exactly two shipped binaries + CLI", "no `Command` outside the allow-list".
- Gate: `ls` of the build outputs shows 1 host + 1 guest + `mvmctl`; lints green; secrets/seccomp tests pass.

**WS-NET — consolidated vsock networking + standardized protocol** (absorbs the old WS3; see §2.9) — the core auditability seam
First vertical slice (build in this order):
- [ ] `mvm-protocol`: versioned frame codec (encode + incremental decoder) + handshake types; fuzz target for the decoder (never panic / OOM / OOB).
- [ ] `VmDuplexTransport` trait + an in-memory / process-UDS test backend (so CI needs no VMM).
- [ ] guest TUN pump (`mvm-agentd` net role): create `mvm-net0`, static IPv4, MTU, default route, DNS → controlled resolver; TUN↔frames.
- [ ] host net worker (`mvm-hostd` role): accept per-VM UDS, validate the identity handshake, default-deny policy engine + one allow rule, smoltcp forward, structured allow/deny audit.
- [ ] one control stream + one packet stream; hard frame/queue limits + credit backpressure.

Then unify + retire the old paths:
- [ ] Route Firecracker off TAP+iptables onto this tunnel (#1717, #1701); HVF host-vsock-proxy (#1601); fail-closed on `--network-allow` where the host can't mediate.
- [ ] Typed connectors = the existing broker/substitution, kept separate from the generic tunnel; secret-substitution via user-defined **`${NAME}`** named placeholders (guest holds the placeholder, host injects the value only for the secret's bound destination — ADR-023) + PII-redaction as host-side L7 inspection on inspectable flows; data-governance CI witness on all workload backends.
- [ ] Delete the dead rvproxy / native-gateway subsystem (~1,281 lines); collapse `NetworkingPreference`; drop `MVM_NETWORKING`. Enforce the mount no-shadow rule (`/mvm` in deny prefixes).
- [ ] Snapshot/restore/warm-start: fresh boot_id + nonce + handshake; stale flows closed; no live-vsock-survives-restore assumption.
- [ ] A networking ADR (networking cluster): why vsock-mandatory, guest-TUN, L3-over-smoltcp, typed-connectors-separate; threat/trust/privilege boundaries; snapshot behavior; transport abstraction.
- Gate: protocol unit + fuzz green; process-level integration proves allow-passes / deny-drops / **stale-session-rejected**; `check_vsock_only_egress` passes on all workload backends; `machine run --image busybox --allow-host google.com` resolves DNS + connects (fixes `ping: bad address`); live smoke Mac (HVF) + Linux (libkrun + FC); no NIC bypass.

**WS9 — lifecycle correctness**
- [ ] Confirm transient teardown (entrypoint exit + no healthcheck → VM stops) — already centralized; add tests.
- [ ] **Capture workload stdout/stderr + exit code over vsock** (reuse the `BuilderStatus`/`BuilderOutcome` pattern the builder VM already uses) so all workload output crosses the auditable seam and the transient exit code is sourced from it.
- [ ] Implement the missing **host-side healthcheck reaper** for persistent machines (probe the stored `health_check`; restart/mark-unhealthy on failure). Today it's persisted but never executed.
- Gate: transient exits propagate the vsock-sourced exit code + tear down; workload stdout/stderr captured over vsock; a persistent machine with a healthcheck is actively probed.

### Phase 3 — Quality: size, dead code, CLI, kernel/memory

**WS8 — file/function size + dead-code removal**
- [ ] Extract inline `#[cfg(test)]` modules from the 39 oversized files (cheap; drops many under 1500).
- [ ] Module-decompose the genuinely large bodies: `libkrun_builder`, `microvm`, `mvm-guest-agent`, `host-vm-init`, `doctor`, `unpack`, `image`, `vsock`.
- [ ] Split giant functions: `handle_client` (734 → per-verb handlers via a verb-handler trait), `run_inner`, `configure_flake_microvm_*`, `build_supervisor_config`, `unpack_layer` (per entry-type). Builders for multi-field config structs.
- [ ] Delete dead/stub code: `mvm/src/vm/egress_proxy.rs` (L7 stub), `mvm/src/storage/` dm-thin substrate, `HttpRegistry` SDK addons, the `MVM_HVF_DUMP_DTB` debug gate; gate `mock` backends behind `test-support`.
- [ ] Security fix: broker config currently parsed **unsigned** — verify signature before parse.
- [x] **Remove ssh-agent forwarding entirely — no SSH anywhere (core promise; ADR-001).** The tree carried a dev-tier ssh-agent-forwarding feature (host `$SSH_AUTH_SOCK` → vsock port 5301 → guest `/run/mvm/ssh-agent.sock`) that contradicted the "no SSH in microVMs, ever" promise and handed the guest the host's whole ssh-agent (bypassing bound-destination secret substitution). Deleted the whole surface: the `ssh_agent` spec field, manifest `[auth] ssh_agent`, `AuthMode::SshAgentSocket` + `AuthPolicy` (dropped the enum/struct entirely — `None` was the only variant left), the proxy (`mvm-cli::commands::ssh_agent_proxy`, `SSH_AGENT_PORT`, `run_ssh_agent_proxy_*`), the guest `SSH_AUTH_SOCK`/`/run/mvm/ssh-agent.sock` injection, tests, and CLI docs. **Strengthened ADR-001 to absolute** — deleted the "SSH-agent forwarding, when offered…" carve-out. Added `scripts/check-no-ssh.sh` (CI: `no-ssh-forwarding` in `security.yml`, beside `prod-agent-no-console`). The one dev interactive surface stays the builder-VM shell — nothing SSH.
- [x] **Eradicate the remaining SSH surface — no SSH in any guest, on any backend (ADR-001 follow-up).** A security audit found a full in-guest SSH server was still pervasive despite the ssh-agent-forwarding removal above: `image.rs`'s legacy Ubuntu-squashfs builder installed `openssh-server`, set `PermitRootLogin yes`/`PubkeyAuthentication yes`, generated an `*.id_rsa` keypair, and ordered workload units `After=… ssh.service`; `MvmState` (`base/config.rs`) carried a required `ssh_key` field that `microvm.rs`/`firecracker.rs` discovered/persisted as a boot-gate asset; the `refresh_builder_rootfs`/`download_builder_artifacts` builder-VM templates carried a dormant `inject_ssh` code path (always `"no"` in production, but live capability); five fully dead `*.tera` scripts (`builder_keygen`, `sync_local_flake`, `extract_artifacts_ssh`, `launch_firecracker_ssh`, `run_nix_build_ssh`) shelled real `ssh-keygen`/`scp`/`ssh`; the orchestrator accepted a legacy `"ssh"` alias for `BuilderMode::Vsock`; and a dead `tenant_ssh_key_path` helper lived in `mvm-core`. All removed — comms stays vsock-only on every backend (libkrun/HVF/Firecracker/qemu/mock), all confirmed SSH-token-free by source scan. Broadened `scripts/check-no-ssh.sh` from the ssh-agent-only pattern to every SSH-capability token (`sshd`/`openssh`/`ssh-keygen`/`authorized_keys`/`id_rsa`/`PermitRootLogin`/`sshd_config`/…), with an explicit, commented `ALLOWED_FILES` list for the pre-existing SSH *deny/detect* code (`command_gate.rs`, `threat_classifier.rs`, the inbound SSH-banner network deny-scan, mkGuest's own build-time SSH-token ban) and no-SSH-assertion docs — verified the broadened gate fails on a planted `openssh-server`/`id_rsa` probe and passes clean on the real tree. Strengthened `no_backend_advertises_production_ssh` (`backend.rs`) to cover all 6 `AnyBackend` variants (was missing `Hvf`/`HvfRunner`).
- Gate: **0 non-test files > 1500 lines**; no `todo!`/`unimplemented!` on a production path; dead modules gone.

**WS7 — simple CLI**
- [ ] Redesign to a small, discoverable verb set; `env` shown in `--help`.
- [ ] Merge `setup`/`bootstrap` into one first-run `bootstrap`. Add the lifecycle verbs: **`upgrade`** (self-update `mvmctl`); **`uninstall`** (remove everything — the binary, `~/.mvm`, and installed host/guest artifacts); **`env cleanup`** (reclaim `~/.mvm` — caches + transient VM/build state, keeping config + keys); **`env reset`** (wipe `~/.mvm` back to a clean slate). These replace the fragmented `cache prune` / `pack prune` / `storage gc`. `env` becomes a visible top-level subcommand (today `hide = true`).
- [ ] Replace the 31-arm dispatch `match` with a `Command` trait (`fn run(&self, ctx: &Cli) -> Result<()>`); one module per command; every command calls `mvm-client`.
- [ ] `mvmctl serve` exposes the agent-facing server behind an `AgentProtocol` trait (MCP impl now; ACP added as a second impl when a consumer exists — no new crate), all backed by `mvm-client`.
- [ ] Remove hidden/duplicate/dead verbs.
- [ ] Slim the **Justfile** — collapse the recipe sprawl to a small set (`build`, `test`, `lint`, `ci`, `bdd`, `run`, `clean`).
- Gate: `mvmctl --help` lists the real surface; `tests/cli.rs` covers it; no command reaches past `mvm-client`; `just --list` is short.

**WS10 — tiny kernel + low memory + density**
- [ ] Kernel: minimal defconfig; stop boot-probing IPVS/btrfs/RAID-autodetect (#1283); bump the kernel pin (#1264).
- [ ] Guest agent ≈ **8 MB**: de-`tokio` the guest (mio / raw epoll+kqueue), strip deps, measure RSS.
- [ ] Host daemon ≈ **64 MB**: minimal runtime, evaluate `mimalloc`, strip deps.
- [ ] **Density levers:** right-size the default `--memory` (64–96 MB, not 512); **demand-fault guest RAM** (MAP_ANON demand-zero instead of eager-dirty — the architectural fix for high VM density); share one **read-only kernel mmap** across VMs.
- [ ] Release profile: `lto = "thin"`, `codegen-units = 1`, `strip = true`, `panic = "abort"` for bins.
- [ ] Dep cut: dedupe ext4 (writer+reader), TLS (`reqwest`/`rustls`/`rcgen`), compression (`flate2`/`lzma-rs`/`tar`), net (`smoltcp`/`etherparse`/`rtnetlink`/`mio`), syscall (`nix`/`rustix`/`libc`); **reimplement trivially-used deps** where it removes an attack surface for little code.
- [ ] **Nix build speed:** local parallel/incremental build (nix-fast-build-style), no external cache providers (hermetic).
- Gate: guest RSS ≤ ~8 MB, host RSS ≤ ~64 MB idle; an idle guest configured at 512 MB resident-costs ~its working set (demand-fault proven); lockfile materially smaller.

**WS-DX — developer experience & performance** (the story #1637 promises)
- [ ] **Sub-second launch**, verified: a timed `mvmctl up` → PTY shell → `mvmctl down` e2e on Mac (HVF) and Linux (libkrun + FC), asserting sub-second boot + clean teardown.
- [ ] **Warm start / warm pool** (pre-warmed standby VMs), **snapshot / fork / restore** (bake once, fork many via CoW, fast restore), **streaming exec**, **`expose_tcp`** (host↔guest port forward), **live host-directory mount** — the supermachine/microsandbox-shaped capabilities, exposed through `mvm-client` + the SDK.
- [ ] A clean **external API** (`Image` / `Vm` / `Pool` / `ExecBuilder`-style) on `mvm-client`, so library and CLI share one surface.
- [ ] **Simple, fast install:** a one-line installer + `mvmctl upgrade`.
- Gate: the timed e2e proves sub-second launch on both hosts; warm-start + snapshot restore measured; the external API is documented and BDD-covered.

### Phase 4 — Docs, close-out, stretch

**WS12 — ADRs alive + website docs**
- [ ] Keep the consolidated ADRs authoritative; update `CLAUDE.md`/`AGENTS.md` to the new crate/binary/dir/feature/backend reality.
- [ ] Update the website docs (`public/src/content/docs/**`) — CLI reference, architecture diagram, backend list (drop QEMU/Vz), single-dir, install/upgrade/clean.
- [ ] Sweep stale `specs/{claims,compliance,threat-models,references,contracts,runbooks}` path references out of `SECURITY.md`, `README.md`, `ops/`, other ADRs, and `public/src/content/docs/**` (flagged by WS0.2a — they now live in ADR-002/050/067/090).
- Gate: docs match the shipped CLI + architecture; no dangling `specs/` paths; `#1637` (one-command microVM) becomes accurate.

**WS13 — issue/PR close-out** (all but #1637 — see Appendix B)
- [ ] Fold each still-relevant intent into its WS; close the 8 issues + 4 PRs with a pointer to the superseding WS. Keep **#1637** open.
- Gate: only #1637 remains open.

**WS11 — wasm-container backend + `no_std` core (CORE goal; see §2.5 + `specs/refactor/02-architecture.md` §Wasm-container)**
- [ ] `mvm-protocol` is `#![no_std] + alloc`, `unsafe_code = "forbid"`, with a `wasm32-unknown-unknown` CI build **and its tests running under wasm**; CI-gated `no_std` boundary (nothing workload-execution-relevant reaches for `std`/OS/crypto-impl). Lands with 1a-protocol + 1b (one designed pass).
- [ ] `WasmBackend` implements the same `VmBackend`/Workload contract, selected via `BackendKind`; runs a workload as a WASI wasm module under a host wasm runtime (`wasmtime`/`wasmer`), end-to-end.
- [ ] Wasm egress/audit/secret-substitution rides a `VmDuplexTransport` **WASI variant** through the same default-deny host seam; wasm guest sees no secrets / emits no PII (data-governance witness covers it; `${NAME}` and all).
- [ ] Browser POC: `mvm-protocol` + the `no_std` OCI layer decoders (per holospaces) run in the browser.
- [ ] Resolve open design Qs: wasm-workload definition (user WASI module vs mvm-compiled), overlay/agent mapping onto a wasm instance with no Linux init, browser `mvm-fs` slice.
- Gate: `mvm-protocol` wasm CI build + tests green; no_std-boundary lint holds; `WasmBackend` runs a workload through the shared egress/audit seam (POC-gated) with the data-governance witness passing.

**WS14 — mvmd contract (secondary)**
- [ ] Freeze the mvmd-facing surface (`mvm-protocol` + `mvm-client` + `BuildEnvironment`/`ShellEnvironment` traits); document it; file the coordinated rename for the mvmd repo.
- Gate: the public surface is documented and stable; mvmd rename tracked as a follow-up.

---

## 4. Sequencing

```
Phase 0 (hygiene)  ─┐   parallel-safe, do first
Phase 1 (foundations: crates, single-dir, features, trait/hardcoding) ─┐  the spine
Phase 2 (binaries, egress invariant, lifecycle) ─┐  depends on Phase 1 crate boundaries
Phase 3 (size, dead-code, CLI, kernel/memory)    ─┐  depends on the new crates existing
Phase 4 (docs, close-out, wasm stretch, mvmd)     ─   last
```

WS4/WS5/WS6 can proceed in parallel with WS1 sub-steps. WS3 depends on `mvm-net` (1d). WS2 depends on the guest/host crate merges (1e/1h). WS10's de-tokio depends on WS2's single-binary shape.

## 5. Definition of done

- Both surfaces build; `cargo nextest run --workspace` + `cargo test --workspace --doc` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all --check` green.
- **Binding Rust coding standard** (gist `c3161f55…`), enforced per-change, not just at the end: traits/enums over stringly dispatch (`name() == "…"` is banned — use a typed discriminant); **exhaustive matches, no wildcard `_ =>` on owned enums**; builder pattern for any type/fn with more than a couple of (esp. optional) fields; **functions ≤ ~500 lines**; borrowed params (`&str`/`&[T]`/`impl AsRef<Path>`); `with_capacity`/no needless `.clone()`; `thiserror` in libs; **clippy is fixed, never `#[allow]`-suppressed** (each surviving `#[allow]` scoped to the smallest item + justified).
- ~11 crates, 2 features, 1 host + 1 guest + 1 CLI binary, 1 base dir, 0 non-test files > 1500 lines, no `Command` outside the allow-list, no hardcoded IPs/ports, vsock-only egress on every workload backend with the data-governance witness passing.
- All security claims still witnessed; live egress + boot smoke on Mac (HVF) and Linux (libkrun + FC); **sub-second launch** proven by the timed e2e; guest RAM demand-faulted for density.
- **Wasm-container capable (core goal):** `mvm-protocol` builds + tests on `wasm32-unknown-unknown` in CI with a CI-enforced `no_std` boundary; a `WasmBackend` runs a workload end-to-end through the same `VmBackend` + egress/audit/secret-substitution seam (POC-gated — the v1 bar is the seam proven, not full production parity).
- Workload stdout/stderr + exit code flow over vsock; the builder VM runs the same single guest binary.
- `just bdd` green; every security claim and top-level CLI verb has a passing Gherkin scenario; `just ci` runs the BDD suite.
- Root is ~8 dirs (§2.8); SDKs live under `crates/`.
- SDK usage (decorator + runtime) unchanged; ADRs consolidated but intact; website docs current; only #1637 open.

---

## Appendix A — ADR consolidation clusters (~91 → ~15)

| Canonical ADR (theme) | Merge these |
|---|---|
| Security posture & trust boundary (SoT) | 002, 032, 063, 070, 083, 088, 104, 108, 109, 111 + claims + compliance + threat-models |
| Networking / egress / vsock | 004, 006, 055, 064, 067, 078, 082, 085, 100, 101, 110 |
| Backends / hypervisor abstraction | 014, 046, 056, 072, 076, 093, 094, 095, 098, 099, 102 |
| Builder VM / Stage 0 / seed | 005, 013, 054, 057, 065, 068, 071, 096, 106, 107 |
| Host services broker / daemon | 059, 061, 062, 084, 089, 090 |
| Signed/audited execution + claims substrate | 041, 044, 047, 048, 058, 079, 103 |
| OCI / image / registry / verity | 050, 052, 074, 097 |
| Secrets substitution | 049, 067 |
| Machine / CLI surface | 077, 091, 092, 105 |
| Function entrypoints / factories | 007, 008, 010, 011, 039 |
| Encryption | 027, 042 |
| WASM path | 069, 080, 081 |

## Appendix B — issue / PR close-out

| # | Kind | Disposition |
|---|---|---|
| **1637** | PR (draft) | **KEEP OPEN** — one-command microVM docs/blog; WS12 makes it true |
| 1701 | issue | Fold → WS3 (finish vsock tunnel), then close |
| 1717 | PR | Fold → WS3 (FC transparent net over vsock), then close |
| 1601 | issue | Fold → WS3 (HVF host-vsock-proxy), then close |
| 1674 | issue | Fold → WS1c / WS8 (OCI unpack O_EXCL), then close |
| 1654 | issue | Fold → WS4 (runtime sockets under `~/.mvm/run`), then close |
| 1462 | issue | Fold → WS2 (verb-grant delivery), then close |
| 1366 | issue | Fold → WS7 (Sandbox.connect dev-only exec guard), then close |
| 1283 | issue | Fold → WS10 (kernel boot-probe strip), then close |
| 1264 | issue | Fold → WS10 (kernel pin bump), then close |
| 1716 | PR | Superseded by this sprint — close |
| 1718 | PR | Folded (dev_vz→builder_vm rename subsumed by WS1) — close |
| 1713 | PR | Contradicts consolidation (splits SDK) — close |

## Appendix C — biggest confirmed removals

- Userspace network gateways — passt, gvproxy, and the opt-in native/rvproxy `native_gateway` subsystem (~1,281 lines); replaced by the one vsock seam (WS-NET).
- `mvm/src/vm/egress_proxy.rs` L7 stub — dead (WS8).
- `mvm/src/storage/` dm-thin substrate — every method returns "phase-2 work" (WS8).
- QEMU backend (WS1e), Vz remnants, `mvm-vz-supervisor` Swift dir (WS0.4).
- 28 member features → 2 (WS5); ~24 `#[cfg]`-heavy gates collapse.
