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

- Backends: **libkrun** (macOS 13–25 + Linux), **HVF** (macOS 26+), **Firecracker** (Linux workload). QEMU **dropped**. `mock` behind `test-support`.
- Selected via the existing `BackendKind` enum + `backend_catalog!` registry — **never string-matched**. The ~6 remaining `backend.name() == "…"` sites in `mvm-cli` and the dead `"vz"` arms are removed.
- **Vsock/UDS is the sole egress seam on every workload backend.** libkrun + HVF already comply; **Firecracker moves off TAP+iptables onto the smoltcp vsock tunnel** (folds PR #1717 / issue #1701). Any backend that cannot mediate egress through the host fails closed on `--network-allow`.
- Mount ordering is `rootfs → runtime-overlay → custom`, with an **explicit no-shadow rule**: a later mount may never shadow an earlier target; `/mvm` and `/mvm/runtime` join the deny-prefix set.

### 2.6 Security & data-governance model (preserved/strengthened)

- **Guest sees no secrets, emits no PII** becomes a *universal* invariant once all egress crosses the host seam: bidirectional secret **substitution** (placeholders in the guest, real secret injected host-side on egress) + bidirectional **PII redaction/masking**, both written to the chain-signed audit log. Backed by a CI witness across all workload backends. (Architecture guarantees the host inspects every byte; ruleset completeness is a policy concern.)
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
- [ ] Move `sdks/` into `crates/` — Rust SDK = `crates/mvm-sdk`; language bindings = `crates/mvm-sdk-<lang>` (Python surface stays `mvm`).
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
- [ ] 1c `mvm-fs`: fold `mvm-ext4` + `mvm-oci` + rootfs/overlay/unpack; one ext4 writer + one reader; "image → rootfs + vmlinux" is its public surface. Prefer **virtiofs-root for OCI** (boot directly off the unpacked OCI dir, skipping ext4 materialize) where the backend supports it; keep materialize as the fallback.
- [ ] 1d `mvm-net`: fold `mvm-network` + host tunnel/gateway/dns + guest net; vsock/UDS transport + egress seam.
- [ ] 1e `mvm-runtime`: fold `mvm` + `mvm-backend`; `VmBackend` trait + libkrun/hvf/firecracker; delete `qemu.rs`.
- [ ] 1f `mvm-build`: slim the builder pipeline.
- [ ] 1g `mvm-sdk`: authoring + the tree-sitter → Workload IR → **nix-template** pipeline (IR imported from `mvm-protocol`); support a user-specified **base OCI image** as the generated template's base layer.
- [ ] 1h `mvm-client`: facade covering every runtime operation the CLI needs.
- [ ] 1i `mvm-cli`: delete direct reaches into runtime internals; route through `mvm-client`.
- Gate: `cargo build --workspace` for both `user` and `host` surfaces; full suite green; dependency graph acyclic and matches §2.1.

**WS4 — single `~/.mvm`** (can land alongside 1b)
- [ ] Reparent cache/state/share/runtime/config under `~/.mvm`; `MVM_HOME` override; delete the `~/microvm/vms` const; move per-VM UDS under `~/.mvm/run` (#1654).
- [ ] Route the ~10 known bypass sites through `mvm-core::config`; add the anti-bypass CI lint.
- Gate: fresh run creates exactly one root; lint green.

**WS5 — two features**
- [ ] Collapse the 28 member features to the `user`/`host` surfaces; make `builder-vm`/`pure-mkfs`/`manifest-verify` always-on; move `schema` to build-time; keep `dev-shell` as the prod/dev agent boundary.
- Gate: `xtask check-two-surfaces`; feature-powerset shrinks to the two surfaces.

**WS6 — trait dispatch + zero hardcoding**
- [ ] Replace `backend.name() == "…"` sites with `BackendKind` matches; delete dead `"vz"` arms.
- [ ] Remove baked network literals (`172.16.x`, `127.0.0.1:1080`, `/tmp/firecracker.socket`); inject via config; name `DEFAULT_MEM_MIB`/`DEFAULT_CPUS`; add a CI lint for hardcoded IPs/ports.
- Gate: hardcoding lint green; no string-typed backend dispatch remains.

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
- [ ] Typed connectors = the existing broker/substitution, kept separate from the generic tunnel; secret-substitution + PII-redaction as host-side L7 inspection on inspectable flows; data-governance CI witness on all workload backends.
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

**WS11 — wasm-container (exploratory, non-gating)**
- [ ] Verify `mvm-protocol` builds + runs on `wasm32` in the browser.
- [ ] Define a `WasmBackend` seam implementing the same `VmBackend`/Workload shape (run the workload as a wasm container); a browser POC. Scaffold only — not a v1 gate.
- Gate: `mvm-protocol` wasm demo runs; the backend seam compiles.

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
- ~11 crates, 2 features, 1 host + 1 guest + 1 CLI binary, 1 base dir, 0 non-test files > 1500 lines, no `Command` outside the allow-list, no hardcoded IPs/ports, vsock-only egress on every workload backend with the data-governance witness passing.
- All security claims still witnessed; live egress + boot smoke on Mac (HVF) and Linux (libkrun + FC); **sub-second launch** proven by the timed e2e; guest RAM demand-faulted for density.
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

- rvproxy / native-gateway subsystem — ~1,281 lines, zero live callers (WS3).
- `mvm/src/vm/egress_proxy.rs` L7 stub — dead (WS8).
- `mvm/src/storage/` dm-thin substrate — every method returns "phase-2 work" (WS8).
- QEMU backend (WS1e), Vz remnants, `mvm-vz-supervisor` Swift dir (WS0.4).
- 28 member features → 2 (WS5); ~24 `#[cfg]`-heavy gates collapse.
