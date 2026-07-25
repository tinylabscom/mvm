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

| Symptom                                 | Measured today                            | Target                                                                           |
| --------------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------- |
| Workspace crates                        | 19 members (+xtask, +root)                | **~11**, named by domain area                                                    |
| Cargo.lock packages                     | **490** (~72 direct)                      | material cut (dedupe TLS/net/ext4/compression stacks; drop dead deps)            |
| Cargo features                          | **28 names, 396 `#[cfg(feature)]` sites** | **2** (`user`, `host`) + the prod/dev guest-agent build split                    |
| Production binaries                     | **~29** (15 host, 13 guest, 1 CLI)        | **1 host + 1 guest + 1 CLI**                                                     |
| Base directories                        | **6 roots** + stray `~/microvm/vms`       | **1** (`~/.mvm`)                                                                 |
| Files > 1500 lines                      | **39** (worst 7,997)                      | **0** non-test                                                                   |
| Egress through the auditable vsock seam | **2 of 4 backends** (libkrun/HVF only)    | **100%** of workload backends                                                    |
| specs/                                  | 512 files / 156k lines                    | ADRs only (consolidated)                                                         |
| Top-level directories                   | ~30                                       | **~8** (`crates` `features` `nix` `specs` `xtask` `examples` `public` `scripts`) |
| Open worktrees                          | 77                                        | the working set                                                                  |

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

| New crate        | Absorbs                                                                  | Role                                                                                                                                                          | `no_std`?                    |
| ---------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| **mvm-protocol** | `mvm-sdk::ir` + protocol wire types + policy types + `mvm-verify`        | Workload IR, wire protocol, policy/audit types, audit-log verifier. The wasm/browser-capable core.                                                            | **yes** (`no_std` + `alloc`) |
| **mvm-core**     | `mvm-core` (std parts)                                                   | Single-dir config/paths, crypto (keystore/attestation/signing), catalog.                                                                                      | no (std)                     |
| **mvm-fs**       | `mvm-ext4` + `mvm-oci` + build's rootfs/overlay/unpack                   | Turn any image (OCI **or** nix) into a mountable rootfs + `vmlinux`; ext4 writer/reader; runtime overlay; mount ordering/policy; OCI registry fetch + unpack. | no                           |
| **mvm-net**      | `mvm-network` + hostd gateway/dns + guest net/netinit                  | vsock/UDS transport, host-mediated egress, DNS, network-policy enforcement, secret-substitution + PII-redaction seam.                                      | no                           |
| **mvm-runtime**  | `mvm` + `mvm-backend`                                                    | `VmBackend` trait + libkrun/hvf/firecracker impls (mock behind `test-support`); VM lifecycle, templates, pool, warm-start.                                    | no                           |
| **mvm-build**    | `mvm-build`                                                              | Nix builder-VM pipeline (the nix-execution engine).                                                                                                           | no                           |
| **mvm-hostd**    | `mvm-hostd` + `mvm-vm-host` + host-side builder bins                     | **The single host binary.** Resident single-process daemon; all host roles as in-process tasks.                                                               | no                           |
| **mvm-agentd**   | `mvm-guest` + `mvm-guest-helpers` + `mvm-host-services-ffi`              | **The single guest binary.** Shipped in the runtime-overlay volume.                                                                                           | no                           |
| **mvm-sdk**      | `mvm-sdk` (minus `ir`)                                                   | Decorator + runtime authoring + the **tree-sitter → Workload IR → nix template** pipeline.                                                                    | no                           |
| **mvm-client**   | `mvm-client`                                                             | Facade (`MvmClient`). **Every CLI command routes through it.** The stable surface mvmd consumes.                                                              | no                           |
| **mvm-cli**      | `mvm-cli`                                                                | `mvmctl`. Thin; delegates to `mvm-client`.                                                                                                                    | no                           |

Kept as-is: `crates/deps/libkrun-sys` (FFI), `xtask`. **Dropped/folded:** `mvm-ext4`, `mvm-network`, `mvm-verify`, `mvm-guest-helpers`, `mvm-vm-host`, `mvm-host-services-ffi`, `mvm-mcp` (folded into `mvmctl serve` behind an `AgentProtocol` trait — MCP now, ACP later, no per-protocol crate; see WS7), orphan Swift `mvm-vz-supervisor`, `qemu` backend, dead deps (`colored`, `names`, `hickory-server`, stale `mvm-egress-proxy` path).

Logging is **`mvm-core::log`** (a module, not a crate): structured `tracing` for operational logs (→ `~/.mvm/logs`) **and** the seam that emits chain-signed, tamper-evident entries to the audit log for every security-relevant action. Secrets/PII are redacted at the boundary — never logged. "Auditable everywhere" means every guest↔host RPC and every egress byte is traceable through the vsock seam and the chain-signed audit log.

**Dependency direction (high → low), acyclic:**
`mvm-cli → mvm-client → mvm-runtime → {mvm-build, mvm-net, mvm-fs} → mvm-core → mvm-protocol`, with `mvm-hostd`/`mvm-agentd` at the top (bin crates nothing depends on), and `libkrun-sys` a near-leaf pulled by runtime/build.

### 2.2 Binary model — 1 host + 1 guest, no subprocess forks

- `mvm-hostd` and `mvm-agentd` are each **one process**. Roles (supervisor, broker, signer, audit, substitution, DNS; and in the guest: agent, runner, netinit, oci-init, verity-init) are **in-process async tasks / threads**, never fork-`exec`'d helpers.
- **No `std::process::Command` / `tokio::process::Command` anywhere** in the host, runtime, or guest-agent paths. All former shell-outs become native Rust: ext4 (pure-Rust writer/reader), supervisor L4 policy, tar/gzip/zstd (Rust crates). CI lint enforces zero `Command` in these crates.
- **Two carved exemptions** (the process _is_ the workload, not a helper we spawn for our own logic): (1) launching the **Firecracker** VMM process; (2) the **builder VM** invoking `nix` — the builder VM is a nix-execution engine and that is its sole purpose. Both are allow-listed explicitly in the lint.
- **Secrets isolation (Option A):** keys/secrets live in a dedicated module — `mlock`ed, `zeroize`-on-drop, constant-time compare (`subtle`), never logged; the whole daemon runs under seccomp + landlock; the vsock parsers stay fuzzed. This trades the previous address-space process-moat for in-process isolation + memory hygiene; the primary guarantee (_secrets never enter the guest_) is untouched.
- **Multi-role dispatch** is by subcommand/argv0 within the single binary (no fork). PID-1 variants (verity-init, oci-init) are selected by the overlay's init symlink.
- The **builder VM runs the same single guest binary** (`mvm-agentd` in a "builder" role: drive the nix build, report status/outcome, emit the artifact location) — one guest binary across workload _and_ builder VMs, not a separate builder-VM binary set.
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
- **One host-mediated, default-deny, audited egress boundary on every workload backend**, transport-abstracted via `VmDuplexTransport`: vsock/UDS for the microVM backends, WASI host-calls for the wasm backend. Firecracker, libkrun, and HVF all use the `WorkloadRunner` endpoint seam; any backend that cannot mediate egress through the host fails closed on `--network-allow`.
- Mount ordering is `rootfs → runtime-overlay → custom`, with an **explicit no-shadow rule**: a later mount may never shadow an earlier target; `/mvm` and `/mvm/runtime` join the deny-prefix set.

### 2.6 Security & data-governance model (preserved/strengthened)

- **Guest sees no secrets, emits no PII** becomes a _universal_ invariant once all egress crosses the host seam: bidirectional secret **substitution** (user-named `${NAME}` placeholders in the guest, real secret injected host-side on egress only for the secret's bound destination) + bidirectional **PII redaction/masking**, both written to the chain-signed audit log. Backed by a CI witness across all workload backends. (Architecture guarantees the host inspects every byte; ruleset completeness is a policy concern.)
- Verified boot (dm-verity rootfs + sealed runtime overlay), signed `ExecutionPlan` admission, content-addressed bundles, and the chain-signed audit log are all retained. Attestation via nix templates and the machine-checked claims catalog stay.
- **Auditable logging everywhere:** `mvm-core::log` emits operational logs _and_ chain-signed audit entries for every security-relevant action; secrets/PII redacted at the boundary; the audit chain stays verifiable via `mvmctl trust audit verify`.
- The guest binary ships **only** as the read-only, dm-verity-sealed **runtime-overlay volume** every microVM mounts — updating the overlay updates every microVM; it is never baked per-rootfs.

### 2.7 Testing model — BDD-first

Every user-facing behavior and every security claim begins as a Gherkin `.feature` scenario, becomes a green cucumber-rs test, then a parametric implementation. **Nothing is "done" until its scenario is green and CI-gated.**

- Top-level `features/suites/sN_<name>/*.feature`, numbered by area — e.g. `s0_cli`, `s1_build_run`, `s2_egress_vsock`, `s3_secrets_pii`, `s4_verified_boot`, `s5_lifecycle`, `s6_admission_audit`.
- A dev-only **cucumber-rs runner** (`crates/mvm-conformance`, _not_ one of the ~11 product crates) wires step definitions to `mvm-client`, so scenarios drive the real facade rather than mocks.
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

ALL workload guest ingress/egress rides vsock through a single authenticated,
default-deny, auditable boundary. Workload backends expose no guest NIC surface
to the runner; Firecracker's former guest-TAP Model-A path is deleted. Data path:

```
guest app → guest loopback / guest egress client → authenticated vsock
  → RealEndpointSpawner + broker/substitution gate → approved endpoints
```

Two capabilities over that one seam:

- **Typed connectors** — secret-bearing requests; the host holds the credential and performs the request; secrets never enter the guest. Reuses the existing broker and the live supervisor L4 gate.
- **Raw admitted egress** — the guest egress client sends approved host/port flows over vsock to the host endpoint spawner; no guest NIC, TUN, TAP, smoltcp, or L3 tunnel is involved.

**Standardized protocol**: workload control and egress requests use the
authenticated vsock transports and strict host/guest protocol types already
owned by the runtime runner, broker, substitution endpoint, and supervisor L4
gate. Default-deny admission, destination policy, secret binding, and audit
are enforced at those typed seams; there is no raw packet stream or L3 worker.

---

## 3. Workstreams

Checkbox legend: `- [ ]` todo. Each WS lists its acceptance gate. Execution is subagent-driven (fresh task + two-stage review per WS), `cargo nextest run --workspace` + `cargo clippy --workspace -- -D warnings` + `cargo fmt --all --check` green before any WS is marked done.

### Phase 0 — Repo & spec hygiene (low-risk, unblocks a clean base)

**Done so far:** `specs/` sweep (`72a4214a7`) · claims/compliance/threat-models consolidated into their topic ADRs (`985225f4e`; `check-claim-catalog` verifies 16 claims / 38 witnesses from ADR-002) · dead workspace deps dropped (`dfc70f6a7`) · worktrees swept to the 2-tree working set.

**WS0.2 — ADR consolidation + renumber (~92 → ~15)**

- [ ] Merge the 13 clusters (Appendix A) into ~15 canonical ADRs; **renumber to a clean `0001..NN` sequence** (updating every cross-reference, the claim witnesses, and CLAUDE.md/AGENTS.md); delete merged files (no decision lost); fix the dup 008/010 titles + the 012 mismatch. Keep ADR-002's content as the security SoT; no mega-ADRs.
- Gate: ADR set ~15 files, cleanly numbered; `check-claim-catalog` + `check-adr-coverage` green.

**WS0.3 — top-level directory compression** (target layout in §2.8)

- [ ] `sdks/` — the SDK _layout_ is **deferred to WS1g** (which creates `crates/mvm-sdk/languages/`, co-locates the Python/TS/… surfaces, and moves the `.argv` machine-fixtures → `tests/`). This WS does only the non-SDK moves below.
- [ ] Fold `ops/` + `packaging/` into `nix/` (+ `scripts/` for the shell bits); move `resources/` into the owning crate's `assets/` (or a shared top-level `assets/`); merge stray `docs/` + `web/` into `public/`.
- [ ] Delete `spikes/`, `web/audit-verify/` (superseded by wasm `mvm-protocol`), `schema/` (regenerated by xtask), `bin/`, `out/`, `.mvm-test/`, `.DS_Store` — each after confirming no CI gate depends on it.
- Gate: root matches §2.8; CI green; nothing a gate needs is lost.

**WS0.4 — dep-hygiene CI** (dead deps already dropped)

- [ ] Add a `cargo machete` (unused-dep) gate to CI so dead deps can't creep back.
- Gate: `cargo machete` clean in CI.

**WS0.6 — BDD conformance harness (cucumber-rs)** (see §2.7)

- [ ] Add `features/suites/sN_<name>/` + the `crates/mvm-conformance` cucumber-rs runner + a `just bdd` recipe (folded into `just ci`); seed scenarios for the current security claims and the top-level CLI verbs, wired through `mvm-client`.
  - [x] Gate every software-publication path on a reusable GitHub Actions workflow that runs `just bdd`: runtime releases, kernel release assets, SDK registry releases, and crates.io publication. Keep emergency revocation-list publication independent of the product suite.
- [ ] Standing rule for every later WS: land its Gherkin scenarios in the same change (feature-first — the scenario is written and red before the implementation).
- Gate: `just bdd` green in CI; each security claim has a scenario.

### Phase 1 — Foundations

- [x] **Cross-cutting guest protocol hardening (Plan 254):** made the logical
      control/data-plane split executable with exhaustive verb classification,
      64 total / 48 data request admission, symmetric 256 KiB frame limits,
      48 KiB filesystem/process chunks, offset-addressed `fs`/`cp` transfers,
      host-CID-only console data admission, and mandatory authenticated /
      encrypted host↔guest control sessions on every backend. Guest protocol v2 is a hard cutover;
      schemas and Python/TypeScript bindings are regenerated. Host workspace tests
      and checks plus affected-crate clippy are green; Linux workspace-wide clippy
      remains the required merge-CI gate.

**WS1 — crate restructure** (the spine; each sub-step keeps tests green)

- [ ] 1a `mvm-protocol`: extract `mvm-sdk::ir` + wire + policy + `mvm-verify`; make it `#![no_std]` + `alloc`; add a `wasm32-unknown-unknown` CI build; `unsafe_code = "forbid"`.
- [ ] 1b `mvm-core`: rebuild on `mvm-protocol`; own single-dir config, crypto, keystore, attestation, catalog, `log`.
- [x] 1c `mvm-fs`: fold `mvm-ext4` + `mvm-oci` + rootfs/overlay/unpack; one ext4 writer + one reader; "image → rootfs + vmlinux" is its public surface. _(`mvm-ext4`+`mvm-oci` merged into `mvm-fs` with `ext4`/`oci` submodules;_ **`oci_to_rootfs` moved mvm-build→mvm-fs `67e492f87`** _— the OCI-image→ext4-rootfs materializer (unpack/path-validation/ext4-materialize/verity-seal, ~2000 LOC + its integration tests) now lives in `mvm_fs::oci_to_rootfs`, using `crate::ext4`; mvm-fs stays a zero-mvm-dep leaf (+uuid). The builder-VM-orchestrated `rootfs.rs` (builder_backend_select/builder_vm) + `runtime_overlay.rs` (guest_agent_build) STAY in mvm-build — correctly a build concern, not fs. **1c.1 walker/materializer unification landed `a28f583b2`** (subagent-driven, spec ✅ + quality Approved): the two duplicate mid-layer tree-walk+materialize implementations (`mvm_build::rootfs::{collect_nodes,UnsupportedNodePolicy,materialize_ext4_pure*}` and `oci_to_rootfs::ext4`'s private `collect_nodes`) are now ONE `mvm_fs::rootfs` module (unconditional; xattr-aware walker + pure materializer + options); `oci_to_rootfs::ext4` = thin adapter (keeps `StagedRootfs` entry, `OciUnpackError` mapping, mke2fs escape hatch); `mvm_build::rootfs` = builder-VM dispatcher only; mvm-runtime `image.rs` rewired to the source. One disclosed behavior change: the OCI in-process arm inherits widen+restore read of owner-unreadable files (error→success only; emitted bytes unchanged, xattr policy pinned `Ignore`). 7518/7518 nextest (+10 net moved/new tests), all gates + Linux zigbuild cross-check green. Review Minor (follow-up): the widen/restore chmod-read-chmod has a narrow pre-existing TOCTOU window — consider open-then-fstat hardening. **1c.2 landed `c944a5bc2`** (subagent-driven, spec ✅ + quality Approved): the runtime-overlay cache-RESOLVE half (`RuntimeOverlayLayout`/`Artifact`/`ArtifactNames`/`Resolver`, `read_overlay_artifact_from_dir`) moved to a new **`mvm_fs::overlay`** module — a pure local probe (seed-from-default-cache deliberately relocated to build-side `resolve_or_seed_from_default_cache`; reviewer traced every in-repo caller still seeds); arch crosses as the dir-name string so **mvm-fs stays a zero-mvm-dep leaf** (`cargo tree` verified); new `OverlayError` with `#[error(transparent)]` mapping keeps messages byte-identical; build/nix-build/download/install/orchestrator stay in `mvm_build::runtime_overlay`; consumers (up.rs, both runtime_overlay commands, xtask version-check) rewired to the source. 7522/7522 (+4 tests), all gates + zigbuild green. **1c is now COMPLETE** — deferred: virtiofs-root-for-OCI (Phase 2), ext4-read facade, the fleet-repo one-line `resolve` switch, the pre-existing-broken Linux+nix `build_produces_resolver_compatible_artifact` test (stages no checksums manifest). `oci_verity_sealing.rs` test stayed in mvm-build (uses mvm-build-only `run_image::seal_run_rootfs_with_verity`). DEFERRED to the pre-PR CI-YAML sweep: `.github/workflows/{ci-full,security}.yml` OCI path-filters/comments are stale across BOTH the old `mvm-oci`→`mvm-fs` merge AND this move (+ nix flake comments) — fix all at once, not piecemeal.)_ Prefer **virtiofs-root for OCI** (boot directly off the unpacked OCI dir, skipping ext4 materialize) where the backend supports it; keep materialize as the fallback.
- [x] 1d `mvm-net`: fold `mvm-network` + guest/host network helpers; vsock transport + egress seam. The DNS codec, policy guard, loopback stub, resolver seeding, and claim-10 wiring are complete; the former L3 tunnel and guest-netd absorption is deleted in the uniform-vsock convergence.
- [x] 1e `mvm-runtime`: fold `mvm` + `mvm-backend`; `VmBackend` trait + libkrun/hvf/firecracker. _(merged flat, workspace green; `qemu.rs` KEPT as the opt-in Linux dev substrate — drop **ratified against**: QEMU stays a Tier-2 dev/test backend, never workload-bearing)_
- [ ] 1f `mvm-build`: slim the builder pipeline.
- [ ] 1g `mvm-sdk`: authoring + the tree-sitter → Workload IR → **nix-template** pipeline (IR from `mvm-protocol`); user-specified **base OCI image** as the template base.
  - **`PackageType` trait** under `crates/mvm-sdk/languages/` (moved off the root): each language detects its manifest and surfaces a **locked** dependency set — prefer `uv.lock`/`poetry.lock` over `requirements.txt`, the lockfile over `package.json`, `Cargo.lock`, `Package.resolved`; fall back to the loose manifest and flag it. Built-ins: Python / TypeScript / Rust / Swift; **users register their own**.
  - Custom package types run in the user's trust domain, but the deps they produce still flow through the sealed app-deps audit (claim 11) — extensibility never bypasses the hash-lock/CVE/SBOM seal. Polyglot repos use explicit or ordered detection (no silent first-wins). Co-locate `sdks/python` + fixtures here.
  - **Runtime SDK + decorator are first-class / enabled** (control a live microVM via `mvm-client`). Security boundary = **no shell in prod**: lifecycle + the declared entrypoint + audited output / `expose_tcp` / snapshot / fork are allowed; arbitrary interactive `exec` or console into a _sealed prod_ VM stays dev-only (`dev-shell`; claims 4 + 15).
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
- [x] `mvm-protocol` extraction (staged, `no_std`+wasm-clean each step) — **ALL 3 INCREMENTS COMPLETE**: **Increment 1** — `mvm-verify` → `mvm_protocol::verify`; crate born `#![no_std]+alloc+forbid(unsafe)`, builds on `wasm32` (`13c2a46dd`). **Increment 2** — Workload IR (`mvm-sdk::ir`) → `mvm_protocol::ir` + `detect_shell_entrypoint_argv` down from `mvm-core`; 35 consumers rewired, `mvm-net`/`mvm-runtime`/`mvm-storage` dropped `mvm-sdk` for `mvm-protocol` (dep-graph tightened); schemars gated behind a `schema` feature so the default/wasm build stays truly `no_std` (`9aa8ba372`). **Increment 3 (DESIGNED — execution remaining, the hard one)**: pull the pure wire/policy DTOs out of `mvm-core`'s `plan/`+`policy/`+`protocol/` (~126 `crate::` refs into `config`/`crypto`/`security`/`instance`/`tenant`) down to `mvm-protocol`, logic stays in `mvm-core` on top. Full design of record in `specs/refactor/10-increment3-protocol-core-split.md`: per-module cut (moves/stays/split across all three folders), the byte-identity invariant guarding the mvm↔mvmd signed contract (relocate DTOs **verbatim** — no serde-shape change), four resolved mechanics (keep `DateTime<Utc>` via scoped no_std `chrono`; `std::net`→`core::net`; scoped `thiserror`; orphan-rule crypto-method→free-fn rewrite), companion moves (`lifecycle::SnapshotAt`, `RedactionPolicy`+`ReversibleReplacementPolicy`, `{TenantId,PlanId,WorkloadId}`) that unblock `ExecutionPlan`, the `BundleNetworkPolicy` rename, explicit deferrals (`security_profile`, `HostdRequest`, `VmStartConfig`/`VerbGrantEnvelope`), and the leaf-first Tier 0→4 extraction order (green + wasm-clean after every step).
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
    - [x] **Batch K** (`0d966d018`): `protocol/vm_backend.rs` (2693) split — ~28 DTOs (`VmPortMapping`/`VmVolume`/`VmFile`/`VmStatus`/`VmId`/`VmExitStatus`/`VmCapabilities`/`RequiredCapabilities`/`SnapshotCapability`/`WarmStart*`/`Standby{Spec,Compat,Handle,State,Error}`/`Balloon`/`ClaimStatus`/`LayerCoverage`/`BackendSecurityProfile`/`VmInfo`/`BackendKind`/`RuntimeSource*`/`GuestChannelInfo`/`VmNetworkInfo`) + 4 pure cmdline encode fns→P; `GuestChannelInfo`/`StandbySpec`/`StandbyHandle` path fields→wire String. `VmBackend` trait + `VmStartConfig`/`VerbGrantEnvelope`/`StandbyClaim` (embed those + VerbGrant) + `select_runtime_source_policy` + anyhow cmdline codecs STAY. Byte-identity clean (serde attrs preserved; StandbyClaim keeps PathBuf). Green (wasm + nextest 6596/0 + `check-no-string-backend-dispatch`). Impl yielded on auto-backgrounded nextest → controller ran gate + committed.
    - [x] **Batch L — FINAL DTO move** (`51471dd7`): `plan/execution_plan.rs` (claim-8 signed `ExecutionPlan` + `SCHEMA_VERSION`) + companion `lifecycle.rs` (`SnapshotAt`+`LifecycleMarker`) → `mvm-protocol`. **ExecutionPlan byte-identity PERFECT** (46/46 field+attr lines identical; only diff = 2 field-type path qualifications `policy::X`→`policy::x::X`, serde-invisible). Roundtrip test rebuilt inline (core `sample_plan` unreachable). Green (wasm + nextest 6596/0 incl. plan signing/verify/admission). **The entire signed plan now compiles no_std on wasm32.**
  - [x] **Tier 3 COMPLETE.** **ALL Increment-3 DTO extraction DONE** — every `plan/`+`policy/`+`protocol/` wire/policy DTO (leaves + splits + the 2 biggest files + the signed ExecutionPlan) now lives in `#![no_std]+alloc` `mvm-protocol`; all logic (signing/verify/synthesis/resolve/fs/net/tar) stays in `mvm-core` on top. 13 batches, every one green + byte-identity verified.
  - [x] **Tier 4 — COMPLETE** (the substantive rewire happened incrementally; each split repointed its own facade + fixed imports, so the workspace was green after every batch — no broken imports remained). Closeout was documentation: the 2 "deferred" items resolved to **permanent `mvm-core` residents**, NOT pending moves — `policy/security_profile` (a `Copy` runtime value, not a serde DTO, + `crypto::seccomp` dep) and `protocol/protocol.rs` `HostdRequest`/`HostdResponse` (host-side mvmd↔hostd IPC embedding `domain::{VolumeAttach,TenantNet}` — which stay in core per architecture — over `hostd-transport` tokio framing; nothing runs in guest/browser). This is the clean line: **mvm-protocol = DTOs a no_std/edge/guest/browser consumer needs; host-only IPC + orchestration domain stay in mvm-core.** Design doc `10-…` updated to Status:COMPLETE. (Cosmetic: 1 masked test-only `ToString` import left as-is — adding it risks a redundant-import lint under the std/schema build.)
  - [x] **INCREMENT 3 COMPLETE** — the `mvm-core`→`mvm-protocol` DTO inversion (the Phase 1a long pole) is done. Entire signed plan + all wire/policy/plan DTOs compile no_std on wasm32; the wasm-container core-goal (WS11) foundation is real.
  - [ ] **Tier 4** — logic rewire (imports→mvm_protocol) + `mod.rs` re-export shims; deferred items (`security_profile`, `protocol.rs` HostdRequest/domain).
- [x] `mvm-storage` placement — folded into `mvm-runtime` as `crate::storage::volume` (nested under the pre-existing `crate::storage` dm-thin CoW pool module — a naming collision the original decision didn't anticipate — to avoid clashing `backend.rs`/`mod.rs` filenames and a second unrelated `StorageError`). `s3` feature renamed `storage-s3`, off by default (`cargo tree -p mvm-runtime -e no-dev` carries no `object_store` by default, present only with `--features storage-s3`); Linux `tempfile` dep was already an unconditional normal dep of `mvm-runtime`, no change needed; `SnapshotUpper` import in `libkrun.rs` repointed. Crate deleted, workspace member + `[workspace.dependencies]` entries removed. Crate count 15 → 14.
- [x] Full `nextest --workspace` ran — **6598 passed / 0 failed** (`176adc793`) after fixing a class the ident-rewrites missed: **stale crate-name STRING literals** (dir paths, `-p` pkgs, features, allowlist paths) in the builder-VM guest-build/libkrun-supervisor paths. Excl `mvm-runtime` (macOS codesign-SIGKILL) + `mvm-conformance` (cucumber `harness=false` → `just bdd`). Also unblocked **5 xtask claim gates that were failing-open** (paths pointed at renamed `crates/mvm-guest`) + a vacuous `no_backend_dep` cycle guard. Lesson: after crate renames, grep strings, not just idents; `nextest --no-fail-fast` catches runtime-wrong-but-compiling.
- [x] **CI/ADR stale-ref sweep** (`b0a9d2477`): the workflows + `ADR-022` were never updated through the 7 consolidations, so several jobs invoked deleted packages. Remapped every functional `cargo -p <gone>` (`mvm-guest`→`mvm-agentd`, `mvm-ext4`/`mvm-oci`→`mvm-fs`, `mvm-vm-host`→`mvm-hostd`, +3 stray `mvm-build`→`mvm-fs` test invocations) **verified by RUNNING each** (mvm-agentd 560/560, mvm-fs oci 25/25 + hermetic 4/4 + the 3 ext4 examples, mvm-hostd bins build); repointed `ci-full` OCI path-filters + `architecture` globs + `security` fuzz-cache paths; refreshed the `ADR-022` crate table (dropped `mvm-verify`). Both dead-crate-`-p` + stale-path-filter rg sweeps now EMPTY; all 5 YAMLs still parse. Config/doc only. **STILL DEFERRED (cosmetic/frozen/pre-existing, reported):** prose crate-name mentions in ADRs 001/002/009/010/014/016/020/024; the `security.yml` FROZEN fuzz-lane `working-directory: crates/mvm-{guest,oci,vm-host,ext4}` (needs care re pinned locks); two OLDER broken refs `mvm-jailer-lite`/`mvm-host-vm-init` (pre-this-session consolidation); a non-breaking `crates/mvm/src/hostd/**` glob + an `ext4-real-mount` job label. `scripts/*.sh` not yet swept.
- [ ] **Follow-up (WS2↔WS10):** `check-guest-agent-runtime-free` now FAILS — merging the tokio addon bins (`addon-dns`/`vsock-bridge`/`egress-client`) into the single guest binary drags tokio into the guest closure, against the tokio-free/~8 MB goal. Single guest binary requires de-tokio'ing the addons (WS10) or a per-binary check scope.

**WS4 — single `~/.mvm`** (can land alongside 1b)

- [x] Reparent cache/state/share/runtime/config under `~/.mvm`; `MVM_HOME` override; delete the `~/microvm/vms` const; move per-VM UDS under `~/.mvm/run` (#1654). _(**WS4.1 landed `1b62d8212`** + review-fix `31d793bd0`, subagent-driven, spec ✅ + quality Approved: one root resolver pair `mvm_home()`/`mvm_home_strict()` (`MVM_HOME` | `$HOME/.mvm`; lenient keeps the documented `/tmp` fallback, strict errors — security-sensitive callers verified on strict), children `cache/ config/ run/ state/ share/ vms/`, data at root; SIX per-dir env vars + ALL XDG consultation DELETED with no fallback reads (138 files, +831/−1044; ~220 test refs swept via `TestEnv`); `VMS_DIR` tilde const deleted, `vms_dir()`/`vm_state_dir()` absolute; doctor/cache/prune + Justfile/dev-env/CI YAML on `MVM_HOME`; no migration (first-version). 7517/7517 (−5 = obsolete XDG-order tests consolidated). Review caught the root-`tests/` boot-bench hand-built FC path (outside the grep scope) → fixed by deriving both bench arms from `vm_state_dir`. Grep survivors, both justified: in-guest XDG exports in the builder-VM runtime (guest env, not host resolution) + 2 stale comments in untouched `mvm-protocol` (→ WS4.2).)_
- [x] Route the remaining bypass sites through `mvm-core::config`; add the anti-bypass CI lint. _(**WS4.2 landed `2b85a8ff6` + `cc16c511d`**, subagent-driven, spec ✅ + quality Approved with NO findings: the new `xtask check-single-home` lint (4 rule classes — literal home-relative mvm paths, deleted env vars + XDG reads, raw `HOME` reads, re-rolled `mvm_home+"vms"` joins; 12 self-tests; CI Lint step) baselined at **117 hits → all FIXED, not allowlisted** (49 files; only 7 narrow rule-scoped allowlist entries incl. the resolver itself). The sweep surfaced real bypass BUGS beyond the review's 10: observer allowlist, tenant policy root, metrics scrape, attestation key dir, tenant config.toml all read raw `$HOME` and ignored `MVM_HOME` — now resolver-routed with per-site fail-closed posture REVIEW-VERIFIED preserved (strict-guard table in the review), and one prior gap closed: the volume-mount `denied_host_roots` used to be EMPTY when `$HOME` was unset, now unconditionally denies keys/audit roots. secret_store's cwd last-resort fallback renamed `./.mvm/secrets`→`./.mvm-secrets` (stops mimicking the home layout). Dead in-VM `echo` tilde-expansion round-trip in `microvm.rs::resolve_vm_dir` deleted (5 callers inlined). 7529/7529 (+12 lint self-tests), all gates green.)_
- [x] Gate: fresh run creates exactly one root; lint green. _(check-single-home clean on the tree; reviewer re-ran it independently.)_

**WS4 is COMPLETE.**

**WS5 — two features** _(root collapse DONE earlier; member-feature audit done — remaining items are maintainer-ratification calls, not mechanical work)_

- [x] Root surfaces collapsed to exactly `host`/`user` (+ `dev` union + a 7-entry internal allowlist); `check-two-surfaces` enforces it. The per-crate member features are the composition units the surfaces aggregate — correct Cargo layering, NOT sprawl to delete.
- [x] **mcp composed into `user`** (`e77c90230`): the implemented+tested MCP server was gated by no surface → shipped in no build; folded into `user` (zero extra deps). Builds clean; two-surfaces stays green.
- [~] **Member-feature decision matrix (audited; the below need a maintainer call, so NOT executed blindly):**
  - `manifest-verify` "always-on" is **REJECTED** — it pulls the sigstore stack (tokio) into mvm-core's default closure and would break the shipped `check-core-runtime-free` gate + the runtime-free invariant. It stays opt-in (the SPRINT "always-on" wording was over-simplified). `builder-vm`/`pure-mkfs` stay member composition units (a VM-driving consumer must be able to skip the builder pipeline); not made unconditional.
  - `attestation-tpm2`/`attestation-sev-snp`/`attestation-tdx` are **stub providers** (return `NotYetImplemented`) gating hardware-backed key attestation, which ADR-002 lists **out of scope**. Candidate for YAGNI deletion (3 features + `HwProviderKind` arms + stub impls) — but that removes documented future scaffolding, so it's a maintainer ratification call, flagged not executed.
  - `storage-s3`/`wasm-backend`: legit heavy-dep opt-ins intentionally outside both shipped surfaces (a consumer opts in at the member level); leave as-is (optionally add to the root internal allowlist for discoverability — cosmetic).
  - `schema` is already codegen/tooling-only (in no product surface); "move to build-time" is satisfied in spirit — the schemars derives can't be build-time-only without the feature enabling the derive, so the feature stays as the codegen knob.
- Gate: `xtask check-two-surfaces` green (2 surfaces, 7 internal). **WS5 substantially COMPLETE**; only the attestation-stub deletion awaits ratification.

**WS6 — trait dispatch + zero hardcoding**

- [x] Replace `backend.name() == "…"` sites with `BackendKind` matches; delete dead `"vz"` arms. `VmBackend::kind()` is now a required trait method (every backend implements it); `xtask check-no-string-backend-dispatch` guards the regression.
- [x] Remove baked network literals (`172.16.x`, `127.0.0.1:1080`, `/tmp/firecracker.socket`); inject via config; name `DEFAULT_MEM_MIB`/`DEFAULT_CPUS`; add a CI lint for hardcoded IPs/ports. _(**WS6.2 landed `3d098ecb0` (sweep) + `30a531141` (lint)**, subagent-driven, spec ✅ + quality Approved, value-preservation reviewer-verified byte-for-byte per const: dev subnet `172.16.x` → `mvm_core::dev_network` consts (`DEFAULT_SUBNET_CIDR`/`DEFAULT_GATEWAY_IP`/`DEFAULT_GUEST_IP`/`DEFAULT_GATEWAY_CIDR` + `default_guest_ip_for_index`); `127.0.0.1:1080` → `mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN`/`_URL` (5 sites); `DEFAULT_MEM_MIB=2048`/`DEFAULT_CPUS=2` named at the image-manifest defaults (other differently-valued mem/cpu defaults deliberately left); the `API_SOCKET="/tmp/firecracker.socket"` process-global DELETED → per-VM `firecracker_api_socket_path(dir)="{dir}/fc.socket"` (start/stop resolve the same socket; matches the per-VM start path + `FirecrackerGuard` cleanup that already expected it). New `xtask check-no-network-literals` (3 rule classes: subnet/egress-port/fixed-tmp-socket; skips test code incl. whole-file `#![cfg(test)]`; per-instance `{…}` sockets allowed; narrow rule-scoped exemptions for the 2 definition sites + 1 dev smoke example; CI-wired). Controller-takeover (implementer wedged): I ran all gates + FIXED 2 real lint bugs — a whole-file `#![cfg(test)]` skip gap and a line-continuation newline-counting desync that under-counted hit line numbers (both now regression-tested). 7543/7543 nextest, workspace clippy, fmt, wasm32 all green. Zero mvm-protocol diff.)_
- Gate: hardcoding lint green; no string-typed backend dispatch remains. **WS6 COMPLETE.**

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
- [x] Guest loopback/egress-client path and host `RealEndpointSpawner` enforce the admitted policy.
- [x] Supervisor L4 gate owns raw host/port forwarding and structured allow/deny audit.
- [x] SOCKS5 UDP Associate uses the same NIC-less vsock seam with shared UDP policy gating.
- [x] User-space egress evaluation, transparent rootless QEMU prototype, local TCP/UDP path benchmark, and non-root networking documentation are complete.

Then unify + retire the old paths:

- [x] Route Firecracker, HVF, and libkrun workload execution through the uniform vsock runner; fail-closed where the host cannot mediate.
- [x] Typed connectors use the broker/substitution seam with user-defined **`${NAME}`** named placeholders; host-side L7 inspection and data-governance witnesses cover all workload backends.
- [ ] Delete the dead rvproxy / native-gateway subsystem (~1,281 lines); collapse `NetworkingPreference`; drop `MVM_NETWORKING`. Enforce the mount no-shadow rule (`/mvm` in deny prefixes).
- [ ] Snapshot/restore/warm-start: fresh boot_id + nonce + handshake; stale flows closed; no live-vsock-survives-restore assumption.
- [x] Networking decision records why vsock is mandatory, why Model A was removed, and how typed connectors remain separate from raw admitted egress.
- Gate: protocol unit + fuzz green; process-level integration proves allow-passes / deny-drops / **stale-session-rejected**; `check_vsock_only_egress` passes on all workload backends; `machine run --image busybox --allow-host google.com` resolves DNS + connects (fixes `ping: bad address`); live smoke Mac (HVF) + Linux (libkrun + FC); no NIC bypass.

**WS9 — lifecycle correctness**

- [x] Confirm transient teardown (entrypoint exit + no healthcheck → VM stops) — already centralized; add tests. _Fixed: emit_launched_if no longer re-persists plan.json for transient runs, so teardown actually removes the VM state directory. Hermetic BDD 27/27; live BDD on Hetzner 36/37 (only Nix-flake network timeout remains, environment issue)._
- [ ] **Capture workload stdout/stderr + exit code over vsock** (reuse the `BuilderStatus`/`BuilderOutcome` pattern the builder VM already uses) so all workload output crosses the auditable seam and the transient exit code is sourced from it.
- [ ] Implement the missing **host-side healthcheck reaper** for persistent machines (probe the stored `health_check`; restart/mark-unhealthy on failure). Today it's persisted but never executed.
- Gate: transient exits propagate the vsock-sourced exit code + tear down; workload stdout/stderr captured over vsock; a persistent machine with a healthcheck is actively probed.

### Phase 3 — Quality: size, dead code, CLI, kernel/memory

**WS8 — file/function size + dead-code removal**

- [ ] Extract inline `#[cfg(test)]` modules from the 39 oversized files (cheap; drops many under 1500).
- [ ] Module-decompose the genuinely large bodies: `libkrun_builder`, `microvm`, `mvm-guest-agent`, `host-vm-init`, `doctor`, `unpack`, `image`, `vsock`.
- [ ] Split giant functions: `handle_client` (734 → per-verb handlers via a verb-handler trait), `run_inner`, `configure_flake_microvm_*`, `build_supervisor_config`, `unpack_layer` (per entry-type). Builders for multi-field config structs.
- [~] Delete dead/stub code: removed `crates/mvm-runtime/src/vm/egress_proxy.rs` (dead L7 stub), the `MVM_HVF_DUMP_DTB` debug gate, and the `HttpRegistry` SDK stub. **`storage/{pool,thin}.rs` dm-thin substrate is NOT dead** — it backs the live `mvmctl storage info`/`gc` verbs (`ThinPoolImpl`/`DeviceMapperBackend`), so it was kept. Still pending: gate `mock` backends behind `test-support`.
- [ ] Security fix: broker config currently parsed **unsigned** — verify signature before parse.
- [x] **Remove ssh-agent forwarding entirely — no SSH anywhere (core promise; ADR-001).** The tree carried a dev-tier ssh-agent-forwarding feature (host `$SSH_AUTH_SOCK` → vsock port 5301 → guest `/run/mvm/ssh-agent.sock`) that contradicted the "no SSH in microVMs, ever" promise and handed the guest the host's whole ssh-agent (bypassing bound-destination secret substitution). Deleted the whole surface: the `ssh_agent` spec field, manifest `[auth] ssh_agent`, `AuthMode::SshAgentSocket` + `AuthPolicy` (dropped the enum/struct entirely — `None` was the only variant left), the proxy (`mvm-cli::commands::ssh_agent_proxy`, `SSH_AGENT_PORT`, `run_ssh_agent_proxy_*`), the guest `SSH_AUTH_SOCK`/`/run/mvm/ssh-agent.sock` injection, tests, and CLI docs. **Strengthened ADR-001 to absolute** — deleted the "SSH-agent forwarding, when offered…" carve-out. Added `scripts/check-no-ssh.sh` (CI: `no-ssh-forwarding` in `security.yml`, beside `prod-agent-no-console`). The one dev interactive surface stays the builder-VM shell — nothing SSH.
- [x] **Eradicate the remaining SSH surface — no SSH in any guest, on any backend (ADR-001 follow-up).** A security audit found a full in-guest SSH server was still pervasive despite the ssh-agent-forwarding removal above: `image.rs`'s legacy Ubuntu-squashfs builder installed `openssh-server`, set `PermitRootLogin yes`/`PubkeyAuthentication yes`, generated an `*.id_rsa` keypair, and ordered workload units `After=… ssh.service`; `MvmState` (`base/config.rs`) carried a required `ssh_key` field that `microvm.rs`/`firecracker.rs` discovered/persisted as a boot-gate asset; the `refresh_builder_rootfs`/`download_builder_artifacts` builder-VM templates carried a dormant `inject_ssh` code path (always `"no"` in production, but live capability); five fully dead `*.tera` scripts (`builder_keygen`, `sync_local_flake`, `extract_artifacts_ssh`, `launch_firecracker_ssh`, `run_nix_build_ssh`) shelled real `ssh-keygen`/`scp`/`ssh`; the orchestrator accepted a legacy `"ssh"` alias for `BuilderMode::Vsock`; and a dead `tenant_ssh_key_path` helper lived in `mvm-core`. All removed — comms stays vsock-only on every backend (libkrun/HVF/Firecracker/qemu/mock), all confirmed SSH-token-free by source scan. Broadened `scripts/check-no-ssh.sh` from the ssh-agent-only pattern to every SSH-capability token (`sshd`/`openssh`/`ssh-keygen`/`authorized_keys`/`id_rsa`/`PermitRootLogin`/`sshd_config`/…), with an explicit, commented `ALLOWED_FILES` list for the pre-existing SSH _deny/detect_ code (`command_gate.rs`, `threat_classifier.rs`, the inbound SSH-banner network deny-scan, mkGuest's own build-time SSH-token ban) and no-SSH-assertion docs — verified the broadened gate fails on a planted `openssh-server`/`id_rsa` probe and passes clean on the real tree. Strengthened `no_backend_advertises_production_ssh` (`backend.rs`) to cover all 5 production `AnyBackend` variants.
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

- [x] Kernel: minimal defconfig; stop boot-probing IPVS/btrfs/RAID-autodetect (#1283); bump the kernel pin (#1264). **Landed via #1786.**
- [ ] Guest agent ≈ **8 MB**: de-`tokio` the guest (mio / raw epoll+kqueue), strip deps, measure RSS.
- [ ] Host daemon ≈ **64 MB**: minimal runtime, evaluate `mimalloc`, strip deps.
- [ ] **Density levers:** right-size the default `--memory` (64–96 MB, not 512); **demand-fault guest RAM** (MAP_ANON demand-zero instead of eager-dirty — the architectural fix for high VM density); share one **read-only kernel mmap** across VMs.
- [ ] Release profile: `lto = "thin"`, `codegen-units = 1`, `strip = true`, `panic = "abort"` for bins.
- [ ] Dep cut: dedupe ext4 (writer+reader), TLS (`reqwest`/`rustls`/`rcgen`), compression (`flate2`/`lzma-rs`/`tar`), net (`etherparse`/`rtnetlink`/`mio`), syscall (`nix`/`rustix`/`libc`); **reimplement trivially-used deps** where it removes an attack surface for little code.
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

**WS11 — wasm-container backend + `no_std` core (CORE goal; DESIGN LANDED — see `specs/refactor/11-wasm-backend.md` + §2.5)**

- [x] **DESIGN + scope decided** (`specs/refactor/11-wasm-backend.md`; ADR-024 → Accepted): `WasmBackend` = the **claim-free portability/demo/browser tier** (host `wasmtime`, opt-in, honest capability matrix, zero numbered claims — ADR-024's 3 constraints); **workload = user-supplied WASI module**; production-untrusted-wasm (engine-in-guest per ADR-024) DEFERRED. Open Qs resolved: no in-guest agent (agent responsibilities → host WASI-imports), browser slice = `no_std` OCI decoders only. `no_std` FOUNDATION already done (Increment 3 — mvm-protocol builds on wasm32).
- [x] `mvm-protocol` is `#![no_std] + alloc`, `unsafe_code = "forbid"`, `wasm32-unknown-unknown` CI build (Increment 1–3). _GAP → P1:_ tests running UNDER wasm (lib-build only today) + explicit no_std-boundary lint.
- [x] **P1 DONE** (`5b01e0f6b`): `wasm-no-std-boundary` CI job in `ci.yml` — builds `mvm-protocol` on `wasm32-unknown-unknown` (the no_std boundary, was a LOCAL-only check, now CI-enforced) AND runs its tests under real wasm (`wasm32-wasip1` via `wasmtime`) — **339 tests pass under wasm**. Crate attr → `#![cfg_attr(all(not(feature="schema"), not(test)), no_std)]` (std-during-test so libtest links; wasm lib build stays no_std). chrono `clock` re-declared dev-only (kept off the wasm lib build → gate stays chrono-clock-free). The wasm32 _build itself_ IS the no_std lint (fails on any std/OS leak). Independently re-confirmed wasm build clean + nextest 6567/0.
- [x] **P2 DONE** (`0ecb04486`): `BackendKind::Wasm` (unconditional, no_std-safe) + `WasmBackend: VmBackend` in `mvm-runtime/src/wasm_backend.rs` runs a user-supplied WASI Preview 1 module under host `wasmtime`/`wasmtime-wasi` (pinned 46) behind opt-in `wasm-backend` feature (default tree = 0 wasmtime; 42 with feature). Honest: `capabilities()` reports no HW-virt/kernel/TAP/vsock/snapshot; `security_profile()` = every numbered claim `DoesNotHold` (claim-free, tested). Fail-closed typed `WasmBackendError` (KernelBoot/VerifiedBoot/Networking/Console/PauseResume-NotSupported + NotCompiledIn) — NO prod panic/unimplemented. Real exit-code tests (`.wat` fixtures: exit 0 + `proc_exit(7)`). Deviation (sound): type/AnyBackend/catalog wiring UNCONDITIONAL (side-effect-free ctor), only wasmtime internals cfg-gated in a private `engine` submod → zero CLI changes (--hypervisor is a String), NotCompiledIn error at first real use (mirrors existing "recognized-but-unavailable" pattern). Green: check/clippy (default + feature), nextest 6567/6567 + mvm-runtime 925/925(feature), wasm32 protocol still clean, check-no-string-backend-dispatch clean.
- [x] **P3 COMPLETE** (P3a + P3b.1 + P3b.2) — the governed egress seam, POC gate met. Design SIMPLIFIED (`bf3eac389`, doc 11): NO new transport — wasm egress is just a `WireRequest` client (`mvm_core::substitution_wire`) over the existing `Uds` to the SAME substitution endpoint the microVM backends use (faithful by construction). Reachability recon (`127b22e44`) flagged that governance lives in mvm-hostd, unreachable in-process from WasmBackend in mvm-runtime — **resolved** by homing the witness in mvm-hostd's own tests (it deps mvm-runtime for `WasmBackend` and owns `SubstitutionService`, so it drives the REAL governance in-process with no dependency inversion — cleaner than the recon's anticipated subprocess route).
  - [x] **P3a** (`5d834b606` + gate-fix `d84912885`): the `mvm:egress` wasmtime host-import on WasmBackend — reads a `WireRequest` from guest memory, relays via REUSED `mvm_agentd::substitution_client::relay` (no 2nd frame codec), writes `WireResponse` back; 10 typed fail-closed error codes (never traps host on guest input); endpoint UDS path = host state (`with_egress_endpoint`, default None). Proven by a stub-UDS + `.wat`-fixture round-trip test (`${API_KEY}` placeholder → `WireResponse::Ok{200,"pong"}`) + 2 fail-closed tests. Default build wasmtime-free; claim-free unchanged. (Also fixed a pre-existing P2 `check-no-spec-refs` fail: ADR-002 in a wasm_backend comment/test-string.)
  - [x] **P3b.1** (`45b1db3e6`): `WasmBackend::start()` spawns the substitution endpoint mirroring libkrun — `wasm_endpoint_plan` (skip iff no-secrets + deny-all) + `wasm_substitution_spawn_params` (`EndpointTransport::Uds` via shared `vm_substitution_endpoint_socket`, `terminator_listen`/`tls_intermediate` `None` [http-only POC], `network_policy: Some`, **`raw_egress: false`** — wasm is always wire-mode, the required deviation from libkrun) + thin `spawn_wasm_egress_endpoint_if_needed` reusing `spawn_substitution_endpoint`; wires the UDS into the P3a host-import + reaps after the synchronous run. Decision/params unit-tested (no subprocess), 26/26, all gates green. **KNOWN FOLLOW-UP**: P2's `reject_unsupported_start_config` still fails `--network-allow` closed (`NetworkingNotSupported`), so the governed-egress path is built + unit-tested but NOT reachable in production `start()` until P3b.2 proves the witness + relaxes that gate (correct fail-closed posture — don't enable governed egress until proven).
  - [x] **P3b.2 DONE** (`e669bcc5d` gate-relax + `4d709d196` allow + `8c270214d` deny) — the **data-governance witness** passes; POC gate met. Executed subagent-plan `specs/plans/13-ws11-wasm-egress-poc.md`. **Home deviation (improved on the plan):** the witness lands in **mvm-hostd** tests (`crates/mvm-hostd/tests/wasm_egress_witness.rs`), not mvm-runtime — mvm-hostd already deps mvm-runtime (`WasmBackend`) + owns `SubstitutionService`/`Recorder`/`verify_audit_chain`, so it drives the REAL governance types **in-process** with NO dependency inversion and NO subprocess. A mvm-hostd `wasm-backend` feature forwards to mvm-runtime's; the test is `#![cfg(feature = "wasm-backend")]` so a default build pulls no wasmtime. **Two tests, four properties each:** allow path — a `.wat` module drives the `mvm:egress` host-import, observes `WireResponse::Ok{200}` through the REAL claim-10 gate, the destination receives the real secret while the module only ever held the placeholder, and a chain-signed `secret.substituted` entry verifies (no secret in it, claim 13); deny path — a claim-12 bind-check drop (destination network-admitted but not in the secret's binding) yields a refusal, the destination is never contacted, and a chain-signed `secret.placeholder_dropped` entry verifies. **Hermetic concession (documented in-file):** the production forward leg refuses loopback (SSRF hardening), so the test swaps ONLY the outbound TCP dial for a `Forwarder` test double — the crate's own test seam — and decouples the policy destination (a public IP the gate admits; loopback is mandatory-denied regardless of allow-list) from the physical loopback dial. Task 1 relaxed P2's networking gate so an allow-egress `VmStartConfig` is no longer rejected by `reject_unsupported_start_config` (config-level unit test `start_config_with_egress_policy_is_now_allowed`; the dead `NetworkingNotSupported` variant then removed — final-review Minor). **Scope honesty (final-review Important):** the witness drives the governance seam directly via `WasmBackend::with_egress_endpoint` + an in-process `SubstitutionService`, so it proves substitution + audit but NOT the full `start()` → `spawn_wasm_egress_endpoint_if_needed` → real-subprocess wiring (both tests use `VmStartConfig::default()` = `deny_all`, so the relaxed gate never fires in them). That decision layer is unit-tested per P3b.1; an end-to-end spawn-path test is a **deferred follow-up** (§below — it hits the same SSRF-refuses-loopback wall). All gates green (workspace clippy, runtime+hostd wasm-backend clippy, 27 wasm_backend units + 2 witnesses, 0 wasmtime in non-dev graph, 4 xtask gates, wasm32 protocol build, fmt). (Full TLS-terminating substitution for HTTPS dests → P3c; browser → P4 — each its own subsequent plan.)
- [ ] **P4**: browser POC — `mvm-protocol` + `no_std` OCI decoders run in the browser (image inspect/verify).
- Gate: `mvm-protocol` wasm build+tests green; no_std-boundary lint holds; `WasmBackend` runs a workload through the shared egress/audit seam (POC-gated) with the data-governance witness passing.

**Semantic address (UOR-ADDR) pilot — IMPLEMENTED (orthogonal to WS11; do NOT weave into P3)**

- [x] **DESIGN** (`specs/refactor/12-semantic-address-pilot.md`): additive `SemanticAddress` (`sha256(JCS(ir))` = UOR-ADDR JSON realization) for Workload IR, with a distinct newtype and no use in exact-byte, signature, nonce, or ephemeral-ID paths. The `uor-addr` crate remains deferred to the verification-gated WS11-P4/browser decision.
- [x] **EXECUTED** (`2f75f268b`, extended by this follow-up): `mvm-core/src/semantic_address.rs` validates schema first, NFC-normalizes JSON strings/object keys, then computes the UOR-ADDR label. The 12 published UOR-ADDR JSON fixtures pass; the Python/TypeScript SDK parity witness remains green. `ir_hash` is intentionally reported as a separate internal fingerprint because it does not perform UOR Unicode normalization.
- [x] **UOR FRAMEWORK EXPLORATION** (`specs/research/uor-framework-integration-exploration.md`, 2026-07-22): broader UOR Framework, Prism, and PrimeShield adoption is not recommended. The host-side UOR-ADDR conformance baseline is complete; `BuildProvenance` addressing and `uor-addr` crate adoption remain separate follow-ups.

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

| Canonical ADR (theme)                       | Merge these                                                                            |
| ------------------------------------------- | -------------------------------------------------------------------------------------- |
| Security posture & trust boundary (SoT)     | 002, 032, 063, 070, 083, 088, 104, 108, 109, 111 + claims + compliance + threat-models |
| Networking / egress / vsock                 | 004, 006, 055, 064, 067, 078, 082, 085, 100, 101, 110                                  |
| Backends / hypervisor abstraction           | 014, 046, 056, 072, 076, 093, 094, 095, 098, 099, 102                                  |
| Builder VM / Stage 0 / seed                 | 005, 013, 054, 057, 065, 068, 071, 096, 106, 107                                       |
| Host services broker / daemon               | 059, 061, 062, 084, 089, 090                                                           |
| Signed/audited execution + claims substrate | 041, 044, 047, 048, 058, 079, 103                                                      |
| OCI / image / registry / verity             | 050, 052, 074, 097                                                                     |
| Secrets substitution                        | 049, 067                                                                               |
| Machine / CLI surface                       | 077, 091, 092, 105                                                                     |
| Function entrypoints / factories            | 007, 008, 010, 011, 039                                                                |
| Encryption                                  | 027, 042                                                                               |
| WASM path                                   | 069, 080, 081                                                                          |

## Appendix B — issue / PR close-out

| #        | Kind       | Disposition                                                         |
| -------- | ---------- | ------------------------------------------------------------------- |
| **1637** | PR (draft) | **KEEP OPEN** — one-command microVM docs/blog; WS12 makes it true   |
| 1701     | issue      | Fold → WS3 (finish vsock tunnel), then close                        |
| 1717     | PR         | Fold → WS3 (FC transparent net over vsock), then close              |
| 1601     | issue      | Fold → WS3 (HVF host-vsock-proxy), then close                       |
| 1674     | issue      | **Fixed by #1804** — prior-layer path tracking                      |
| 1654     | issue      | Fold → WS4 (runtime sockets under `~/.mvm/run`), then close         |
| 1462     | issue      | Fold → WS2 (verb-grant delivery), then close                        |
| 1366     | issue      | **Closed** — landed via #1791 (Sandbox.connect dev-only exec guard) |
| 1283     | issue      | **Closed** — landed via #1786 (boot-probe strip done)               |
| 1264     | issue      | **Closed** — #1786 documents upstream-blocked pin bump; no action   |
| 1716     | PR         | Superseded by this sprint — close                                   |
| 1718     | PR         | Folded (dev_vz→builder_vm rename subsumed by WS1) — close           |
| 1713     | PR         | Contradicts consolidation (splits SDK) — close                      |

## Appendix C — biggest confirmed removals

- Userspace network gateways — passt, gvproxy, and the opt-in native/rvproxy `native_gateway` subsystem (~1,281 lines); replaced by the one vsock seam (WS-NET).
- `crates/mvm-runtime/src/vm/egress_proxy.rs` L7 stub — removed (WS8).
- `crates/mvm-runtime/src/storage/{pool,thin}.rs` dm-thin substrate — **NOT dead**: backs the live `mvmctl storage info`/`gc` verbs (`ThinPoolImpl`/`DeviceMapperBackend`), kept (WS8).
- QEMU backend (WS1e), Vz remnants, `mvm-vz-supervisor` Swift dir (WS0.4).
- 28 member features → 2 (WS5); ~24 `#[cfg]`-heavy gates collapse.
