# Target Architecture

The target crate map, binary model, feature model, directory model, backend/egress model, and top-level repo layout. This is the *design target* — see [07-progress-and-decisions.md](07-progress-and-decisions.md) for how far execution has gotten against it.

## Crate map (~19 → ~11, named by domain area)

| New crate | Absorbs | Role | `no_std`? |
|---|---|---|---|
| **mvm-protocol** | `mvm-sdk::ir` + protocol wire types + policy types + `mvm-verify` | Workload IR, wire protocol, policy/audit types, audit-log verifier. The wasm/browser-capable core. | **yes** (`no_std` + `alloc`) |
| **mvm-core** | `mvm-core` (std parts) | Single-dir config/paths, crypto (keystore/attestation/signing), catalog. | no (std) |
| **mvm-fs** | `mvm-ext4` + `mvm-oci` + build's rootfs/overlay/unpack | Turn any image (OCI **or** nix) into a mountable rootfs + `vmlinux`; ext4 writer/reader; runtime overlay; mount ordering/policy; OCI registry fetch + unpack. | no |
| **mvm-net** | `mvm-network` + hostd gateway/dns + guest net/netinit | vsock transport, DNS, network-policy enforcement, secret-substitution + PII-redaction seam. | no |
| **mvm-runtime** | `mvm` + `mvm-backend` | `VmBackend` trait + libkrun/hvf/firecracker impls (mock behind `test-support`); VM lifecycle, templates, pool, warm-start. | no |
| **mvm-build** | `mvm-build` | Nix builder-VM pipeline (the nix-execution engine). | no |
| **mvm-hostd** | `mvm-hostd` + `mvm-vm-host` + host-side builder bins | **The single host binary.** Resident single-process daemon; all host roles as in-process tasks. | no |
| **mvm-agentd** | `mvm-guest` + `mvm-guest-helpers` + `mvm-host-services-ffi` | **The single guest binary.** Shipped in the runtime-overlay volume. | no |
| **mvm-sdk** | `mvm-sdk` (minus `ir`) | Decorator + runtime authoring + the **tree-sitter → Workload IR → nix template** pipeline. | no |
| **mvm-client** | `mvm-client` | Facade (`MvmClient`). **Every CLI command routes through it.** The stable surface mvmd consumes. | no |
| **mvm-cli** | `mvm-cli` | `mvmctl`. Thin; delegates to `mvm-client`. | no |

Kept as-is: `crates/deps/libkrun-sys` (FFI), `xtask`. **Dropped/folded:** `mvm-ext4`, `mvm-network`, `mvm-verify`, `mvm-guest-helpers`, `mvm-vm-host`, `mvm-host-services-ffi`, `mvm-mcp` (folded into `mvmctl serve` behind an `AgentProtocol` trait — MCP now, ACP later, no per-protocol crate; see [06-execution-plan.md](06-execution-plan.md) WS7), orphan Swift `mvm-vz-supervisor`, dead deps (`colored`, `names`, `hickory-server`, stale `mvm-egress-proxy` path). (The `qemu` backend was *not* dropped — kept as an opt-in Tier-2 dev substrate; see [07-progress-and-decisions.md](07-progress-and-decisions.md).)

Logging is **`mvm-core::log`** (a module, not a crate): structured `tracing` for operational logs (→ `~/.mvm/logs`) **and** the seam that emits chain-signed, tamper-evident entries to the audit log for every security-relevant action. Secrets/PII are redacted at the boundary — never logged. "Auditable everywhere" means every guest↔host RPC and every egress byte is traceable through the vsock seam and the chain-signed audit log.

Note: the crate map above and the deviations recorded in [07-progress-and-decisions.md](07-progress-and-decisions.md) disagree in one place by design — execution kept `mvm-host-services-ffi` standalone rather than folding it into `mvm-agentd`. That's a considered deviation, not a drift; see 07 for the rationale.

### Dependency direction (high → low), acyclic

```
mvm-cli → mvm-client → mvm-runtime → {mvm-build, mvm-net, mvm-fs} → mvm-core → mvm-protocol
```

`mvm-hostd`/`mvm-agentd` sit at the top as bin crates nothing depends on (as a library); `libkrun-sys` is a near-leaf pulled by runtime/build.

## Binary model — 1 host + 1 guest, no subprocess forks

- `mvm-hostd` and `mvm-agentd` are each **one process**. Roles (supervisor, broker, signer, audit, substitution, DNS; and in the guest: agent, runner, netinit, oci-init, verity-init) are **in-process async tasks / threads**, never fork-`exec`'d helpers.
- **No `std::process::Command` / `tokio::process::Command` anywhere** in the host, runtime, or guest-agent paths. All former shell-outs become native Rust: ext4 (pure-Rust writer/reader), supervisor L4 policy, tar/gzip/zstd (Rust crates). CI lint enforces zero `Command` in these crates.
- **Two carved exemptions** (the process *is* the workload, not a helper we spawn for our own logic): (1) launching the **Firecracker** VMM process; (2) the **builder VM** invoking `nix` — the builder VM is a nix-execution engine and that is its sole purpose. Both are allow-listed explicitly in the lint.
- **Secrets isolation (Option A):** keys/secrets live in a dedicated module — `mlock`ed, `zeroize`-on-drop, constant-time compare (`subtle`), never logged; the whole daemon runs under seccomp + landlock; the vsock parsers stay fuzzed. This trades the previous address-space process-moat for in-process isolation + memory hygiene; the primary guarantee (*secrets never enter the guest*) is untouched.
- **Multi-role dispatch** is by subcommand/argv0 within the single binary (no fork). PID-1 variants (verity-init, oci-init) are selected by the overlay's init symlink.
- The **builder VM runs the same single guest binary** (`mvm-agentd` in a "builder" role: drive the nix build, report status/outcome, emit the artifact location) — one guest binary across workload *and* builder VMs, not a separate builder-VM binary set.
- **Host daemon state store = append-only, signed `jsonl`** (the tamper-evident shape the audit chain already uses), never an embedded SQL / `libSQL` database — fewer deps, smaller attack surface, and it doubles as an audit artifact.

## Feature model — exactly two

Two workspace surfaces, enforced by `xtask check-two-surfaces`:
- **`user`** (default): CLI + SDK + build + run microVMs locally.
- **`host`**: library subset — everything to build and run a microVM, no authoring niceties.

The 28 member features collapse: `builder-vm`/`pure-mkfs`/`manifest-verify` become always-on (the default and only path); `schema` moves to build-time codegen in `xtask`; `s3`/`template-registry-s3`/`custom-dns`/`dev-watch`/`mcp`/`remote`/`attestation-*` are folded in or runtime-detected. The **one** remaining compile-time capability boundary is the **prod vs dev guest-agent build** (`dev-shell`) — a security boundary (no console / `do_exec` in prod), a separately compiled artifact, not a convenience flag.

## Directory model — single `~/.mvm`

One base root, `~/.mvm` (override `MVM_HOME`; keep `MVM_DATA_DIR` as an alias only for the transition, then drop):

```
~/.mvm/
  state/     vms, machines, instances, pool
  cache/     builder-vm, stage0, images, packs, nix-store
  run/        per-VM UDS sockets (was scattered; closes #1654)
  keys/  audit/  volumes/  overlays/  images/  builder/  logs/  config.toml
```

Kill: `~/.cache/mvm`, `~/.config/mvm`, `~/.local/{state,share}/mvm`, `$XDG_RUNTIME_DIR/mvm`, and the hardcoded `~/microvm/vms` const. Every path flows through one `mvm-core::config` module; a CI lint bans inline `$HOME/.mvm` / `dirs::` / ad-hoc `.join(".cache")`. The only intentional out-of-tree path is the AF_UNIX 108-byte socket fallback, itself rooted under `~/.mvm/run` via a short hash.

## Backend & egress model

- Backends: **libkrun** (macOS 13–25 + Linux), **HVF** (macOS 26+), **Firecracker** (Linux workload), and **wasm** (a WASI wasm-container — a core goal, see [§Wasm-container backend & `no_std` core](#wasm-container-backend--no_std-core-core-goal) below). **QEMU kept** as an opt-in Tier-2 Linux dev/test substrate (never workload-bearing; the drop was ratified against — see [07-progress-and-decisions.md](07-progress-and-decisions.md)). `mock` behind `test-support`.
- Selected via the existing `BackendKind` enum + `backend_catalog!` registry — **never string-matched**. The ~6 remaining `backend.name() == "…"` sites in `mvm-cli` and the dead `"vz"` arms are removed.
- **One host-mediated, default-deny, audited egress boundary for every backend**, transport-abstracted via the runner seam: vsock for microVM workloads and WASI host-calls for the wasm backend. Firecracker, libkrun, and HVF all use `WorkloadRunner` with `RealEndpointSpawner`; any backend that cannot mediate egress through the host fails closed on `--network-allow`. There is no guest NIC, raw packet tunnel, or smoltcp L3 fallback in the production workload path.
- Mount ordering is `rootfs → runtime-overlay → custom`, with an **explicit no-shadow rule**: a later mount may never shadow an earlier target; `/mvm` and `/mvm/runtime` join the deny-prefix set.

Full networking design (protocol, frame shape, data path): [03-networking.md](03-networking.md). Full security model built on this seam: [04-security.md](04-security.md).

## Wasm-container backend & `no_std` core (core goal)

The `VmBackend` seam, the `Workload` IR, and the one host-mediated egress/audit boundary are hypervisor-agnostic by construction — so the **same architecture also runs a workload as a wasm container, not only as a microVM**. This is a core goal, not a stretch: it is how mvm's sandbox reaches environments without KVM/HVF (CI runners, edge, the browser), and it is the clearest proof that the design *supports more backends from one model*.

- **`WasmBackend`** implements the same `VmBackend`/Workload contract as libkrun/HVF/Firecracker and is selected through the same `BackendKind` registry (never string-matched). Instead of booting a Linux microVM it instantiates the workload as a WASI wasm module under a wasm runtime — host-side (`wasmtime`/`wasmer`) and, for the browser path, wasm-in-wasm.
- **`no_std` is the enabling discipline, and it is CI-gated.** `mvm-protocol` (Workload IR + wire protocol + policy/audit DTOs + audit-log verifier) is `#![no_std] + alloc`, `unsafe_code = "forbid"`, and builds — with its tests — on `wasm32-unknown-unknown` in CI, so mvm's core contract compiles *into* the wasm sandbox and the browser (the holospaces path). Everything workload-execution-relevant stays `no_std`-clean; anything that reaches for `std`/OS/crypto-impl stays above the protocol line in `mvm-core` and up. This is exactly the boundary the `mvm-protocol` extraction has to draw (see [07-progress-and-decisions.md](07-progress-and-decisions.md)) — the wasm-container goal is now a **second, independent reason that cut must be clean**, which is why 1a-protocol and 1b are one designed pass. A `no_std` slice of `mvm-fs` (the OCI layer decoders, per holospaces) feeds the browser path.
- **Same security model, WASI transport.** A wasm container has no vsock, so its egress rides WASI host-calls — but through the *same* default-deny, audited, secret-substituting host seam. The `VmDuplexTransport` abstraction ([03-networking.md](03-networking.md)) gains a WASI variant alongside Firecracker-UDS / libkrun-unixgram / HVF-vsock. A wasm guest **sees no secrets and emits no PII, identically to a microVM guest**; the chain-signed audit log covers it identically. Secrets stay host-side and are substituted only on a bound destination, `${NAME}` placeholders and all.
- **Open design questions** (resolved when the seam is built — tracked in [06-execution-plan.md](06-execution-plan.md) WS11): what a wasm *workload* is (a user-supplied WASI module vs. an mvm-compiled workload), how the runtime-overlay/agent model maps onto a wasm instance that has no Linux init, and which slice of `mvm-fs` the browser path actually needs.

## Top-level layout (root ~30 dirs → ~8)

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

Root files kept: `Cargo.*`, `Justfile`, `README`/`LICENSE`/`SECURITY`/`CHANGELOG`, `AGENTS.md`, `CLAUDE.md`, `deny.toml`, `rust-toolchain.toml`, `treefmt.toml`, `cliff.toml`, `install.sh`, `.github/`, `.githooks/`. Everything else is moved or deleted (WS0.3 — see [06-execution-plan.md](06-execution-plan.md)).
