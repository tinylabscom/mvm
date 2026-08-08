# Goals

Why the restructure exists, what "done" measures against, and the prior art it draws on.

## Why

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

Two capabilities the restructure treats as **core goals**, not by-products of simplification:

1. **One auditable host egress seam for every backend** — every workload backend mediates all ingress/egress through a single default-deny, audited host boundary (see [02-architecture.md](02-architecture.md) §Backend & egress model and [03-networking.md](03-networking.md)).
2. **The same architecture produces wasm containers** — a `WasmBackend` runs a workload as a WASI wasm module, so mvm supports **more backends from one model** and reaches environments without KVM/HVF (CI, edge, the browser). This is enabled by a **`no_std` core** (`mvm-contract`) that compiles to `wasm32`/the browser. Detail: [02-architecture.md](02-architecture.md) §Wasm-container backend & `no_std` core.

## Reference models (studied, not copied)

- **A compact pooled microVM runtime** (single crate, few binaries, minimal features, bundled kernel, HVF/KVM backends, lightweight event loop, low memory, and sub-100ms snapshot restore). Reference for lean dependencies, low memory, and a small external API shape (`Image`/`Vm`/`Pool`/`ExecBuilder`, warmup/snapshot/streaming-exec/`expose_tcp`/live host mounts).
- **Modular runtime crate naming:** `agentd`, `cli`, `filesystem`, `image`, `network`, `protocol`, `runtime`, `utils`. Adopted (with `mvm-` prefix).
- **holospaces**: `default-features = false` no_std core with `std` as an opt-in feature; `unsafe_code = "forbid"` at the workspace; no_std OCI layer decoders → the wasm/browser path.
- **Rust guidelines** (gist `c3161f55…`): builder pattern over many-arg fns; traits over duplicated fns; newtypes over stringly-typed APIs; `thiserror` in libs; minimal deps; minimal default features; `mlock`/`zeroize`/`subtle` for secrets; small functions; `[lints]` with pedantic; release profile tuning.

## Definition of done

- Both surfaces build; `cargo nextest run --workspace` + `cargo test --workspace --doc` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all --check` green.
- ~11 crates, 2 features, 1 host + 1 guest + 1 CLI binary, 1 base dir, 0 non-test files > 1500 lines, no `Command` outside the allow-list, no hardcoded IPs/ports, vsock-only egress on every workload backend with the data-governance witness passing.
- All security claims still witnessed; live egress + boot smoke on Mac (HVF) and Linux (libkrun + FC); **sub-second launch** proven by the timed e2e; guest RAM demand-faulted for density.
- **Wasm-container capable (core goal):** `mvm-contract` builds and passes its tests on `wasm32-unknown-unknown` in CI, with a CI-enforced `no_std` boundary (`unsafe_code = "forbid"`); a `WasmBackend` runs a workload end-to-end through the same `VmBackend` + egress/audit/secret-substitution seam (POC-gated — the v1 bar is the seam proven, not full production parity across every wasm workload).
- Workload stdout/stderr + exit code flow over vsock; the builder VM runs the same single guest binary.
- `just bdd` green; every security claim and top-level CLI verb has a passing Gherkin scenario; `just ci` runs the BDD suite.
- Root is ~8 dirs (see [02-architecture.md](02-architecture.md) §Top-level layout), SDKs live under `crates/`.
- SDK usage (decorator + runtime) unchanged; ADRs consolidated but intact; website docs current; only #1637 open (see [09-closeout.md](09-closeout.md)).

See [06-execution-plan.md](06-execution-plan.md) for the workstreams that get us there and [07-progress-and-decisions.md](07-progress-and-decisions.md) for where we are against this bar today.
