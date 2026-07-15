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

## Reference models (studied, not copied)

- **supermachine** (single crate, 4 bins, ~20 deps, **one** feature, bundled kernel, HVF via `applevisor-sys`, KVM via `kvm-ioctls`, `mio` event loop instead of a full async runtime, `mimalloc`, sub-100ms snapshot restore). North star for lean deps + low memory + external API shape (`Image`/`Vm`/`Pool`/`ExecBuilder`, warmup/snapshot/streaming-exec/`expose_tcp`/live host mounts).
- **microsandbox** crate naming: `agentd`, `cli`, `filesystem`, `image`, `network`, `protocol`, `runtime`, `utils`. Adopted (with `mvm-` prefix).
- **holospaces**: `default-features = false` no_std core with `std` as an opt-in feature; `unsafe_code = "forbid"` at the workspace; no_std OCI layer decoders → the wasm/browser path.
- **Rust guidelines** (gist `c3161f55…`): builder pattern over many-arg fns; traits over duplicated fns; newtypes over stringly-typed APIs; `thiserror` in libs; minimal deps; minimal default features; `mlock`/`zeroize`/`subtle` for secrets; small functions; `[lints]` with pedantic; release profile tuning.

## Definition of done

- Both surfaces build; `cargo nextest run --workspace` + `cargo test --workspace --doc` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all --check` green.
- ~11 crates, 2 features, 1 host + 1 guest + 1 CLI binary, 1 base dir, 0 non-test files > 1500 lines, no `Command` outside the allow-list, no hardcoded IPs/ports, vsock-only egress on every workload backend with the data-governance witness passing.
- All security claims still witnessed; live egress + boot smoke on Mac (HVF) and Linux (libkrun + FC); **sub-second launch** proven by the timed e2e; guest RAM demand-faulted for density.
- Workload stdout/stderr + exit code flow over vsock; the builder VM runs the same single guest binary.
- `just bdd` green; every security claim and top-level CLI verb has a passing Gherkin scenario; `just ci` runs the BDD suite.
- Root is ~8 dirs (see [02-architecture.md](02-architecture.md) §Top-level layout), SDKs live under `crates/`.
- SDK usage (decorator + runtime) unchanged; ADRs consolidated but intact; website docs current; only #1637 open (see [09-closeout.md](09-closeout.md)).

See [06-execution-plan.md](06-execution-plan.md) for the workstreams that get us there and [07-progress-and-decisions.md](07-progress-and-decisions.md) for where we are against this bar today.
