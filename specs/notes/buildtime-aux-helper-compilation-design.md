# Build-time compilation of the native per-VM host helpers

## Problem

On a source checkout, `cargo run -- machine run …` builds only `mvmctl` — cargo
never builds sibling `[[bin]]`s in other workspace crates. The per-VM host
helpers (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`, the substitution
endpoint) are therefore missing when the backend needs them, so
`mvm-backend/src/aux_bin.rs::resolve_or_build` shells out to `cargo build` at
run time, from inside the already-executing `mvmctl` process, deep in backend
dispatch (after Stage 0 bootstrap). The compiler output interleaves with the
running command:

```
Finished dev profile … 20.67s        # cargo run built mvmctl
Running target/debug/mvmctl machine run …
Error: Stage 0 … (retry)             # command is executing
   Compiling mvm-vm-host …           # …and only now does the helper compile
   Finished dev … 16.75s
```

Compiling a binary while the command that needs it is already running is the
antipattern. All compilation must finish before the command runs.

## Goal

`cargo run -- machine run …` compiles every binary it needs — including the
native host helpers — during its compile phase, then executes. No build-then-run
wrapper, no run-time compiler shell-out.

## Scope

Only the **native host helpers** resolved by `mvm-backend/src/aux_bin.rs`:

- `mvm-substitution-endpoint` (`mvm-hostd`) — always buildable.
- `mvm-hvf-supervisor` (`mvm-vm-host`) — macOS/aarch64 only.
- `mvm-libkrun-supervisor` (`mvm-vm-host`, `--features libkrun-sys`) — only where
  libkrun is present (it links `-lkrun`).

Out of scope — left exactly as they are:

- `mvm-build/src/guest_agent_build.rs` (guest binaries) and
  `mvm-cli/src/host_binaries/source_build.rs` (embedded host-vm binaries). These
  are musl **cross-compiles** materialized into a cache, with embedded-bytes
  fallbacks for shipped end-user builds — a different mechanism, not "we failed
  to compile our own native binary before running."

## Design

### 1. `mvm-cli/build.rs` builds the native helpers up front

`build.rs` already cross-compiles + embeds the musl host-vm bins via a nested
`cargo` invocation aimed at a **separate target dir under `OUT_DIR`**, precisely
to avoid cargo's build-lock deadlock (the outer `cargo build` holds an exclusive
lock on the workspace `target/` for the whole build-script run; a nested cargo
aimed at the same `target/` blocks forever). We reuse that proven machinery for
the native helpers:

- Nested `cargo build -p <pkg> --bin <bin> [--features …]` into a dedicated
  host-native dir, e.g. `OUT_DIR/aux-helper-target/<profile>/`, matching the
  running profile (debug/release).
- Because build.rs runs during the compile phase of `cargo run`, the helpers
  finish before `mvmctl` executes.
- Export the resolved directory to the crate via
  `cargo:rustc-env=MVM_AUX_BIN_DIR=<dir>` so `aux_bin` can find them with zero
  run-time search cost.
- `cargo:rerun-if-changed` on `crates/mvm-vm-host/src`,
  `crates/mvm-hostd/src`, and the workspace `Cargo.lock` so a helper-source edit
  retriggers the build on the next `cargo run`; warm builds pay ~nothing.

### 2. Host-conditional, fail-open helper selection

build.rs builds only the helpers this host can produce and **never fails the
outer compile** when a helper is unbuildable:

- `mvm-substitution-endpoint`: always.
- `mvm-hvf-supervisor`: only on macOS/aarch64.
- `mvm-libkrun-supervisor`: only when libkrun is detectable (same probe the
  build already relies on for the `libkrun-sys` feature); skipped otherwise
  (HVF-only macOS, most CI). A skip is silent-but-logged, not an error.

### 3. `aux_bin.rs` becomes resolve-only

Delete `build_in_workspace` and the run-time mtime auto-rebuild. `resolve_or_build`
(renamed `resolve`) walks a fixed precedence, `is_file`-checking each candidate
and skipping absent ones:

1. Explicit per-bin env override (`MVM_HVF_SUPERVISOR_PATH`, …).
2. **Sibling of the current exe** — a shipped release ships helpers next to
   `mvmctl`; this must win so releases resolve correctly.
3. `MVM_AUX_BIN_DIR` (baked in at build time; the dev path).
4. Workspace `target/{release,debug}` (explicit `just build-supervisors`, IDE
   builds, etc.).

`MVM_AUX_BIN_DIR` is baked into release binaries too, but points at the CI
builder's `OUT_DIR`, which does not exist on an end-user machine — so it is
`is_file`-skipped there and the sibling check (2) wins. Release resolution is
unchanged.

If a genuinely-needed helper is absent, `resolve` returns a precise error naming
the bin, the reason it is likely missing (e.g. "requires libkrun"), and the
recovery (`install slp/krun/libkrun and rebuild`, or set the per-bin path
override) — never a run-time compile.

### 4. Fast-path escape hatch

Honor the existing `MVM_SKIP_EMBED_BINARIES=1` in the new build.rs step so
`just test-fast` and the inner test loop stay fast. When set, helpers are not
built; `aux_bin` surfaces its precise error only if one is actually needed at
run time (tests generally do not need a live supervisor).

## Security

- No trust boundary moves: supervisors are host-side code, the host is trusted
  (malicious host is out-of-scope). Same code, same host, same compiler. No
  claim witness references `aux_bin.rs` or the build.rs helper step; the claim
  catalog is unchanged.
- Net posture improvement: deletes a run-time `Command::new(cargo)` that fired
  during `machine run`, so the workload-launch path no longer needs `cargo` on
  `PATH` and cannot be steered into a compile step by a hijacked
  `PATH`/`CARGO` at run time.
- Freshness becomes a compile-time guarantee. `mvm-libkrun-supervisor` is the
  claim-10 egress-enforcement point (gateway-bridge `PlanFlowPolicy`) and the
  audit-chain sidecar; a silently-stale supervisor could enforce an old egress
  policy or emit an old audit format. `rerun-if-changed` ties the running
  supervisor to the source `mvmctl` was built from.

## DX

- Cost: every **cold** `cargo build`/`cargo run` now pays the host-relevant
  helper compile (build.rs cannot know the subcommand), not just the first
  `machine run`. Mitigated by `MVM_SKIP_EMBED_BINARIES=1`, `rerun-if-changed`
  (warm builds ~free), and host-conditional selection (no libkrun supervisor on
  an HVF-only host).
- Separate target dir first-build duplicate-compiles shared deps under
  `OUT_DIR` (same tax the embedded-bins path already pays; cleared by
  `cargo clean`).
- build.rs emits one legible log line ("building per-VM host helpers: …") so the
  compile is not mistaken for an unrelated mvm-cli build-script step.
- `just build-supervisors` stays as the explicit/override route; its stale
  "self-builds on first machine run" comment is corrected. The `e2e-core-demo`
  recipe's manual supervisor build becomes redundant and can be simplified.

## Non-goals

- Changing the guest / embedded-host-vm cross-compile paths (out of scope
  above).
- Any wrapper (`just run` / `bin/dev`) becoming the blessed entrypoint —
  explicitly rejected; `cargo run` must self-suffice.
- Artifact dependencies (`-Z bindeps`) — nightly-only; this repo is on stable.

## Testing

- `aux_bin` unit tests: precedence order (override → sibling → `MVM_AUX_BIN_DIR`
  → target), absent-candidate skip, release-safe skip of a non-existent baked
  `MVM_AUX_BIN_DIR`, and the precise missing-helper error text. The mtime
  auto-rebuild tests are removed with the code they covered.
- build.rs helper-selection unit tests (pure functions): host-conditional
  inclusion, graceful skip of an unbuildable helper, `MVM_SKIP_EMBED_BINARIES`
  short-circuit.
- Manual verification: on this macOS host, `cargo run -- machine run --image
  alpine …` shows the helper compile **above** `Running target/debug/mvmctl`,
  and never mid-command; a second run with no source change compiles nothing.
```
