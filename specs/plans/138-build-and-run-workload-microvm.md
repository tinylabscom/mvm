# Plan 138 — Build and run a workload microVM end-to-end via the builder VM

## Context & goal

The builder/dev VM is already green (`mvmctl dev up` builds + boots from a worktree). Use it as the
build engine to produce a **workload microVM that actually runs**: from this worktree,
`mvmctl compile examples/python/hello-app` → `mvmctl up --flake` builds the image *inside the builder
VM* → boots it on macOS (libkrun) → the guest agent answers Ping → `mvmctl invoke` executes the function
and returns a result. That is `crates/mvm-cli/tests/core_demo_e2e.rs` going green, plus an `invoke`
capstone.

**W5.2 is NOT on this path.** A function workload runs via the agent's `RunEntrypoint` RPC dispatching
into the baked wrapper (`nix/wrappers/python/oneshot.py` via `crates/mvm-runner`) — no host dispatch, no
runtime overlay, no services supervisor. The entrypoint only keeps the VM alive (`sleep infinity`),
exactly the proven lowering in `nix/lib/mkFunctionWorkload.nix:141-165`.

## Blockers, in sequence (all understood, each modest)

1. Workspace staging — workload build routes through `nix/flake.nix`'s `mvm-workspace = path:..` input,
   dragging `target/` (~7.5 GB) / tripping the worktree gitdir.
2. Codegen↔mkGuest mismatch — `mvmctl compile` emits a `mkGuest` shape `mk-guest.nix` rejects.
3. Backend-blind readiness probe (verified) — `wait_for_guest_agent` hardcodes `AppleContainerTransport`
   while the demo runs on libkrun → "agent not reachable" despite a live agent.
4. Run path — boot `vmlinux + rootfs.ext4`, confirm agent + function run.

## Backend decision: libkrun

`workload_hypervisor()` (`core_demo_e2e.rs:42`) pins libkrun on macOS. libkrun boots a workload today
(`crates/mvm-backend/src/libkrun.rs:153`) and supplies its own bundled libkrunfw kernel (AF_VSOCK
built-in) — so **no mkGuest `kernel` arg is needed**. Vz/QEMU are Tier-2 with a kernel direct-boot
blocker (Plan 92/97) and would require a vsock-capable `kernel` — strictly harder. libkrun + a
backend-aware probe (Phase 2b) is the path of least resistance and host-version-agnostic.

## Phase 0 — Pre-flight & gating spikes (cheapest, highest-information; do first)

- [ ] `mvmctl doctor` on THIS host (Darwin 25 ≈ macOS 26, where the auto-default is Vz/Apple Container):
      confirm libkrun (Homebrew trio) is installed, working, and the resolved workload backend. "dev up
      green" came from a frozen session, not here.
- [ ] Spike 1 — confirm which fetcher fails: check what `resolved_mvm_flake_url()`
      (`crates/mvm-sdk/src/compile/mvm_pin.rs`) produces for a source checkout (`path:` bloat vs
      `git+file` gitdir trip). Decides whether the write-up claims one failure or two.
- [ ] Spike 2 — confirm where the cost is paid: a declared-but-unreferenced input is lazy at build time,
      but its narHash is computed when the compiled flake's `flake.lock` is written on the macOS host
      during `mvmctl compile` / `crates/mvm-build/src/pipeline/dev_build.rs`. If host-side locking stages
      the dirty worktree, a host-side leg is also needed (host sets `MVM_WORKSPACE_PATH` + `--impure`, or
      the lock is pre-pinned).

## Phase 1 — Workspace staging fix — DONE via merge (`feat/local-mvm-build`)

- [x] Done by commit `07114cf7` (merged): `mvmctl up/build --flake` mounts the workspace at `/work` and
      builds the user flake with **`--override-input mvm path:/work/nix`** (host-side, in
      `crates/mvm-build/src/builder_vm_runtime.rs` `render_flake_cmd_sh` + `stage_job_dir`). This keeps
      the published `nix/flake.nix` **pure** — no `getEnv` edit. (My earlier draft added `getEnv` to
      `nix/flake.nix`; that was NOT done — it would have been a *second* staging path, exactly the
      duplication we're avoiding. The override-input approach is the single canonical staging path.)
- [ ] Open follow-up (Phase 0 Spike 2): confirm host-side `flake.lock` write during `compile` doesn't
      separately stage the dirty worktree.

Only the workload-microVM path is affected; the builder/dev VM + runtime overlay import `nix/lib`
directly with their own filtered `mvmSrc` (why `dev up` is already green).

## Phase 2 — Codegen reconciliation (`crates/mvm-sdk/src/compile/flake.rs`)

- [x] Rewrote `mkGuestArgs` to emit a single `entrypoint.command = [ bootScript ]` lowering (mirrors
      `mkFunctionWorkload.nix`): `funcBootScript` runs preStart symlink + `before_start.sh` +
      `exec sleep infinity`; `cmdBootScript` runs preStart + `exec` the command. Dropped the stubbed
      `entrypoint.services` divergence + the inert per-service `env`/`mergedEnv`. `uids.entrypoint = 0`;
      `extraFiles`/`servicePackages` still threaded from the factory; `concurrency` unchanged.
- [x] Updated the codegen unit tests: `entrypoint.command` + `!entrypoint.services` + `!hostname`
      assertions; `sleep infinity` + `before_start.sh` lock in the lowering. `cargo test -p mvm-sdk`
      green (9/9).
- [x] No other consumers assert the generated-flake shape (grep: only `flake.rs`; docs + the
      `mk-guest.nix` stub + `mkFunctionWorkload.nix` legitimately reference `entrypoint.services`).
      `app-deps-audit` exercises `mvmctl compile` but doesn't assert flake shape.

This is the minimal "make compiled workloads run," not the top-level `services` API (W5.2 — deferred).

## Phase 2b — Backend-aware readiness probe (`crates/mvm-cli/src/commands/shared/vsock.rs`)

- [x] Switched `wait_for_guest_agent` + `request_port_forward` off the hardcoded `AppleContainerTransport`
      to `vsock_transport::for_vm` (resolved per poll iteration, matching the `readiness.rs` pattern —
      a still-booting guest just fails the attempt and retries). `cargo check -p mvm-cli` + clippy green.
- [x] `mvmctl invoke` already used `vsock_transport::for_vm` (`invoke.rs:393`); `console.rs` keeps its
      own `pick_console_transport` deliberately (adds the dev proxy tier). No further hardcodes.

## Phase 3 — Build, run, verify

- [ ] `MVM_WORKSPACE_PATH=$PWD MVM_BUILDER_BACKEND=libkrun mvmctl compile
      examples/python/hello-app/app.py --out /tmp/hello-app`, then
      `mvmctl up --hypervisor libkrun --flake /tmp/hello-app` (builds in the builder VM, boots on
      libkrun). Use a fresh `--out` / `cache prune` so the codegen change isn't masked by a stale
      `~/.mvm/dev/builds/<hash>/`.
- [ ] Agent alive: `up` exits 0 and the log lacks "Guest agent not reachable" (Phase 2b makes this work
      on libkrun).
- [ ] Workload runs (capstone): `mvmctl invoke hello-app --input name='ari'` returns the function result
      (dispatched via `RunEntrypoint` → baked `oneshot.py`).
- [ ] Confirm `admit_overlay_aware` (`libkrun.rs:184`) passes — mkGuest bakes `/mvm/runtime`
      (`mk-guest.nix:596`); a `--flake` workload is fine (the gap is the no-flake *default* image).

## Verification

- [ ] `cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo test -p mvm-sdk -p mvm-cli`
      (covers the `flake.rs` codegen + `vsock.rs` probe changes).
- [ ] Pure path unchanged: clean tree, `MVM_WORKSPACE_PATH` unset → `nix flake check ./nix` /
      `nix/tests/mk-guest-eval.nix` evaluates with no `--impure`.
- [ ] Filtered path: `MVM_WORKSPACE_PATH=$PWD --impure` → `mvmSrc` store path has `Cargo.lock` +
      `crates/mvm-guest/` but not `target/`.
- [ ] End-to-end: `core_demo_e2e.rs` green on macOS with `MVM_BUILDER_BACKEND=libkrun`; optionally extend
      it with the `invoke` assertion as the capstone.

## Security / production notes

- Phase 1 impurity is opt-in: the `getEnv` branch only fires under `--impure` + a set env var; pure eval
  (clean checkout / CI) takes the pure input. Reproducibility double-build (claim 7) must run with
  `MVM_WORKSPACE_PATH` unset. Confirm prod images (dm-verity / claim 3) take the pure path.
- `workspace-filter.nix` is a basename blocklist; an untracked host file outside it could be staged —
  and now lands in a bootable rootfs / running VM, so the risk is sharper. Already applies to the two
  sibling flakes; if hardened, tighten the *shared* filter toward a cargo-tree allowlist
  (`Cargo.toml`, `Cargo.lock`, `crates`, `xtask`, `src`) once, not here.
- Boot-time hooks run as root in the guest (Route B sets `uids.entrypoint = 0`, runs `before_start.sh`
  as uid 0; per-call wrapper drops privs). Acceptable under ADR-002 (guest is the boundary) but now
  generated for all compiled workloads — state it in the contract. Sealed agent (`entrypoint.command` →
  `do_exec` stripped, claim 4) means no `mvmctl console`/exec into the running workload; debug via
  `invoke` + logs.
- First `up` mints the Ed25519 signer key (`~/.mvm/keys/host-signer.ed25519`, 0600) and starts the
  chain-signed audit log (claim 8 admission runs even in dev) — the demo leaves persistent host state.

## Out of scope / deferred follow-ups

- [ ] Full top-level `services` multi-service API + W5.2 guest supervisor + IR `services` schema — its
      own numbered `specs/plans/` entry (likely 139; verify vs open PRs + main per `check-spec-numbers`).
      Not required to build or run a single-function workload microVM.
- [ ] Optional cross-cutting hardening: tighten the shared `workspace-filter.nix` to a cargo-tree
      allowlist across all three flakes (see Security notes).
