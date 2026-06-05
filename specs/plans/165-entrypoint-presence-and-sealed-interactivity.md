# Plan 165 — Entrypoint-presence policy + sealed-prod interactivity prohibition

> **Status (2026-06-05):** Designed (brainstorm settled); not started.
> Sequenced after the artifact-model line (Plan 134) and the default-image
> work (Plan 158, shipped in v0.16.1). Builds directly on the
> `is_entrypoint_not_offered` classification merged in PR #631.
>
> **Numbering:** 165 was free at write time (`main` tops at 164; open PRs
> claim 123/134). Re-confirm against `check-spec-numbers` (a Lint gate)
> before merge.

**Goal:** make the dev→prod entrypoint boundary coherent and provably
one-way: a developer builds and interacts with a **dev** microVM while
writing their app; when they ship, the **sealed** prod image runs its
function via `RunEntrypoint` with **no interactive access of any kind** —
enforced by construction and machine-checked.

**Architecture:** three composable workstreams over the existing pieces —
mkGuest's `bootCommand`/entrypoint split, the agent's `EntrypointPolicy`
validation, the agent-served PTY-over-vsock console (Plan 162), and the
host `enforce_accessible_gate`. No new interactive transport is added.

**Tech stack:** Rust (`mvm-guest` agent, `mvm-cli`, `mvm-hostd`
supervisor), Nix (`nix/lib/mk-guest.nix`, the SDK compile flake +
factory), `xtask` claim gate, GitHub Actions.

---

## Context — what exists today

- **Two entrypoint roles, one file historically.** mkGuest bakes
  `/etc/mvm/entrypoint` as a shell fragment `/init` sources as PID 1
  (`nix/lib/mk-guest.nix:528-530`). When `bootCommand` is set, PID 1's
  command moves to `/etc/mvm/boot` and `/etc/mvm/entrypoint` is left as the
  agent's **per-call marker** (`mk-guest.nix:551-567`). The SDK compile
  already takes this split for **function** workloads
  (`crates/mvm-sdk/src/compile/flake.rs:160-172`): `bootCommand =
  factoryService.bootCommand` (idle PID 1) + `extraFiles =
  factoryService.extraFiles` (which is supposed to bake the per-call
  wrapper + marker).
- **The agent validates the marker** at boot
  (`crates/mvm-guest/src/entrypoint.rs::EntrypointPolicy::production`): the
  marker must be an **absolute path** to a wrapper under
  `/usr/lib/mvm/wrappers/`, root:root, mode `0555`, on the same filesystem
  as `/usr`. `RunEntrypoint` `fexecve`s the held-open fd (TOCTOU-safe).
- **#631 (merged)** reclassified a *non-absolute* marker as a calm
  `ComponentState::Disabled` ("RunEntrypoint not offered"), not a scary
  `Failed` — `ValidationError::is_entrypoint_not_offered()`. This stopped
  the false alarm on the default/idle image but did **not** make
  `RunEntrypoint` work for functions, nor add a prod policy.
- **The interactive console is agent-served PTY-over-vsock** (Plan 162):
  the dev image's `/init` idles as PID 1, and `mvm-guest::console`
  `openpty()`s and forks `/bin/sh -i`, relayed over vsock
  (`crates/mvm-guest/src/console.rs`). A serial-console shell was tried and
  abandoned (fatal on Vz's input-less console — `mk-guest.nix:485-499`).
- **Host gate exists:** `mvmctl console` refuses a VM whose runtime
  metadata says `accessible = false`
  (`crates/mvm-cli/src/commands/vm/console.rs::enforce_accessible_gate`).
- **The function path "never worked E2E"** — the factory's wrapper does not
  yet *conform* to `EntrypointPolicy::production()` (memory
  `project_function_workload_entrypoint_collision`).

## Decisions (brainstorm 2026-06-05)

1. **One interactive method: keep the agent-served PTY-over-vsock console
   (dev-only).** No serial-console passthrough, no second transport. The
   PTY is a dev-tier, prod-absent implementation detail.
2. **Function-wrapper model:** make the per-call wrapper *conform* so
   `RunEntrypoint` works end-to-end on a sealed prod image.
3. **No-entrypoint policy is mode-aware:** dev image with no declared
   workload → drop to the interactive console shell; **sealed prod** image
   with no declared workload → **fail closed at admission + audit-log an
   error** (do not boot an under-specified sealed workload).
4. **"No interactive access in a sealed production microVM" becomes a
   hardened, CI-gated claim** (new claim 15), not a convention — multiple
   independent layers, machine-checked.

DX north star: *build & interact with a dev microVM while developing; on
ship it is sealed completely for production.*

---

## WS-A — Conforming per-call wrapper (make `RunEntrypoint` work)

Bring the factory-baked wrapper into conformance with
`EntrypointPolicy::production()` so a sealed function image serves calls.

**Files:** `crates/mvm-sdk/src/compile/flake.rs` (factory wiring),
the factory nix it references (`buildFactoryService`; resolve its on-disk
location — `flake.rs:13` notes the factories are generated, not vendored),
`nix/lib/mk-guest.nix` (rootfs hardening / `/usr/lib/mvm/wrappers/`
placement), `crates/mvm-guest/src/entrypoint.rs` (validation, unchanged).

- [x] **A0 — fexecve-on-script spike (decides the wrapper shape).**
      **VERDICT (2026-06-05): the wrapper is a `#!/bin/sh` script — no
      compiled launcher.** The agent already supports it: `spawn_path`
      execs via `/proc/self/fd/<n>` and `dup_above_fd3`
      (`crates/mvm-guest/src/entrypoint.rs:690-711`) deliberately keeps the
      validated fd **non-CLOEXEC** so a shebang interpreter can reopen
      `/proc/self/fd/<n>` — the comment even names the failure mode it fixed
      ("the `mvmctl invoke` failure mode"). Ratified empirically in a Linux
      container: `execve("/proc/self/fd/N")` on a `0555` shebang script with
      a **non-CLOEXEC** fd runs and passes argv through; the **CLOEXEC**
      variant fails `cannot open /proc/self/fd/3` (proving the requirement).
      So the fexecve-on-script concern is solved upstream; WS-A reduces to
      pure conformance (path/owner/mode/marker).
- [ ] **A1 — Emit the wrapper at the conforming path/owner/mode.** The
      factory must write the per-call wrapper to
      `/usr/lib/mvm/wrappers/<workload_id>` (regular file), and mkGuest's
      rootfs-hardening pass must leave it **root:root `0555`** on the verity
      rootfs (same pass that already hardens `/etc/mvm/entrypoint`). The
      wrapper drops privilege internally via `setpriv --reuid=<uid>
      --regid=<uid> --clear-groups --no-new-privs -- <command> "$@"` (uid 0
      wrapper that drops to the entrypoint uid — matches ADR-002 W2.3 and
      the existing `setprivWrap`).
- [ ] **A2 — Write the marker as the wrapper's absolute path.**
      `/etc/mvm/entrypoint` contains exactly
      `/usr/lib/mvm/wrappers/<workload_id>\n` (an absolute path, not a
      script). For function workloads this is the factory's `extraFiles`
      entry; assert it is consistent with the wrapper A1 bakes.
- [ ] **A3 — Pass-through of call args/stdin.** The wrapper appends `"$@"`
      so `RunEntrypoint`'s argv reaches the command; stdin/stdout/stderr are
      already wired by the agent's spawn. Add a function fixture that echoes
      argv + stdin and assert round-trip.
- [ ] **A4 — Validation passes (the witness).** Add an in-guest integration
      check (gated behind the libkrun/Vz E2E lane) that builds a function
      image, boots it, and asserts `EntrypointPolicy::production().validate()`
      returns `Ok` and a `RunEntrypoint` call returns the function's output +
      exit code. This is the standing proof the collision is resolved.
- [ ] **A5 — Host-side runner.** Confirm `mvmctl` invokes `RunEntrypoint`
      against a sealed function image end-to-end (no console, no exec) and
      surfaces the exit code; extend `examples/` with a function fixture.

## WS-B — No-entrypoint policy: dev shell / prod fail-closed + audit

Define and enforce what happens when a workload declares no callable
entrypoint, split by tier.

**Files:** `nix/lib/mk-guest.nix` (classification + dev `/init`),
`crates/mvm-sdk/src/compile/flake.rs` (compile-time refusal),
`crates/mvm-hostd/src/supervisor/` (admission-time refusal + audit),
`crates/mvm-guest/src/bin/mvm-guest-agent.rs` (boot-state reporting).

- [ ] **B1 — Define "no entrypoint."** It means *no declared workload
      command*: the SDK IR carries neither a function nor a command/service
      entrypoint. (`sleep infinity` / the default idle image *is* a declared
      command and is unaffected — it boots.) Encode the predicate once in
      `mvm-sdk` IR (`crates/mvm-sdk/src/ir/workload.rs`) so both the compile
      path and admission read the same signal.
- [ ] **B2 — Dev: drop to the interactive console.** A **dev** image with no
      declared entrypoint boots and idles PID 1 (as today), and the agent's
      console serves `/bin/sh -i` — i.e., the developer lands in the
      interactive console (WS-C's single method). No new code beyond
      ensuring classification routes an empty-entrypoint dev build to the
      console-capable dev `/init` variant.
- [ ] **B3 — Prod: fail closed at compile time.** `mvm-sdk` compile **must
      refuse** to produce a *sealed* image with no declared entrypoint —
      a sealed workload that does nothing is a misconfiguration. Emit a clear
      `CompileError` ("sealed/prod workloads must declare an entrypoint;
      `dev` images may omit it for an interactive shell").
- [ ] **B4 — Prod: fail closed at admission (defense in depth).** If a
      sealed image with no valid entrypoint reaches the supervisor anyway,
      `admit_for_run` refuses it and emits a chain-signed audit entry
      (`plan.failed` with reason `entrypoint.absent`). Reuses the existing
      admission audit path (claim 8).
- [ ] **B5 — Tests.** compile-refusal unit test (B3), admission-refusal +
      audit-entry test (B4), and a dev-empty-entrypoint build that asserts
      the console path is wired (B2).

## WS-C — Sealed-prod interactivity prohibition (hardened + CI-gated claim)

Keep PTY-over-vsock as the single interactive method and make
"no interactive access to a sealed prod microVM" a machine-checked claim.

**Files:** `nix/lib/mk-guest.nix` (`isDev` gating, console attachment),
`crates/mvm-guest/src/console.rs` + `Cargo.toml` (`dev-shell` feature
gate), `crates/mvm-cli/src/commands/vm/console.rs` (host gate),
`crates/mvm-backend/...` (prod VMM console = write-only), `specs/claims/`,
`specs/adrs/002-microvm-security-posture.md`, `.github/workflows/`,
`xtask`.

- [ ] **C1 — Audit the five existing barriers; close any gaps.**
      (1) only the **dev** `/init` variant runs/relays a shell
      (`mk-guest.nix:485` `variant=dev` branch); (2) prod rootfs is
      dm-verity sealed (claim 3); (3) prod VMM console attaches a
      **write-only** `console.log` with **no host input fd**; (4) host
      `enforce_accessible_gate` refuses sealed VMs
      (`vm/console.rs:69`); (5) the agent's console service is behind the
      `dev-shell` Cargo feature — **verify** `mvm-guest::console`'s vsock
      relay is `#[cfg(feature = "dev-shell")]` so the prod agent contains no
      console symbol (mirror the `do_exec` / `prod-agent-no-exec` gate).
      Fix whichever of these is not currently true (item 5 is the most
      likely gap — confirm and gate it if not).
- [ ] **C2 — Prod console is input-less by construction.** In the backend
      VM-launch path, a sealed image's guest console is wired output-only
      (to `console.log`); never attach a readable host fd. Add a unit/assert
      that the prod console attachment carries no input side.
- [ ] **C3 — New claim 15 + witnesses.** Add to
      `specs/claims/catalog.md`:
      `| 15 | No interactive access to a sealed production microVM |
      fn:console_refused_on_sealed_image, ci:prod-agent-no-console,
      fn:prod_console_attachment_has_no_input | dev-image-only console +
      verity + host gate + dev-shell-gated agent (ADR-002 §W4.3 extension)
      | Shipped |`. Provide each witness:
      a `console_refused_on_sealed_image` test (host gate), a
      `prod-agent-no-console` CI lane asserting the console symbol is absent
      from a prod agent build (mirror `prod-agent-no-exec`), and a
      `prod_console_attachment_has_no_input` backend test.
- [ ] **C4 — ADR-002 update.** Add claim 15 to the numbered table + the
      threat-model note (keep §"Out of scope" discipline — this is the same
      interactive-access threat as claim 4 / `do_exec`; co-locate the
      narrative). Update CLAUDE.md §"Security model" to fourteen→fifteen.
- [ ] **C5 — `xtask check-claim-catalog` passes** with the new row; run the
      Lint gate locally.

---

## Verification

Validate on the local Vz/libkrun dev host (this Mac — isolate with
`MVM_CACHE_DIR`/`MVM_DATA_DIR`; never run `core_demo_e2e` unbounded —
background + `gtimeout` + reap):

1. **WS-A:** build a function image, boot it (sealed), `RunEntrypoint`
   returns the function output + exit code; `EntrypointPolicy::validate()`
   is `Ok`. A non-zero function exit propagates to `mvmctl`.
2. **WS-B:** a sealed build with no entrypoint is **refused** at compile
   (clear error) and, if forced, at admission (audited `plan.failed`); a dev
   build with no entrypoint boots to the interactive console.
3. **WS-C:** `mvmctl console` on a sealed VM is refused; a prod agent binary
   contains **no** console symbol; the prod console attachment has no input
   fd; `xtask check-claim-catalog` green.
4. `cargo nextest run --workspace`, `cargo test --workspace --doc`,
   `rustup run nightly cargo fmt --all -- --check` (CI Lint uses nightly
   rustfmt), `cargo clippy --workspace -- -D warnings`. Note `mvm-backend`
   test binaries can be SIGKILL'd by macOS codesign locally
   (`reference_mvm_backend_test_binary_macos_codesign_sigkill`) — lean on
   Linux CI for that crate.

## Non-goals

- **Serial-console passthrough / any second interactive transport.**
  Explicitly rejected this brainstorm — one method (PTY-over-vsock), the PTY
  is a dev-only, prod-absent detail.
- **Interactive `exec` (`exec -it`).** `do_exec` stays a *non-interactive*
  programmatic one-shot RPC (already `dev-shell`-gated, `prod-agent-no-exec`
  CI lane). If you want a terminal, use the console.
- **Relaxing `EntrypointPolicy`'s TOCTOU/ownership checks.** The wrapper
  conforms to the policy; the policy does not bend to the wrapper.
- **Any interactive capability on a sealed/prod image.** The entire point.

## References

- `nix/lib/mk-guest.nix` — entrypoint/bootCommand split (`:101-112`,
  `:520-567`), dev `/init` console idle (`:485-499`), rootfs hardening.
- `crates/mvm-guest/src/entrypoint.rs` — `EntrypointPolicy::production`,
  `ValidationError::is_entrypoint_not_offered` (PR #631).
- `crates/mvm-guest/src/console.rs` — the PTY-over-vsock console (the single
  interactive method).
- `crates/mvm-cli/src/commands/vm/console.rs` — `enforce_accessible_gate`.
- `crates/mvm-sdk/src/compile/flake.rs:160-172` — function vs command
  `mkGuestArgs`; `buildFactoryService` (the wrapper/marker factory).
- `specs/claims/catalog.md` + `xtask check-claim-catalog` — the witness
  ledger and its gate.
- `specs/adrs/002-microvm-security-posture.md` — claim table; claim 4
  (`prod-agent-no-exec`) is the sibling interactive-access claim.
- `specs/plans/162-dev-mode-interactivity.md` — why the console is
  agent-served PTY-over-vsock (serial-shell was fatal on Vz).
- Memory: `project_function_workload_entrypoint_collision`,
  `project_default_image_apple_container_boot_bug`,
  `reference_dev_mode_interactivity_devpts`,
  `feedback_dev_vm_vs_prod_security_tiers`.

## Deferred follow-ups

- [ ] If A0 forces a compiled launcher, factor a shared `mvm-entry-launcher`
      static bin (musl) and bake it per-workload — fold into the embedded
      host-binaries build (Plan 164) rather than per-image.
- [ ] Multiplex/queue concurrent `mvmctl console` attaches (today: one
      session at a time) — DX nicety, not security.
