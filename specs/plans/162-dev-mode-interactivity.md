# Plan 162 — Dev-mode interactivity (guest devpts + `MVM_ENV=dev`)

> **Status: PLANNED (2026-06-04).** Surfaced while finishing #582 (PR #587):
> the non-interactive TTY gate added there (`dev up` only attaches a console
> when `stdin().is_terminal()`) is correct, but it masked a deeper bug — the
> dev VM guest **cannot open a PTY at all**, so the interactive `dev` shell
> would fail even from a real terminal. This plan makes dev-mode
> interactivity actually work and formalizes "dev mode".

**Goal:** Running any `dev` subcommand (or any command with `MVM_ENV=dev`)
from a real terminal drops the user into a working interactive shell on the
dev VM. Non-interactive contexts (CI, scripts, `core_demo_e2e`) keep booting
and returning cleanly — no regression to the green spine.

## Finding (root cause)

The dev VM's mkGuest `/init` mounts `/proc`, `/sys`, `/dev` (devtmpfs),
`/tmp`, `/run` — but **not devpts at `/dev/pts`** (`nix/lib/mk-guest.nix`,
the mount block around the `mount -t devtmpfs devtmpfs /dev` line). `openpty(3)`
needs the devpts filesystem mounted to allocate PTY slaves, so the guest
agent's `openpty()` (`crates/mvm-guest/src/console.rs`) fails with
`"openpty() failed"`. The host's `console_interactive` surfaces this as
`Console open failed: console open failed: openpty() failed`.

Consequence: **the interactive `dev` shell is broken even from a real
terminal.** PR #587's host-side TTY gate only stopped non-interactive
callers (the test) from *reaching* the guest failure; it did not — and
could not — fix the guest's missing PTY support.

This is a guest-`/init` fix, not a host toggle.

## Part 1 — Guest: mount devpts (the real enabler)

`nix/lib/mk-guest.nix`, immediately after `mount -t devtmpfs devtmpfs /dev`:

```sh
# devpts is required for openpty(3) — the guest agent allocates a PTY per
# interactive `dev` console session (mvm-guest::console). devtmpfs alone
# gives /dev/ptmx the node but not the /dev/pts slave fs, so without this
# openpty() fails ("openpty() failed") and the interactive dev shell can't
# open even from a real terminal. Harmless for sealed workload guests
# (they never openpty); mode 0620,gid=5 is the standard tty-group layout.
/bin/busybox mkdir -p /dev/pts
/bin/busybox mount -t devpts -o mode=0620,gid=5,nosuid,noexec devpts /dev/pts
```

Mount it unconditionally (all mkGuest variants) — it is inert for workload
guests and avoids a variant-specific branch. The guest kernel already
supports devpts (standard in the libkrunfw / builder-VM kernel config); if
a future minimal kernel drops `CONFIG_DEVPTS_*`, the `mount` fails
best-effort and we fall back to the current (non-interactive) behavior.

- [ ] Add the devpts `mkdir` + `mount` after the `/dev` devtmpfs mount in `nix/lib/mk-guest.nix`.
- [ ] Confirm the guest kernel exposes devpts (`grep -a CONFIG_DEVPTS` on the dev image, or boot + `mount | grep devpts`).

## Part 2 — Host: formalize "dev mode" (`MVM_ENV=dev`)

Add a `mvm-core::config` helper, sibling to the existing `is_production_mode()`
(`MVM_PRODUCTION=1`):

```rust
/// Check if running in dev mode (`MVM_ENV=dev`). Dev-mode commands default
/// to interactive (drop into the dev VM shell when a TTY is present) and
/// run at the dev security tier. `dev` subcommands are inherently dev mode
/// regardless of this var; `MVM_ENV=dev` marks a whole session (so other
/// commands can opt into the dev experience). Mutually exclusive with
/// `is_production_mode()` in intent; if both are set, production wins
/// (fail-safe — never silently relax the prod tier).
pub fn is_dev_mode() -> bool {
    !is_production_mode()
        && std::env::var("MVM_ENV")
            .map(|v| v.eq_ignore_ascii_case("dev") || v.eq_ignore_ascii_case("development"))
            .unwrap_or(false)
}
```

Interactivity stays keyed on a host TTY (see the physical constraint below);
`MVM_ENV=dev` is the dev-mode **marker**, not a TTY override. The `dev up`
gate added in PR #587 (`crates/mvm-cli/src/commands/env/dev.rs`) already
reads `std::io::stdin().is_terminal()`; this plan only formalizes the
concept and applies it consistently.

- [ ] Add `config::is_dev_mode()` + unit tests (`MVM_ENV` unset / `dev` / `DEV` / `development` / with `MVM_PRODUCTION=1` set → false).
- [ ] Confirm the `dev up` interactive gate reads the TTY (already shipped in #587); leave the no-TTY boot-and-return + hint as-is.
- [ ] Audit the other `dev` console call sites (`dev shell`, `dev` default, `console`) so they give a clear "needs a terminal" message instead of an `openpty`/raw-mode error when run without a TTY.

### Physical constraint (documented, not a bug)

The interactive bridge puts the **host** terminal into raw mode
(`enter_raw_mode` reads host stdin's `termios`, `console.rs`), so it
genuinely needs a host TTY. Therefore:

**interactivity = dev mode AND a host TTY.**

`MVM_ENV=dev` marks the session as dev but cannot conjure a TTY; it will not
force a raw-mode attach where there is no terminal (that would just fail at
`enter_raw_mode`). Decision (confirmed with the owner): `MVM_ENV=dev` is a
marker, not a force-attach. Without a TTY, dev commands boot the VM and
return (with the `dev shell` hint), exactly as the non-interactive path does
today.

## Part 3 — Guest: dev VM PID 1 must idle, not run `/bin/sh` on the console (the Vz blocker)

**Found while verifying Parts 1+2 on Vz (2026-06-05):** `dev up` on the
macOS-26 Vz-default host *started* the dev VM and then died — `console.log`
empty, `vz.pid` dead, no agent vsock socket ever appeared. Root cause:
mkGuest `/init`'s dev variant ran the `/etc/mvm/entrypoint` `/bin/sh` as
**PID 1 on `/dev/console`**. Vz's serial console is **input-less**
(output-capture only), so the shell's read hits EOF → the shell exits →
PID 1 dies → the VM powers off ~5 s after boot. (Vz-specific: libkrun's
console *blocks* on read, so its dev VM survived — which is why core_demo
is green on libkrun.) This makes Parts 1+2 moot on Vz: the VM is dead
before anything can `openpty()` into it.

Key realization: the interactive shell does **not** come from PID 1's
`/dev/console` shell. `console_interactive` / `dev shell` go through the
**agent**, which `openpty()`s and forks its OWN `/bin/sh -i`
(`crates/mvm-guest/src/console.rs:159-184`), independent of PID 1. So PID 1
never needed to be a shell.

Fix (`nix/lib/mk-guest.nix` `/init`, dev variant): after the agent fork,
**PID 1 idles** (busybox-portable `while :; do sleep …; done`) instead of
running the entrypoint `/bin/sh` on `/dev/console`. The dev VM stays alive
on both backends; the agent serves the interactive shell. Workload/prod
variants are unchanged (PID 1 is still the workload; its exit/poweroff
handling is Plan 152 WS-A — the *opposite* variant at the same `/init`
edit site: a finished workload should poweroff + propagate `$?`).

- [x] Dev-variant `/init` idles PID 1 (agent serves the shell); don't `exec`/source `/bin/sh` on the input-less Vz console.
- [ ] Verify on Vz: `dev up` keeps the dev VM alive (`vz.pid` stays up, agent reachable) and `dev shell` attaches. Needs the Swift Vz supervisor built; libkrun verified separately (`dev up` → VM stays up → `dev shell`).

## Verification

- [ ] **Live (manual, needs a real terminal):** `mvmctl dev up` from a TTY drops into a working shell on the dev VM; `exit` returns cleanly. Repeat with `MVM_ENV=dev mvmctl dev up`.
- [ ] **Non-interactive regression:** `core_demo_e2e` stays green (dev up boots + returns, no console attempt) — the proof PR #587 restored.
- [ ] **Guest mount:** `mvmctl dev shell --command "mount | grep /dev/pts"` shows devpts mounted; `mvmctl dev shell --command "tty"` succeeds (exercises guest openpty end-to-end).
- [ ] `cargo nextest run --workspace` (or `-E 'not package(mvm-backend)'` on macOS — see the codesign-SIGKILL note); `rustup run nightly cargo fmt --all -- --check`; `cargo clippy --workspace -- -D warnings`.

**Verification caveat:** the live interactive drop-in cannot be fully
auto-tested in a headless/CI session (no TTY). The devpts mount + the
non-interactive path are auto-verifiable; the actual shell is a manual
confirm on a real terminal.

## Success criteria

- [ ] Interactive `dev` shell works from a real terminal (guest `openpty()` succeeds; devpts mounted).
- [ ] `MVM_ENV=dev` recognized as the dev-mode marker via `config::is_dev_mode()`.
- [ ] No regression to `core_demo_e2e` or any non-interactive caller.
- [ ] No stray "sidecar" terminology reintroduced (tracked separately; the metadata is `mvm-meta.json`).
