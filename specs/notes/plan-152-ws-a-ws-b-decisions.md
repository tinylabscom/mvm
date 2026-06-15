# Plan 152 — WS-A exit channel + WS-B threading model: decisions

Two design forks the plan deferred ("decide first / confirm before building"),
settled 2026-06-07 against the current tree. Grounded, not speculative.

## WS-A — exit channel: vsock control port + baked PID-1 helper

**Premise correction.** Today's prod `/init` does not `reboot`; it falls through
to a kernel panic when the entrypoint returns without `exec`
(`nix/lib/mk-guest.nix:526-540`). Dev `/init` idles on `sleep`. WS-A is therefore
"give PID-1 a real terminal action + an exit channel", not "stop rebooting".

**Decision: vsock, not a control-share.**
- vsock 5252 (`GUEST_AGENT_PORT`, `crates/mvm-guest/src/vsock.rs:15-49`) exists on
  libkrun + Vz + Firecracker uniformly, but is RPC-only — no exit verb today.
- The Vz control socket (PAUSE/RESUME/STATUS/SAVE, `vz_control.rs` +
  `ControlSocket.swift`) is host↔supervisor, Swift-only, absent on libkrun — it
  is not a guest→host channel.
- No writable virtio-fs control share is guaranteed across backends.

**Shape:** the per-VM supervisor listens on a dedicated control vsock port; `/init`
runs the command, captures `$?`, sends `exit <code>\n`, `sync`s, then
`poweroff -f`. The supervisor records the code and emits a `plan.exited` audit
entry (extend the terminal-event path on `VzBackend`/`LibkrunBackend`).

**Key constraint:** busybox `/init` cannot open AF_VSOCK (no `nc --vsock`). The
exit report needs a tiny static helper baked into the rootfs, sibling to
`mvm-addon-vsock-bridge` in `mvm-guest-helpers` (already wired into mkGuest). This
is the crux of WS-A and the reason vsock+helper beats a share: backend-symmetric,
and independent of whether the full agent is present in a sealed prod image.

## WS-B — threading: port the shipping Swift model (serial queue + delegate)

**Decision: private serial dispatch queue + `VZVirtualMachineDelegate`, NOT
main-thread `CFRunLoop`.**

The Swift supervisor already ships this exact model and works
(`Supervisor.swift:93-126,516-523`): a private serial
`DispatchQueue("mvm.vz.supervisor", .userInitiated)` passed to the
`VZVirtualMachine` constructor, a `VZVirtualMachineDelegate`
(`guestDidStop` / `didStopWithError`), and a `DispatchSemaphore` the start path
blocks on — no main thread, no runloop.

Port it 1:1 to Rust: `dispatch2` serial queue + `declare_class!` delegate +
`QueueBound<Send>` for the `!Send` `Retained` handles + `block2::RcBlock`
completion handlers. All are already workspace deps.

Why not main-thread CFRunLoop:
- Lowest risk for a security-sensitive rewrite; makes the mandatory parity matrix
  a true apples-to-apples port of a known-good design.
- Keeps main free so the control socket + vsock proxy run on tokio worker threads
  — the precise axis the plan said to decide on. CFRunLoop-on-main forces VZ onto
  main *and* still needs workers for control/vsock, while diverging from the
  proven design.
- `apple_container`'s `DispatchQueue::main()` is the weaker precedent; the plan
  itself flags the serial-queue model as the better one for the supervisor.
