# `*_legacy` driver modules were never legacy

`driver/hvf_legacy.rs`, `libkrun_legacy.rs` and `qemu_legacy.rs` sat beside
`hvf.rs` / `libkrun.rs` / `qemu.rs` and read like superseded implementations
kept for compatibility. They are not. `qemu.rs` calls
`qemu_legacy::locate_qemu()` on every boot; `libkrun_legacy` is the live path on
Linux and macOS 13-25; `hvf_legacy` is on the macOS default path. 55 references
across the workspace, all live.

They are now `*_process.rs`, which is what they hold: the host side of running
that VMM — resolve the supervisor binary, wait on a PID file, allocate a CID,
enumerate console sockets and workload disks, spawn the vsock bridges, answer
whether the platform supports the VMM at all. The `VmmDriver` impl stays in the
unsuffixed sibling.

## The doc headers were stale too

Each opened by describing a `VmBackend` implementation — "`HvfBackend` — the
`VmBackend` impl for the raw-HVF macOS path". There is no `HvfBackend` in the
tree and no `impl VmBackend` in any of the three files; that lifecycle moved to
`mvm-runtime`'s workload runner and left these behind as the process mechanics.
The headers now describe what the modules contain, and each says explicitly that
nothing in it is legacy, so the next sweep does not flag them again.

One test name went with them:
`carrying_a_plan_does_not_move_the_supervisor_off_its_legacy_route` →
`..._onto_the_admission_route`. Its body already explained that "legacy route"
meant the non-admission route.

## Gates

`fmt --all`, `clippy --workspace --all-targets` (zero warnings),
`nextest --workspace` against an empty `MVM_HOME` (12,238 pass),
`xtask check-all` (61 gates), `just check-gated`.
