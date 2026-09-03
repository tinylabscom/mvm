# mvm-demo-guest

`mvm-demo-guest` is the WASI guest program embedded in the browser sandbox
demo. It simulates the visible boot and shell experience of an mvm workload so
the static website can demonstrate policy decisions without starting a Linux
VM in the visitor's browser.

## Who uses it

`web/mvm-demo/build.sh` invokes this crate's build script and stages the
optimized module into the browser demo. The JavaScript/WASI host loads the
result and calls its exported entry points. It is not used by `mvmctl`, native
runtime backends, or production guest images.

## How it works

The binary compiles for `wasm32-wasip1` and exports two host-driven functions:

- `init()` prints a curated boot sequence and the first shell prompt.
- `exec(ptr, len)` parses one command line, updates in-memory shell state,
  prints the command result, and emits the next prompt.

The guest implements a small POSIX-like command set over WASI files and local
state. Network demonstrations call the imported `mvm::egress` function; the
browser host applies the demo's `VmStartConfig.network_policy` before making a
request. Native test builds use a deny-only fallback and never access the real
network.

This is explicitly a simulated browser tier, not a Linux kernel or a security
boundary equivalent to a native microVM.

## Build

Run the checked-in wrapper:

```bash
./web/mvm-demo-guest/build.sh
```

It builds a size-optimized release module, runs `wasm-opt`, and copies
`mvm-demo-guest.wasm` into `web/mvm-demo/guest/` for the parent demo build.

## Workspace relationship

The crate is excluded from the root workspace so normal host builds do not
require the WASI target. Its release profile enables size optimization, LTO,
stripping, and abort-on-panic because the artifact is downloaded by browsers.
