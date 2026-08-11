# Plan 321: wasm as a workload format inside a real microVM

## Status

DESIGN — not started. Captured so it is not lost; sequenced after
[plan 320](320-wasm-browser-demo.md), which is independent of it.

This is the **engine-in-guest** path [ADR-024](../adrs/024-wasm-sandbox-backend.md)
explicitly sanctions:

> If the backend is ever used to execute a workload as more than a demo/preview
> […] the untrusted-bytes-executing engine (wasmtime or equivalent) runs as a
> guest binary inside a real microVM, never as a host process dependency.

## Why this, and not "finish the host wasm tier"

"Support wasm fully as a backend" splits into two things, and only one of them
is reachable.

**Finishing the host tier** — plan 301 Part A (end-to-end `start()` coverage,
TLS-terminating substitution, transparent WASI socket interception, Preview 1
vs 2) — produces a better *portability* backend. Its ceiling is fixed by
ADR-024 §3: no numbered claims, ever. Not for lack of effort; a host wasm
engine provides no hardware isolation boundary, so there is nothing to claim.

**This plan** produces something different: a wasm workload that **inherits
every numbered claim from the microVM it runs inside** — verity-sealed rootfs
(claim 3), NIC-less vsock-only egress (claim 10), no raw secret in the guest
(claim 13), no shell or PTY (claim 15). The isolation boundary is the microVM;
wasm is merely the executable format. Nothing new gets claimed, no ADR is
amended, and no new backend is introduced.

It is also the smaller of the two, because most of it already exists.

## What already exists

- `crates/mvm-agentd/src/runner/config.rs:30` — `Language::Wasm` is a variant of
  the closed runtime language enum, with `interpreter() == "wasmtime"` and
  `dispatch_filename() == "dispatch.wasm"`.
- `crates/mvm-agentd/src/bin/mvm-runner.rs:154` — already emits
  `wasmtime run <fragment>` in-guest.
- `crates/mvm-contract/data/supported_languages.txt` already lists `wasm`, so
  the host validator does not reject it with `E_UNSUPPORTED_LANGUAGE`.

## What is missing

The image half. `nix/lib/factories/languages/default.nix:17-20` states it
plainly:

> Wasm intentionally lives outside the registry today because its inputs differ
> (the user's `.wasm` module IS the wrapper; no interpreter package is baked).
> When it lands it becomes a row with `interpreter = null` + a wrapper-kind
> discriminator the builder branches on.

`nix/wrappers/` has `python/` and `node/` and no `wasm/` — correctly, since the
user's module is the dispatch fragment and there is no wrapper script to write.

## Workstreams

### WS1 — the Nix factory row

- [ ] Add a `wasm` row to `nix/lib/factories/languages/registry.nix` with
      `interpreter = null` and a wrapper-kind discriminator, exactly as
      `default.nix`'s comment prescribes.
- [ ] Branch the generic builder in `default.nix` on that discriminator: bake
      `pkgs.wasmtime` into `servicePackages` and the user-supplied `.wasm` as
      `dispatch.wasm`, with no wrapper script and no shebang stamp.
- [ ] Confirm `wasmtime` is on PATH inside the busybox workload rootfs. The
      rootfs has no `/usr/bin/env`, which is why the other languages stamp store
      paths; wasmtime is invoked as a real binary rather than via a shebang, so
      this should be simpler — verify rather than assume.
- [ ] Record the rootfs size delta. `wasmtime` is a large binary relative to a
      busybox workload rootfs, and this tier boots per workload.
- Gate: an image builds with a `.wasm` dispatch fragment and `wasmtime` on PATH.

### WS2 — end-to-end run, compute-only

- [ ] `mvmctl` builds and runs a `.wasm` workload end to end: image → boot on a
      real backend → agent execs `wasmtime run dispatch.wasm` → stdin args → fn
      → stdout return, over the existing framed wire contract.
- [ ] Exercise on at least Firecracker and one macOS backend.
- [ ] Assert the workload inherits the sealed-tier posture: verity-sealed
      rootfs, no shell, no PTY, no DevOnly verbs.
- Gate: a wasm workload runs to completion on a real microVM and returns its
      value; the sealed-tier refusals hold.

### WS3 — egress, and the Preview 1 wall

**This is the plan's one real unknown, and it should not be discovered during
implementation.**

In-guest workloads reach the network through `HTTP_PROXY`/`HTTPS_PROXY` pointed
at `mvm-agentd`'s loopback forward proxy
(`crates/mvm-agentd/src/forward_proxy.rs`), which rides vsock to the host
substitution endpoint. That is how Python and Node workloads get governed
egress with no NIC.

A wasm workload cannot use it as written: **WASI Preview 1 has no sockets at
all.** `wasmtime run` under Preview 1 gives the module stdin, stdout and exit —
nothing else. Proxy environment variables are meaningless to a module that
cannot open a socket.

So:

- [ ] Ship WS1+WS2 as **compute-only wasm workloads** and say so plainly:
      deterministic stdin → fn → stdout, no network. This is honest, useful,
      and complete on its own — it is the shape most compile-to-wasm functions
      take anyway.
- [ ] Only then evaluate egress, which requires WASI Preview 2 sockets (or
      `wasmtime serve -S http`), and resolve the same Preview 1 vs Preview 2
      divergence plan 301 A4 tracks on the host tier. Do not start it before
      WS2 is green.
- [ ] When egress does land, confirm the loopback forward proxy is reachable —
      the NIC-less tier has a known trap where `lo` is down under default-deny.
- Gate for the compute-only cut: a wasm workload with no network runs green,
  and any attempt at network access fails closed rather than silently
  succeeding.

### WS4 — documentation and stale-reference cleanup

Found while scoping this; small, and it misleads the next reader.

- [ ] `crates/mvm-agentd/src/runner/config.rs` cites
      `mvm-sdk/src/ir/workload.rs` and `crates/mvm-ir/data/supported_languages.txt`.
      Both moved: the IR is `crates/mvm-contract/src/ir/workload.rs` and the
      allowlist is `crates/mvm-contract/data/supported_languages.txt`.
- [ ] `crates/mvm-contract/data/supported_languages.txt` refers to "mvmforge"
      and `crates/mvmforge/src/shims/`. There is no `mvmforge` crate.
- [ ] Document the wasm workload path in the site's SDK/guides section once WS2
      is green.
- [ ] Update ADR-024's Status: it asserts "No implementation has landed yet",
      which has been false since plan 301 P2 landed `WasmBackend`. (Also
      tracked as plan 301 A5 — do it in whichever lands first.)

## Non-goals

- A host-side wasm backend carrying numbered claims. ADR-024 §3; that is
  what plan 301 Part A's ceiling is about.
- Replacing the host `WasmBackend`. It remains the claim-free portability tier
  and this plan does not touch it.
- Egress in the first cut. WS3 defers it deliberately rather than shipping a
  half-governed network path.
- A new `BackendKind`. This is a workload format on the existing backends, not
  a backend.

## Relationship to other plans

- [Plan 320](320-wasm-browser-demo.md) — the browser demo. Independent; ships
  first. Its page links here as the claims-bearing way to actually run a wasm
  workload.
- Plan 301 Part A — the host wasm tier's completion. Independent of this plan;
  shares only the Preview 1 vs Preview 2 question (301 A4 / this plan's WS3) and
  the ADR-024 Status fix (301 A5 / this plan's WS4).
