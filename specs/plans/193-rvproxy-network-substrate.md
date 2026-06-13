# Plan 193 — rvproxy network substrate (replace gvproxy/passt)

> **For agentic workers:** proposed / cross-repo-gated. Each workstream needs a
> who-calls audit + failing-test step fleshed out before implementation (Plan
> 177 style). Steps use checkbox (`- [ ]`) syntax.

**Status: 🔴 proposed — cross-repo dependency on `rvproxy`.** The matching
requirements doc lives in the sibling repo at
`rvproxy/specs/plans/014-mvm-adoption-requirements.md`; rvproxy's own
`docs/mvm-integration.md` + `specs/plans/008-orchestration-plane.md` define the
contract. Do not start the mvm cutover (WS-3) until rvproxy confirms the
libkrun-`unixgram` transport (WS-1 finding below).

**Goal:** replace the external **gvproxy** (macOS: libkrun `unixgram` + Vz
`vfkit`) and **passt** (Linux Firecracker) host-side gateways with a single
embeddable/supervised **`rvproxy`** substrate — a Rust-native virtual network
daemon with a typed control API + flow/audit event pipeline.

**Why (the three structural gvproxy/passt problems this removes):**

1. **No native flow API → mvm wraps the datapath in-line.** Claim 10 (default-
   deny egress) + Plan 129 egress-secret substitution + Plan 141's packet
   observer all hang off an *in-line splice + `etherparse`* wrapper bolted onto
   gvproxy **and** passt **separately** (`mvm-hostd` `gateway_bridge.rs`:
   `PlanFlowPolicy`, `FlowOpened`/`FlowClosed`/`PolicyDropped`, deny-by-default).
   rvproxy exposes flow decisions + audit events natively — this collapses mvm's
   most brittle, security-load-bearing networking code into a contract. **Biggest
   win.**
2. **gvproxy(macOS) vs passt(Linux) divergence** special-cased throughout. One
   rvproxy substrate spans mvm's workload backends (macOS VZ/vfkit + libkrun,
   Linux Firecracker, QEMU-unix).
3. **Unclean teardown noise (the bug below).**

## Tracked bug — gvproxy ERROR-on-poweroff (the teardown noise)

mvm's builder VMs are one-shot: they power off when the `nix` build finishes,
closing the vfkit/unixgram socket **before** mvm can stop gvproxy. gvproxy (Go
subprocess) treats this normal disconnect as an error, so **every** builder-VM
completion emits, e.g.:

```
level=error msg="cannot receive packets from …/gvproxy.sock-krun.sock,
  disconnecting: … use of closed network connection"
level=error msg="gvproxy exiting: …"
```

The build succeeds — it is benign log noise that *looks* like a failure. It is
**structurally hard to fix in the gvproxy model**: the VM self-exits before the
host's `GvproxyHandle::Drop` SIGTERM can land, so gvproxy always sees the socket
close first. rvproxy (R1 in the requirements doc) fixes it cleanly: a guest
poweroff is an expected typed event, not an ERROR. Until then it is accepted
noise — do not chase a gvproxy-side fix (gvproxy v0.8.8 has only a `-debug`
bool; there is no log-level flag, and the "bad log level" warning is gvproxy's
own internal default).

## Not-a-fix findings (verified 2026-06-12, do not redo)

- **gvproxy "bad log level" warning** — not mvm-fixable; gvproxy v0.8.8 exposes
  no log-level flag. Goes away with rvproxy.
- **nix-seed re-download** — *not* a normal-use problem: the nix-2.31.1 seed is
  cached under `<cache>/stage0/` and only re-downloaded for a *fresh/isolated*
  `MVM_CACHE_DIR` (e.g. a CI or smoke run). No change warranted.
- **Build slowness** is the **base-VM fingerprint churn**, NOT networking:
  `builder_vm_source_fingerprint` folds in the whole workspace `Cargo.lock` + the
  embedded host-binary byte hashes, so active development busts the builder-VM
  cache (and re-materializes Stage 0, ~9s) on most builds. A separate, careful
  change (narrow the fingerprint to a `Cargo.lock` subset / source identity);
  tracked here as context but out of scope for the rvproxy cutover.

## Workstreams (proposed)

- [ ] **WS-1 — transport spike (gate).** Confirm rvproxy serves mvm's host
      transports, especially **libkrun `krun_add_net_unixgram`** (mvm's default
      macOS backend), Vz `vfkit`, and a Firecracker passt replacement. Owner:
      coordinate with the rvproxy session (their Plan 014 R3).
- [ ] **WS-2 — flow-decision + audit seam.** Port `gateway_bridge`'s
      `PlanFlowPolicy` deny-by-default gate + flow-audit onto rvproxy's native
      flow API; delete the in-line splice/`etherparse` wrapper (Plan 141) and the
      per-backend `on_packet` hooks once parity is proven. Keep claim-10/12/13
      witnesses green throughout.
- [ ] **WS-3 — backend cutover.** Replace the gvproxy spawn
      (`mvm-build/host_gvproxy.rs`, `libkrun-sys/gvproxy.rs`) + passt with
      `rvproxy run --config` per the integration contract; drop the Homebrew
      gvproxy/passt host deps. Clean teardown (R1) verified: zero error-level
      noise on one-shot builder-VM completion.
- [ ] **WS-4 — `mvm net` verbs.** `mvm net stats/leases/forward` over rvproxy's
      control API (per `docs/mvm-integration.md`); `mvm run --net rvproxy`.

## Cross-repo dependency
rvproxy `specs/plans/014-mvm-adoption-requirements.md` (mvm-authored requirements)
+ `docs/mvm-integration.md` + `specs/plans/008-orchestration-plane.md`. The
rvproxy session owns the substrate; mvm owns the cutover + the claim witnesses.

## Non-goals
- mvm's vsock agent/substitution channel (separate from the network gateway).
- mvmd fleet placement (rvproxy stays host-local + replaceable).
- The base-VM fingerprint slowness (separate change; noted above for context).
