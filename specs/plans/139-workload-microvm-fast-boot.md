# Plan 139 — Workload microVM fast-boot (cold-boot shaving)

## Context

`mvmctl up` boots the workload microVM in "seconds" — but the kernel itself is
already ms-class (~100–250 ms; the builder's own `boot_timings` shows
`network_ready=250ms`, `job_start=260ms`). The seconds are everything *around*
the kernel. This plan attacks the cold-boot critical path on the libkrun/macOS
and Firecracker paths (no snapshot needed — that's Plan 140 / mvmd). Goal: get
`up → agent-ready` to low-hundreds-of-ms and, more importantly, **measure it**
so we cut the biggest bar first instead of guessing.

Builds on Plan 138 (workload build+run path). Genuine single-digit-ms cold boot
of a real Linux guest is not physical; that's snapshot restore (Plan 140).

## Status — A measured (2026-06-02), B NOT pursued

Instrumented `up` and measured a real libkrun `up --flake`:
- **Build ≈ 126 s; VM start < 1 s; total ≈ 99% build.** Cold boot is dwarfed by
  the builder-VM build.
- **libkrun `up` never awaits the guest agent** — `wait_for_guest_agent` is gated
  to `apple-container` (up.rs ~1866). The guest boots asynchronously and
  un-awaited; the workload emits no `boot_timings`, so guest boot-to-agent is
  currently *unmeasured* (the builder VM has timings; the workload doesn't).
- → **B (static IP) dropped:** DHCP/static-IP is not on the workload `up`
  critical path. The real levers are **build cost** (dev loop) and
  **snapshot/restore** (Plan 140 — and templates already restore-from-snapshot
  on the `up` path: "Snapshot available — will restore instantly").

Tasks A/B below are retained as the record; only the deferred item is live.

### Deferred follow-ups
- [ ] **Guest-side workload `boot_timings`** — mirror the builder VM's
      `boot_timings` in the workload guest so boot-to-agent is measurable. Only
      worth doing if we pursue cold-boot guest optimization; currently
      de-prioritized behind Plan 140.

## Critical-path contributors (confirmed)

- **DHCP**: guest net is `udhcpc -i eth0 -n -q` (`mvm-host-vm-init/src/main.rs`
  ~1857) — a broadcast DISCOVER→SELECT→lease round-trip on `network_ready_ms`.
- **Agent start latency + polling**: host blocks in `wait_for_guest_agent`
  polling vsock Ping; the agent also starts mid-init.
- **Verbose kernel cmdline**: full dmesg lands in `console.log` (no `quiet`).
- **Host overhead**: `extract_bundled_kernel` re-pulls the kernel from
  libkrunfw `.rodata` every boot; gvproxy socket-wait + plan/audit I/O.

## Tasks

### A. Instrument the whole path (do this first — measure before cutting)
- [ ] Reuse `boot_timings::BootTimings` (already emits init→pseudofs→
      nix_device→mounted→network_ready→job_start) on the **workload** init path,
      not just the builder. Add `agent_listen_ms` (vsock listener bound) and
      `agent_first_ping_ms`.
- [ ] Emit timings to the host: `write_boot_timings` already writes the JSON;
      surface it from the workload VM's scratch dir and log it at the end of
      `up` behind `MVM_BOOT_PROFILE=1`.
- [ ] Add a **host-side span** around `up`: stamp wall-clock at (plan admitted,
      supervisor spawned, gvproxy socket ready, VM launched, agent first Ping).
      Print the breakdown under `MVM_BOOT_PROFILE=1`.

### B. DHCP → static IP, by policy
> **Measurement gate (found during A setup):** the DHCP tax was confirmed on the
> **builder VM**, whose init blocks on `udhcpc` before `job_start`. The
> **workload** microVM's agent answers over **vsock** (`wait_for_guest_agent` is
> vsock, not IP) and `mvm-guest-netinit` only installs egress deny-routes — so
> DHCP may **not** be on the workload's `up→ping` critical path. Do **not** start
> B until A's `agent_wait` bar shows guest networking actually gates readiness.
> If it doesn't, B becomes "static IP for the *app's* egress latency," a
> different (lower) priority. Resolution surface (config-disk → cmdline → DHCP):

- [ ] Host: extend the workload cmdline (`LibkrunConfig::with_cmdline` /
      backend launch) with `mvm.ip=<a.b.c.d/len> mvm.gw=<a.b.c.d>` derived from
      the per-VM gvproxy subnet (default `192.168.127.2/24` gw `.1`) or, for a
      named network, the `dev_network` allocator's assigned IP. This is the
      "by policy" knob — the host owns the address.
- [ ] Guest (`mvm-host-vm-init`): parse `mvm.ip`/`mvm.gw` from `/proc/cmdline`.
      When present, after `bring_iface_up("eth0")`, configure statically
      (`ip addr add` + default route via the SIOCSIFADDR/SIOCADDRT ioctls
      already in this module, or `/bin/ip`) and **skip `udhcpc`**. When absent,
      keep the current `udhcpc` path (fallback for passt / unconfigured boots).
- [ ] Stamp `network_ready_ms` immediately after static config so the win is
      visible in the profile.
- Collision note: every microVM has its own gvproxy → own `192.168.127.0/24`,
  so a fixed `.2` never collides across concurrent VMs. Tracking stays via
  `name_registry` + per-VM state dir + vsock CID, never the guest IP.

### C. Start the guest agent as early as possible
- [ ] Move the workload agent's vsock listener bind ahead of non-essential init
      (before any optional service setup) so `wait_for_guest_agent` can succeed
      the instant the kernel + net are up.
- [ ] Make host readiness event-driven where cheap: tighten
      `wait_for_guest_agent`'s poll interval (or have the agent connect out on a
      known port so the host blocks on accept, not a poll loop). Keep the 30s
      budget as the ceiling.

### D. Production kernel cmdline (keep verbose for debug)
- [ ] Add a quiet production cmdline (`quiet loglevel=1`, drop console spam on
      the hot path; keep `console=hvc0` per libkrun requirement) selected by
      default, with the current verbose cmdline behind `MVM_DEBUG_BOOT=1` (or
      `--debug-boot`). Never strip in debug.
- [ ] Cache the libkrunfw-extracted kernel (`extract_bundled_kernel`) on disk
      keyed by libkrunfw version, instead of re-extracting from `.rodata` each
      boot.

## Files
- `crates/mvm-host-vm-init/src/main.rs` — static-IP parse/config + skip udhcpc
  (~1857), agent-listener ordering, `boot_timings` additions.
- `crates/mvm-host-vm-init/src/boot_timings.rs` — new `agent_listen_ms`,
  `agent_first_ping_ms` fields.
- `crates/mvm-libkrun/src/lib.rs` — cmdline (`mvm.ip`/`mvm.gw`, quiet-vs-debug),
  cached kernel extraction.
- `crates/mvm-cli/src/commands/vm/up.rs` — host-side span + `MVM_BOOT_PROFILE`
  reporting; pass the resolved static IP into the launch config.
- `crates/mvm/src/...` (workload launch) + `wait_for_guest_agent` cadence.

## Verification
- [ ] `MVM_BOOT_PROFILE=1 mvmctl up …` prints a stage breakdown; record the
      baseline, then the post-static-IP delta (expect the DHCP bar to vanish).
- [ ] Two concurrent `up`s on one host both get `192.168.127.2`, both reachable,
      tracked distinctly in `name_registry` — no collision.
- [ ] Debug boot (`MVM_DEBUG_BOOT=1`) still emits full dmesg.
- [ ] `cargo fmt --all`, `cargo clippy --workspace -D warnings`, workspace tests.

## Deferred follow-ups
- [ ] Event-driven agent readiness (replace poll with connect-out) if the poll
      cadence is still a visible bar after B/C.
