# F5 — WS-NET endgame: HVF converge + fail-closed, then delete smoltcp-L3

**Context:** F3 (#1779) + F4 (#1781) merged. FC + libkrun run through the one
`WorkloadRunner`/`RealEndpointSpawner` vsock seam (Model B) and are machine-checked by
`check-uniform-vsock-egress`. F5 finishes the convergence: converge HVF (the last raw workload
variant, still the macOS-26 default) and then delete the smoltcp-L3 (Model A) second egress model.

Owner-approved: **HVF fail-closed** — a degraded HVF host (supervisor can't launch) loses egress
rather than falling back to a routable NIC. That fallback is the exact vsock-only-invariant
violation F5 removes.

## Why the order is forced
After F3, FC + libkrun advertise `host_vsock_proxy: true` unconditionally, so
`drop_l3_tunnel_for_host_vsock_proxy` (exec.rs) always clears `config.network_tunnel` for them —
they never touch Model A. **HVF is the only remaining Model-A consumer, and only in its fail-open
fallback:** `hvf_backend.rs:343` gates the egress caps on `proxy_path_ready =
hvf_workload_support_available()`, so when the supervisor can't launch, HVF stops advertising
`host_vsock_proxy` (tunnel not dropped) and advertises a routable NIC (`no_routable_guest_nic:
proxy_path_ready`, :352-353). So the L3 stack cannot be deleted until HVF stops using it.

## F5.1 — HVF converge + fail-closed (needs a LIVE HVF witness on this Mac)
This Mac is macOS 26 → HVF is the native `auto_select` default and boots real workloads here, so the
witness is **local** (not the KVM box).

1. **Ungate the egress caps** (`hvf_backend.rs:352-353`): `no_routable_guest_nic` and
   `host_vsock_proxy` become **unconditional `true`**. Leave `virtiofs_root: proxy_path_ready`
   (:357) alone — it's a separate dev-tier gate, not egress. Update the two cap tests (:812-813
   unavailable, :838-839 available) to the new unconditional posture. This is the fail-closed
   change: HVF never advertises a NIC, and `drop_l3_tunnel_for_host_vsock_proxy` always clears the
   tunnel for HVF.
2. **Retype `AnyBackend::Hvf` → `Hvf(HvfRunner)`** (mirror the F3 FC/libkrun retype; `HvfRunner =
   WorkloadRunner<HvfDriver, RealEndpointSpawner, RealBrokerRegistrar>` already exists,
   `HvfDriver` is a complete `VmmDriver`). Collapse to ONE HVF variant: retype the `Hvf` arm to
   hold the runner and DELETE the redundant `HvfRunner(HvfRunner)` variant + the `"hvf-runner"`
   `from_hypervisor` special-case (no backcompat — `hvf` now IS the runner). Add an `hvf_runner()`
   constructor. Flip: `auto_select` (backend.rs:660-661), catalog Hvf row constructor
   (catalog.rs:217), `selection.rs` capability_candidates (:67), `inner`/`into_dyn`/
   `as_workload_backend` (delete the HvfRunner arm, Hvf arm now the runner). Update the raw-Hvf +
   hvf-runner tests. HVF has no warm-start/standby (nothing to descope there); keep the catalog
   flags accurate.
3. **Flip the F4 gate's last exemption** (`xtask/src/check_uniform_vsock_egress.rs`): add
   `"Hvf(HvfRunner)"` to `REQUIRED_ENUM_ARMS` (:65) and `"Hvf(HvfBackend)"` to
   `FORBIDDEN_ENUM_ARMS` (:69); update the exemption module doc + pass/bail messages to drop raw
   Hvf (Wasm stays exempt — still raw); update `current_tree_passes` + the revert test.
   `REQUIRED_ALIASES` already lists `HvfRunner`.
4. The raw HVF L3 wiring (`hvf_backend.rs:435-447,511`) becomes **dead** after (1) (network_tunnel
   always None) — leave it for F5.2's stack deletion. Raw `HvfBackend::start` stays (the
   `examples/hvf-backend-*.rs` pin it; they double as the local witnesses).

**Live HVF witness (the F5.1 merge gate):** local, macOS 26. Default-deny, egress-attempting
workload; observe boots + reachable agent + no routable NIC + egress port pinned to
`substitution-endpoint.sock` + default-deny blocks the outbound. Build `mvmctl` +
`mvm-hvf-supervisor` (the per-VM supervisor bin does not auto-rebuild). Watch for the macOS-26
codesign SIGKILL gotcha on test bins.

## F5.2 — delete the smoltcp-L3 (Model A) stack
After F5.1 (nothing populates a live `network_tunnel`), remove the dead second egress model:
- Wiring: the four spawn sites (`workload_runner/runner.rs:261`, `hvf_backend.rs:440`,
  `libkrun.rs:929`, `microvm/flake_run.rs:312`) + reaps; the `mvm.network_tunnel=` emission
  (`workload_runner/cmdline.rs:89-92`); the CLI populators (`exec.rs:1315,1796`) +
  `drop_l3_tunnel_for_host_vsock_proxy` (now vacuous).
- Modules: `mvm-runtime/src/network_tunnel_spawn.rs`; host
  `smoltcp_egress.rs`/`network_tunnel.rs`/`net_l3.rs`/`bin/mvm-network-tunnel-worker.rs` +
  `fuzz/fuzz_targets/fuzz_l3_gate.rs` + the `packet-forwarder` feature + the `smoltcp` dep; guest
  `network_tunnel.rs`/`bin/mvm-guest-netd.rs` + the L3 parts of `guest_net.rs` +
  `bin/mvm-guest-netinit.rs` consumers; protocol `network_tunnel.rs` +
  `encode/decode_network_tunnel_cmdline` (`mvm-core/src/protocol/vm_backend.rs:243,255`).
- **Do NOT delete `supervisor/proxy/l4.rs`** — it is the hostd supervisor's live L4 egress gate,
  not Model A.
- Confirm the two out-of-scope raw spawn sites (`libkrun.rs:929`, `microvm/flake_run.rs:312`) have
  no live `network_tunnel` populator before deletion (a leftover reference is a safe compile break).
- Host-testable (compile + `check-uniform-vsock-egress` + tests) + a light re-witness that FC +
  libkrun + HVF still egress-gate after the deletion.

## Slices
- **F5.1** — HVF converge + fail-closed + gate flip → local HVF witness → merge.
- **F5.2** — delete the smoltcp-L3 stack → host gates + light re-witness → merge.
