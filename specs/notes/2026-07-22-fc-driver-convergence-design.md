# F3 — FcDriver convergence: design & scoping note

**Date:** 2026-07-22
**Context:** Plan 258 (uniform vsock-egress convergence). libkrun converged + live-witnessed
(#1766); HVF routes via `HvfDriver`. Firecracker is the last workload backend with its own
`VmBackend` impl. This note scopes F3 — converging Firecracker onto
`WorkloadRunner<FcDriver, RealEndpointSpawner, RealBrokerRegistrar>` — before any code.

Firecracker is the **Linux default** workload backend and `auto_select`'s final fallback, so a
regression here has higher blast radius than the libkrun flip. This note mirrors the libkrun
flip exactly: a dormant driver PR, then a retype PR gated on an observed live-KVM egress witness.

## What the seam already gives us (nothing to port from the backend)

The runner does every role step backend-agnostically, above the driver:

- **Egress endpoint** — `RealEndpointSpawner` spawns one per-VM `mvm-substitution-endpoint`
  (`EndpointTransport::Uds` → `vm_substitution_endpoint_socket(vm)`), threads its UDS into the
  spec as the `EGRESS_PORT` `GuestDials` channel (`runner.rs`, `spec_map.rs`). The claim-10 gate
  + claims-12/13 substitution live there.
- **`mvm.vsock_egress=1`, verity, grants, runtime-overlay, uvols** — assembled once in
  `workload_runner/cmdline.rs` and handed to the driver as `spec.cmdline`. FC gets the egress
  token for free on retype (it emits none today).
- **Broker** — `RealBrokerRegistrar` (claims 12/13). **Admission gates** — overlay contract +
  `record_from_start_config` (claim-15 console gate) in `WorkloadRunner::start`.
- **No NIC** — `VmmSpec` has no network field by construction; a driver cannot add or bypass
  egress policy. "No routable guest NIC" is a property of the type.

So the scoped-but-superseded `wsnet/fc-model-b` branch (stale: 1 ahead / 24 behind, both its
companion fixes — OCI overlay-first #1747, seccomp `lseek` #1749 — already on main) contributes
almost nothing to port. Its only reusable nuggets: the FC vsock per-port UDS naming, the
capability values, and the live confirmation that a guest vsock dial reaches the host endpoint
over FC userspace virtio-vsock. **Build FcDriver on origin/main; do not rebase that branch.**

## Current Firecracker state (from code, file:line)

- `FirecrackerBackend` — `backend.rs:155` (struct), `impl VmBackend` `backend.rs:220`, `start`
  `backend.rs:285`. `firecracker.rs` is only install/asset/checkpoint helpers.
- Boot: `start` → `FirecrackerConfig::from_start_config` (slot + `FlakeRunConfig`) →
  `microvm::run_from_build` (`flake_run.rs:163`) → `run_configured_firecracker` (`flake_run.rs:236`):
  TAP provision + iptables policy → optional `mvm-bridge` → `start_vm_firecracker`
  (`daemon.rs:86`, `firecracker --api-sock`, pid→`fc.pid`) → `spawn_egress_endpoint` →
  tunnel worker → `configure_flake_microvm` (API sequence, `boot_config.rs:175`) → `InstanceStart`
  → `install_egress_redirect` (post-boot nft REDIRECT).
- API config sequence (`boot_config.rs:175`): logger, boot-source (kernel+initrd+cmdline),
  machine-config, drives, **network-interfaces/net1**, vsock, balloon.
- Reusable primitives (call, don't fork): kernel-prep `mvm_build::fc_kernel::ensure_fc_loadable_kernel`
  (`boot_config.rs:309`; FC's `libkrun_kernel_for_host` analogue), `build_verity_cmdline_args`
  (`boot_config.rs:59`), `build_runtime_overlay_cmdline_args` (`:79`), `configure_drives` (`:360`),
  `configure_vsock` (`:504`), `configure_machine` (`:339`), `start_vm_firecracker`/`api_put_socket`
  (`daemon.rs`).
- vsock: `guest_cid=GUEST_CID(3)`, `uds_path=firecracker_vsock_uds_path(dir)` =
  `<vm_dir>/runtime/v.sock` (`mod.rs:84`). Host→guest = connect `v.sock` + `CONNECT <port>\n`
  (`vsock_transport.rs`). Guest→host = FC muxes to sibling **`v.sock_<port>`**.
- Egress today: routable NIC (`configure_network` `boot_config.rs:486`, `mvm.ip=`/`mvm.gw=`
  `:226`), TAP + **iptables** deny (`network.rs::apply_network_policy`; provider default
  `deny_all`), substitution endpoint `EndpointTransport::Vsock{EGRESS_PORT}` **+ transparent
  terminator** (`egress_bridge.rs:185`), nft `:80/:443` REDIRECT (`egress_redirect.rs`). FC emits
  neither `mvm.vsock_egress=1` nor `mvm.network_tunnel=` (its token builder is `#[cfg(test)]`),
  so its tunnel worker is spawned but never activated — FC egress today is purely NIC+iptables.
- Caps (`backend.rs:229`): `tap_networking:true`, `no_routable_guest_nic:false` (default),
  `host_vsock_proxy:false` (default). The converged driver flips to the libkrun profile.

### Mission-brief corrections

- FC's TAP deny is **iptables** (`network.rs`), not nftables `install_default_deny` — the latter
  is the hostd-supervisor firewall (`supervisor/firewall/linux_nft.rs`), a *different* subsystem
  not on the FC start path. nftables on FC is only the `:80/:443` REDIRECT.
- **Raw FC start is not deletable in F4.** Besides `FirecrackerBackend::start`, the hostd
  supervisor's admitted-plan launcher (`FirecrackerRunConfigLauncher::launch` →
  `mvm_runtime::microvm::run_from_build`, `mvm-hostd/src/supervisor/backend.rs:144`) drives
  `run_from_build` directly. That is the mvmd/fleet multi-tenant path; converging it is out of
  F3/F4 scope (its egress is the supervisor nft firewall). The libkrun flip left its supervisor
  path raw too. So the F4 gate scopes to the **`AnyBackend` (mvmctl CLI/local) workload path**.
- `bench_probe` pins **libkrun**, not FC — there is no raw-FC bench caller to migrate.

## FcDriver design (`crates/mvm-runtime/src/driver/fc.rs`)

`FcDriver: VmmDriver`, wrapping a `FirecrackerBackend` for identity/`is_available`/kind, mirroring
`LibkrunDriver`. Pure mechanics: it never sees a plan, tenant, or `NetworkPolicy`.

- `workload_base_bootargs(virtiofs_root, has_disk)` — FC's serial-console base
  (`console=ttyS0 reboot=k panic=1 net.ifnames=0` + root/init by shape), **no `mvm.ip=`/`mvm.gw=`**.
  Routed through the seam (do not hardcode a console class — libkrun=hvc0, HVF=pl011, FC=ttyS0).
- `capabilities()` — `tap_networking:false`, `no_routable_guest_nic:true`, `host_vsock_proxy:true`
  (the libkrun profile).
- `boot(&VmmSpec)` — a NIC-less, endpoint-free FC boot assembled from the spec, reusing the
  boot_config/daemon primitives above (not `run_configured_firecracker`, which is entangled with
  TAP/egress/FlakeRunConfig):
  1. `ensure_fc_loadable_kernel(spec.kernel)`; `start_vm_firecracker(dir, socket)` → `fc.pid`.
  2. API: logger; boot-source (kernel, `spec.initramfs`, **`spec.cmdline` verbatim** — the runner
     already assembled every token); machine-config (`spec.vcpus`/`memory_mib`/`mem_initial_mib`);
     drives from `spec.blocks` sorted by `slot` (vda/vdb/vdc/… — the shared verity slot model
     the runner's `build_verity_cmdline_args` names); vsock (`v.sock`, `guest_cid`); balloon if
     `mem_initial`.
  3. **No** `configure_network`, TAP, iptables, `spawn_egress_endpoint`, or `install_egress_redirect`.
  4. vsock egress bridge (the one FC-specific nugget): for each `GuestDials` port, make the FC
     sibling socket `v.sock_<port>` resolve to the spec's `host_uds`. For `EGRESS_PORT` that is
     the runner endpoint's `substitution-endpoint.sock`; for `WORKLOAD_EXIT_PORT`/`BROKER_PORT`
     the runner's state-dir sockets. This is FC's analogue of libkrun's `egress_relay_socket` /
     `add_host_listen_port_at`. Mechanism (symlink vs bind-relay) decided in F3.1; a symlink of
     `v.sock_<port>` → `host_uds` is the zero-overhead candidate (FC *connects* to that path for a
     guest-initiated dial), validated live.
  5. `InstanceStart`; poll `fc.pid` + the agent socket; return `FcRunningVm { id, state_dir, pid_file }`.
- `RunningVm` — `fc.pid` lifecycle (kill/status/wait via the existing FC helpers);
  `vsock_connect(port)` = `connect_to_port(v.sock, port)` (agent + dev-console ports only, claim-15).
- `attach(id)` — disk-backed (re-derive `fc.pid` + state dir), like `LibkrunDriver::attach`.

**Reuse-first rule for F3.1:** where a boot_config primitive is entangled with FlakeRunConfig or
the NIC, extract the shared inner helper both the raw path and the driver call — never a second
copy. The 0-byte-console libkrun regression came from a forked cmdline branch; the driver must
reuse `ensure_fc_loadable_kernel` + `build_verity_cmdline_args` + `configure_drives`/`configure_vsock`,
not reimplement them.

## Slices (each its own PR + task review; the retype gated on a live witness)

- **F3.1 — FcDriver mechanics, dormant.** New `driver/fc.rs` + `driver/mod.rs` export. Full host
  unit tests (relay-config-style: no NIC, egress/exit/broker `v.sock_<port>` bridged to the spec
  `host_uds`, `spec.cmdline` threaded verbatim, drives slot-ordered vda/vdb/vdc, caps flipped,
  bundled-kernel rejected, `attach` disk-backed). Extract shared FC boot primitives (no fork).
  **Not** wired into `AnyBackend` — dormant, exactly as the libkrun driver landed before its flip.
- **F3.2 — retype `AnyBackend::Firecracker`.** `type FcRunner` + `fc_runner()`; swap the enum
  variant + `default_backend`/`from_build_output`/`auto_select`(×2)/`capability_candidates`
  (selection.rs) + catalog + `from_hypervisor`. Flip catalog rows (warm_start/balloon → false,
  needs_plan_json → false, marker stays `fc.pid`). Update the enum/kind/dispatch tests. Host gates
  green. This makes the runner FC's sole mvmctl-CLI path.
- **F3.3 — live FC egress witness (Hetzner KVM, run from the main loop via SSH).** Default-deny,
  egress-attempting workload. Arm the merge only after it passes.

## Decisions for the owner (batched, before F3.1)

1. **Warm-start/standby + balloon descope on the Linux default.** Retyping FC onto the runner
   drops FC's warm-start (snapshot restore), standby pool, and balloon from the mvmctl path (the
   runner takes trait defaults, like libkrun). A plain transient `machine run` calls `start`, not
   `warm_start`, so this only affects explicit warm-pool usage; FC warm-start also stays available
   on the raw hostd-supervisor path. **Recommend descope** (flip catalog rows, mirror libkrun) +
   track "port standby into the runner" as a deferred follow-up. Flagged because FC is the
   production default, not a Tier-2 backend.
2. **claim-10 enforcement-point shift for FC.** FC today pins admission-time IPs at iptables on
   the TAP (Model A). The runner moves claim-10 to the host-side endpoint that re-resolves the
   destination per connection (Model B, pin-consistency → host-resolution). libkrun/HVF already
   made this shift and it is witnessed; FC makes the same shift. The live witness must re-confirm
   default-deny holds on the FC vsock path. (Owner-awareness item, not a blocker.)
3. **Convergence claim is scoped to the CLI path.** The F4 gate proves the `AnyBackend` workload
   backends are runners with egress only in `RealEndpointSpawner`. The hostd-supervisor / mvmd
   fleet FC launcher keeps raw `run_from_build` + its nft firewall — the same scope boundary
   libkrun's flip left. If the intent is "every FC launch," converging the supervisor launcher is
   a separate, larger effort to sequence after F3.

## Live witness definition (F3.3 — the merge gate)

`MVM_HYPERVISOR=firecracker` (or `--hypervisor` once F1/#1772 lands), `machine run --image alpine`,
entrypoint that attempts egress (`wget -T 8 -O- http://example.com`), **no `--network-allow`**.
Observe all of: boots (console fills), agent reachable (`listening on vsock port 5252`), **no
routable NIC** (`eth0: No such device`), egress endpoint spawned with the guest EGRESS_PORT pinned
to `substitution-endpoint.sock` (via the `v.sock_5253` bridge), and default-deny **blocks** the
outbound attempt. Host tests do not boot a guest — this witness is mandatory, not CI alone.

## Deferred follow-ups (track in plan 258)

- Port FC warm-start/standby into the runner (if CLI warm-pool needs it).
- Converge the hostd-supervisor FC launcher onto the runner (fleet path).
- F4 gate + retire libkrun `spawn_libkrun_egress_endpoint` / FC `egress_bridge` raw wiring on the
  CLI path; delete raw `LibkrunBackend::start` after migrating `bench_probe`.
- F5: delete the smoltcp-L3 stack; HVF fail-closed on the endpoint.

### Post-F3 review follow-ups (from the final whole-branch review; non-blocking)

- Delete or route `AnyBackend::start_firecracker` — it still drives the raw `microvm::run_from_build`
  (NIC/TAP) path for the Firecracker arm. Zero callers today, but now that the variant is the
  NIC-less runner it reads as a raw-boot bypass; fold into F4's raw-path retirement.
- Detached-VM exit capture asymmetry: `FcDriver`'s workload-exit listener lives in the ephemeral
  `mvmctl` process, so a `-d`/`--name` FC VM never gets `workload.exit` written (mvmctl exits after
  boot). Transient (the default lifecycle) captures it and was live-witnessed; the persistent path
  needs a supervisor-like owner (mirror libkrun's per-VM supervisor) if detached FC exit codes matter.
- Investigate the tail `Failed to read frame length (EAGAIN)` on a transient run whose exec'd
  command outlives the expected response (trailing `sleep`); no-sleep runs are clean, and the review
  read it as a benign long-open-exec-stream artifact, but confirm it is not a transient-teardown race.
- Correct the stale `doctor/warm_start.rs` prose that still says the substrate backs "Firecracker's
  live-memory path" — true only for the raw hostd path now, not the CLI path.
