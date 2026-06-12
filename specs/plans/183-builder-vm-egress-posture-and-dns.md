# Plan 183 — Builder-VM egress posture + guest network bootstrap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unblock networked flake builds in the libkrun/Vz builder VM (broken since
2026-06-05) by scoping the in-guest egress lockdown to the deps-install arm instead of
the whole VM, and harden the builder guest's IP/DNS bootstrap (Vz DHCP no-lease,
read-only resolv.conf).

**Architecture:** Move `install_egress_lockdown` from PID-1 boot to the install-arm
entry (and per-dispatch in the persistent loop), so the flake-build arm has nix's
normal open egress while untrusted dep installs stay uid-locked. Add a static-IP
fallback (gvproxy's fixed subnet) when DHCP yields no lease, and make
`/etc/resolv.conf` writable via a `/run` bind-mount seeded with the per-backend
gateway resolver.

**Tech stack:** Rust (`mvm-build`: `mvm-host-vm-init`, `stage0-init`), iptables-legacy
(x_tables), busybox udhcpc, gvproxy.

---

## Diagnosis (proven 2026-06-11 on the macOS-26 Vz/libkrun dev host)

Every cold or new-dep `mvmctl up --flake` / `dev up` build on macOS fails with
`Could not resolve host: …` inside the builder VM. Three independent defects, ranked:

1. **Egress lockdown applies to the whole builder VM (primary).**
   `mvm-host-vm-init`'s PID-1 boot sequence (`run()`,
   `crates/mvm-build/src/bin/mvm-host-vm-init.rs:929`) installs
   `network::install_egress_lockdown` — `OUTPUT` policy `DROP` with only
   loopback + `PROXY_UID` accepts (`crates/mvm-build/src/bin/mvm-host-vm-init/network.rs:71-86`).
   The inner `nix build` runs with no proxy env (the proxy path is install-pipeline
   only), so every fetch — DNS first — is dropped. The rules existed earlier but
   silently failed to install until `f184b17d` (2026-06-05) put `iptables-legacy` in
   the rootfs (the kernel is x_tables); from the next image rebuild on, the lockdown
   *actually applies*. It stayed masked while builds hit the promoted store; the first
   build needing an uncached fetch (the guest agent's new TLS-CA crates) exposed it.
   `53ea0859` (same day) added a dev-tier skip — but keyed on `mvm.backend=qemu`
   only, and macOS has no QEMU tier: the macOS dev-tier builders are libkrun/Vz.
   Controlled A/B from one `dev up` run: Stage 0 (no lockdown — `stage0-init`, not
   `mvm-host-vm-init`) fetched the full builder-image closure from cache.nixos.org;
   minutes later the builder VM on the same host could not resolve `github.com`.

2. **Vz builder gets no DHCP lease (independent of 1).**
   Vz builder console: `udhcpc: broadcasting discover` ×3 → `no lease, failing` →
   `setup_network warning (non-fatal): udhcpc exit 1` → eth0 never configured → no
   network at all. The libkrun builder on the same host leases `192.168.127.3` from
   `192.168.127.1` fine, so gvproxy itself serves DHCP; the loss is specific to the
   Vz supervisor's unixgram datagram path.

3. **`/etc/resolv.conf` is read-only, so leased DNS never lands.**
   libkrun builder console: busybox's in-store `default.script` →
   `can't create /etc/resolv.conf: Read-only file system`. The rootfs mounts `ro`
   and `/etc/resolv.conf` is a baked regular file (`nameserver 1.1.1.1`/`8.8.8.8`),
   not the `/run` symlink `setup_network`'s comments assume
   (`crates/mvm-build/src/bin/mvm-host-vm-init.rs:2185-2247`). The guest is pinned to
   external resolvers instead of the gateway resolver the lease provides — masked
   today by defect 1, but a correctness bug on its own (Stage 0 uses
   `192.168.127.1`, proven; `stage0-init.rs:292-304`).

Out of scope: mvmd's Firecracker/jailer builder (separate substrate), the QEMU
builder's `ip=` autoconfig path (working, box-proven), gvproxy upstream changes.

## Design decision — per-arm egress posture

The lockdown's stated intent (builder flake comment, ADR-047/claim-11 context) is
defense-in-depth for the **deps-install pipeline** — untrusted dependency code whose
only legitimate egress is `mvm-egress-proxy`. The flake-build arm is nix fetching
pinned sources/substitutes — its egress is nix's standard model and must be open.

**Chosen:** install the lockdown at the **install-arm entry** (fail-closed), not at
boot; in the persistent dispatch loop set the posture **per job kind** (install →
locked, flake build → open). The QEMU-only boot skip becomes dead and is removed —
one posture mechanism, no per-backend special case.

**Rejected:** extending the `mvm.backend=qemu`-style boot skip to libkrun/Vz
(tier-keyed whole-VM skip). That would unbreak flake builds but drop claim-11
defense-in-depth for installs on macOS dev hosts, where deps sealing still runs.
Per-arm posture keeps the lockdown exactly where the threat is.

---

## WS-A — egress posture per arm

**Files:**
- Modify: `crates/mvm-build/src/bin/mvm-host-vm-init/network.rs`
- Modify: `crates/mvm-build/src/bin/mvm-host-vm-init.rs` (boot `run()` ~:900-960,
  persistent dispatch ~:1628, `dev_tier_builder_from_cmdline` :185)
- Modify: `crates/mvm-build/src/bin/mvm-host-vm-init/install.rs` (`run_install` :305)
- Modify: `crates/mvm-build/src/qemu_builder.rs` (:142 cmdline — drop the now-unused
  tier token only if nothing else consumes `mvm.backend=qemu`; verify with rg first)
- Modify: `nix/images/builder-vm/flake.nix` (egress comment block ~:160)

- [x] **A1: add `open_egress` to `network.rs` with tests.** New function beside
  `install_egress_lockdown`:

  ```rust
  /// Reset the OUTPUT chain to open egress for a trusted flake-build
  /// dispatch. The inner `nix build` fetches substitutes and pinned
  /// flake inputs directly (no proxy), so the chain must not filter it.
  pub fn open_egress(runner: &dyn IptablesRunner) -> Result<(), String> {
      runner.run(&["-F", "OUTPUT"])?;
      runner.run(&["-P", "OUTPUT", "ACCEPT"])?;
      Ok(())
  }
  ```

  Tests (same `RecordingRunner` pattern as the existing module tests): exact
  invocation sequence; first-call failure propagates.
- [x] **A2: remove the boot-time lockdown.** Delete the
  `qemu_dev_tier`/`install_egress_lockdown` block from `run()`
  (`mvm-host-vm-init.rs` ~:900-960) including the
  `egress_error_indicates_no_netfilter` Stage-0 fallback branch it guards (keep the
  helper only if the install-arm path still needs it — it does not: the steady-state
  builder kernel carries netfilter, and the install arm must fail closed). Delete
  `dev_tier_builder_from_cmdline` (:185) and its tests; it has no remaining callers.
- [x] **A3: lock at install-arm entry.** At the top of `run_install`
  (`install.rs:305`), before the egress proxy spawn and any dep tooling runs:

  ```rust
  crate::network::install_egress_lockdown(
      &crate::network::SystemIptables,
      crate::network::PROXY_UID,
  )
  .map_err(InstallError::EgressLockdown)?;
  ```

  Add the `EgressLockdown(String)` variant to `InstallError` (fail-closed: a builder
  whose kernel can't enforce the lockdown refuses install jobs). Unit-test via the
  existing `run_install_with_fakes` seam (inject a failing runner → install refuses).
- [x] **A4: per-job posture in the persistent dispatch loop.** At the ~:1628
  `reapply_egress_lockdown` site, set posture by job kind instead of
  unconditionally re-locking: install dispatch → `reapply_egress_lockdown`,
  flake-build dispatch → `open_egress`. Failure stays a hard refusal of the
  dispatched job either way.
- [x] **A5: drop the QEMU boot-skip remnants + fix comments.** Remove the
  `mvm.builder-tier` skip prose from the builder flake's egress comment block and
  describe the per-arm posture instead. In `qemu_builder.rs:142` keep
  `mvm.backend=qemu` only if `rg "mvm.backend"` shows another consumer (stage0's
  backend detection does consume it — verify before touching).
- [x] **A6: gates.** `cargo fmt --all -- --check`,
  `cargo clippy --workspace -- -D warnings`,
  `cargo nextest run -p mvm-build`, then commit
  `fix(builder-vm): scope egress lockdown to the install arm`.

## WS-B — Vz builder DHCP no-lease + static-IP fallback

**Files:**
- Create: `crates/mvm-build/src/guest_net.rs` (shared in-guest ioctl helpers)
- Modify: `crates/mvm-build/src/bin/stage0-init.rs` (:178-260 — re-export/reuse)
- Modify: `crates/mvm-build/src/bin/mvm-host-vm-init.rs` (`setup_network` :2185)

- [x] **B1: lift stage0's static-config ioctls into a shared module.** Move
  `configure_network_qemu`'s `ifreq_for` / `SIOCSIFADDR` / `SIOCSIFNETMASK` /
  `SIOCADDRT` plumbing (`stage0-init.rs:178-260`) into
  `mvm_build::guest_net::configure_static(iface, addr, netmask, gateway)`
  (cfg-gated linux like the bins). stage0-init's QEMU arm calls it with
  `10.0.2.15/24 via 10.0.2.2`; no behavior change there. Unit-test the pure parts
  (address parsing/encoding) on the host.
- [x] **B2: static fallback in `setup_network`.** When udhcpc exits nonzero on a
  gvproxy backend, fall back instead of warning-and-continuing:

  ```rust
  if !status.success() {
      eprintln!(
          "mvm-host-vm-init: udhcpc exit {} — falling back to static \
           gvproxy addressing",
          status.code().unwrap_or(-1)
      );
      mvm_build::guest_net::configure_static(
          "eth0", "192.168.127.3", "255.255.255.0", "192.168.127.1",
      )?;
  }
  ```

  gvproxy's virtual subnet is fixed (`192.168.127.0/24`, gateway+resolver `.1`,
  first DHCP client `.3`), and each builder VM has its own gvproxy instance, so the
  static address cannot collide. This makes the Vz builder networked **now** without
  waiting on the datagram-path root cause.
- [x] **B3: root-cause the Vz DHCP loss (investigation, time-boxed).** Root cause
  confirmed: `connect_gvproxy_dgram` in `crates/mvm-vm-host/src/vz_objc.rs` connected
  the AF_UNIX SOCK_DGRAM socket without first binding a local address. An unbound
  unix-datagram socket has no return address, so every `sendto()` reply from gvproxy
  (DHCP offer, DNS response, etc.) was silently dropped by the kernel. The fix (WS-E
  below) binds to a sibling `vz-net-reply.sock` path before `connect()`.
- [x] **B4: gates + commit** `fix(builder-vm): static gvproxy fallback when DHCP
  yields no lease`.

## WS-C — writable resolv.conf seeded with the gateway resolver

**Files:**
- Modify: `crates/mvm-build/src/bin/mvm-host-vm-init.rs` (`setup_network` :2185)

- [x] **C1: bind-mount a `/run`-backed resolv.conf before udhcpc.** Replace the
  no-op fallback copy (the image bakes no `/etc/resolv.conf.fallback`; the file is
  a read-only regular file, not a `/run` symlink — both comments are wrong) with a
  `resolver_seed(cmdline)`-seeded write + busybox bind-mount. *(Deviation from
  plan text: `resolver_seed` is per-backend — QEMU gets `10.0.2.3`, gvproxy gets
  `192.168.127.1` — superseding the "QEMU builder arm untouched" clause; the
  per-backend seed matches stage0's proven values and gives the QEMU builder the
  correct DNS too.)*
- [x] **C2: delete the stale fallback-copy block + wrong comments** (the
  `/etc/resolv.conf.fallback` seed at :2194-2203 and the "symlink into /run" /
  "udhcpc still sets the IP" prose).
- [x] **C3: gates + commit** `fix(builder-vm): writable gateway-resolver
  resolv.conf via /run bind-mount`.

## WS-D — verification + resume the live Vz validation

- [x] **D1: cold E2E on this host (the exact scenario that failed).** PROVEN
  2026-06-12: isolated cold `dev up` (libkrun) exit 0, zero resolve failures,
  the builder VM's inner nix build fetched 703 store paths from
  cache.nixos.org, and the EROFS resolv.conf error is gone from the console.
  Vz leg: the WS-B static fallback fired exactly as designed on the unfixed
  link (`udhcpc exit 1 — falling back to static gvproxy addressing`); after
  WS-E2 (bound reply socket) the Vz builder leases normally
  (`lease of 192.168.127.3 obtained from 192.168.127.1`) and a sleeper image
  build via `--builder vz` completes with zero resolve failures.
- [x] **D2: deps-install gate still locked.** 17/17 app-deps gate tests green
  locally; the install-arm refusal + per-job posture tests compile for the
  Linux target and run in CI (green on the WS-A/B/C merges).
- [x] **D3: live Vz WS-2 validation — run 2026-06-12 (first ever).** With WS-E:
  `up --flake examples/sleeper --builder libkrun --hypervisor vz` admitted the
  plan, booted on the fallback kernel, survived far past the old ~5 s crash
  window, and the guest agent came up on vsock 5252. Round-trip results:
  - `checkpoint create --class vm-full` on the RUNNING VM: **works** (live
    pause→save→clone→resume window).
  - `pause` / `resume` (native vCPU quiesce): **works**.
  - `checkpoint create --class fs-quick`: **unreachable on Vz today** — the
    quiesce gate does not recognize the Vz paused state (supervisor pid stays
    alive), and `down` removes the per-instance CoW rootfs so there is nothing
    to clone after a stop. Follow-up below.
  - `checkpoint restore` (vm_full, same identity): **fails** — the restore arm
    does not re-spawn the per-VM gvproxy sidecar, so the supervisor dies on
    `connect() gvproxy.sock: No such file or directory`; a failed restore also
    leaves its materialized rootfs behind (non-idempotent retry). Follow-ups
    below.
  - `checkpoint fork` (vm_full): child materialization + child gvproxy spawn
    **work**; the boot-into-child fails with `VZErrorDomain:12` — VZ refuses
    to restore saved machine state into a changed device config (new MAC).
    **This answers the fork semantic-A spike**: cross-identity vm_full fork
    via VZ machine-state restore is not viable; semantic B (the shipped
    `FORK_FRESH_MACHINE_ID=false` / `FORK_ALLOW_PARENT_RUNNING=false`) stands.
    A live two-copy fork on Vz needs the fs_quick (cold-boot) class instead.
- [x] **D4: rollups.** Tick this plan's boxes + update `specs/REFACTOR-STATUS.md`
  (PLAN 183 section) + `specs/SPRINT.md` (Sprint 55 live-Vz-validation note) in the
  same change as each workstream lands.

## WS-E — Vz workload boot (added 2026-06-12)

Two independent defects blocked `mvmctl up --flake <workload> --hypervisor vz`:

- [x] **E1: kernel fallback for kernel-less workload images.**
  `dev_build` unconditionally reports `vmlinux_path = <build_dir>/vmlinux`, but mkGuest
  workload images ship no kernel (libkrun self-materializes its bundled libkrunfw kernel
  and ignores the path). The Vz backend hands the nonexistent path to `VZLinuxBootLoader`
  and gets `VZErrorDomain:2` ("boot loader invalid"). Fix: `resolve_vz_workload_kernel()`
  helper in `crates/mvm-cli/src/commands/vm/up.rs` — called after `effective_hypervisor`
  is resolved and before both the snapshot-restore and cold-boot arms consume
  `vmlinux_path`. When the path is missing and the hypervisor is `vz` or
  `apple-container`, it falls back to `<mvm_cache_dir>/builder-vm/<arch>/vmlinux` (the
  cached builder-VM kernel that boots the same supervisor), or returns an actionable
  error pointing to `mvmctl dev up`. Non-VZ hypervisors pass through unchanged
  (libkrun's boot path is unaffected). Four unit tests cover all branches.

- [x] **E2: bind the guest-side gvproxy datagram socket so replies route back.**
  `connect_gvproxy_dgram` in `crates/mvm-vm-host/src/vz_objc.rs` (the Vz workload
  supervisor's direct NIC path) opened an AF_UNIX SOCK_DGRAM socket and `connect()`ed
  to gvproxy's vfkit listener without first `bind()`ing a local address. An unbound
  unix-datagram socket has no return address, so every `sendto()` reply from gvproxy
  (DHCP offer, DNS response, any guest-to-host packet reply) was silently dropped by
  the kernel — matching the observed `udhcpc no lease` + DNS-to-192.168.127.1
  no-reply symptoms. Fix: before `connect()`, derive a sibling reply-socket path
  (`<dir>/vz-net-reply.sock`), unlink any stale file, and `bind()` the socket to it.
  `sockaddr_un_from_path()` is extracted as a small shared helper to avoid duplicating
  the `sun_path` length guard. The bind file is cleaned up by the existing VM state-dir
  removal on teardown. One unit test (`bound_dgram_socket_receives_reply`) wires up a
  simulated gvproxy listener, sends a datagram from the fixed client fd, and asserts
  that a `sendto()` reply from the listener is received on the client — the exact
  defect path.

### deferred follow-ups

- [ ] Vz DHCP datagram-path root cause was resolved by WS-E2 (unbound dgram socket);
  the static-IP fallback from WS-B2 remains as belt-and-suspenders for any residual
  race during udhcpc startup.
- [ ] Persistent Vz builder (`VzPersistentBuilderVm`) still runs `network: None`;
  wire gvproxy when that path leaves scaffold status.
- [ ] `mvmctl doctor` line surfacing the in-builder egress posture + last builder
  network bootstrap outcome (lease vs static vs none), so this class of failure is
  diagnosable without console archaeology.
- [x] fs_quick on Vz: teach the quiesce gate to recognize the Vz paused state
  (pid stays alive under pause), and/or stop deleting the per-instance CoW
  rootfs on `down` so a stopped VM remains checkpointable.
  fixed: `pause` stamps the live supervisor pid into a `vz.paused` marker in
  the VM state dir (`resume` removes it; a stale marker self-invalidates by
  pid mismatch — the name registry was the wrong substrate, `up`-created VMs
  are never in it); `vm_is_quiesced` accepts running+matching-marker.
  Missing-rootfs arm returns an actionable error naming the pause workflow.
  Live-validated 2026-06-12: pause → fs_quick create → resume green; vm_full
  restore green incl. responsive control plane (pause/resume on the restored
  VM) and restore-while-running refusal.
- [x] vm_full restore: re-provision the per-VM gvproxy sidecar before spawning
  the restore supervisor, and make a failed restore clean up its materialized
  rootfs so the retry isn't blocked by `File exists`.
  fixed: `snapshot_restore` spawns gvproxy via `host_gvproxy::spawn_detached`
  when config has Gvproxy network; `restore_with_spawn` removes the cloned
  rootfs on any post-clone failure and errors actionably on pre-existing target.
- [ ] restore-failure leaks the freshly-spawned gvproxy (supervisor never
  wrote its PID, the sidecar lingers; the retry orphans it) — reap the
  sidecar on the restore error path, consistent with `start()`'s behavior.
- [ ] Vz two-copy fork: route live forks through the fs_quick (cold-boot)
  class on Vz — VZ machine-state restore pins the saved device config
  (`VZErrorDomain:12` on a changed MAC), so memory-state forks can't change
  identity.
