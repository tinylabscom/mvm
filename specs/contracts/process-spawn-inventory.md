# Production process-spawn inventory

Backing: preview
Validation: none — a generated inventory with a drift check (`--check`); no xtask gate enforces it yet. The raw-constructor half of the picture is enforced separately by `xtask check-helper-env-hygiene`, and the SDK/client/hostlib CLI-shellout rule by `xtask check-no-cli-shellout`.

Scope: the umbrella audit box "audit the full reachable production call graph, not just literal `Command::new` sites". This records every production place `mvm` creates an OS process, why, who can reach it, and what guards it. Test-only processes are excluded and counted, not listed.

Snapshot: tree at `origin/main` `152ed1cebf` (2026-10-31). Regenerate with `python3 scripts/gen-process-spawn-inventory.py`; `--check` fails when this table is stale or a spawn file has no annotation.

## Spawn API set

A site is one of:

- `Command::new(..)` from `std::process` or `tokio::process` (no aliases or `type` re-exports of `Command` exist; searched for `use .. Command as`, `type .. = Command`).
- A factory that returns a ready `Command`: `mvm_core::env_hygiene::helper_command`, `helper_command_with` (the sanctioned constructors — they call `Command::new` once, in `env_hygiene.rs`), `scrub_command`, and `spawn_scope`'s `wrap_checked` (rewrites a command into a `systemd-run` scope). Other `-> Command` functions (`build_trace_command`, `egress_client_command`, `user_script_command`, `agent_spawn_command`, `ext4_format_command`, `child_command`, `contract_probe_command`) are wrappers over those sites and are not counted twice.
- Direct process calls: `libc::fork`/`vfork`/`exec*`/`posix_spawn*`/`system`/`popen`, bare or `nix::unistd::` `fork`/`execve`/`execvp`/`execvpe`, a raw `execveat`/`clone` `libc::syscall`, and PTY creation (`openpty`, `forkpty`, `posix_openpt`).
- Not present: `portable-pty`, `nix` process APIs outside `seccomp_audit`, `duct`, `subprocess`-style crates (checked in every `Cargo.toml`), and no `CommandExt::exec` beyond the sites counted.

`.spawn()`/`.output()`/`.status()` on a command built elsewhere add no row of their own; the constructor is the row. Four terminals take a command from a caller and are listed under "Spawn terminals" below so none is missed.

Excluded: `#[cfg(test)]` items and files (including `#[cfg(test)] mod x;` targets and `*_tests.rs`), `tests/`, `examples/`, `benches/`, `build.rs`, `xtask`, `fuzz/`, `crates/mvm-sdk/sdks/` (non-Rust SDK trees, covered by `check-no-cli-shellout`), and `third_party/`.

## Rerun

```sh
git rev-parse HEAD                                   # record the SHA
python3 scripts/gen-process-spawn-inventory.py       # rewrites the table below
python3 scripts/gen-process-spawn-inventory.py --check
# independent cross-checks
rg -n 'Command::new|helper_command|scrub_command|wrap_checked' -g '*.rs' -g '!**/tests/**' -g '!xtask/**' -g '!**/examples/**' -g '!**/benches/**' -g '!build.rs' crates src
rg -n 'nix::unistd::(fork|exec)|libc::(fork|exec|posix_spawn|system|popen)|openpty|forkpty' -g '*.rs' crates src
ast-grep run -l rust -p 'Command::new($A)' crates src          # constructor sites, AST-level
cargo run -p xtask -- check-helper-env-hygiene                 # every raw constructor must be in RAW_SITES
cargo run -p xtask -- check-no-cli-shellout
cargo tree --offline -p mvm-client -e normal --prefix none | sort -u   # closure behind "Linked"
```

The scanner is independent of `check-helper-env-hygiene`, and the two agree: every raw `Command::new`/fork/exec site the scanner finds in `crates/` is a `RAW_SITES` entry, except the `fork(` of a VM checkpoint (`checkpoint::fork`, not a process), which the scanner's argument filter drops.

## How to read the columns

- **Class**: what is spawned (hypervisor/VMM or its supervisor, `systemd-run`, nft, storage tools, toolchain, shell script, `mvmctl` self re-exec, helper bin, guest workload, host probe).
- **Authority**: who can make the process start. `guest` and `builder VM` run inside a microVM, not on the host. `CLI` is the `mvmctl` process only. `host daemon role` / `per-VM ... bin` are separate `mvm-hostd` processes. `library code in the calling process` means the caller decides: the CLI, a daemon, or an embedder through `mvm-client`.
- **Linked**: the row's crate is in the normal-dependency closure of `C` mvm-client, `H` mvm-hostlib, `S` mvm-sdk (`cargo tree`). Upper bound: it proves the code is linked in, not that it is called.
- **Traced**: a name-based static call graph from every function in those three crates reaches an enclosing function of the row. Lower bound: names defined in more than two files are not followed and dynamic dispatch (`AnyBackend`, `VmBackend`, trait objects) is invisible, so the VMM launch chain under `LocalBackend` does not show here even though it runs.
- **Guard**: `helper_command` env scrub (loader, shell, interpreter and password-manager-session variables removed); `RAW_SITES (place)` the raw constructor is classified in `check-helper-env-hygiene` as guest, builder or on-host; `embedder refusal` the site goes through `refuse_cli_spawn`, so a process that declared itself a library embedder refuses to run `mvmctl`; `check-single-network-path`, `check-no-cli-shellout` as named.

## Inventory

<!-- inventory:begin -->
| Crate | Module (under `src/` unless a crate root file) | Sites | Class | Purpose | Authority | Linked | Traced | Guard |
|---|---|--:|---|---|---|:-:|:-:|---|
| mvm-agentd | `src/bin/mvm-builder-agent.rs` | 1 | builder job | run a builder job's command | builder VM | CHS | - | RAW_SITES (builder) |
| mvm-agentd | `src/bin/mvm-guest-agent/health.rs` | 1 | guest workload | workload health check via /bin/sh | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/bin/mvm-guest-agent/interactive.rs` | 2 | guest workload | detached workload process and its exit reporter | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/bin/mvm-oci-entrypoint.rs` | 1 | guest workload | exec the OCI image entrypoint | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/bin/mvm-runner.rs` | 1 | guest workload | start the language runtime for a workload | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/bin/mvm-seccomp-apply.rs` | 1 | guest workload | exec the workload under its seccomp filter | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/builder_agent.rs` | 1 | builder job | run a builder job's command | builder VM | CHS | - | RAW_SITES (builder) |
| mvm-agentd | `src/builder_build.rs` | 2 | builder job | nix build and artifact staging via sh | builder VM | CHS | - | RAW_SITES (builder) |
| mvm-agentd | `src/console.rs` | 3 | guest workload | dev-image PTY console: openpty, fork, execve of the shell | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/crng_reseed/helper.rs` | 1 | guest helper | re-exec self as the entropy-reseed helper | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/entrypoint.rs` | 1 | guest workload | run the declared entrypoint | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/exec_stream.rs` | 2 | guest workload | exec / streamed exec of a requested command (dev verbs) | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/guest_bootstrap.rs` | 5 | guest init | busybox setup at boot, egress client, PTY device provisioning | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/guest_net.rs` | 2 | guest init | loopback/DHCP bring-up through busybox and udhcpc | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/late_volumes.rs` | 1 | guest helper | re-exec self as the late-volume mount helper | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/lifecycle_hooks.rs` | 2 | guest workload | before_/after_ lifecycle hook scripts | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/process_rpc.rs` | 1 | guest workload | process-control RPC start of a requested program | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/tool_helper.rs` | 3 | guest helper | fork and execveat of a mediated tool invocation | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/tool_install.rs` | 1 | guest helper | start the declared-command tool helper before privilege drop | guest | CHS | - | RAW_SITES (guest) |
| mvm-agentd | `src/worker_pool.rs` | 1 | guest workload | warm worker-pool process | guest | CHS | - | RAW_SITES (guest) |
| mvm-backends | `src/driver/fc.rs` | 1 | systemd-run / sudo | signal a Firecracker process through sudo kill on Linux | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-backends | `src/driver/hvf.rs` | 2 | hypervisor supervisor | spawn mvm-hvf-supervisor for an HVF VM (cold and restore) | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-backends | `src/driver/hvf_restore.rs` | 1 | hypervisor supervisor | spawn mvm-hvf-supervisor for a snapshot restore | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-backends | `src/driver/libkrun.rs` | 1 | hypervisor supervisor | spawn mvm-libkrun-supervisor | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-backends | `src/driver/qemu.rs` | 1 | hypervisor | launch QEMU | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-backends | `src/driver/qemu_process.rs` | 1 | mvmctl self re-exec | start `mvmctl __qemu-vsock-bridge` | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub; embedder refusal |
| mvm-backends | `src/fc/idle_pool.rs` | 1 | process control | setsid-detached idle standby holder | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-build | `src/builder_egress_process.rs` | 1 | mvmctl self re-exec | start `mvmctl __builder-egress-supervisor` | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub; embedder refusal |
| mvm-build | `src/builder_vm_bootstrap.rs` | 1 | mvmctl self re-exec | run the bootstrap helper to prepare the builder image | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub; embedder refusal |
| mvm-build | `src/builder_vm_image.rs` | 1 | storage tool | host mkfs of the builder store image | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-build | `src/builder_vm_runtime.rs` | 1 | storage tool | debugfs read of a builder image | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-build | `src/builder_vm_transport.rs` | 1 | toolchain | cargo build of the network endpoint binary | library: caller's process (CLI, daemon, embedder) | CH | C | `helper_command` env scrub; embedder refusal |
| mvm-build | `src/embed_toolchain.rs` | 8 | toolchain | probe rustup/cargo/rustc/zig/python3 for the pinned embed toolchain | library: caller's process (CLI, daemon, embedder) | CH | CH | `helper_command` env scrub |
| mvm-build | `src/guest_agent_build.rs` | 3 | toolchain | cargo / rustup build of guest binaries from this tree | library: caller's process (CLI, daemon, embedder) | CH | CH | `helper_command` env scrub |
| mvm-build | `src/libkrun_builder.rs` | 3 | hypervisor supervisor | cargo build of helpers, libkrun builder supervisor (explicit libkrun only) | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-build | `src/provenance_mark.rs` | 1 | storage tool | debugfs read of image provenance mark | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-build | `src/qemu_builder.rs` | 6 | hypervisor | QEMU builder: timeout-wrapped boot, zstd, mkfs.ext4, debugfs | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-build | `src/runtime_overlay.rs` | 1 | network fetch | curl download of a release artifact | library: caller's process (CLI, daemon, embedder) | CH | C | `helper_command` env scrub |
| mvm-build | `src/stage0.rs` | 1 | archive tool | native tar -xJf of the Stage 0 root tarball (pure-Rust path is the alternative) | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-builder-guest | `src/bin/mvm-host-vm-init.rs` | 15 | builder init | builder VM PID 1: busybox/mount/network setup, nix-store, mkfs, workload netns, agent fork | builder VM | CH | - | RAW_SITES (builder) |
| mvm-builder-guest | `src/bin/mvm-host-vm-init/boot_stage.rs` | 1 | builder init | exec the next boot stage | builder VM | CH | - | RAW_SITES (builder) |
| mvm-builder-guest | `src/bin/mvm-host-vm-init/builder_hooks.rs` | 4 | builder init | fsck and loop-device hooks | builder VM | CH | - | RAW_SITES (builder) |
| mvm-builder-guest | `src/bin/mvm-host-vm-init/install.rs` | 1 | builder job | dependency install job (uv/pnpm) | builder VM | CH | - | RAW_SITES (builder) |
| mvm-builder-guest | `src/bin/mvm-host-vm-init/workload.rs` | 1 | builder init | start Firecracker for a nested workload | builder VM | CH | CH | RAW_SITES (builder) |
| mvm-builder-guest | `src/bin/stage0-init.rs` | 5 | builder init | Stage 0 bootstrap: network, mkfs, nix | builder VM | CH | - | RAW_SITES (builder) |
| mvm-builder-guest | `src/bin/stage0-init/kernel_emit.rs` | 1 | builder job | nix build of the emitted kernel | builder VM | CH | - | RAW_SITES (builder) |
| mvm-builder-guest | `src/bin/stage0-init/store_gc.rs` | 2 | builder job | nix store garbage collection | builder VM | CH | - | RAW_SITES (builder) |
| mvm-builder-guest | `src/builderd.rs` | 2 | builder job | builderd runs job argv and the rootfs runner | builder VM | CH | - | RAW_SITES (builder) |
| mvm-capture | `src/collect/package.rs` | 3 | capture probe | dpkg / dpkg-query / nix-locate package ownership | library: caller's process (CLI, daemon, embedder) | - | - | `helper_command` env scrub |
| mvm-capture | `src/collect/trace.rs` | 2 | capture probe | strace under timeout to trace a project command | library: caller's process (CLI, daemon, embedder) | - | - | `helper_command` env scrub |
| mvm-capture | `src/verify.rs` | 1 | mvmctl self re-exec | run `mvmctl __builder-shell-job` to verify a capture | library: caller's process (CLI, daemon, embedder) | - | - | `helper_command` env scrub |
| mvm-cli | `src/bench/cold_launch_runner.rs` | 2 | mvmctl self re-exec | `mvmctl pool status` / launch for the bench harness | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/bootstrap.rs` | 1 | host probe | wsl.exe on Windows hosts | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/bootstrap.rs` | 1 | helper bin | builder egress supervisor runs the endpoint binary | CLI hidden verb | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/build/kernel.rs` | 1 | mvmctl self re-exec | `mvmctl` subcommands for kernel build steps (run_self) | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/build/sandbox_record.rs` | 1 | user script | interpreter for user workload record mode (user_script_command) | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/deps/audit.rs` | 2 | toolchain | pip-audit / pnpm audit of app deps | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/env/artifact_verify.rs` | 1 | network fetch | curl of the pinned image-set manifest | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/env/builder_vm/vm_helpers.rs` | 1 | host probe | ps to find builder processes | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/env/uninstall.rs` | 1 | shell script | sh -c uninstall step | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/image/trust.rs` | 1 | toolchain | cosign verify | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/ops/config.rs` | 1 | user editor | $EDITOR for `mvmctl config edit` | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/ops/secret.rs` | 1 | user opener | xdg-open / open of an OAuth URL | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/pool/refill.rs` | 1 | mvmctl self re-exec | detached `mvmctl` pool refill helper | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/commands/seccomp_audit.rs` | 2 | fork + execvpe | audit a program under a seccomp filter (filtered env) | CLI (`mvmctl`) | - | - | RAW_SITES (on_host) |
| mvm-cli | `src/commands/vm/sdk_no_vm.rs` | 1 | user script | run an SDK wrapper script without a VM | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/doctor/security_checks.rs` | 3 | host probe | fdesetup / findmnt / lsblk posture checks | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/doctor/toolchain.rs` | 1 | host probe | `<tool> --version` probes in doctor | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/host_binaries/payload_build.rs` | 2 | toolchain | cargo zigbuild of the embedded host binaries (refusal is in host_binaries/source.rs) | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-cli | `src/update.rs` | 2 | mvmctl self re-exec | `--version` smoke test and `bootstrap` of the freshly installed mvmctl | CLI (`mvmctl`) | - | - | `helper_command` env scrub |
| mvm-client | `src/secret/source.rs` | 1 | password manager | run the user's configured secret-source CLI (op, etc.) to read a credential | library: caller's process (CLI, daemon, embedder) | CH | C | `helper_command` env scrub; check-no-cli-shellout |
| mvm-conformance | `src/vmm_reaper.rs` | 3 | test harness | ps / kill / sudo to reap leaked VMMs in conformance runs | dev harness, not shipped | - | - | `helper_command` env scrub |
| mvm-core | `src/crypto/key_rotation.rs` | 1 | storage tool | cryptsetup luksChangeKey | library: caller's process (CLI, daemon, embedder) | CHS | - | `helper_command` env scrub |
| mvm-core | `src/env_hygiene.rs` | 3 | factory | the sanctioned Command constructor: scrubs denied env, then everything above calls it | library: caller's process (CLI, daemon, embedder) | CHS | CH | `helper_command` env scrub; RAW_SITES (on_host) |
| mvm-core | `src/host_storage_encryption.rs` | 4 | host probe | diskutil / findmnt / tune2fs / lsblk encryption-at-rest probes | library: caller's process (CLI, daemon, embedder) | CHS | - | `helper_command` env scrub |
| mvm-core | `src/platform/platform.rs` | 2 | host probe | sw_vers and nix presence probe | library: caller's process (CLI, daemon, embedder) | CHS | CH | `helper_command` env scrub |
| mvm-core | `src/spawn_scope.rs` | 4 | systemd-run | wrap a VMM spawn in a systemd transient scope; kill and systemctl show | library: caller's process (CLI, daemon, embedder) | CHS | C | `helper_command` env scrub |
| mvm-fs | `src/oci_to_rootfs/ext4.rs` | 1 | storage tool | mke2fs to materialize an OCI rootfs (Linux) | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-fs | `src/oci_to_rootfs/verity.rs` | 1 | storage tool | veritysetup format of a rootfs (Linux) | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-hostd | `src/bin/mvm-host-agent.rs` | 2 | helper bin | re-exec self as a worker process | host daemon bin | CH | - | `helper_command` env scrub |
| mvm-hostd | `src/bin/mvm-hvf-supervisor.rs` | 3 | codesign / self re-exec | ad-hoc codesign of the binary, then re-exec self signed | per-VM supervisor bin | CH | - | `helper_command` env scrub |
| mvm-hostd | `src/bin/mvm-network-endpoint.rs` | 1 | helper bin | keeper re-execs the endpoint binary for a long-lived VM | per-VM endpoint bin | CH | - | `helper_command` env scrub |
| mvm-hostd | `src/health_probe.rs` | 1 | mvmctl self re-exec | `mvmctl machine restart` after a failed healthcheck (embedder-refused) | host daemon role | CH | - | `helper_command` env scrub; embedder refusal |
| mvm-hostd | `src/supervisor/firewall/linux_nft.rs` | 1 | net (nft) | install host nftables rules | host daemon role | CH | - | `helper_command` env scrub |
| mvm-hostd | `src/supervisor/services/spawn.rs` | 1 | helper bin | ProcessSpawner: start a signed, integrity-checked host service binary | host daemon role | CH | - | `helper_command` env scrub |
| mvm-runtime | `src/host_shell.rs` | 3 | shell script | bash -c for ShellEnvironment host commands | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-runtime | `src/microvm/run_info.rs` | 1 | process control | kill of a recorded VM pid | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-runtime | `src/storage/backend.rs` | 1 | storage tool | dmsetup thin-pool operations | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-runtime | `src/storage/volume/encrypted_linux.rs` | 7 | storage tool | cryptsetup, mount, umount, mkfs.ext4 for an encrypted volume | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |
| mvm-setpriv | `src/lib.rs` | 1 | guest helper | privilege-drop-and-exec of the target command | guest | CHS | - | RAW_SITES (guest) |
| mvm-vmm | `src/host/aux_bin.rs` | 2 | helper bin | `--contract-version` probe of a helper; cargo build of helpers from source | library: caller's process (CLI, daemon, embedder) | CH | C | `helper_command` env scrub; embedder refusal |
| mvm-vmm | `src/host/broker_services_spawn.rs` | 1 | helper bin | spawn the per-VM host-services broker | library: caller's process (CLI, daemon, embedder) | CH | CH | `helper_command` env scrub |
| mvm-vmm | `src/host/gpu_endpoint_spawn.rs` | 1 | helper bin | spawn the per-VM GPU endpoint | library: caller's process (CLI, daemon, embedder) | CH | C | `helper_command` env scrub; check-single-network-path |
| mvm-vmm | `src/host/linux_env.rs` | 3 | shell script | bash -c in the Linux environment (run / run_visible) | library: caller's process (CLI, daemon, embedder) | CH | C | `helper_command` env scrub |
| mvm-vmm | `src/host/network_endpoint_spawn.rs` | 1 | helper bin | spawn the per-VM network endpoint (the egress gate) | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub; check-single-network-path |
| mvm-vmm | `src/host/network_endpoint_spawn/collector.rs` | 1 | helper bin | spawn the egress telemetry collector | library: caller's process (CLI, daemon, embedder) | CH | C | `helper_command` env scrub; check-single-network-path |
| mvm-vmm | `src/host/network_endpoint_spawn/owned.rs` | 1 | helper bin | spawn an owned network endpoint | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub; check-single-network-path |
| mvm-vmm | `src/host/shell/exec.rs` | 6 | shell script | run_in_vm / run_host: bash -c and direct program exec for every ShellEnvironment caller | library: caller's process (CLI, daemon, embedder) | CH | - | `helper_command` env scrub |

Totals: 191 production sites in 98 files.

| Crate | Sites |
|---|--:|
| mvm-agentd | 33 |
| mvm-backends | 8 |
| mvm-build | 28 |
| mvm-builder-guest | 32 |
| mvm-capture | 6 |
| mvm-cli | 26 |
| mvm-client | 1 |
| mvm-conformance | 3 |
| mvm-core | 14 |
| mvm-fs | 2 |
| mvm-hostd | 9 |
| mvm-runtime | 12 |
| mvm-setpriv | 1 |
| mvm-vmm | 16 |

By construct: `Command::new` 60, `SYS_execve` 1, `helper_command` 117, `helper_command_with` 3, `libc::fork` 1, `openpty` 2, `raw:execve` 1, `raw:execveat_raw` 1, `raw:execvpe` 1, `raw:fork` 2, `scrub_command` 1, `wrap_checked` 1.
<!-- inventory:end -->

Linked and Traced are host-side facts about the crate and the call graph. A `guest` or `builder VM` row is crate-linked into the host closure (so `CHS`), but its binary only ever runs inside the microVM; the host never calls it. Read those rows by Authority.

## Spawn terminals

These call `.spawn()`/`.status()` on a `Command` a caller built, so the constructor row is elsewhere:

| Where | Terminal | Command comes from | Authority |
|---|---|---|---|
| `mvm-agentd/src/tool_attribution.rs` | `spawn_attributed`, `spawn_decided_relay` | guest tool-mediation callers | guest |
| `mvm-hostd/src/vm_lifetime.rs` | `keep_endpoint_for_vm` | `mvm-network-endpoint` keeper (`helper_command` on its own exe) | per-VM endpoint bin |
| `mvm-hostd/src/host_agent_sessions.rs` | `CliSessionReaper::reap` | `mvmctl_command_for(.., CliSpawn::SessionReap)`: `mvmctl machine session reap`, embedder-refused | host daemon role |
| `mvm-cli/src/commands/vm/run_plan.rs` | live-mode script run | `user_script_command` (the user's interpreter) | CLI |

## Test-only processes

About 220 constructor matches sit in `#[cfg(test)]` code, `*_tests.rs`/`tests.rs` files and `#[cfg(test)] mod x;` targets (`sleep`, `true`, `sh`, `mkfifo`, the test binary itself). They are excluded by construction, not listed.

## Findings: production spawns reachable from mvm-client, mvm-hostlib and mvm-sdk

1. **`mvm-sdk`: no spawn, no traced path.** Zero direct sites; no spawning function is reachable by name from any `mvm-sdk` function. The crate links `mvm-core` (`helper_command`, `key_rotation`, `host_storage_encryption`, `spawn_scope`, `platform`) and `mvm-agentd`/`mvm-setpriv` (guest-only binaries), none of which SDK source calls. `check-no-cli-shellout` holds the source line.
2. **`mvm-hostlib`: no direct site.** Everything it can start goes through `mvm-client`.
3. **`mvm-client` has one direct production spawn**: `secret/source.rs`, the user's configured secret-source CLI (a password manager), env-readmit through `helper_command_with`. The gate allows it deliberately (`cli_only` forbids only `mvmctl`).
4. **By design, `mvm-client`'s launch surface starts host helpers**: hypervisor supervisors (`mvm-libkrun-supervisor`, `mvm-hvf-supervisor`), QEMU, the per-VM network endpoint, GPU endpoint and broker helpers, a systemd transient scope (`spawn_scope`), and encrypted-volume tools. The static trace cannot show this chain (dynamic dispatch through `AnyBackend`/`VmBackend`), so the Traced column under-reports it. This is the intended embedder authority, not a gap.
5. **`mvmctl` self re-exec is refused for an embedder at every site that reaches it from the library crates**: the `CliSpawn` variants cover `qemu_process`, `builder_egress_process`, `builder_vm_bootstrap`, `builder_vm_transport`, `health_probe`, `host_agent_sessions`, `host_binaries::source` (which gates `payload_build`) and the aux-binary resolver (Guard column).
6. **Not guarded, and reachable by a public `mvm-client` API: guest-runtime acquisition.** `mvm_client::launch::runtime_overlay::{prepare_oci_guest_runtime, acquire_runtime_overlay}` reach `mvm_build::guest_runtime`/`guest_bins`/`guest_agent_build`/`embed_toolchain` and `runtime_overlay::curl_download`, which spawn `cargo`, `rustup`, `rustc`, `zig` and `curl` through `helper_command`. None of those files consults `refuse_cli_spawn`, and no xtask gate pins them. Only `mvm-cli` (`bootstrap`, `image pull`, `build runtime-overlay`) calls them today; `mvm-hostlib` does not, and the launch path (`acquire_runtime_overlay_for_launch`, `require_prepared_oci_guest_runtime`) reads prepared artifacts only. Follow-up: give this chain a refusal for a library embedder, or move the acquisition entry points out of `mvm-client`. Not changed here.
7. **`helper_command` pins the environment, not the program.** `check-helper-env-hygiene` guarantees a scrubbed environment and that no raw constructor appears outside `RAW_SITES`; it does not constrain which program a `helper_command(<variable>)` runs. The variable-program sites are the supervisor/QEMU/endpoint/broker binaries, `interpreter`, `editor`, `opener`, `cosign`, `pip_audit`/`pnpm` and the secret-source binary; each takes a resolved path, but the choice is a code-review fact, not a gate.
8. **`check-no-cli-shellout` is name-based for the client.** It rejects `Command::new`/`helper_command*` naming `mvmctl` and the `MVM_CLI_BIN` overrides. A `helper_command(path_variable)` that resolves to `mvmctl` (as `builder_egress_process` does) passes it and relies on the `CliSpawn` refusal instead.

## Coverage and limits

- Method: comment-stripped text scan of every `.rs` file under `crates/` and `src/` for the spawn API set, `#[cfg(test)]` ranges and test-only files removed; cross-checked against `check-helper-env-hygiene`'s independent `RAW_SITES` list (agreement noted above) and against a sweep of `.spawn()`/`.output()`/`.status()` on commands built elsewhere (the terminals above, plus thread and HTTP `.status()` false positives).
- Checked: aliases of `Command` (none), factories returning `Command` (all end in the counted constructors), native calls (`fork`, `exec*`, `execveat`, PTY), `pre_exec`/`CommandExt` use (attached to counted sites), crate closures by `cargo tree`.
- Graph tools: the codebase-memory/trail graph was not used for the numbers; the call graph above is the script's own name-based one. It is a lower bound and does not follow trait objects, closures stored for later, or names defined in more than two files.
- Not audited: processes started by third-party crates (the vendored `third_party/gix-object` `signature-basic` feature runs the configured `gpg`/`ssh-keygen` for commit signing and verification; whether any `mvm` path calls it is not traced here), install and release shell scripts (`install.sh`, `scripts/`), shell run inside guests by Nix `mkGuest` init scripts, and the non-Rust SDK sources beyond the existing gate.

