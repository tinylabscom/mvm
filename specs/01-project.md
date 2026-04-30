# mvm — Firecracker MicroVM CLI

## Project Overview

Rust CLI tool that manages Firecracker microVMs on Apple Silicon (M3+) via Lima virtualization. It orchestrates a three-layer stack:

```
macOS Host (this CLI) → Lima VM ("mvm", Ubuntu) → Firecracker microVM (172.16.0.2)
```

## Architecture

The CLI runs on the macOS host. All Linux operations happen inside the Lima VM via `limactl shell mvm-builder bash -c "..."`. The Firecracker microVM runs inside the Lima VM using nested virtualization (/dev/kvm).

### Module Map

- `main.rs` — clap CLI dispatch with subcommands: setup, start, stop, ssh, status, destroy
- `config.rs` — constants (VM_NAME, FC_VERSION, ARCH, network config), MvmState struct, lima.yaml locator
- `shell.rs` — command helpers: `run_host`, `run_in_vm`, `run_in_vm_visible`, `run_in_vm_stdout`, `replace_process`
- `lima.rs` — Lima VM lifecycle: get_status, create, start, ensure_running, require_running, destroy
- `firecracker.rs` — Firecracker installation, asset download (kernel/rootfs from S3), rootfs preparation, state file management
- `network.rs` — TAP device setup/teardown, IP forwarding, iptables NAT
- `microvm.rs` — MicroVM lifecycle: start (full sequence), stop, ssh, is_ssh_reachable

### Key Design Decisions

- **Persistent microVM**: `mvm start` launches Firecracker as a daemon (nohup setsid). Exiting SSH does NOT kill the VM. Use `mvm stop` to shut down, `mvm ssh` to reconnect.
- **Shell scripts inside run_in_vm**: Complex operations (API calls, asset discovery) are bash scripts passed to `limactl shell`. This is deliberate — the operations need to run inside the Linux VM.
- **replace_process for SSH**: Uses Unix process replacement for clean TTY pass-through.
- **Idempotent setup**: Every step checks if already done before acting.

### Dependencies on Sibling Project

`resources/lima.yaml` is copied from `../firecracker-lima-vm/lima.yaml`. It configures:
- Ubuntu base image
- Writable home directory mount
- Nested virtualization enabled
- Provisioning script for /dev/kvm permissions (kvm group + udev rules)

## Current State

All subcommands are implemented and the project compiles cleanly. The CLI has been tested with `mvm status` against a running VM+microVM stack.

## What Needs Work

### Testing and Hardening
- Test full `mvm setup` flow from scratch (no existing VM)
- Test `mvm start` then interactive SSH then exit then `mvm ssh` reconnect then `mvm stop`
- Test `mvm destroy` and re-setup
- The `api_put` helper in microvm.rs uses single quotes around data which may not work if the JSON contains single quotes — consider escaping
- The logfile path in `configure_microvm` uses `$HOME/microvm` which needs to expand inside the VM shell, verify this works

### Features to Add
- `mvm shell` — open a Lima VM shell (not microVM), useful for accessing host-mounted files in Linux
- Better error messages when Firecracker fails to start (parse firecracker.log)
- `--verbose` flag for debug output
- Consider making FC_VERSION, ARCH configurable via CLI args or config file
- Multiple microVM support (currently hardcoded to single instance)

### Code Quality
- Add `#[cfg(test)]` unit tests for config.rs (lima.yaml finding logic)
- The shell scripts embedded in Rust strings are hard to maintain — consider extracting to .sh files in resources/
- Consistent error prefix ([mvm] vs no prefix)

## Build and Run

```bash
cargo build
cargo run -- --help
cargo run -- status
cargo run -- setup    # creates Lima VM + installs everything
cargo run -- start    # starts microVM, drops into SSH
cargo run -- ssh      # reconnects to running microVM
cargo run -- stop     # stops microVM
cargo run -- destroy  # tears down Lima VM entirely
```

## Network Layout

```
MicroVM (172.16.0.2, eth0)
    | TAP interface
Lima VM (172.16.0.1, tap0) — iptables NAT — internet
    | Lima virtualization
macOS Host
```
