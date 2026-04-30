# mvm-runtime

Shell execution, VM lifecycle management, and platform-aware operations. Implements the `ShellEnvironment` trait for dev builds and manages the full Lima + Firecracker stack.

## Modules

| Module | Purpose |
|--------|---------|
| `shell` | `run_in_vm()`, `run_in_vm_visible()`, `run_in_vm_stdout()` — platform-aware shell execution |
| `build_env` | `RuntimeBuildEnv` implementing `ShellEnvironment` (delegates to `shell`) |
| `config` | VM constants, `VmSlot`, `MvmState`, `RunInfo`, Lima template discovery |
| `ui` | CLI UI helpers (colored output, spinners, prompts) |
| `shell_mock` | Test mocking for shell commands |

### VM Subsystem (`vm/`)

| Module | Purpose |
|--------|---------|
| `lima` | Lima VM lifecycle (create, start, stop, destroy, status) |
| `lima_state` | Lima state queries |
| `firecracker` | Firecracker process lifecycle |
| `microvm` | MicroVM orchestration (dev-mode start/stop/run) |
| `bridge` | Bridge network setup (`br-mvm`) |
| `network` | TAP device and network configuration |
| `disk_manager` | Disk/volume management |
| `image` | Image download and caching |
| `template/` | Template CRUD and lifecycle (`template_create`, `template_build`) |
| `pool/` | Pool-level operations |
| `tenant/` | Tenant-level operations |
| `instance/` | Instance-level operations |

## Platform Behavior

- **macOS**: Routes all Linux operations through `limactl shell mvm-builder bash -c <script>`
- **Native Linux with KVM**: Runs `bash -c <script>` directly
- **Linux without KVM**: Falls back to Lima (same as macOS)

Detection happens automatically via `platform::current().needs_lima()`.

## Dev Network Layout

```
MicroVM (172.16.0.2, eth0)
    | TAP interface
Lima VM (172.16.0.1, tap0) -- iptables NAT -- internet
    | Lima virtualization
macOS / Linux Host
```

Multi-VM mode uses bridge `br-mvm` at `172.16.0.1/24` with per-VM TAP devices.

## Dependencies

- `mvm-core` (types, traits, config)
- `mvm-guest` (vsock protocol for VM communication)
- `mvm-build` (build pipeline)
