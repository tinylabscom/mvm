# mvm

Shell execution, VM lifecycle management, and platform-aware operations. Implements the `ShellEnvironment` trait for dev builds and manages the libkrun / HVF / Firecracker backends.

## Modules

| Module | Purpose |
|--------|---------|
| `shell` | `run_in_vm()`, `run_in_vm_visible()`, `run_in_vm_stdout()` — platform-aware shell execution |
| `build_env` | `RuntimeBuildEnv` implementing `ShellEnvironment` (delegates to `shell`) |
| `config` | VM constants, `VmSlot`, `MvmState`, `RunInfo` |
| `ui` | CLI UI helpers (terminal-aware ANSI output, spinners, prompts) |
| `shell_mock` | Test mocking for shell commands |

### VM Subsystem (`vm/`)

| Module | Purpose |
|--------|---------|
| `libkrun` | libkrun VMM lifecycle (macOS 13-25 default, opt-in on Linux) |
| `hvf_backend` | Raw HVF (Hypervisor.framework) VMM lifecycle (macOS 26+ Apple Silicon default) |
| `firecracker` | Firecracker process lifecycle (Linux/KVM) |
| `qemu` | QEMU/microvm_nix backend (Linux dev/test substrate) |
| `microvm` | MicroVM orchestration (dev-mode start/stop/run) |
| `network` | TAP device and network configuration |
| `image` | Image download and caching |
| `vm/template/` | Template CRUD and lifecycle (`template_create`, `template_build`) |

## Platform Behavior

- **macOS 26+ Apple Silicon**: HVF (Hypervisor.framework, no Homebrew deps) is the auto-detect default.
- **Other macOS**: libkrun (the `slp/krun/*` Homebrew trio) is the auto-detect default.
- **Native Linux with KVM**: Runs Firecracker directly; libkrun is a selectable opt-in.
- **Linux without KVM**: No supported local microVM path (nested-KVM / WSL2 is future work).

Detection happens automatically via `mvm_core::platform::current()` and `AnyBackend::auto_select()`.

## Workload Communication Layout

```
MicroVM (no guest NIC)
    | vsock
Host egress endpoint (claim-10 gate + secret substitution)
    | admitted host connection
Host OS / builder VM
```

## Dependencies

- `mvm-core` (types, traits, config)
- `mvm-agentd` (vsock protocol for VM communication)
- `mvm-build` (build pipeline)
