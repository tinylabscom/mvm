# Plan: Apple Container Dev Environment (Sprint 40)

> **Scope**: Dev DX only. Does NOT affect production (Firecracker + KVM on Linux).
> All Apple Container code is `#[cfg(target_os = "macos")]` — doesn't compile on Linux.
>
> **On approval**: Save this plan to `specs/plans/23-apple-container-dev.md` and update `specs/SPRINT.md`.

## Context

`mvmctl dev` currently always uses Lima on macOS — even on macOS 26+ with Apple Containers. The user gets this message:

```
Apple Containers available. Dev shell via Apple Container is not yet implemented.
Falling back to Lima. Use '--lima' to suppress this message.
```

The goal is to make `mvmctl dev` boot a Linux dev VM via Apple Containers (Virtualization.framework) with Nix + build tools, and give the user an interactive shell via the PTY-over-vsock console from Sprint 39. Lima becomes an optional fallback via `--lima`.

### Why this works

The `mvm-apple-container` crate uses `VZLinuxBootLoader` directly — it boots **our** kernel with **our** init (`init=/init`), not Apple's vminitd. The "boot model mismatch" blocker in MEMORY.md only applies to Apple's higher-level Containerization.framework, which we don't use. Our guest agent runs as normal on vsock port 52.

---

## Phase 1: Platform Routing (commands.rs, platform.rs)

**Make `needs_lima()` conditional on Apple Container availability.**

- `crates/mvm-core/src/platform.rs:23` — Change `Platform::MacOS => true` to `Platform::MacOS => !self.has_apple_containers()`
- Audit all `needs_lima()` callsites for safe behavior when this changes:
  - `bootstrap.rs:is_lima_required()` — will now skip Lima install on macOS 26+
  - `commands.rs:cmd_dev()` — already has Apple Container detection, needs real routing
  - `commands.rs:cmd_dev_down()` — needs Apple Container stop path
  - `commands.rs:cmd_shell()` — needs console_interactive fallback
  - `linux_env.rs:create_linux_env()` — needs AppleContainerEnv option
  - `commands.rs:run_setup_steps()` — needs to skip Lima VM creation

**Route dev commands:**

- `cmd_dev()` with `DevCmd::Up` when `has_apple_containers() && !lima`:
  1. Ensure dev image exists (Phase 2)
  2. Start Apple Container VM named `mvm-dev` if not running
  3. Wait for guest agent on vsock port 52
  4. Open interactive console via `console_interactive("mvm-dev")`

- `cmd_dev()` with `DevCmd::Down` when `has_apple_containers()`:
  - `mvm_apple_container::stop("mvm-dev")`

- `cmd_dev()` with `DevCmd::Shell`:
  - `console_interactive("mvm-dev")` (reuses Sprint 39 PTY)

- `cmd_dev()` with `DevCmd::Status`:
  - Check if `mvm-dev` in `mvm_apple_container::list_ids()`
  - Query versions via `Exec` over vsock

---

## Phase 2: Dev Image (Nix flake for dev rootfs)

**Build a rootfs with our init + guest agent + Nix + build tools.**

Create `nix/dev-image/flake.nix` using the existing `mkGuest` library:
- Base: the existing minimal rootfs from `nix/guest-lib/`
- Add packages: nix, bash, coreutils, git, curl, gnumake, gcc
- Include the `mvm-guest-agent` binary (for vsock communication)
- Use ext4 rootfs format (Apple Container needs read-write)

**Dev image caching:**

- Store at `~/.cache/mvm/dev/vmlinux` and `~/.cache/mvm/dev/rootfs.ext4`
- `ensure_dev_image()` function checks cache, builds if missing
- Building requires host Nix (`platform.has_host_nix()`) — if unavailable, error with install instructions

**Shared directory support:**

- Add `VZSharedDirectory` + `VZVirtioFileSystemDeviceConfiguration` to `macos.rs:start_vm()`
- Mount the user's home directory (or project directory) inside the VM at the same path
- This lets users edit code on macOS and build inside the VM, just like Lima

---

## Phase 3: AppleContainerEnv (linux_env.rs)

**New `LinuxEnv` implementation for executing commands inside the Apple Container dev VM.**

- `crates/mvm-runtime/src/linux_env.rs` — Add `AppleContainerEnv` struct:
  - Holds VM ID (`"mvm-dev"`)
  - `run()`: Connect via `mvm_apple_container::vsock_connect(id, 52)`, send `GuestRequest::Exec`, return output
  - `run_visible()`: Same but stream stdout/stderr to terminal in real-time
  - `run_stdout()`: Capture stdout only

- Update `create_linux_env()` factory:
  ```rust
  if platform.has_apple_containers() {
      Box::new(AppleContainerEnv::new("mvm-dev"))
  } else if platform.needs_lima() {
      Box::new(LimaEnv::new(VM_NAME))
  } else {
      Box::new(NativeEnv)
  }
  ```

- This makes `shell::run_in_vm()` automatically route through Apple Container

---

## Phase 4: Build Pipeline Without Lima

**Ensure `mvmctl build --flake .` works without Lima on macOS 26+.**

- `crates/mvm-runtime/src/build_env.rs` — `default_build_env()` already returns `HostBuildEnv` when `has_host_nix()` is true. Verify this path works for:
  - `nix build` on macOS producing Linux ext4 rootfs (requires Nix cross-compilation or Linux builder)
  - If host Nix can't cross-compile: route build through `AppleContainerEnv` (run `nix build` inside the dev VM)

- `crates/mvm-cli/src/commands.rs` — `run_setup_steps()`: skip Lima VM creation when `has_apple_containers()`, instead ensure dev image exists

---

## Phase 5: Tests & Docs

- Unit tests for `AppleContainerEnv` (mock vsock responses)
- CLI tests: `dev --help`, `dev up --lima`, `dev down`
- Platform test: `needs_lima()` returns false on macOS 26+
- Update `specs/SPRINT.md` to Sprint 40
- Update CLI reference docs
- Update CLAUDE.md with Apple Container dev info

---

## Key Files

| File | Changes |
|------|---------|
| `crates/mvm-core/src/platform.rs` | `needs_lima()` conditional on `has_apple_containers()` |
| `crates/mvm-cli/src/commands.rs` | Dev command routing, `cmd_dev_apple_container()` |
| `crates/mvm-runtime/src/linux_env.rs` | New `AppleContainerEnv` struct |
| `crates/mvm-apple-container/src/macos.rs` | Shared directory support in `start_vm()` |
| `crates/mvm-runtime/src/build_env.rs` | Build env selection for Apple Container |
| `nix/dev-image/flake.nix` | New: dev environment rootfs flake |
| `specs/SPRINT.md` | Sprint 40 |

---

## Verification

```bash
# On macOS 26+ Apple Silicon:
cargo test --workspace
cargo clippy --workspace -- -D warnings
mvmctl dev                    # Should boot Apple Container, not Lima
mvmctl dev shell              # Interactive PTY console into dev VM
mvmctl dev status             # Shows Apple Container dev VM status
mvmctl dev down               # Stops Apple Container dev VM
mvmctl dev --lima              # Falls back to Lima explicitly
mvmctl build --flake .        # Nix build without Lima
```
