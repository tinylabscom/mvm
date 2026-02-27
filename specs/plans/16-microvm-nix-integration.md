# Plan 16: microvm.nix Integration — Hypervisor Decoupling

**Status: IN PROGRESS**

## Motivation

mvm is tightly coupled to Lima — ~282 `run_in_vm`/`run_on_vm` call sites across ~38 files. Lima serves two distinct roles that should be separated:

1. **Linux Execution Environment (LEE)**: On macOS, all bash scripts route through `limactl shell mvm bash -c "..."`. Necessary because Firecracker requires `/dev/kvm`.
2. **Guest VM configuration/lifecycle**: Custom Nix boilerplate (`mkGuest`) in every user flake builds kernel+rootfs, and manual Firecracker API calls (`api_put` chain in `microvm.rs`) manage VM start/stop.

[microvm.nix](https://github.com/astro/microvm.nix) supports 8 hypervisors from a single declarative config. It handles kernel selection, rootfs building, networking, vsock, and generates per-hypervisor runner scripts.

### Key design principle: microvm.nix is an internal dependency

Users never reference microvm.nix directly. mvm's flake internally pulls in microvm.nix and exports `mvm.lib.<system>.mkGuest` — a single function that handles everything. The user-facing flake becomes:

```nix
{
  inputs = {
    mvm.url = "github:auser/mvm";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let system = "x86_64-linux";
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-vm";
        modules = [ ./my-config.nix ];
      };
    };
}
```

Compare to today's user flake which requires ~90 lines of `mkGuest` boilerplate (kernel extraction, `make-ext4-fs.nix`, `populateImageCommands`, architecture fallbacks, rust-overlay, guest-agent-pkg, etc.).

### What this replaces

- Custom `mkGuest` boilerplate in every user flake -> `mvm.lib.<system>.mkGuest`
- Manual Firecracker API call chain -> generated runner scripts
- Single-hypervisor lock-in -> multi-hypervisor from one config

### What stays the same

- Lima as macOS execution environment (vfkit lacks TAP networking)
- The shell execution layer (`run_in_vm`)
- The vsock communication/security layer
- TAP/bridge networking setup
- Build output contract: `$out/vmlinux`, `$out/rootfs.ext4`, optional `$out/initrd`
- Any user flake that already produces the right output continues to work

### macOS strategy

Keep Lima as the execution environment. microvm.nix handles guest config and runner scripts, which execute inside Lima on macOS and directly on native Linux.

---

## Phase 1: Abstract the Linux Execution Layer

**Goal**: Separate "where scripts run" (LEE) from "how VMs are managed" (backend) at the type level.

### 1a: `LinuxEnv` trait in mvm-core

New file: `crates/mvm-core/src/linux_env.rs`

```rust
use anyhow::Result;
use std::process::Output;

/// Abstraction for running Linux commands.
///
/// On macOS: delegates to a Lima VM via `limactl shell`.
/// On native Linux with KVM: runs bash directly on the host.
/// In the future: could route to OrbStack, UTM, or a remote host.
pub trait LinuxEnv: Send + Sync {
    /// Run a bash script, capturing output.
    fn exec(&self, script: &str) -> Result<Output>;

    /// Run a bash script with output visible to the user (inherited stdio).
    fn exec_visible(&self, script: &str) -> Result<()>;

    /// Run a bash script and return stdout as a String.
    fn exec_stdout(&self, script: &str) -> Result<String>;

    /// Run a bash script, capturing both stdout and stderr (piped, not inherited).
    fn exec_capture(&self, script: &str) -> Result<Output>;
}
```

### 1b: `LimaEnv` + `NativeEnv` in mvm-runtime

New file: `crates/mvm-runtime/src/linux_env.rs`

- `LimaEnv { vm_name: String }` — wraps `limactl shell <vm_name> bash -c "..."`
- `NativeEnv` — wraps `bash -c "..."`
- Factory: `pub fn create_linux_env() -> Box<dyn LinuxEnv>` — returns `LimaEnv` or `NativeEnv` based on `Platform::current()`

### 1c: Refactor `shell.rs` internals

The existing free functions (`run_in_vm`, `run_in_vm_visible`, etc.) remain as the public API. Internally they delegate to a default `LinuxEnv` instance. This avoids touching 282 call sites while establishing the trait boundary.

### 1d: Inject `LinuxEnv` into `RuntimeBuildEnv`

`RuntimeBuildEnv` currently hardcodes `shell::run_in_vm()`. Make it accept a `&dyn LinuxEnv`:

```rust
pub struct RuntimeBuildEnv<'a> {
    env: &'a dyn LinuxEnv,
}
```

### Files

| File | Change |
|------|--------|
| `crates/mvm-core/src/linux_env.rs` | New trait |
| `crates/mvm-core/src/lib.rs` | Add `pub mod linux_env` |
| `crates/mvm-runtime/src/linux_env.rs` | New: LimaEnv, NativeEnv, factory |
| `crates/mvm-runtime/src/lib.rs` | Add `pub mod linux_env` |
| `crates/mvm-runtime/src/shell.rs` | Internal delegation to default LinuxEnv |
| `crates/mvm-runtime/src/build_env.rs` | Accept `&dyn LinuxEnv` |

### Tests

- Unit tests for `NativeEnv` (mock-based, verify command construction)
- `RuntimeBuildEnv` with injected mock env
- Existing tests pass (free functions unchanged)

---

## Phase 2: mvm Flake + microvm.nix Integration

**Goal**: Create `flake.nix` at the mvm repo root that exports `lib.<system>.mkGuest` and NixOS modules. microvm.nix is an internal dependency users never see.

### 2a: Create mvm root `flake.nix`

New file: `flake.nix` (repo root)

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    microvm.url = "github:astro/microvm.nix";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, microvm, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.minimal;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        mvm-guest-agent = import ./nix/modules/guest-agent-pkg.nix {
          inherit pkgs rustPlatform;
          mvmSrc = ./.;
        };
      in {
        # ── User-facing API ──────────────────────────────────────────
        # mvm.lib.<system>.mkGuest { name, modules, hypervisor? }
        #
        # Builds a NixOS microVM guest image producing:
        #   $out/vmlinux      — kernel
        #   $out/initrd        — initial ramdisk
        #   $out/rootfs.ext4   — root filesystem
        #   $out/bin/microvm-run — runner script (when available)
        lib.mkGuest = { name, modules ? [], hypervisor ? "firecracker" }:
          let
            eval = nixpkgs.lib.nixosSystem {
              inherit system;
              specialArgs = { inherit mvm-guest-agent; };
              modules = [
                microvm.nixosModules.microvm
                ./nix/modules/mvm-guest.nix
                ./nix/modules/guest-agent.nix
                { microvm.hypervisor = hypervisor; }
              ] ++ modules;
            };
            cfg = eval.config;
            kernel = cfg.boot.kernelPackages.kernel;

            rootfs = pkgs.callPackage
              (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
              storePaths = [ cfg.system.build.toplevel ];
              volumeLabel = "nixos";
              populateImageCommands = ''
                mkdir -p ./files/etc ./files/sbin
                ln -s ${cfg.system.build.toplevel} ./files/etc/system-toplevel
                ln -s ${cfg.system.build.toplevel}/init ./files/sbin/init
                ln -s .${cfg.system.build.toplevel}/init ./files/init
                echo "${cfg.system.build.toplevel}" > ./files/etc/NIXOS_CLOSURE
                touch ./files/etc/NIXOS
              '';
            };
          in
          pkgs.runCommand "mvm-${name}" {
            passthru = { inherit eval; config = cfg; };
          } ''
            mkdir -p $out
            # Kernel
            if [ -f "${kernel}/vmlinux" ]; then
              cp "${kernel}/vmlinux" "$out/vmlinux"
            elif [ -f "${kernel}/Image" ]; then
              cp "${kernel}/Image" "$out/vmlinux"
            elif [ -f "${kernel}/bzImage" ]; then
              cp "${kernel}/bzImage" "$out/kernel"
            else
              echo "ERROR: kernel not found in ${kernel}" >&2; exit 1
            fi
            # Initrd + rootfs
            cp "${cfg.system.build.initialRamdisk}/initrd" "$out/initrd"
            cp "${rootfs}" "$out/rootfs.ext4"
            echo "${cfg.system.build.toplevel}" > "$out/toplevel-path"

            # Runner script (for Phase 4 — microvm.nix runner backend)
            runner="${cfg.microvm.declaredRunner or ""}"
            if [ -n "$runner" ] && [ -d "$runner/bin" ]; then
              cp -r "$runner/bin" "$out/bin"
            fi
          '';

        # ── NixOS modules (for advanced users) ──────────────────────
        nixosModules = {
          mvm-guest = ./nix/modules/mvm-guest.nix;
          guest-agent = ./nix/modules/guest-agent.nix;
        };

        packages.mvm-guest-agent = mvm-guest-agent;
      }
    );
}
```

### 2b: Create `nix/modules/mvm-guest.nix`

New file replacing the role of `baseline.nix`. Contains all Firecracker-specific NixOS config:
- Boot params (console, reboot, panic, net.ifnames)
- Minimal initrd (only virtio modules)
- Root filesystem on /dev/vda
- Drive mounts (config on /dev/vdb, secrets on /dev/vdc, data on /dev/vdd)
- Network config from kernel cmdline (mvm.ip, mvm.gw)
- Security hardening (no SSH, no sudo, no mutable users)
- microvm.nix defaults: vcpu=2, mem=512, vsock cid=3

### 2c: Update OpenClaw flake (reference implementation)

Rewrite `nix/openclaw/flake.nix` — becomes trivial:

```nix
{
  inputs = {
    mvm.url = "path:../../";  # or github:auser/mvm
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let system = "aarch64-linux";
    in {
      packages.${system} = {
        tenant-gateway = mvm.lib.${system}.mkGuest {
          name = "gateway";
          modules = [ ./roles/gateway.nix ./guests/profiles/gateway.nix ];
        };
        tenant-worker = mvm.lib.${system}.mkGuest {
          name = "worker";
          modules = [ ./roles/worker.nix ./guests/profiles/worker.nix ];
        };
        default = mvm.lib.${system}.mkGuest {
          name = "worker";
          modules = [ ./roles/worker.nix ./guests/profiles/worker.nix ];
        };
      };
    };
}
```

**~90 lines of boilerplate reduced to ~20.**

### 2d: Update template scaffold

`resources/template_scaffold/flake.nix`:

```nix
{
  inputs.mvm.url = "github:auser/mvm";

  outputs = { mvm, ... }:
    let system = "aarch64-linux"; # change to x86_64-linux if needed
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-vm";
        modules = [ ./config.nix ];
        # hypervisor = "qemu";  # optional: default is firecracker
      };
    };
}
```

### Files

| File | Change |
|------|--------|
| `flake.nix` | **New**: repo root flake exporting `lib.mkGuest` |
| `nix/modules/mvm-guest.nix` | **New**: unified guest baseline module |
| `nix/openclaw/flake.nix` | Rewrite to use `mvm.lib.mkGuest` |
| `resources/template_scaffold/flake.nix` | Rewrite to use `mvm.lib.mkGuest` |
| `crates/mvm-cli/resources/template_scaffold/flake.nix` | Mirror of above |
| `nix/openclaw/guests/baseline.nix` | Content moves to `mvm-guest.nix` |

### Verification

- `nix flake check` passes on repo root and openclaw flakes
- `nix build` from openclaw produces `vmlinux` + `initrd` + `rootfs.ext4`
- `dev_build()` works unchanged (same output structure)
- Existing custom flakes (without `mvm.lib`) continue to work

---

## Phase 3: Wire VmBackend into CLI

**Goal**: Make the existing `VmBackend` trait active in CLI dispatch.

### 3a: Create `AnyBackend` enum

```rust
pub enum AnyBackend {
    Firecracker(FirecrackerBackend),
    // MicrovmNix(MicrovmNixBackend),  // Phase 4
}
```

### 3b: Refactor CLI commands

`cmd_run`, `cmd_stop`, `cmd_status` dispatch through `AnyBackend` instead of calling `microvm::*` directly.

### Files

| File | Change |
|------|--------|
| `crates/mvm-runtime/src/vm/backend.rs` | Add AnyBackend, UnifiedRunConfig |
| `crates/mvm-cli/src/commands.rs` | Dispatch through AnyBackend |

---

## Phase 4: microvm.nix Runner Backend

**Goal**: Use microvm.nix runner scripts instead of manual FC API calls.

### 4a: `MicrovmNixBackend`

New file: `crates/mvm-runtime/src/vm/microvm_nix.rs`

- `start()`: runs the preserved runner script from build output (`$out/bin/microvm-run`)
- `stop()`: `SendCtrlAltDel` via FC API socket or kill
- Routes through `LinuxEnv` (direct on Linux, via Lima on macOS)

### 4b: Extend build pipeline

`dev_build()` copies runner script when present in Nix output.

### Files

| File | Change |
|------|--------|
| `crates/mvm-runtime/src/vm/microvm_nix.rs` | New backend |
| `crates/mvm-runtime/src/vm/backend.rs` | Add MicrovmNix variant |
| `crates/mvm-build/src/dev_build.rs` | Copy runner script |

---

## Phase 5: macOS Coexistence

`MicrovmNixBackend` routes runner execution through `LinuxEnv`. On macOS this transparently delegates to Lima. Add `Platform::supports_native_microvm_nix()`.

---

## Phase 6: Multi-Hypervisor (Future)

Add `--hypervisor` CLI flag. Users pass `hypervisor = "qemu"` to `mkGuest`. QEMU for dev (richer debugging, GDB attach), Firecracker for prod, cloud-hypervisor as alternative. Each reports different `VmCapabilities`.

---

## Migration Summary

| Phase | Risk | Lima Impact | Incremental? |
|-------|------|-------------|--------------|
| 1: LEE trait | Low | None (internal) | Yes |
| 2: mvm flake + modules | Medium | None (Nix-only) | Yes |
| 3: Wire VmBackend | Low | None (CLI plumbing) | Yes |
| 4: Runner backend | Medium | None on macOS | Yes (feature-gated) |
| 5: macOS coexistence | Low | Lima stays | Yes |
| 6: Multi-hypervisor | High | None | Future |

## Invariants

- `mvmctl dev` still drops into Lima shell on macOS
- `mvmctl build --flake` still runs `nix build`
- Any user Nix flake producing `vmlinux` + `rootfs.ext4` continues to work
- `mvmctl run` still boots Firecracker (via runner script when available)
- vsock communication unchanged
- No SSH in microVMs, ever
- All existing tests pass at each phase boundary
