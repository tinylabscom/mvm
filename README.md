# mvm

> **mvm** is a Rust CLI (`mvmctl`) for building and running microVMs from
> Nix flakes. It targets Firecracker on Linux+KVM, Apple Container on
> macOS 26+ Apple Silicon, and direct libkrun on macOS Apple Silicon
> and Intel, with a vsock-only guest contract.
>
> **v0.14.0 is a rewrite.** v1's final tip is preserved as the `legacy/v1`
> branch and the `v1-final` tag. See
> [`MIGRATING-FROM-V1.md`](MIGRATING-FROM-V1.md) and
> [`CHANGELOG.md`](CHANGELOG.md) for the upgrade path and what changed.

## Quick start

Boot a transient dev-tier microVM, run a command, get its output back — five
lines with the Python SDK:

```python
import mvm

with mvm.Sandbox.create(image="python-3.12") as sb:
    result = sb.exec("python", "-c", "print(2 + 2)")
    print(result.stdout.strip())   # -> 4
```

Run it against a real local microVM with `mvmctl run --mode live ./quickstart.py`.
`exec` is dev-tier (live mode); it refuses prod templates with `SandboxDevOnly`.
See the [Python quickstart](public/src/content/docs/getting-started/python-quickstart.md)
for the imperative-lifecycle and static-declaration paths, and the build/derive
flow (`mvmctl compile` / `up --flake`) below.

## Backends

`mvmctl` picks a backend per `AnyBackend::auto_select()` (see ADR-013).
Override with `--hypervisor`:

| Backend | Host | Tier | Notes |
|---|---|---|---|
| [Firecracker](https://firecracker-microvm.github.io/) | Linux + `/dev/kvm`, WSL2 | 1 | Default on KVM hosts; snapshots, dm-verity, full security posture |
| [Apple Container](https://developer.apple.com/documentation/virtualization) | macOS 26+ Apple Silicon | 2 | Native Virtualization.framework |
| [libkrun](https://github.com/containers/libkrun) | macOS Apple Silicon / Intel, Linux + KVM | 2 | Direct Hypervisor.framework/KVM backend; macOS Intel path |
| [Cloud Hypervisor](https://www.cloudhypervisor.org/) | Linux + KVM | 1 (opt-in) | Wider device model than Firecracker — VFIO, virtio-fs, larger guests |

All backends consume the same Nix-built ext4 rootfs produced by
`mkGuest`. The runtime differs; the image doesn't.

## Install

```bash
# Pre-built release
curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh

# From source
git clone https://github.com/tinylabscom/mvm.git && cd mvm
cargo build --release
cp target/release/mvmctl ~/.local/bin/

# Via Cargo (after first crates.io release of 0.14.0)
cargo install mvmctl
```

## Quick start

```bash
# Build and run a VM from a Nix flake
mvmctl up --flake .

# Run in background with port forwarding
mvmctl up --flake . -d -p 8080:8080

# Run a debug build (accessible image; console works without --force)
mvmctl up --dev --flake .

# List running VMs
mvmctl ls

# Stop one VM, or all
mvmctl down app1
mvmctl down

# Force a specific backend
mvmctl up --flake . --hypervisor cloud-hypervisor

# One-shot invoke against a function-entrypoint VM
mvmctl invoke <vm> --stdin '{"name": "world"}'
```

`mvmctl up <flake>` produces a **sealed** image by default —
`mvmctl console <vm>` will refuse on it unless you pass `--force`.
Pass `--dev` to `up` for the accessible posture. This is the
runtime enforcement of security claim 4 (CLAUDE.md "Security model").

## Architecture

```
Layer 1: Host (Linux, macOS, Windows-via-WSL2 in progress)
  mvmctl runs natively. Direct host shell on Linux+KVM.

Layer 2: VM backend (auto-selected per ADR-013)
  Firecracker  ─── KVM microVMs (Tier 1; default on Linux+KVM)
  Cloud Hypervisor ─ KVM, wider device model (Tier 1; opt-in)
  Apple Container ─ Virtualization.framework (macOS 26+ AS)
  libkrun ─────── Hypervisor.framework / KVM (macOS AS + Intel, Linux)

Layer 3: Guest
  Busybox PID 1 (built by mkGuest, ext4 rootfs)
  Real mvm-guest-agent on vsock — NO SSH ever
  Drives: /dev/vda rootfs, /dev/vdb verity sidecar (when claim 3 active)
  Service-level isolation: setpriv, seccomp, RO /etc/passwd
```

## Workspace

13 crates plus the root `mvmctl` facade and `xtask`:

| Crate | Purpose |
|---|---|
| **mvm-core** | Pure types, IDs, config, protocol, signing — no runtime deps |
| **mvm-security** | AES-GCM + KeyProvider + snapshot HMAC + command/threat gates |
| **mvm-storage** | Volume backend trait (sister-crate with mvmd) |
| **mvm-plan** | `ExecutionPlan` typed plan substrate (plan 60 Wave 1) |
| **mvm-policy** | Tenant policy types (plan 60 Wave 1) |
| **mvm-supervisor** | Supervisor process surface (plan 60 Wave 1, in progress) |
| **mvm-providers** | FFI/SDK shim — Apple Container + libkrun + ... |
| **mvm-backend** | Concrete `VmBackend` impls — Firecracker, CH, libkrun, Apple Container, Docker |
| **mvm-base** | Shell, linux_env, runtime_meta, cow, snapshot_integrity substrate |
| **mvm** | VM lifecycle, template management, runtime UI |
| **mvm-build** | Nix builder pipeline + builder VM support |
| **mvm-guest** | Vsock protocol, guest agent binary, integration manifest |
| **mvm-cli** | Clap CLI, bootstrap, doctor, command surface |
| **mvm-mcp** | MCP (Model Context Protocol) sandbox server |

Plus `mvmctl` (root facade, re-exports everything via `mvmctl::core`,
`mvmctl::runtime`, etc.) and `xtask` (build helpers,
`check-adr-coverage`).

## Building images

`mkGuest` is the authoring surface. Three entrypoint forms — pick the
one that matches your workload:

```nix
{
  inputs = {
    mvm.url = "github:tinylabscom/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        inherit pkgs;
        name = "my-app";

        # Form 1 — shell entrypoint (accessible; console drops to a shell)
        # entrypoint.shell = "bash";

        # Form 2 — command entrypoint (sealed; one-shot)
        # entrypoint.command = [ "${pkgs.python3}/bin/python3" "-m" "http.server" "8080" ];

        # Form 3 — services (sealed; supervised long-running)
        entrypoint.services = {
          my-app = {
            exec = "${pkgs.python3}/bin/python3 -m http.server 8080";
          };
        };
      };
    };
}
```

Build and run:

```bash
mvmctl build --flake .
mvmctl up --flake . --cpus 2 --memory 1024
```

See `nix/lib/default.nix` for the full `mkGuest` API and
`nix/images/examples/` for working flakes.

## CLI reference

### VM lifecycle

| Command | Description |
|---|---|
| `mvmctl up --flake <ref>` | Build and run a VM (aliases: `run`, `start`) |
| `mvmctl up --dev --flake <ref>` | Dev posture (accessible image; console works without `--force`) |
| `mvmctl up --manifest <path>` | Boot from a built manifest (`mvm.toml`) |
| `mvmctl up -d` | Detached background mode |
| `mvmctl up -p HOST:GUEST` | Port mapping (repeatable) |
| `mvmctl up --hypervisor <backend>` | Force backend selection |
| `mvmctl down [name]` | Stop a VM by name, or all if omitted |
| `mvmctl ls` / `mvmctl ls -a` | List running / all VMs |
| `mvmctl logs <name>` | Console logs (`-f` to follow) |
| `mvmctl invoke <vm>` | Function-entrypoint call (production-safe) |
| `mvmctl exec <vm>` | One-shot exec (dev-only — sealed images refuse) |
| `mvmctl console <vm>` | Attach console (refuses on sealed VMs; `--force` overrides) |
| `mvmctl forward <name> -p PORT` | Forward a guest port to localhost |

### Building

| Command | Description |
|---|---|
| `mvmctl build --flake <ref>` | Build from a Nix flake |
| `mvmctl build --flake <ref> --dev` | Dev-posture build |
| `mvmctl build --flake <ref> --watch` | Rebuild on flake.lock changes |
| `mvmctl validate <flake>` | Static-validate a flake without building |
| `mvmctl manifest ls/info/verify` | Inspect built manifests |
| `mvmctl manifest prune` | GC stale build outputs |

### Environment

| Command | Description |
|---|---|
| `mvmctl dev up` | Start dev environment (host shell on Linux+KVM, Apple Container on macOS 26+) |
| `mvmctl dev down` | Stop the dev environment |
| `mvmctl dev shell` | Open a shell |
| `mvmctl dev status` | Show env state + `/dev/kvm` / Firecracker / assets |
| `mvmctl doctor` | Full diagnostics — backends, security posture, snapshot HMAC, FDE |
| `mvmctl config show/edit/set` | Global config at `~/.mvm/config.toml` |

### Utilities

| Command | Description |
|---|---|
| `mvmctl update` | Self-update (`--check` for dry run) |
| `mvmctl uninstall` | Clean uninstall |
| `mvmctl audit tail` | View audit log |
| `mvmctl metrics` | Runtime metrics (Prometheus or JSON) |
| `mvmctl shell-init` | Print shell config + completions |

## Security model

mvm makes seven CI-enforced claims. Each is backed by a test or a
workflow gate; the canonical statement lives in
[`CLAUDE.md`](CLAUDE.md) §"Security model"; the threat model is
[ADR-002](specs/adrs/002-microvm-security-posture.md).

1. No host-fs access from a guest beyond explicit shares
2. No guest binary can elevate to uid 0
3. Tampered rootfs ext4 fails to boot (dm-verity)
4. Guest agent has no `do_exec` in production builds
5. Vsock framing is fuzzed
6. Pre-built dev image is hash-verified
7. Cargo deps are audited on every PR

Out of scope (named in ADR-002):

- Malicious *host*. mvmctl trusts the host with the hypervisor and
  private build keys.
- Multi-tenant guests. One guest = one workload.
- Hardware-backed attestation (TPM2 / SEV-SNP / TDX) — deferred to
  plan 60 Phase 3.

## Development

```bash
cargo build                              # Debug
cargo test --workspace                   # All tests (1937+ passing)
cargo clippy --workspace -- -D warnings  # Lint (0 warnings required)
cargo +nightly fmt                       # Format (CI uses nightly)
```

See [`public/src/content/docs/contributing/development.md`](public/src/content/docs/contributing/development.md)
for contributor guidelines, CI/CD lanes, and release process.

### Running the suite on real Linux+KVM (Hetzner)

macOS can't run live Firecracker microVMs natively. For the full
suite — workspace clippy on x86_64-linux, the seccomp functional
probes, longer `cargo fuzz` runs, and live-KVM smokes — spin up a
Hetzner Cloud test box with the cloud-init scaffolding in
[`ops/hetzner/`](ops/hetzner/):

```bash
hcloud server create \
  --name mvm-test-1 \
  --type ccx23 \
  --image ubuntu-24.04 \
  --location nbg1 \
  --ssh-key <your-key-name> \
  --user-data-from-file ops/hetzner/cloud-init.yaml

ssh root@<server-ip> 'cloud-init status --wait'
ssh root@<server-ip>
su - mvm
bash ~/warm-cache.sh        # one-time: cargo fetch + workspace build
bash ~/run-tests.sh         # full suite, stops at first failure
```

CCX (x86_64) or CAX (ARM) Hetzner instances expose `/dev/kvm`;
CPX/CX (shared CPU) don't.

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) — release notes
- [`MIGRATING-FROM-V1.md`](MIGRATING-FROM-V1.md) — v1→v2 upgrade guide + feature parity ledger
- [`CLAUDE.md`](CLAUDE.md) — project conventions, security model
- [`specs/plans/60-mvm-libkrun-migration.md`](specs/plans/60-mvm-libkrun-migration.md) — full migration plan (Phases 0–10)
- [`specs/SPRINT.md`](specs/SPRINT.md) — current sprint
- [`public/src/content/docs/`](public/src/content/docs/) — docs site sources (rendered at <https://gomicrovm.com>)

## v1 history

v1's final state is preserved on this repo:

- Branch: [`legacy/v1`](https://github.com/tinylabscom/mvm/tree/legacy/v1)
- Tag: [`v1-final`](https://github.com/tinylabscom/mvm/tree/v1-final)
- Releases: `v0.7.1` through `v0.13.0` continue to resolve

Every v1 commit URL, PR URL, and release tag URL still works.

## License

Apache 2.0 — see [LICENSE](LICENSE).
