---
title: Writing Nix Flakes
description: Create custom Nix flakes that build microVM images for mvm.
---

:::caution[Declared, not enforced]
`healthChecks`, `volumeMounts` and `serviceGroup` are accepted by `mkGuest`
and recorded in `passthru.mvm.unenforced`, but nothing acts on them yet: the
multi-service supervisor is still a stub. A flake using them builds, and
prints a warning at evaluation saying so.
:::

mvmctl uses Nix flakes to produce reproducible microVM images. You run `mvmctl machine build` from the host, and mvm runs Nix evaluation and `nix build` inside the Linux builder VM. The result is a kernel and rootfs that can boot on any supported runtime backend, including Firecracker, HVF, libkrun, and QEMU.

You do not need to enter a dev shell to build a flake. The dev shell is only for manually debugging the Linux build environment. See [Builder VM](/guides/builder-vm/) for the full host-vs-builder model.

## Minimal Flake

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
        name = "my-app";
        packages = [ pkgs.curl ];

        services.my-app = {
          command = "${pkgs.python3}/bin/python3 -m http.server 8080";
        };

        healthChecks.my-app = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
          healthIntervalSecs = 5;
        };
      };
    };
}
```

## mkGuest API

| Parameter | Description |
|-----------|-------------|
| `name` | VM name (used in image filename) |
| `packages` | Nix packages to include in the rootfs |
| `hostname` | Guest hostname (default: same as `name`) |
| `serviceGroup` | Default service user/group name (default: `"mvm"`). Services run as this user; secrets are readable by this group. |
| `users.<name>.uid` | User ID (optional, auto-assigned from 1000) |
| `users.<name>.group` | Group name (optional, defaults to user name) |
| `users.<name>.home` | Home directory (optional, defaults to `/home/<name>`) |
| `services.<name>.command` | Long-running service command (supervised with respawn) |
| `services.<name>.preStart` | Optional setup script (runs as root before the service) |
| `services.<name>.env` | Optional environment variables (`{ KEY = "value"; }`) |
| `services.<name>.user` | User to run as (default: `serviceGroup`) |
| `services.<name>.logFile` | Optional log file path (default: `/dev/console`) |
| `healthChecks.<name>.healthCmd` | Health check command (exit 0 = healthy) |
| `healthChecks.<name>.healthIntervalSecs` | How often to run the check (default: 30) |
| `healthChecks.<name>.healthTimeoutSecs` | Timeout for each check (default: 10) |
| `volumeMounts."<guest-path>"` | Plan 45 — declarative virtio-fs volume mount declarations. See "Volume Mounts" below. |

## Volume Mounts

`volumeMounts` declares which virtio-fs volumes the guest expects at boot. Each entry maps an absolute guest path to a volume name and read-only flag:

```nix
mkGuest {
  name = "worker";
  packages = with pkgs; [ python311 ];
  volumeMounts = {
    "/mnt/work"   = { volume = "workspace"; readOnly = false; };
    "/mnt/inputs" = { volume = "fixtures"; readOnly = true; };
  };
}
```

The host (`mvmctl machine run` or mvmd) reads these declarations via `passthru.volumeMounts`:

```sh
nix eval .#mvm-worker.passthru.volumeMounts --json
# → [
#     {"guestPath":"/mnt/inputs","volumeName":"fixtures","readOnly":true},
#     {"guestPath":"/mnt/work","volumeName":"workspace","readOnly":false}
#   ]
```

At boot the host attaches a virtio-fs device per declaration and the guest agent runs the matching `MountVolume` vsock verb. Validation:

- **Guest paths** must be absolute and **outside** `/nix*`, `/run/booted-system`, `/run/current-system` — Nix-immutable paths are off-limits per plan 45 §"Nix semantics alignment".
- **Volume names** must be non-empty strings ≤32 chars (used as the virtio-fs tag).
- The host's `mvm_security::policy::MountPathPolicy` re-validates at runtime (defence-in-depth) — the eval-time checks fail fast for malformed flakes.

**Reproducibility boundary:** volume *contents* do not influence the image hash. The flake hash captures the *declaration* of the mounts, not the data behind them. Volumes are the explicit mutable layer; the rootfs stays immutable + verity-protected.

`volumeMounts` is optional; the default is `{}`.

## What mkGuest Provides

`mkGuest` handles everything automatically:

- **Firecracker kernel** (vmlinux) — tuned for microVM workloads
- **Busybox init** — sub-5s boot, no systemd overhead
- **Overlay-aware runtime boot** — the `/init` path, `/mvm/runtime` mount
  point, and policy needed to boot from a sealed runtime overlay
- **Guest agent** — vsock-based health checks, status reporting, snapshot
  coordination; baked into dev/fallback images and supplied by the runtime
  overlay on sealed required-overlay boots
- **Networking** — eth0 configured via kernel boot args, NAT to host network
- **Drive mounting** — `/mnt/config` (ro), `/mnt/secrets` (ro), `/mnt/data` (rw)
- **Service supervision** — automatic restart on failure with backoff

## Runtime overlay contract

`mkGuest` images are **overlay-aware** by default: they carry the
`/mvm/runtime` mount point and boot logic needed to use the sealed runtime
overlay when the selected backend/policy attaches one.

For sealed images on admitted block-backed backends, mvm now uses a
`RequiredOverlay` contract:

- The workload rootfs keeps the mount point and boot logic.
- The guest runtime binaries come from a separate read-only,
  verity-protected runtime overlay.
- The overlay is **version-matched** to the host `mvmctl` build, not "whatever
  overlay is newest in cache".

Operationally, this means:

- Updating the runtime overlay is the normal way to update guest runtime
  binaries for **future boots**.
- You can prebuild that artifact explicitly with
  `mvmctl build runtime-overlay build` (or `just runtime-overlay-build` in a
  source checkout) so later required-overlay boots do not pay guest-binary
  rebuild cost on the hot path.
- A stopped VM picks up the newer overlay on its next `machine start` /
  `machine restart`.
- A running VM keeps the overlay version it already booted with until restart;
  mvm does not live-remount a different runtime overlay into an active guest.

## Adding Services

Services defined in `services.<name>` are supervised by the init system:

```nix
services.my-app = {
  # Setup (runs once as root before the service starts)
  preStart = "mkdir -p /tmp/data";

  # Long-running process (supervised, auto-restart on failure)
  command = "${pkgs.nodejs}/bin/node /app/server.js";

  # Environment variables
  env = {
    PORT = "8080";
    NODE_ENV = "production";
  };

  # Run as a specific user (default: serviceGroup, which defaults to "mvm")
  user = "app";

  # Log to a file instead of console
  logFile = "/var/log/my-app.log";
};
```

## Health Checks

Health checks defined in `healthChecks` are automatically written to `/etc/mvm/integrations.d/` at build time. The guest agent picks them up on boot:

```nix
healthChecks.my-app = {
  healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/health";
  healthIntervalSecs = 10;
  healthTimeoutSecs = 5;
};
```

Query health status from the host:

```bash
mvmctl machine logs <name>       # view guest console (includes health check results)
mvmctl machine logs <name> -f    # follow in real time
```

## Users

All services run as a built-in non-root user (default: `mvm`, uid 900) — never as root. Secrets at `/mnt/secrets` are owned by `root:<serviceGroup>` with mode `0440`, so only members of the service group can read them. Custom users are automatically added to this group.

To change the default service user/group name, set `serviceGroup`:

```nix
mvm.lib.${system}.mkGuest {
  name = "my-app";
  serviceGroup = "app";  # default: "mvm"
  # ...
};
```

To run a service as a custom user, define it in `users` and reference it in the service. The custom user is automatically added to the service group for secrets access:

```nix
users.app = {
  uid = 1000;
  group = "app";
  home = "/home/app";
};

services.my-app = {
  command = "${pkgs.nodejs}/bin/node /app/server.js";
  user = "app";  # overrides the default serviceGroup user
};
```

The `preStart` script always runs as root regardless of the `user` setting, so it can perform privileged setup like mounting filesystems or creating directories.

## Rootfs Types

By default, `mkGuest` produces an **ext4** rootfs. The build system also supports **squashfs** for smaller, read-only images (~76% smaller with LZ4 compression). When using squashfs, the init system mounts tmpfs overlays on `/etc` and `/var` automatically.

## Service Builder Helpers

The guest library provides high-level helpers that return a `{ package, service, healthCheck }` set. Compose them with `mkGuest`:

### mkPythonService

Build a Python HTTP service using `python3.withPackages` (nixpkgs packages only):

```nix
let
  pythonApp = mvm.lib.${system}.mkPythonService {
    name = "my-api";
    src = ./.;
    pythonPackages = ps: [ ps.flask ];
    entrypoint = "app/main.py";
    port = 8080;
    env = { WORKERS = "2"; };
  };
in
  mvm.lib.${system}.mkGuest {
    name = "my-api";
    packages = [ pythonApp.package ];
    services.app = pythonApp.service;
    healthChecks.app = pythonApp.healthCheck;
  };
```

### mkStaticSite

Serve static files with busybox httpd (zero extra packages):

```nix
let
  site = mvm.lib.${system}.mkStaticSite {
    name = "docs";
    src = ./public;
    port = 8080;
  };
in
  mvm.lib.${system}.mkGuest {
    name = "docs";
    packages = [ site.package ];
    services.www = site.service;
    healthChecks.www = site.healthCheck;
  };
```

### mkNodeService

Build a Node.js service with npm install + tsc:

```nix
let
  app = mvm.lib.${system}.mkNodeService {
    name = "my-app";
    src = fetchGit { url = "..."; rev = "..."; };
    npmHash = "sha256-...";
    entrypoint = "dist/index.js";
    port = 3000;
  };
in
  mvm.lib.${system}.mkGuest {
    name = "my-app";
    packages = [ app.package ];
    services.app = app.service;
    healthChecks.app = app.healthCheck;
  };
```

All three helpers return the same shape: `{ package, service, healthCheck }`. This makes it easy to swap between runtimes or compose multiple services in a single guest.

## Build Process

When you run `mvmctl machine build --flake .`:

1. The host CLI reads config and stages the selected flake/profile as a builder job.
2. The builder VM runs Nix evaluation and `nix build` in Linux.
3. The resulting closure is packed into the rootfs.
4. Kernel and rootfs artifacts are copied back to the host cache.
5. Runtime commands boot those already-built artifacts on the selected backend,
   attaching a version-matched runtime overlay when the workload policy
   requires or prefers it.

The same rootfs works on all backends (Firecracker, HVF, microvm.nix).

## Profiles

The `--profile` flag selects which Nix output to build:

```bash
mvmctl machine build --flake . --profile minimal
mvmctl machine build --flake . --profile gateway
```

These map to `packages.${system}.<profile>` in the flake.

## Running an LLM agent inside a microVM

A worked example: a microVM that boots `claude-code` (or any other
agent binary) and reads its API key from a file you mount into the
guest yourself. This is a manual file-materialization path, not the
managed-secret model. For host-mediated managed secret refs, use
`mvm.toml` or the SDKs. You write this in **your project's** flake —
mvm doesn't ship a starter image to fork; you compose `mkGuest`
yourself per [Building MicroVM Images](/guides/building-microvm-images).

```nix
# my-claude-code-vm/flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    mvm.url     = "github:tinylabscom/mvm";
    # Or from numtide/llm-agents.nix for the agent binary.
  };

  outputs = { self, nixpkgs, mvm, ... }:
    let
      system = "x86_64-linux";
      pkgs   = import nixpkgs { inherit system; };
    in
    {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "claude-code";

        entrypoint.command = [ "${pkgs.claude-code}/bin/claude" "code" ];

        # If you choose to mount a credentials file manually, keep it
        # out of the rootfs and point the app at the mounted path.
        # Managed secret refs are declared through mvm.toml / SDKs,
        # not through this flake-only example.

        # Defense in depth: the workload is rootless by default in
        # prod (uid 1000); per-service seccomp tier lands in Phase 6.
        # See /guides/building-microvm-images#rootless-workloads.
      };
    };
}
```

```bash
mkdir -p ~/.mvm/config/secrets
printf '%s\n' 'sk-ant-…' > ~/.mvm/config/secrets/anthropic
chmod 0400 ~/.mvm/config/secrets/anthropic

cd my-claude-code-vm
mvmctl machine build
mvmctl machine run --manifest . --profile dev \
  --mount "$PWD:/workspace:rw" \
  --mount "$HOME/.mvm/config/secrets:/mnt/secrets"
```

Inside the guest, your workload can read the file you mounted under
`/mnt/secrets`. If you do not want the guest to ever see the raw
credential, do not use this manual file-mount pattern; use managed
secret refs instead.

Why a microVM and not a process sandbox: process sandboxes share the host kernel and trust it. A microVM gives the agent its own kernel, so a kernel exploit can't pivot to the host.

Full security composition (per-service uid, seccomp tier, secrets mode, verified boot) is documented in [ADR-001](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/001-microvm-security-posture.md) and the [Rootless workloads section](/guides/building-microvm-images#rootless-workloads).
