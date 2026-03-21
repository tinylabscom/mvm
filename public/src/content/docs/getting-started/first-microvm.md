---
title: Your First MicroVM
description: Write a Nix flake and boot a microVM.
---

This guide walks through writing a Nix flake that builds a microVM image, then booting it with mvmctl.

## Understanding the Layers

mvmctl auto-selects the best backend for your platform:

```
Linux (KVM):    mvmctl up  -->  Firecracker microVM (direct)
macOS 26+:      mvmctl up  -->  Apple Container (Virtualization.framework)
Docker:         mvmctl up  -->  Docker container (universal fallback)
macOS <26:      mvmctl up  -->  Lima VM  -->  Firecracker microVM
```

| Layer | Access command | Has your project files? |
|-------|---------------|------------------------|
| Host | Your normal terminal | Yes |
| Lima VM (macOS <26) | `mvmctl dev` or `mvmctl dev shell` | Yes (~ mounted read/write) |
| MicroVM | (headless, no SSH) | No (isolated filesystem) |

MicroVMs are **headless workloads** with no SSH access -- they communicate via vsock only.

:::note
On Linux with `/dev/kvm`, the Lima layer is skipped entirely -- Firecracker runs directly. On macOS 26+, Apple Virtualization.framework is used instead of Lima + Firecracker. If neither is available, Docker serves as a universal fallback.
:::

## Write a Flake

Create a `flake.nix` in your project:

```nix
{
  inputs = {
    mvm.url = "github:auser/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "hello";
        packages = [ pkgs.curl ];

        services.hello = {
          command = "${pkgs.python3}/bin/python3 -m http.server 8080";
        };

        healthChecks.hello = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
```

`mkGuest` handles everything internally -- the kernel, busybox init, guest agent, networking, drive mounting, and service supervision are all built into the image automatically. You just define your services and health checks.

## Build and Run

```bash
# Build the image
mvmctl build --flake .

# Boot a VM (auto-selects best backend)
mvmctl up --flake . --cpus 2 --memory 1024

# Or run in background with port forwarding
mvmctl up --flake . -d -p 8080:8080
```

## Check Status

```bash
# List running VMs
mvmctl ls

# View guest console logs
mvmctl logs hello
```

## Run with Config and Secrets

Pass custom files to the guest drives:

```bash
mkdir -p /tmp/config /tmp/secrets
echo '{"port": 8080}' > /tmp/config/app.json
echo 'API_KEY=sk-...' > /tmp/secrets/app.env

mvmctl up --flake . \
    -v /tmp/config:/mnt/config \
    -v /tmp/secrets:/mnt/secrets
```

Inside the guest, config files appear at `/mnt/config/` and secrets at `/mnt/secrets/`.

## Stop

```bash
mvmctl down hello
```

## Next Steps

- [Writing Nix Flakes](/guides/nix-flakes/) -- the full `mkGuest` API
- [Templates](/guides/templates/) -- build once, reuse everywhere
- [Config & Secrets](/guides/config-secrets/) -- inject files at boot
