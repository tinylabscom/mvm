---
title: Your First MicroVM
description: Write a Nix flake and boot a microVM.
---

:::caution[Declared, not enforced]
`healthChecks`, `volumeMounts` and `serviceGroup` are accepted by `mkGuest`
and recorded in `passthru.mvm.unenforced`, but nothing acts on them yet: the
multi-service supervisor is still a stub. A flake using them builds, and
prints a warning at evaluation saying so.
:::

This guide walks through writing a Nix flake that builds a microVM image, then booting it with mvmctl.

## Understanding the Layers

mvmctl auto-selects the best backend for your platform:

```
Linux (KVM):       mvmctl machine run  -->  Firecracker microVM (direct)
macOS 26+ (AS):    mvmctl machine run  -->  HVF microVM (Hypervisor.framework, vsock-only)
macOS 13-25 (AS):  mvmctl machine run  -->  libkrun microVM
```

| Layer | Access | Has your project files? |
|-------|--------|--------------------------|
| Host | Your normal terminal | Yes |
| Builder VM (`--flake` builds only) | Headless — runs `nix build` on your behalf, no shell | Staged in for the build only |
| MicroVM (workload) | `mvmctl machine console` (dev-tier images) or `mvmctl machine run -it` | Only what you explicitly `--mount` |

MicroVMs are **headless workloads** with no SSH access -- they communicate via vsock only. The builder VM is headless too -- it auto-bootstraps the first time you run `mvmctl machine build` or `mvmctl machine run --flake ...`; `mvmctl bootstrap` pre-fetches its image ahead of time and `mvmctl doctor` reports the resolved builder backend.

:::note
On Linux with `/dev/kvm`, workloads boot straight on Firecracker; a `--flake` build still routes `nix build` through the headless builder VM. On macOS Apple Silicon, workloads run on the HVF backend (macOS 26+) or libkrun (macOS 13–25). There is no Docker or container runtime path.
:::

## Scaffold a project

The fastest path is `mvmctl init`, which writes both a `mvm.toml` (sizing/profile) and a `flake.nix` (rootfs/kernel content) for you:

```bash
mvmctl init hello                    # creates ./hello/
cd hello
$EDITOR mvm.toml                      # tweak vcpus / mem if you like
$EDITOR flake.nix                     # add your services
```

The rest of this guide writes the flake by hand to show how `mkGuest` works underneath.

> The plan-38 manifest model is shipped. Older docs that reference `mvmctl template create/build/…` are stale; the `template` namespace was removed outright. See the [Manifests guide](/guides/manifests/) for the current flow.

## Write a Flake

Create a `flake.nix` in your project (or edit the one `mvmctl init` produced):

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

With a `mvm.toml` next to `flake.nix`:

```bash
# Build (manifest discovered from cwd)
mvmctl machine build

# Boot (auto-selects best backend)
mvmctl machine run --manifest .

# Or declare signed ingress before boot
mvmctl machine run --manifest . --name my-vm --port 8080:8080
```

Without a `mvm.toml` (just a flake), pass `--flake` explicitly — that legacy path still works:

```bash
mvmctl machine build --flake .
mvmctl machine run --flake . --cpus 2 --memory 1024
```

## Check Status

```bash
# List running VMs
mvmctl machine ls

# View guest console logs
mvmctl machine logs hello
```

## Run with Config and Secrets

Pass custom files to the guest drives:

```bash
mkdir -p /tmp/config /tmp/secrets
echo '{"port": 8080}' > /tmp/config/app.json
echo 'API_KEY=sk-...' > /tmp/secrets/app.env

mvmctl machine run --flake . \
    -v /tmp/config:/mnt/config \
    -v /tmp/secrets:/mnt/secrets
```

Inside the guest, config files appear at `/mnt/config/` and secrets at `/mnt/secrets/`.

## Stop

```bash
mvmctl machine stop hello
```

## Next Steps

- [Writing Nix Flakes](/guides/nix-flakes/) -- the full `mkGuest` API
- [Manifests](/guides/manifests/) -- the `mvm.toml` user model (init → build → up)
- [Config & Secrets](/guides/config-secrets/) -- inject files at boot
