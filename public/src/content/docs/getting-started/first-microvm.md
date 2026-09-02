---
title: Your First MicroVM
description: Write a Nix flake and boot a microVM.
---

:::note[Health checks run in the guest]
`healthChecks` is rendered into `/etc/mvm/probes.d/<name>.json` in the image.
The guest agent scans that directory at boot and runs each check on its own
interval; results come back over vsock. `volumeMounts` and `serviceGroup` are
still recorded rather than acted on — the multi-service supervisor is not wired.
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

> The plan-38 manifest model is shipped. Older docs that reference `mvmctl template create/build/…` are stale: the mutation verbs were removed. `mvmctl template` still exists as a read-only registry browser — `list`, `search`, and `info`. See the [Manifests guide](/guides/manifests/) for the current build flow.

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
        packages = [ pkgs.python3 pkgs.curl ];

        # `entrypoint` is REQUIRED and must declare exactly one of
        # `shell`, `command`, or `services`. mkGuest throws at eval time
        # otherwise. `command` is the sealed (production) form.
        entrypoint.command = [
          "${pkgs.python3}/bin/python3" "-m" "http.server" "8080"
        ];

        healthChecks.hello = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
```

`mkGuest` handles everything internally -- the kernel, busybox init, guest agent, and drive mounting are all built into the image automatically. You describe the entrypoint and its health checks.

:::caution[One process, not a service set]
`entrypoint.command` runs a single program as PID 1. The multi-service form (`entrypoint.services`, and the top-level `services` attribute) is accepted by `mkGuest` but **not implemented** — the supervisor is unwired, so `entrypoint.services` prints "not yet wired" and drops the guest to a recovery shell, and a top-level `services` block is only recorded in `passthru.mvm`. Use `entrypoint.command` (or `entrypoint.shell` for a dev-tier image) until the supervisor lands.
:::

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
mkdir -p /tmp/config
echo '{"port": 8080}' > /tmp/config/app.json

mvmctl machine run --flake . \
    --mount /tmp/config:/data/config
```

The share flag is `--mount` (alias `--volume`); there is no short form — `-v` is
the global verbosity counter.

A guest mount path must live under `/data` or `/work`. `/mnt/config` and
`/mnt/secrets` are runtime-owned: `/init` mounts mvm's own read-only config and
secret drives there before any user volume is attached, and the mount policy
refuses a share that would sit inside or shadow them. Mounts are read-only by
default; a transient run is read-only under every profile.

Inside the guest, the files appear at the path you asked for — `/data/config/`
above. For credentials, use `mvmctl secret` and host-side substitution rather
than shipping a secrets file into the guest.

## Stop

```bash
mvmctl machine stop hello
```

## Next Steps

- [Writing Nix Flakes](/guides/nix-flakes/) -- the full `mkGuest` API
- [Manifests](/guides/manifests/) -- the `mvm.toml` user model (init → build → up)
- [Config & Secrets](/guides/config-secrets/) -- inject files at boot
