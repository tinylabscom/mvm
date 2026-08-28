---
title: Dev Image
description: How to boot a development microVM with an interactive shell, the fastest zero-config path to one, and how to write your own.
---

A **dev image** is a microVM image whose entrypoint is an interactive shell — what you boot when you want a sandboxed shell for build/test/exploration. It's just an `mkGuest` call with `entrypoint.shell` set; the same library, the same flake shape, the same builder pipeline as any other mvm image. There's no separate "dev VM" command anymore: a dev image is a workload like any other, booted through `mvmctl machine`.

There are two paths:

1. **Boot a shell with zero config** — no flake needed: `mvmctl machine run --image alpine -it -- /bin/sh`. Good for "I just want a sandboxed Linux shell to poke around in." See [The fastest path](#the-fastest-path) below.
2. **Write your own dev image** — declare it in your project's flake using `mvm.lib.<system>.mkGuest`. Adds your packages, your services, your config. The mvm repository's internals stay untouched — you're a consumer of the library, not a fork. See [Writing your own dev image](#writing-your-own-dev-image) below.

Per [ADR-030](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/030-libkrun-pivot.md), the dev/prod distinction is encoded in the entrypoint shape (`shell` → accessible, `command`/`services` → sealed). The same `mvm.lib.<system>.mkGuest` API serves both.

## Writing your own dev image

A dev image is just an mkGuest call with `entrypoint.shell` set. Your project's `flake.nix` already imports `mvm` as an input ([Building MicroVM Images](/guides/building-microvm-images) covers the basics); add a `packages.<system>.dev` output:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    mvm.url     = "github:tinylabscom/mvm";
  };

  outputs = { self, nixpkgs, mvm, ... }:
    let
      system = "x86_64-linux";
      pkgs   = import nixpkgs { inherit system; };
    in
    {
      packages.${system} = {
        # Production image — what `mvmctl machine run` builds.
        default = mvm.lib.${system}.mkGuest {
          name = "my-app";
          entrypoint.command = [ "/usr/local/bin/serve" ];
        };

        # Dev image — what `mvmctl machine create` + `start` below builds.
        dev = mvm.lib.${system}.mkGuest {
          name = "my-app-dev";

          # entrypoint.shell auto-infers `dev = true` (accessible).
          # `mvmctl machine console <vm>` attaches via vsock.
          entrypoint.shell = "/bin/bash";

          # Anything in nixpkgs.
          packages = with pkgs; [
            git
            jq
            ripgrep
            python3
          ];

          # Optional: per-tenant defaults; mvm.toml overrides at run time.
          vcpus = 2;
          memory_mib = 1024;
        };
      };
    };
}
```

Point `mvm.toml` at the dev output:

```toml
flake     = "."
profile   = "dev"
cpus      = 2          # `vcpus` is an accepted alias
mem       = "1024M"
```

`mvm.toml` rejects unknown keys. Memory is `mem` (a size string) — `memory_mib`
is a `mkGuest` argument, not a manifest key.

Then:

```sh
mvmctl machine create my-app-dev          # reads mvm.toml (profile = "dev") from cwd
mvmctl machine start my-app-dev           # builds the .dev output, boots it
mvmctl machine console my-app-dev         # attach the interactive shell
# Ctrl-D / exit detaches — the machine and any background services keep running.
mvmctl machine stop my-app-dev            # tear it down
```

You **never edit anything inside the mvm repository** to customize your dev image. Your project owns its dev image; mvm is the library.

### Adding services to your dev image

:::caution[Not wired yet]
The `services` field is accepted and recorded, but nothing supervises it — the
multi-service supervisor is not built. `mkGuest` warns at evaluation time. The
shape below is the declared surface, not running behaviour.
:::

The declared shape:

```nix
dev = mvm.lib.${system}.mkGuest {
  name = "my-app-dev";
  entrypoint.shell = "/bin/bash";

  services.postgres = {
    command = [ "${pkgs.postgresql}/bin/postgres" "-D" "/var/lib/postgresql/data" ];
    restart = "always";
  };
  services.redis = {
    command = [ "${pkgs.redis}/bin/redis-server" ];
  };

  packages = with pkgs; [ postgresql redis ];
};
```

The intent is that each service runs as its own supervised process with the
shell as your foreground. None of that supervision exists yet.

### Forcing the dev path on a sealed entrypoint

If you want a dev image whose primary entrypoint is a *program* (not a shell) but still want `mvmctl machine console` to attach for debugging:

```nix
dev = mvm.lib.${system}.mkGuest {
  name = "my-app-dev";
  entrypoint.command = [ "/usr/local/bin/serve" "--debug" ];
  dev = true;   # explicit override; auto-infer is `false` for command form
};
```

See [Building MicroVM Images](/guides/building-microvm-images#sealed-vs-accessible--the-same-flake-works-for-both) for the full sealed/accessible matrix.

## The fastest path

For "I just want a shell," skip the flake entirely:

```sh
mvmctl machine run --image alpine -it -- /bin/sh
```

This pulls (or reuses the cached) `alpine` OCI image, boots a transient microVM, and attaches your terminal to `/bin/sh` inside it. Exiting the shell tears the VM down — the same lifecycle as any other transient `machine run`. No `flake.nix`, no `mvm.toml`, no host Nix.

Once you have specific package or service requirements — beyond what an off-the-shelf OCI image gives you — switch to writing your own dev image per the section above.

## Building the dev image locally

The build path is the same as any mvm image:

```sh
# From your project directory:
mvmctl machine build --flake . --profile dev
```

If you intentionally manage your own Nix environment, you can run `nix build .#dev` directly. The normal mvm path is `mvmctl machine build`, which runs Nix inside the builder VM. Output is a derivation with `passthru.mvm.{accessible, sealed, expectedBootMs}`. Check it from a Nix-enabled debug environment:

```sh
nix eval .#dev.passthru.mvm
# { accessible = true; entrypointKind = "shell"; expectedBootMs = 300; ... }
```

`mvmctl machine start` (against a manifest with `profile = "dev"`) runs the same `nix build` under the hood and boots the result.

### Cross-platform build notes

mvm runs Nix builds inside the project builder VM and copies the finished artifacts back to the host cache. You don't need Nix on your host, and you don't need to enter a dev shell before building. See [Builder VM](/guides/builder-vm/).

- **Linux** (with `/dev/kvm`): the builder VM owns image construction; Firecracker is the default runtime backend.
- **macOS Apple Silicon**: the host `mvmctl machine build` command orchestrates the builder VM. The resulting dev image can then boot on the selected macOS runtime backend.
- **Windows / WSL2**: WSL2 with nested `/dev/kvm` is supported for the libkrun-backed workload runtime path. Native Windows and a Hyper-V managed Linux builder are not supported local paths today.

## Why this is structured this way

ADR-013 names a single architectural commitment: **mvm is a library, your project owns its flake.** The previous iteration of mvm shipped a `nix/images/builder/` directory with a default dev-image flake that users would fork or edit. That coupled every user's dev workflow to mvm's internal layout, so any refactor of the library broke everyone's build.

The current shape:

- mvm exposes `mvm.lib.<system>.mkGuest` — a stable function the library promises not to break.
- Your project's flake calls `mkGuest` and exports a `.dev` package.
- `mvmctl machine start` reads `mvm.toml`, runs `nix build .#dev` against your flake, and boots the result.
- mvm's internal layout (where `mkGuest` lives, what tests use it, etc.) can change freely without your project noticing.

[Building MicroVM Images](/guides/building-microvm-images) covers the same model for production (sealed) images. The dev case is the same library with `entrypoint.shell` set.
