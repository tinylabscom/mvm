---
title: Reproducible dev VM from a flake
description: Build a repeatable local development microVM from Nix.
---

Use a flake when you want the development runtime to be reviewable and
repeatable.

## Project layout

```text
my-dev-vm/
├── flake.nix
├── flake.lock
└── mvm.toml
```

`flake.nix` declares the guest content. `mvm.toml` selects the profile and
runtime sizing.

## Build and boot

```sh
mvmctl build ./my-dev-vm
mvmctl up ./my-dev-vm --name my-dev-vm
mvmctl machine console my-dev-vm
```

Use `mvmctl exec` for scripted commands and `mvmctl machine console` for interactive
debugging.

## Iterate

```sh
$EDITOR flake.nix
nix flake update
mvmctl build ./my-dev-vm
mvmctl machine stop my-dev-vm
mvmctl up ./my-dev-vm --name my-dev-vm
```

Only update `flake.lock` when you intend to change inputs. Review that diff.

## Security checklist

- Pin flake inputs.
- Keep secrets out of the flake and manifest.
- Use declared volumes or file transfer for state that should survive.
- Treat snapshots as sensitive state.
