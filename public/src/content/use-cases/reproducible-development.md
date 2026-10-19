---
title: Share a development environment, not a setup checklist
description: Define a repeatable development microVM with Nix so teammates can review and reuse the same runtime inputs.
team: Developer experience
outcome: Make environment changes reviewable
order: 4
guide: /examples/dev-vm-from-flake/
guideLabel: Build a development VM from a flake
---

## The situation

A project depends on particular compilers, system packages, and runtime versions. New teammates reproduce a setup by hand, and environment changes are hard to distinguish from application changes.

## A workflow with mvm

1. Declare guest packages in `flake.nix` and commit the pinned `flake.lock`.
2. Choose runtime sizing and profile in `mvm.toml`.
3. Build and boot a named development VM. Use console access for interactive debugging and guest execution for scripted commands.
4. Review lockfile changes when updating dependencies. Rebuild the guest and explicitly preserve only the state the project needs.

For example, a team maintaining a Python service with native dependencies could share the guest definition so a new teammate starts from reviewed inputs rather than a sequence of workstation modifications.

## What your team gains

The environment is code that can be reviewed with the application. Runtime dependencies live inside the guest rather than becoming another collection of packages installed on every developer’s host.

## What to plan for

Repeatable inputs do not guarantee identical application behavior across different hardware or external services. Check platform support, keep secrets out of flakes and manifests, and use declared volumes or file transfer for intentional persistence. Treat saved snapshots as sensitive state.
