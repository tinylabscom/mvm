---
title: Transparent rebuilds
description: Rebuild a development image while preserving intentional workspace state.
---

> **Status:** Planned product workflow. The current safe workflow is explicit:
> edit the flake or manifest, run `mvmctl machine build`, restart or replace the VM,
> and keep persistent data in declared workspace state.

Transparent rebuilds are the target developer experience for package changes:
the user asks for a new dependency, `mvm` rebuilds the rootfs through the
builder VM, the running development session is replaced, and the intended
workspace state remains available.

## Current explicit workflow

```sh
$EDITOR flake.nix
mvmctl machine build --flake ./my-app
mvmctl machine stop devbox
mvmctl machine run --flake ./my-app --name devbox -d
mvmctl machine console devbox
```

This keeps rebuild semantics obvious. The rootfs comes from the Nix flake; the
runtime guest boots the built artifact; persistent files must live in declared
workspace state rather than accidental image mutation.

## Planned workflow shape

The transparent version should preserve the same security boundary:

1. Detect the requested package or flake change.
2. Build the new artifact in the builder VM.
3. Show the rebuild plan and changed inputs.
4. Stop or pause the development VM.
5. Boot the new artifact.
6. Reattach the console when the guest is ready.

Live in-guest processes should be treated as restarted unless a future
checkpoint mechanism is explicitly implemented and verified.

## Security requirements

- Rebuilds must go through the builder VM, not ad-hoc in-guest mutation.
- Changed inputs should be visible before replacement.
- Persistent state must be deliberate and scoped.
- Secrets should not be baked into the rebuilt image.
- Rollback should use an earlier recorded artifact, not an untracked rootfs.
