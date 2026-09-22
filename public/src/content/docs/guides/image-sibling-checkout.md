---
title: "Developing Images with a Sibling Checkout"
description: Point mvmctl at a local mvm-images checkout to build and boot images you are editing, without publishing anything.
---

mvm's own system images — the builder VM, the default workload image, the
rootless workload image, their profile-matched workload kernels, the guest
runtime overlay, and the SDK sidecars — are built
from the [mvm-images](https://github.com/tinylabscom/mvm-images)
repository, not from the mvm checkout. Ordinarily a contributor build uses
the image flakes still inside the mvm checkout, and release builds use
published sets. This page is the third mode: you are **editing an image**
and want `mvmctl` to build and boot exactly your working tree, with no
release round-trip.

## The one rule: name the checkout explicitly

Nothing searches for a sibling checkout. You select one by pointing
`MVM_IMAGES_DIR` at it:

```sh
export MVM_IMAGES_DIR=../mvm-images
```

The path must be the root of a usable `mvm-images` checkout — a git
checkout carrying the repository's layout markers as regular files. A path
that is not one is an **error**, never a quiet fall back to the in-tree
flakes or the published set. Unset the variable and everything returns to
the default behavior.

Everything mutable is keyed by the pair of checkouts, so two pairs can work
concurrently without sharing state: images you build land in the local
image cache stamped with the identity of both checkouts, and an edit in
either one invalidates exactly the affected entries.

## The paired wrapper: `bin/dev`

`bin/dev` in the mvm checkout runs this mvmctl against the named images
checkout, with `MVM_HOME` and `CARGO_TARGET_DIR` scoped to the pair:

```sh
MVM_IMAGES_DIR=../mvm-images bin/dev machine run --flake ./examples/exit_code
```

Use it for any `mvmctl` invocation while developing images; it is the
supported entry point, and it keeps pair state out of both checkouts so
nothing written at runtime changes either one's recorded identity.

## Building one image

`mvmctl build image-set` builds one role of the selected checkout inside
the builder VM (never host Nix) and publishes it to the local image cache:

```sh
MVM_IMAGES_DIR=../mvm-images bin/dev build image-set builder-vm
MVM_IMAGES_DIR=../mvm-images bin/dev build image-set default-tenant
MVM_IMAGES_DIR=../mvm-images bin/dev build image-set rootless-tenant
MVM_IMAGES_DIR=../mvm-images bin/dev build image-set runtime-overlay
```

The SDK sidecars are attributes of the runtime-overlay role:

```sh
MVM_IMAGES_DIR=../mvm-images bin/dev build image-set runtime-overlay \
  --attr sdk-sidecar-image        # glibc
MVM_IMAGES_DIR=../mvm-images bin/dev build image-set runtime-overlay \
  --attr sdk-sidecar-image-musl   # musl
```

An unchanged pair answers from the cache without booting anything; change
either checkout and the affected target rebuilds. The `mvm-images`
repository's own [justfile](https://github.com/tinylabscom/mvm-images)
wraps the same operations from its side (`just image-set`, `just
release-check`), plus the gates a release runs.

## What consumes the selection

With `MVM_IMAGES_DIR` set, every image consumer builds from the checkout it
names: the builder VM a build runs in, the profile-selected workload image
and its matching kernel, the launch-time runtime overlay, and the SDK
sidecars. Default and rootless kernels/rootfses are separate members of one
atomic schema-v2 image set; a consumer selects both from the same generic
profile and architecture. With the selector unset, each consumer keeps using
the in-tree flakes or published artifacts, unchanged.

## Trust tiers

Everything built from a local checkout is classified **local-dev**, and the
records are enforced, not advisory:

- A **release build** of mvmctl refuses `MVM_IMAGES_DIR` outright — which
  images a released binary boots must not depend on the shell it was
  started from.
- A **production admission** refuses a local-dev image however it was
  selected — including a locally built image already sitting in the cache
  with the selector unset.
- Development boots are unaffected; the refusal is scoped to the
  sealed-production profile.

Comparing against a signed release during development is
`MVM_BOOT_IMAGE=fetch` (or `mvmctl image boot update`) with the selector
unset.

## A complete two-repository example

Starting from nothing, with the two repositories as siblings:

```text
~/work/
├── mvm/         # this repository, on a contributor branch
└── mvm-images/  # the image sources, on your image branch
```

```sh
# 1. Boot the stock exit_code fixture through the sibling's images.
cd ~/work/mvm
MVM_IMAGES_DIR=../mvm-images bin/dev machine run --flake ./examples/exit_code

# 2. Edit an image — say the default workload rootfs in
#    ~/work/mvm-images/images/default-tenant/image.nix — and rebuild only
#    that role.
MVM_IMAGES_DIR=../mvm-images bin/dev build image-set default-tenant

# 3. Boot again; the just-built bytes are what runs.
MVM_IMAGES_DIR=../mvm-images bin/dev machine run --flake ./examples/exit_code
```

Step 2 rebuilds once and caches the result under the identity of both
checkouts; step 3 answers from that cache. Revert the edit (or advance
either repository) and the next boot rebuilds exactly what changed.
