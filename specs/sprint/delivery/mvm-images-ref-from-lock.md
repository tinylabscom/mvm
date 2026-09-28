# Gating lanes build from the mvm-images commit images.lock pins

Backing: shipped-source
Validation: cargo run -q -p xtask -- check-image-lock

The v0.18.0 release failed after it was tagged, in "Documented surface e2e
(macOS, HVF)". That lane builds the source-matched SDK sidecar from an
`mvm-images` checkout, and the checkout was `ref: main`. `mvm-images` `main` had
just started writing `compatibility.builder_boot_abi` into the local image-set
manifest, which this tree parses with `deny_unknown_fields`, so the sidecar
build was refused at the parse stage. Nothing in this repository had changed.

`ci.yml`'s merge-queue guest-image witness had the same `ref: main`, so the
same change would have blocked every merge as well.

## What changed

- `xtask image-source-ref` prints the `mvm-images` commit that produced the
  locked image set. It downloads the root manifest the lock names, refuses it
  unless it hashes to the lock's `manifest_sha256` and passes
  `check_against_lock`, and prints `producer.source_commit`. The lock stays the
  only pin: the commit is derived from the bytes it pins, not copied beside
  them, and unlike the release tag it cannot be moved.
- `e2e-docs.yml` (both jobs; called by `release.yml` and nightly Extended CI)
  and `ci.yml`'s `guest-image-boot` check `mvm-images` out at that commit.
- `image-pair.yml` keeps comparing the two `main`s. It is the cross-repository
  canary: schedule and dispatch only, so a red run blocks nothing.
- `xtask check-image-lock` now fails when a workflow checks the image
  repository out at any ref not produced by `image-source-ref` (including no
  ref, which is the default branch), and when a canary gains a pull-request,
  merge-queue, push or `workflow_call` trigger.

## Consequence

A change here that needs newer `mvm-images` sources can no longer pick them up
from `main` implicitly: they have to be published in an image set and pinned
first. That is the cost of a release lane that the other repository cannot
break.
