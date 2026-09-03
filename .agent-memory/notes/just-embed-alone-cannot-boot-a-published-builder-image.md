---
title: A `just embed` binary cannot boot a guest from the published builder image — it lacks manifest-verify
date: 2026-09-02
tags: [embed, features, builder-vm, verification, e2e, falsification]
---

`just embed` builds with default features. That binary runs every host-side verb
and **cannot bootstrap a builder VM from the published image**, because verifying
the image's signed checksum manifest needs `manifest-verify`, which arrives via
the `user` feature and is not on by default.

The failure looks like a product bug and is not:

```
Error: ensuring the builder VM image before flake build

Caused by:
    0: building the source-checkout builder VM image via root-dir Stage 0
    1: refusing to parse an unauthenticated checksum manifest
       (builder-vm-aarch64-checksums-sha256.txt)
    2: release archive builder-vm-aarch64-checksums-sha256.txt failed signature
       verification: manifest signature is invalid: manifest-verify feature is
       disabled in this build; rebuild mvmctl with default features or set
       MVM_SKIP_COSIGN_VERIFY=1 in an emergency rotation.
```

Note the message's own advice — "rebuild with default features" — is exactly
backwards for this case. Default features are what produced the binary that
cannot verify. The fix is to add `user`.

## What to build instead

What `scripts/e2e-documented-surface.sh` builds, which is the only
configuration proven to boot a guest from the published artifacts:

```sh
cargo build --bin mvmctl --features user,release-artifact-bootstrap,embed-host-bins
just build-supervisors     # the per-VM helpers are separate bin targets
```

`just embed` is still the right thing for host-side work and for the payload
itself; it is only the *verified-fetch* path it cannot walk.

## Why this wastes time specifically

It surfaces in the middle of a live reproduction, minutes in, after the builder
VM has already been prepared — so it reads as "the thing I am debugging is
broken" rather than "I built the wrong binary". It cost one full builder-VM
cycle while verifying the fix for #3130, and it is the second of three distinct
failures that run hit, all of which wore the same clothes: this one, a
`timeout_secs: 0` sentinel that returned `124: wrapper exceeded 0s timeout`, and
finally the real bug. None of the three were what the previous one looked like.

## Do not

Do not reach for `MVM_SKIP_COSIGN_VERIFY=1`. It is documented as an emergency
rotation hatch, and using it to get past a local build-configuration mistake
means the run no longer exercises the verified-fetch path — so a green result
proves less than the one before it, silently.
