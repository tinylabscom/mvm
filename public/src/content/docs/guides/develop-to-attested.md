---
title: From dev loop to attested image
description: Start from an OCI image or a Nix flake, capture what your workload actually needs, and end with a sealed, hashed, recorded artifact.
---

The path from "does this even run?" to "this is an attested artifact" is meant to
be one line of travel: pick a base, iterate until it works, then seal and record
the result.

This page documents that path **as it works today**, and is explicit about the
parts that are designed but not yet built.

## 1. Pick a base — OCI or Nix, both are first class

```bash
# OCI: fastest start, no flake and no host Nix
mvmctl machine run --image python:3.12 -- python -c "print(2 + 2)"

# Nix flake: reproducible, minimal, carries only what you declare
mvmctl machine run --flake . -- ./app
```

Both compile to the same thing — a signed image plus a launch plan — and boot
identically on every backend. They do not carry the same provenance story;
see [Nix and OCI](/guides/nix-and-oci/) for the difference.

## 2. Declare what the workload needs

Dependencies are declared alongside the workload, and **the lockfile must be
hash-pinned**. An entry without an integrity hash is rejected at compile time
rather than resolved at build time:

```python
# app.py
import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    dependencies=mvm.python_deps(lockfile="uv.lock", tool="uv"),
)
def detect(path: str) -> int:
    import cv2                     # opencv, resolved from the pinned lockfile
    return len(cv2.imread(path))
```

```bash
mvmctl build compile app.py --out ./out
mvmctl machine build --flake ./out
```

`uv.lock`, `yarn.lock` and the other supported formats are each checked for
per-entry integrity hashes. This is what makes the resulting dependency set
reproducible rather than merely recorded.

## 3. What you get: a sealed dependency volume

Building installs the declared dependencies into a **sealed volume**, not into
the image. That volume carries:

- the installed content, hash-locked
- an SBOM (`sbom.cdx.json`)
- a CVE scan (`cve.json`)
- a fetch log
- a hash-chained `meta.json` binding all of the above together

```bash
mvmctl deps inspect HASH   # read the sidecars without booting a VM
mvmctl deps audit
```

The supervisor verifies this volume before launch and refuses a tampered one, so
the dependency set is part of the workload's admitted identity — not a
convention. `--prod` additionally fails closed on high or critical CVE findings,
and on a stub SBOM or CVE report.

## 4. Run it

```bash
mvmctl machine run --entrypoint --flake ./out
```

The image, the environment it boots in, and the sealed dependency volume are all
pinned into the signed execution plan, and every admission is recorded in the
chain-signed audit log.

## Designed, not yet built

The following are specified in `specs/plans/291-develop-build-deploy-attested.md`
and **do not exist yet**. They are listed here so the intended shape is legible,
not because they can be run:

- **`mvmctl deploy`** — seal, compute the artifact's BLAKE3 identity alongside
  its SHA-256 interop digest, and write a deploy record. If a remote (`mvmd`) is
  configured it ships the recorded artifact; if not, you still end up holding a
  sealed, recorded artifact locally.
- **`mvmctl watch`** — rebuild on source change during development, skipping
  no-op rebuilds by content address.
- **Capture from the sandbox** — install a dependency inside a dev sandbox and
  capture it into the sealed volume, then emit it back out as a declaration you
  can commit. The capture path is designed to converge on the declared path
  above, keeping the same hash-pin requirement, rather than becoming a second
  way to specify dependencies.

Until those land, the declared route in step 2 is the supported way to get a
dependency into an attested workload.

## Why two digests

Deployed artifacts are designed to carry both BLAKE3 and SHA-256, and the
distinction is deliberate:

- **BLAKE3 is identity.** It is a tree hash, so a large rootfs can be verified
  incrementally and in part rather than read end to end.
- **SHA-256 is interop.** OCI registry digests, cosign signatures, and in-kernel
  dm-verity all specify SHA-256, and dm-verity has no BLAKE3 support at all — so
  verified boot keeps its SHA-256 roothash.

Anything that pins a digest states which of the two it means.
