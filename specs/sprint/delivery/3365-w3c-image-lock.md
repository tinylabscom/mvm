# One checked-in lock for the published image pins

Backing: shipped-source
Validation: cargo run -p xtask -- check-image-lock

The boot-image tag was written out by hand in `mvm-core`'s config, in
`mvm-build`'s Stage 0 pins, in four workflows, in a shell script and in two
integration tests. A copy left behind is not a type error and fails no test: it
is a 404 on a fresh install's first boot, or a CI lane validating different
bytes from the ones users receive.

`crates/mvm-core/images.lock` is now the one place those pins live, compiled
into `mvm-core` and read through `mvm_core::image_set::image_train_lock()`:

- the repository every artifact is published under;
- the boot-image release tag;
- the Stage 0 bootstrap kernel's release tag and its per-architecture asset
  name and SHA-256.

Stage 0 composes its download URL from the locked repository, tag and asset
name, so a pin cannot name a host the lock does not trust. Jobs with no Rust
toolchain read the tag through `scripts/locked-image-tag.sh`.

## What it does not pin

No `manifest_sha256`. No image set has been published, so that digest does not
exist, and a lock carrying an invented one would be a placeholder dressed as a
pin. `ImageLock` joins the file as its own section when the first set is
published.

## `latest` is gone

`workers.yml` and `scripts/download-qemu-wasm-smoke-pack.sh` each listed
published releases and took the highest version, which made what they fetched a
property of whoever published last. Both read the locked tag now.

## The gate

`xtask check-image-lock`, run by `check-all`, scans workflows, scripts and
tests. It refuses a concrete boot-image tag that is not the locked one and a
pattern that enumerates published releases, naming the file and line. The push
glob that fires the publishing workflow and the wildcard in a signing identity
select nothing and pass. It also runs the shell reader and refuses if it
disagrees with the parsed lock.

Writing a stale tag back into `.github/workflows/ci-full.yml` turned the gate
red with that file and line named; restoring it turned it green again.

The first run over the shipped tree found two false positives, both fixed here:
an illustrative tag in a `release-boot-image.yml` comment, now the
`boot-image/vX.Y.Z` placeholder, and the bare `boot-image/v` prefix a test
asserts a composed URL sits under, which the classifier had read as a regexp.
A token that ends right after the prefix is now its own non-finding, and every
other character after it still fails closed.
