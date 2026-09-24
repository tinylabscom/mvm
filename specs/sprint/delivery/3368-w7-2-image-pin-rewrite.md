# W7.2 — the image-pin update workflow could not update the pin

Backing: shipped-source
Validation: cargo nextest run -p xtask repin_image_lock; cargo nextest run -p mvmctl --test release_assets image_pin

Issue #3368, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md` W7.2.

W7.2 needs one green `update-image-pin.yml` dry run as a window signal. The
workflow had never run, and running its lock-rewrite script against the real
`images.lock` and `image-set/v0.1.0` root failed immediately:
`missing [stage0_kernel.aarch64] in images.lock`. The script named sections and
keys from an earlier lock layout (`[stage0_kernel.<arch>]`, `asset`) where the
lock has `[stage0_kernel.artifact.<arch>]` and `name`, and it never advanced
`[stage0_kernel] release_tag`, which the lock parser requires to match the root.
The weekly schedule would have failed every Monday without proposing a pin.

The rewrite is now `xtask repin-image-lock <image-set.json>`. It reads the root
through `ImageSetManifest`, edits values in place so comments survive, and
re-parses the result with `ImageTrainLock::parse`, refusing a lock that does not
read back as exactly the candidate's tag, digest, compatibility and Stage 0
artifacts. Against the real root it reports the current lock unchanged.
