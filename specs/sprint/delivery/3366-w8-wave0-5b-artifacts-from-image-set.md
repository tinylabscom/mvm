# W8 Wave 0.5b — the overlay, sidecars and initramfs come from the image set

Backing: shipped-source
Validation: cargo nextest run -p mvm-build --features test-support

Issue #3366, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md`
Wave 0.5b.

The runtime overlay, both SDK sidecars and the initramfs were the last three
guest artifacts a CLI fetched from its own `tinylabscom/mvm` `v{version}`
release, under the CLI release identity. They are now acquired as members of
the image set `images.lock` pins: the signed root is verified first, then each
member's digest and size against it, through one acquisition boundary.
`PublishedImageSet` moved from `mvm-cli` into `mvm-build` so `mvm-client`
reaches the same boundary instead of a copy.

The install half is unchanged, including the refusal of a `VERSION` that
differs from the running CLI. That holds today: the pinned `image-set/v0.2.1`
members carry `VERSION` `0.18.0-rc.2`, the version `main` builds. The
release-decoupling item in the plan removes that coupling for set members
before the next CLI release.

This is what lets Wave 3 remove the release mirror: no CLI built from `main`
reads those three artifacts from its own release any more, and released CLIs
keep reading the copies already attached to theirs.

CI: mvm-build's `test-support` tests joined the targeted lane, so the
acquisition tests that need the image-set fixture run on every PR.
