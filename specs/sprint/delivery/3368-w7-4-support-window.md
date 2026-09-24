# W7.4 — the image support window is published

Backing: shipped-source
Validation: check-doc-links

Issue #3368, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md` W7.4.

The releases reference now says which CLI versions read which image URLs, that
no release is deleted, when the legacy producer's lock entry goes (2026-12-31),
how pin updates arrive (weekly `update-image-pin.yml` proposals through the
merge queue), and that image changes land in `mvm-images`. The release-notes
prefix carries the same summary. It also corrects the page's claim that
`release.yml` builds the boot images; it has not since W6.

The per-version table was read from the source at each tag, not inferred:
v0.16.1 and v0.17.0 fetch everything from their own `v{version}` release;
v0.18.0-rc.1 fetches boot images from `boot-image/v0.1.5`; `main` fetches them
from the `mvm-images` set pinned by `images.lock`. Every version, including
`main`, still fetches the runtime overlay, SDK sidecar and initramfs from its
own `v{version}` release — recorded in the plan as a precondition for W8's
workflow wave, since removing the mirror before those move would strand every
new CLI.

Recorded in the same change: the W7.3 rollback drill cannot target the
`legacy` lock entry, because `boot-image/v0.1.5` publishes no signed root to
pin; it needs a second `image-set/v*` release.
