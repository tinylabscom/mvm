# W8 Wave 0 — the in-tree image deletion inventory

Backing: shipped-source
Validation: check-doc-links

Issue #3366, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md` Wave 0.

`specs/plans/2026-09-24-w8-image-deletion-inventory.md` re-scans every
reference to the in-tree image producer from `main` and classifies it: delete
with its wave, keep, edit text, or re-point code that reaches the flakes
through a helper rather than a literal path. That fourth class is why the
count grew from the 2026-09-24 snapshot's 44 crate files and 7 workflows to 80
files outside `specs/`, including `kernel-build.yml` and twelve crate files
that name no `nix/images` path at all.

Three findings re-sequenced the waves:

- Waves 1 and 2 are compile-coupled — the CLI's source-checkout signal is the
  in-tree builder flake — so they land as one change.
- The runtime overlay, SDK sidecar and initramfs are still fetched from the
  CLI's own release. They move to the image set (Waves 0.5a and 0.5b) before
  Wave 3 can drop the release mirror. That move has to be on `main` before
  Wave 3, not in a separate CLI release: removing the mirror affects only
  releases cut afterwards, which all contain it.
- The initramfs is not yet a signed root member, and `mvm-images` refuses a
  role its pinned `mvm` cannot parse, so the role lands in `mvm` first and the
  image set publishes after `mvm-images` advances its pin.

No code changes.
