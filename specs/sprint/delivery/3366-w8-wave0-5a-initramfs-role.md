# W8 Wave 0.5a (mvm side) — the initramfs is an image-set root role

Backing: shipped-source
Validation: cargo nextest run -p mvm-core image_set

Issue #3366, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md`
Wave 0.5a.

`ImageSetRole::Initramfs` enters the image-set contract in `mvm-core`: a
per-architecture member carrying `initramfs-<arch>.tar.gz`, the role and
artifact names `mvm-images` publishes. `mvm` must parse the role before
`mvm-images` can publish a set carrying it, because the producer's publish step
verifies the signed set with its own pinned `mvm` and refuses a role that `mvm`
cannot read. `image-set/v0.2.0` failed exactly there, fail-closed, before
anything was published.

The role is accepted but not yet required: `current_train()` still omits it,
because every set a released CLI pins today carries no initramfs member and
requiring one would refuse them all. The requirement gains the role in the same
change that first pins a set carrying it (`image-set/v0.2.1`).

Tests: a set carrying per-architecture initramfs members is well-formed,
complete and selectable; the role serialises as `"initramfs"`; the current
train does not require it.
