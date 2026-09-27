# Reinstalling a template revision no longer trips on a read-only `mvm-meta.json`

`mvmctl machine run --flake <dir>` could fail installing its build into the
template slot with `Permission denied` copying `mvm-meta.json` into
`~/.mvm/templates/<slot>/artifacts/revisions/<rev>/`. Contributors had been
running `chmod -R u+w ~/.mvm/{cache/builder-vm,templates,dev}` before rebuilds
to get past it.

## Root cause

It is one code path run twice, not two paths racing within a run.
`machine run --flake` calls `build_flake_to_slot` once, which calls
`template_build_from_manifest`, which always ends in
`install_revision_artifacts`. The dev-build cache hands back the same revision
for unchanged inputs (the fingerprint cache hit, or the builder's own "cache hit
on rev" when the revision directory already exists), so the second run of the
same flake reinstalls into a revision directory the first run already filled.
`template_build_from_image` does the same by design: its revision is keyed by
rootfs content.

`install_revision_artifacts` copied each artifact with `std::fs::copy`, which
gives the destination the source's mode. The sources are Nix store outputs at
`0444`, so the first install left `mvm-meta.json` (and `initrd` and
`image.tar.gz` when present) read-only, and the reinstall's `fs::copy` then had
to open that read-only file for writing. The rootfs escaped only because it was
`chmod u+w`'d after its copy; `fc-base.json` and `revision.json` are written
fresh by `fs::write` and were never read-only, which is why the failing
directory showed them freshly written next to a `0444` sidecar with the
source's mtime.

## Fix

One helper, `mvm_core::util::atomic_io::copy_writable`: copy into a temporary
sibling, add the owner-write bit (every other mode bit kept), rename over the
destination. The rename needs directory write access only, so an existing
`0444` destination is replaced rather than refused; readers see the old file or
the new one, never a partial copy; and a process with the old file open keeps
its bytes instead of having them truncated under it. The copied bytes are the
source's, so the digests and `.sha256cache` sidecars computed from them are
unchanged.

Routed through it:

- `install_revision_artifacts` (every revision artifact; the rootfs-only
  `chmod u+w` it had is gone).
- `copy_contract_file` in the local-pair installer, now a single
  implementation on top of the helper rather than a unix/non-unix pair with its
  own `chmod 0644`. For the sealed `0444` entries it copies, the result is the
  same `0644`. The redundant sidecar `chmod` after it in the default-image
  install is removed.
- The attested builder-pack copy into the builder-VM cache — the same cache the
  local-pair installer fills.
- The builder-VM cache seed from the shared default cache, whose target may
  still hold a previous entry's read-only files.
- The rootfs injection copy the patcher VM opens read-write.

Copies into a freshly created staging directory whose files are only ever read
(the dev-build staging copies, Stage 0's kernel pairing, the HVF bake's kernel
copy) were left as they are. `manifest export-oci` still uses a plain copy on
purpose: its `--out` is a user path that may be a device or a symlink, where
replace-by-rename would be the wrong semantics.

Tests: `copy_writable_leaves_a_fresh_destination_owner_writable`,
`copy_writable_replaces_an_existing_read_only_destination`,
`copy_writable_keeps_the_other_mode_bits`,
`copy_writable_failure_leaves_the_destination_alone`, and
`install_revision_artifacts_reinstalls_over_read_only_nix_outputs`, which
installs the same read-only artifacts into the same revision twice.
