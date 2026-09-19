# A local image cache for sets built from a selected checkout

Backing: shipped-source
Validation: cargo nextest run -p mvm-build -E 'test(image_source)'

Slice W5d of the sibling-checkout workflow (#3364). A set built from a local
image checkout and a paired mvm checkout is kept so the same pair is not built
twice, and published so that no reader ever sees half of one. Nothing builds
into the cache yet; W5e's build verb is its first writer, and W5f–W5k move the
image consumers onto it.

## What changed

- `LocalImageCacheKey` names everything one output depends on: both checkouts'
  identities (commit plus working-tree state), the build target (an image role
  — `builder-vm`, `default-tenant`, `runtime-overlay`, `initramfs` or `kernel`
  — and a one-segment flake attribute), the guest architecture, the mvm
  checkout's toolchain pins (the `rust-toolchain.toml` digest and
  `[workspace.metadata.mvm.toolchain]` read through `embed_toolchain`), and the
  digest of each flake lock the role evaluates (`kernel/flake.lock` for the
  kernel, `flake.lock` for every image role). Paths are not part of the key, so
  two worktree pairs at the same identities share an entry. `derive`
  re-verifies the image selection first and refuses a lock or toolchain file
  that is missing or a symlink.
- An entry is `<mvm cache>/local-images/v1/<key digest>`, the digest taken
  over a domain-separated serialization of the key. It holds the set's
  `image-set.json`, the artifacts it names, and `cache-entry.json` recording
  the key, its digest, the manifest digest and the tier, which is always
  `local-dev`. Nothing else writes under `local-images/`.
- Publishing: `stage` hands out a fresh directory under `v1/.staging/` (the
  `cache_install` staging convention, so abandoned ones are reaped after six
  hours); `publish` requires the key's checkouts to still be the ones on disk,
  refuses a symlink, subdirectory or file the manifest does not name, verifies
  the set with `read_local_image_set`, requires it to record the key's
  checkouts, writes the record, makes every file read-only, syncs files and
  directory, and renames it into place. A second publisher of the same key
  finds the target occupied, verifies the winner, and discards its own copy.
- Reading: `lookup` refuses a key whose checkouts have changed since it was
  derived (an error, not a miss, since it would name the wrong entry), then
  re-verifies the entry — record, exact file list, manifest digest, and the
  full local-set verification. An entry that fails is renamed out of the
  namespace and deleted, and reported as `Evicted`; the caller builds as on a
  miss.
- `read_local_image_set` now has a caller, so its `xtask/dormant-controls.toml`
  entry is live rather than dormant.

## Evidence

The mvm-build `image_source` suite has 64 tests, 29 of them new, over real git
checkouts and a real cache directory: miss then hit for an unchanged pair; the
key records every input; each input — image edit, lock edit, arch, role,
attribute, zig pin, mvm edit — yields a distinct key, and a reverted edit
restores the original; an edit misses without destroying the old state's
entry; entries for two targets coexist; a stale key is an error and does not
evict; an image edit after selection is refused before the cache is read; a
stale set cannot be published under a fresh key; a crash mid-publish leaves no
visible entry and does not block the next publish; an abandoned staging
directory is reaped; an unpublished one is removed on drop; four concurrent
publishers of one key yield one `Published` and three `AlreadyPresent` with no
staging left; a symlink, a subdirectory, an unnamed file, a `../` artifact
name, a release producer, another architecture and a build-written record are
each refused at publish; an entry whose record claims `verified-release`, a
tampered artifact, and an entry moved under another key's name are each
evicted rather than served; a publish over a corrupt entry replaces it; the
default cache sits under `mvm_cache_dir()`; the key digest is
domain-separated; a symlinked flake lock and a missing toolchain file refuse
to key an entry.
