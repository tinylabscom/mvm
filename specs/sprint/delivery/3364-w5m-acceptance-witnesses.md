# W5 acceptance witnesses

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -p mvm-client -p mvm-build -E 'test(local_pair) | test(pair_default_image) | test(pair_routing) | test(two_pairs) | test(admission) | test(recorded_tier) | test(image_source)'

Slice W5m of the sibling-checkout workflow (#3364): the acceptance witnesses for
the whole selector workflow, and the fixes the witnessing surfaced.

## What the acceptance run found and fixed

The headline witness — a live boot from a sibling checkout through the selector —
ran end to end on physical Apple Silicon HVF (pair: an mvm worktree +
`mvm-images` at main, `MVM_IMAGES_DIR` set, `bin/dev machine run --flake
./examples/exit_code`). It exposed four real defects, each fixed here:

1. **Manifest-named entry files.** Pair cache entries name their files the way
   the image repository's manifest emitter names them — `<role>-<arch>-<name>` —
   while every consumer assumed the contract's plain names, installing bytes
   that did not exist (`vmlinux` → ENOENT after a successful 19-minute pair
   build). `CachedImageSet::contract_file` now resolves entry files by manifest
   role and contract-name suffix; the overlay and SDK-sidecar installers stage
   the contract files under their canonical names first
   (`stage_contract_files`, `stage_overlay_contract_files`). The test fixture
   now names artifacts the producer's way, so the tests exercise reality.
2. **Sealed perms leaking into writable caches.** Entry files are sealed at
   0444; the installed builder rootfs inherited that and the HVF bake's
   read-write open failed with EACCES. Installs now chmod copies to 0644.
3. **`Unknown` libc under a selector.** The launch-time sidecar arm bailed on
   `GuestLibc::Unknown`; `Unknown` selects no sidecar at all, so the pair arm
   now skips it and the resolver answers `None` as before.
4. **Admission over-refusal of the paired workflow.** W5a's blanket refusal
   (production admission refuses while the selector is set) rejected the
   headline flow itself: a developer's sealed workload from their own flake is
   `Variant::Prod` and the selector was set. With W5k landed, the tier
   refusals carry the production gate — the variable itself is now refused in
   admission only on release-channel binaries (which also refuse it at CLI
   entry, so a production run still cannot be steered by a local path), and a
   contributor build's sealed boot of its own-flake workload is admitted.
   Managed local-dev images remain refused however they were selected.

The boot then reached guest activation, where the workload's own flake-built
kernel has no device-mapper; the W4c x86_64 witness used the verity-capable
workload kernel for the same fixture. That kernel-selection difference is filed
as #3615 with the captured evidence; it is not an image-set defect
(`kernel/workload.nix` is byte-identical on both sides and sets
`BLK_DEV_DM`/`DM_VERITY`).

## Acceptance criteria × witnesses

- **Change an image in a sibling worktree and boot it without publishing** —
  witnessed live through the stages above (selector → pair builds of the
  builder-vm and overlay in the builder VM → install → HVF bake → workload
  boot to activation); the remaining activation gap is #3615.
- **A second run reuses the content-addressed result** —
  `an_unchanged_pair_misses_once_then_hits` and the W5d cache suite.
- **Changing either repository invalidates only the affected entries** —
  `every_input_changes_the_key`,
  `an_edit_misses_without_destroying_the_entry_for_the_old_state`,
  `an_entry_for_one_target_survives_a_build_of_another`.
- **Two paired changes run concurrently without sharing mutable state** — the
  new `two_pairs_publish_concurrently_without_sharing_cache_entries`
  (distinct keys, per-home entries, single-sided invalidation per pair); the
  wrapper's pair-scoped `MVM_HOME` keeps VM identities apart by construction.
- **Release binaries and production admission refuse the unsigned local pack**
  — release builds refuse the variable at CLI entry (W5a, unchanged);
  admission refuses recorded local-dev managed images under Prod before
  signing (W5k), and the in-admission variable refusal now gates on the
  release channel.
- **Path traversal, symlink substitution, stale manifest, wrong architecture
  fail safely** — the W5a/W5c negative suites and
  `a_set_for_another_architecture_is_refused`.
- **One base image, every Linux-direct backend** — the W4c witness record: the
  same default-image bytes boot on x86_64 Firecracker, aarch64 Firecracker on
  real hardware (rpi1), and HVF, with per-backend host-side adaptation only.

## Not done

- #3615: sealed flake workload kernel selection under the selector (filed,
  evidence attached). The W5h verity-capability gap for sidecar-less pair
  kernels is part of that question.
