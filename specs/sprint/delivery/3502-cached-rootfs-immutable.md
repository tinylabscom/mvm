# A Linux boot no longer rewrites the admitted rootfs (issue #3502)

On a Linux host every `mvmctl run --no-detect -- <cmd>` changed the bytes of
the cached default development image at
`$MVM_HOME/cache/default-microvm/dev/rootfs.ext4`, after admission had hashed
it, so `plan.admitted` recorded a digest the file no longer had.

Root cause: the guest did not write it. The root drive is attached read-only
(`is_read_only: true` on Firecracker). The writer was the host. `WorkloadRunner::start`
ran `/sbin/e2fsck -f -y` on every unsealed rootfs immediately before boot, on
Linux only. A forced check of a clean filesystem still rewrites the superblock
(last-write and last-check times, lifetime writes, checksum), so the digest
moved on every run. That is why HVF on macOS and the verity-sealed image were
unaffected: the repair was compiled only for Linux and skipped any image with a
verity sidecar. Under `strace`, that `e2fsck` was the only process that opened
the image `O_RDWR`.

- The pre-boot host repair is gone, along with `mvm_build::builderd_host`, whose
  only caller it was.
- `mvm_fs::ext4::journal_state` reads the primary superblock without opening
  the image for write. `start` refuses, by name and before any boot, an ext4
  rootfs whose journal still needs replay. A read-only guest cannot mount one,
  and the host may not repair an admitted, shared image in place. Builders
  already seal the journal before export (`e2fsck -p -f` inside the builder VM),
  so a fresh image passes.
- `mvm_core::config::default_microvm_cache_dir_at` resolves the cache under an
  explicit home, for the harness.
- Docs: the filesystem reference no longer calls `/dev/vda` read-write, and
  troubleshooting covers the new refusal.

Witnesses:

- `start_boots_the_admitted_rootfs_without_rewriting_it` and
  `start_refuses_a_rootfs_whose_journal_needs_replay_before_boot` (runner), and
  the `refuse_rootfs_needing_journal_replay` and `journal_state` unit tests.
  Revert experiment on the Linux KVM host: with the old start path restored,
  both runner tests fail. The first fails with "start rewrote the rootfs after
  it was admitted".
- BDD `@live @firecracker` scenario "a transient run leaves the cached default
  development rootfs byte-identical" in `s5_lifecycle/transient_sandbox_boot`.
  It checks the digest across a second run and the last `plan.admitted`
  `image_sha256` against the file. It fails against the old binary and passes
  against the fix.

Live witness (x86_64 KVM host, Firecracker v1.14.1, isolated `MVM_HOME`):

- Before: admitted `0dacd16e…`, and the file afterwards was `7c2895f5…`.
  `e2fsck -f -y` was exec'd on the image.
- After, on a warm home: three runs left the digest at `7c2895f5…` every time.
  The mtime did not change, nothing opened the image read-write, no `e2fsck`
  ran, and `plan.admitted` recorded `7c2895f5…`.
- After, on a fresh home: the first run built and cached `7e71ca79…` and was
  not refused. Runs two through four each left it at `7e71ca79…`, with
  `plan.admitted` recording `7e71ca79…`.
