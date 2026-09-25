# HVF restore of a chunked checkpoint stages the whole content dir (issue #3666)

Every `mvmctl machine checkpoint restore` of a chunked HVF checkpoint failed
reading `supervisor-config.json` from the target's state dir.

Root cause: `HvfVmFullRestore::restore` took `rootfs_src.parent()` to be the
checkpoint's content dir and cloned every file in it into the state dir. Since
checkpoint content became chunked, `restore_checkpoint` materializes
`rootfs.ext4` and `memory.bin` into a scratch `.restore-*` dir, which holds
only those two files. The launch config, the device frame, the verity sidecars
and `device-anchors.json` stayed behind in the store's content dir, and the
`config_src` argument that names that dir was ignored.

- Staging is now `stage_restore_state_dir`. It clones the content dir, taken
  from `config_src` and falling back to the rootfs's own directory for a
  checkpoint that predates persisted launch configs, and then adds the rootfs
  and memory blobs wherever they were materialized.
- A whole blob that lives in the content dir is not cloned twice.
- The `VmFullRestore` signature and the chunked store are unchanged.

Witnesses:

- `a_chunked_checkpoint_stages_the_content_dir_and_the_materialized_blobs`.
  Revert experiment: with the old `rootfs_src.parent()` rule restored, it fails.
- `a_whole_blob_checkpoint_without_a_config_stages_its_content_dir`: the legacy
  layout still restores.
- `restore_refuses_before_spawning_when_the_checkpoint_has_no_saved_state`
  still reports the missing launch config.
