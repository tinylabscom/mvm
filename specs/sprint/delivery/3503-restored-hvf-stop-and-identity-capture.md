# 3503 — a restored HVF machine's stop reaps its state dir, and the checkpoint carries its identity drive

On an HVF Mac, `machine stop` of a machine created by `checkpoint restore` returned 0
but left `$MVM_HOME/vms/<name>/` behind, so the next restore of the same checkpoint
failed with `File exists`. The root cause spanned two sides, and fixing one without the
other would have replaced a leftover-directory bug with a missing-drive one.

## Stop side — nothing reaped a stopped machine's state dir

Only the reconcile pass removed a machine's state dir, and it runs on the next
state-touching command — which a checkpoint restore is not. A stop now removes the
stopped machine's runtime state under the machine's lifecycle lock
(`reap_unowned_state_dir`), sharing the socket-dir-aware removal
(`remove_runtime_dirs`) with the launch cleanup path. The lock is what tells a genuine
orphan apart from a restore that is still filling the directory before its supervisor
publishes a pid: a restore holds the same lock, so a concurrent stop or reconcile leaves
its directory in place. Reconcile's `reap_orphan` returns `Ok(false)` for a dir an owner
still holds rather than deleting it.

## Capture side — the checkpoint did not carry the identity drive

A restored HVF machine boots from the captured supervisor config, which lists the
guest's FlowMux identity drive (`flowmux-identity.ext4`) as a read-only virtio-blk disk.
`HvfVmFullControl::device_anchors` returned `identity: None`, so the drive never entered
the checkpoint content; the restore only worked because the parent's leftover state dir
still held it. The moment the stop fix reaps that directory, `remap_disk` refuses the
restore for a disk that is no longer on disk.

`device_anchors` now anchors the identity drive from the state dir when present, mirroring
the Firecracker control that already did. The generic capture path copies it into the
checkpoint content, and the merged chunked-restore staging (#3666) clones it back into the
restored state dir. `remap_disk` resolves the identity disk to the restore's own state-dir
copy, so a restore no longer depends on the parent's directory surviving.

## Fork mints its own identity

`materialize_checkpoint_blobs` clones every captured blob into a fork's child dir,
including the identity drive. A fork branches a new VM identity and must never boot on the
parent's captured signing key, so `fork_vm_full` mints a fresh identity drive over the
cloned copy (`reseed_forked_identity_drive`) — a no-op for checkpoints that captured none.

## Witnesses

- `reap_unowned_state_dir_keeps_a_dir_with_a_live_supervisor`,
  `reap_unowned_state_dir_removes_a_dead_dir_and_its_separate_socket_dir`,
  `fs_actions_reap_orphan_leaves_a_dir_whose_lifecycle_lock_is_held`,
  `a_held_lifecycle_lock_shields_a_dir_from_reap_orphan_state_dirs` — stop reaps under the lock.
- `stop_restore_stop_restore_needs_no_second_stop`,
  `stop_leaves_the_state_dir_of_a_restore_in_progress` — stop→restore→stop→restore, and the race.
- `capture_vm_full_includes_sidecar_blob_when_present`,
  `device_anchors_capture_the_identity_drive_when_present` — capture carries the identity drive.
- `child_config_remaps_the_identity_drive_to_the_child_copy` — restore resolves it into its own state dir.
- `fork_vm_full_mints_a_fresh_identity_drive_for_the_child` — a fork does not inherit the parent's drive.
- LIVE on a macOS 26 HVF host: create → start → checkpoint → stop → restore → stop → restore,
  three alternations, `vms/<name>/` gone after each stop. Transcript in the PR.

Companion issue #3690 (capture gap) closes with this change alongside #3503.
