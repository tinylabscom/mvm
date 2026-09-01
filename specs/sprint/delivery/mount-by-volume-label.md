# A materialized mount is found by label, not by slot

Stage A of `specs/plans/2026-08-31-remove-virtio-fs.md`, the box that read:
*"The guest mounts by volume label rather than by the device node
`workload_volume_devices` resolves. The image **is** labelled, but the guest is
still handed a node… the difference between 'works' and 'cannot silently mount
the wrong device'."*

## What changed

`VmVolume` gains `volume_label`, set by `materialize_mount_volumes` from the
same authority that stamps the image (`mount_volume_label`, extracted so the
writer and the volume description cannot drift apart). `VolumeConfig` carries it
to the guest, and `resolve_volume_mount_source` prefers it over the node.

Resolution failure is **fatal, not a fallback**. Falling back to the device node
would mount whatever landed in that slot, which is precisely the failure the
label exists to prevent. A virtio-fs volume carrying a label is also refused —
a share has no filesystem to read one from, so its presence means the host built
a contradictory config.

## Reusing the resolver that already existed

The first version of this change hand-rolled a superblock parser and scanned a
guessed `/dev/vd[a-z]` range. `mvm-agentd` already had the whole thing:
`flowmux_drive::{read_ext4_volume_label, find_labeled_ext4_disk_among,
virtio_block_devices}`, written for the FlowMux identity disk.

The existing one is better in three concrete ways, which is the argument for the
rule rather than just the rule: it enumerates from `/sys/class/block` instead of
guessing a letter range, it checks the ext4 magic before trusting the label
field, and it is the decoder the writer's stamp is already tested against. The
duplicate is gone.

## Live validation

`mvmctl machine run --image alpine --mount /tmp/…:/work:ro -- cat /work/marker.txt`
on macOS 26.5.2 / arm64 printed the payload, before and after the dedup.

A passing mount alone would not prove the label path ran, so the image was read
while the VM was alive:

    magic@1080 = 53ef        (ext4)
    label@1144 = b'mvmmnt0\x00…'

That is `s_volume_name` at `1024 + 0x78`. Combined with the guest failing closed
on an unresolvable label, a successful mount means the label resolved.

**A measurement bug worth recording.** The first read of that offset returned
empty and looked like "the writer never stamped a label". It was `dd` reading a
path that had already been reaped when the transient VM exited, with `2>/dev/null`
hiding the missing-file error. Empty output read as absence. The rerun held the
VM open with a `sleep` and confirmed the file existed before reading it.

## Scope

Only `--mount` images are labelled today, so only they mount by label. Managed
volumes (`mvmctl volume`) keep mounting by node: their images are created
elsewhere and this change does not assume they carry labels. `volume_label` is
`None` for them, which selects the node path explicitly rather than by accident.

This is a guest-side change in `mvm-agentd`, baked into workload rootfs images,
so it takes effect for an image once that image is rebuilt. An image carrying an
older agent ignores the unknown field via `#[serde(default)]` and mounts by node
exactly as before — it does not fail.

## Not done: retiring `DirShare`

The sibling box (`VmVolumeKind::DirShare` / `LocalVolumeKind::Directory`) stays
open. `DirShare` is what records a *directory* grant in the plan, which claim 1
matches against, so removing it means relocating a claim-bearing fact through
the admission path. That is a security-model change, not cleanup, and does not
belong bundled with a mount-resolution fix.

## Verification

`cargo fmt --all --check`, `just check-gated`, `cargo clippy --workspace
--all-targets -D warnings`, `cargo nextest run --workspace` (12,891 passed),
`cargo test --workspace --doc`, `cargo run -p xtask -- check-all` (63 gates).

`check-gated` earned its keep twice here: it caught a `&str`/`String` mismatch in
the `cfg(target_os = "linux")` mount call and two exhaustive `VmVolume`
constructions in `mvm-conformance`, both invisible to `--all-targets` on macOS.
`check-stubs` caught the generated SDK stubs going stale from the new field.
