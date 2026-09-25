# `machine rm` removes the machine's instance directory

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli commands::machine

The `v0.18.0-rc.2` release dry run on the GPU-endpoint fix branch failed both
GPU witness scenarios at `machine volume mount … --guest /data/shims` with
`VM already has a volume mount at "/data/shims"; remove it first`, although the
previous run on the same self-hosted runner had removed both machines.

`machine rm` deleted `machines/<name>/` and `vms/<name>/` but not
`instances/<name>/`, which holds the per-VM volume mount registry
(`volume_mounts.json`) and any sealed snapshot. The documented-surface run
sweeps leftover `bdd-` machines with `machine rm`, the registry survived, and
the next machine created under the same name inherited mounts it never asked
for. Any user re-using a machine name hit the same thing.

Two changes, because fixing removal alone leaves every orphan already on disk in
place — which is what a second dry run on the same runner showed:

- `remove_machine_runtime_state` removes the instance directory as well, under
  the same no-live-process condition as the runtime state directory
  (`a_machine_recreated_under_a_removed_name_starts_with_no_volume_mounts`).
- `save_machine_spec`'s exclusive create discards `instances/<name>/` it finds
  already present, since a machine that did not exist a moment ago cannot own
  it; a live process on the name's runtime state leaves it alone, and a forced
  overwrite of an existing machine keeps it
  (`a_new_machine_does_not_adopt_an_earlier_machines_instance_state`,
  `overwriting_a_spec_keeps_the_machines_own_instance_state`). All three create
  paths — `machine create`, `machine run --name`, and the client's persistent
  launch — go through that write.
