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

`remove_machine_runtime_state` now removes the instance directory as well, under
the same no-live-process condition as the runtime state directory. New test:
`a_machine_recreated_under_a_removed_name_starts_with_no_volume_mounts`.
