# Writable disk-image volumes no longer need `--profile dev`

Keeping data across a persistent `machine run` required `--profile dev`,
because the gate refused every `:rw` volume outside `dev` and `permissive`. The
dev profile also flips `dev_guest`: the dev shell agent and the DevOnly verbs.
So persisting data forced unsealing the guest. That coupling was the bug.

**What changed.** `ProfileGrants` now carries `writable_disk_images`, which
covers `HOST.img:/GUEST:SIZE:rw`: the guest writes into its own ext4 image
file, never into the host filesystem, and `standard`, `dev` and `permissive`
all grant it.

The old `writable_shares_when_persistent` grant is gone rather than renamed. It
let `dev` and `permissive` accept a `:rw` host directory on a persistent
machine, but a persistent machine cannot attach a live host directory at all:
`build_machine_volume_cfg` refuses every directory share at boot, read-only
included, and that refusal is architecture, not a bug. So the grant could never
be exercised, and the specs it admitted were guaranteed to fail at start. A
transient run's directory share is a read-only snapshot under every profile, so
no profile has a writable host directory left to grant.

`machine run` (persistent), `machine create` and `machine start` now go
through one gate, `enforce_volume_profile`. It refuses any directory volume
under every profile, with the same message the boot-time check prints —
`persistent_dir_share_refusal` words both, and names the two alternatives: a
disk image (`HOST.img:/GUEST:SIZE[:rw]`) or a snapshot registered with
`mvmctl machine volume mount`. A writable disk passes wherever
`writable_disk_images` is granted. `machine create` checked no volume grant
before this change, so a manifest volume under `--profile restrictive` got
through; it is now refused, and so is any volume on a persistent `machine run`
under `restrictive`. `machine start` re-checks a stored spec by its profile
name, beside the `dev.init` check, so a spec saved before the gate existed
refuses before admission; the boot-time check stays as defense in depth.

`machine create` defaults to `dev`, so a manifest whose `[dev].volumes` names
a directory is now refused at create time instead of at start. The test that
sourced machine defaults from such a manifest now uses a disk image, and the
create tests assert the refusal under every profile, the default included. No
BDD scenario created a machine with a directory volume. The library start path
(`mvm-client`'s `LocalBackend`) needs no gate: it already refuses every
CLI-grammar volume string.

The transient validator already let a writable disk through. It now reads
`writable_disk_images` rather than assuming it. `--prod` is transient-only and needed no change: nothing in admission treated a writable
disk differently. The new tests pin both the disk acceptance and the directory
refusal under `--prod`.

**What did not change.** A transient run's directory snapshot is still
read-only under every profile. `restrictive` still accepts no volume. The guest
mount allow-list (`MountPathPolicy`) is untouched, and it is still what keeps a
writable disk off `/usr/bin`; a test holds that under `standard` and `dev`.
Managed volumes attached with `machine volume mount` keep their own
`AdmittedProfile` rule, which still limits read-write to the dev tier.

`doctor`'s default-profile line now reads "env allowed; read-only host
directories on transient runs; writable disk images". ADR-001's dev-tier-hook
sentence, the CLI reference, and the profile, exec, filesystem, limits,
manifests, networking, config and nix-for-mvm guides describe the split. The
exec, config-secrets and nix-for-mvm guides showed persistent machines
(`-d`, or `--port`) taking a directory `--mount`, which fails at boot; they now
use a disk image or register the directory with `machine volume mount`.

The profile table moved out of `commands/vm/exec.rs` into `commands/vm/profile.rs`
together with its tests. The shared volume gate lives in
`commands/machine/volume_profile.rs`. Both grandfathered files shrank, and
`check-file-size` now pins them at their counts on top of current main: 1535
for `exec.rs` (from 1654) and 1733 for `machine/mod.rs` (from 1745).
