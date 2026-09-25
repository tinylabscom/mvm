# Writable disk-image volumes no longer need `--profile dev`

Keeping data across a persistent `machine run` required `--profile dev`,
because the gate refused every `:rw` volume outside `dev` and `permissive`. The
dev profile also flips `dev_guest`: the dev shell agent and the DevOnly verbs.
So persisting data forced unsealing the guest. That coupling was the bug.

**What changed.** `ProfileGrants` now splits writability by what the guest
writes into. `writable_disk_images` covers `HOST.img:/GUEST:SIZE:rw`: the guest
writes into its own ext4 image file, never into the host filesystem, and
`standard`, `dev` and `permissive` all grant it. `writable_host_dirs_when_persistent`
(renamed from `writable_shares_when_persistent`) covers a `:rw` host directory
and stays with `dev` and `permissive`. A directory share's content digest is
pinned at admission and fails closed on drift, so a guest writing into one
belongs with the profiles that already unseal the guest.

`machine run` and `machine create` now go through one gate,
`enforce_volume_profile`. It reads the table and splits on
`VolumeSpec::{DirShare, Disk}`. `machine create` checked no volume grant before
this change, so a manifest volume under `--profile restrictive` got through; it
is now refused, and so is any volume on a persistent `machine run` under
`restrictive`. The transient validator already let a writable disk through. It
now reads `writable_disk_images` rather than assuming it. `--prod` is
transient-only and needed no change: nothing in admission treated a writable
disk differently. The new tests pin both the disk acceptance and the directory
refusal under `--prod`.

**What did not change.** A transient run's directory snapshot is still
read-only under every profile. `restrictive` still accepts no volume. The guest
mount allow-list (`MountPathPolicy`) is untouched, and it is still what keeps a
writable disk off `/usr/bin`; a test holds that under `standard` and `dev`.
Managed volumes attached with `machine volume mount` keep their own
`AdmittedProfile` rule, which still limits read-write to the dev tier.

`doctor`'s default-profile line now reads "read-only host directories; writable
disk images". ADR-001's dev-tier-hook sentence, the CLI reference, and the
profile, exec, filesystem, limits and config guides describe the split.

The profile table moved out of `commands/vm/exec.rs` into `commands/vm/profile.rs`
together with its tests. The shared volume gate lives in
`commands/machine/volume_profile.rs`. Both grandfathered files shrank, and
`check-file-size` now pins them at their new counts: 1533 and 1720.
