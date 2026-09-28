# Writable managed volumes under `standard`

The previous change let a `HOST.img:/GUEST:SIZE:rw` disk image be writable
under `standard`, and left managed volumes on their own older rule: read-write
only under `dev` and `permissive`, decided by an `AdmittedProfile` enum with a
`Dev` and a `Sealed` variant and a `matches!(profile, "dev" | "permissive")`
name mapping. The CLI's volume commands hardcoded the dev tier, so `mvmctl` never
hit the rule. The library paths did: `LocalBackend` (launch and create) and the
embedder start host map the machine's profile name through it, so an embedder
under the default `standard` profile could not attach a writable managed data
volume, while the same user could pass `--mount HOST.img:/data:SIZE:rw` to
`mvmctl`.

**Managed-volume kinds.** There is one attachable shape. `LocalVolumeKind` has a
single variant, `BlockImage`, and `VmVolumeKind` has a single variant, `Disk`:
every registered attachment resolves to an ext4 image on a virtio-blk device.
It comes from one of two places:

- a managed block volume (`machine volume create`), an ext4 image decrypted
  into a private plaintext file while unlocked;
- a host directory registered with `machine volume mount --host`, which the CLI
  snapshots into an ext4 image in the content-addressed mount cache. A
  read-write registration attaches `writable_copy` of that image, a private
  reflink or copy under `volumes/host-snapshots/<vm>/`, so guest writes land in
  the copy and never in the source directory. A changed source replaces the
  copy at the next start.

No managed kind reaches the host filesystem live, so every kind now follows the
disk-image rule and none is held back to `dev`. `VolumeSourceKind` still
declares `ManagedDirectory` and `AdHocHostDirectory`, but nothing constructs
either: `volume_record` maps every catalog entry to `ManagedBlock`.

**One table.** The profile presets and `ProfileGrants` moved from
`mvm-cli/src/commands/vm/profile.rs` into `mvm-client` as
`mvm_client::profile`, with their tests. The library start paths receive a
profile by name and sit in `mvm-client`, below the CLI, so they could not read
a table kept in the CLI; putting the table where both can reach it avoids a
second copy. `mvmctl`'s `--profile` flag still parses straight into the enum:
`mvm-client` gained an off-by-default `clap` feature that derives `ValueEnum`,
and `mvm-cli` is the one crate that enables it. `clap` was already in the
`mvmctl` closure, and an embedder that does not enable the feature does not
link it.

`AdmittedProfile` is now a newtype over `Option<RunProfile>`, and
`permits_read_write` reads `grants().writable_disk_images`. The default
admits no profile, and so does a name that is not one of the four (`prod`, for
instance), and both refuse a writable attachment, as `Sealed` did. The two
refusal sites, attachment registration and launch-lease resolution, share one
message from `require_read_write`. It names the refusing profile and lists the
granting profiles, read off the table. The builders' `profile` methods take
`impl Into<AdmittedProfile>`, so a caller passes a `RunProfile` directly.

**Behaviour.** Every start checks a read-write managed volume against the
profile the machine's spec names: `standard`, `dev` and `permissive` admit it,
`restrictive` and an unrecognised name refuse it. That covers a library launch,
create or start, and `mvmctl machine start`. The CLI start host used to lease
registered volumes under a hardcoded dev tier, so a `restrictive` CLI machine
got a writable registered volume that `--mount` would have refused. It now
carries the stored spec's profile (`CliStartHost::for_spec`) into
`merge_registered_volumes_for_launch`.

`machine volume mount --rw` against a machine that already has a spec is
checked against that spec's profile at registration (`registration_profile`),
so a `restrictive` machine refuses there rather than at the next start. A
registration made before the machine exists has no profile to check yet and
registers as before; the first start applies the gate. Read-only managed
volumes are still admitted under every profile, `restrictive` included. The
guest mount allow-list is untouched.

**Surface.** `AdmittedProfile` was never serialized into a request or record,
so no wire, hostlib JSON, SDK stub or `schema/` shape changed. Its now-unused
serde derives were dropped. It is a public Rust type, and its `Dev`/`Sealed`
variants are gone.

**Tests.** `admitted_profile_follows_the_writable_disk_grant`,
`an_unrecognised_or_missing_profile_refuses_read_write`,
`the_read_write_refusal_names_the_granting_profiles`,
`attachment_request_refuses_read_write_without_a_granting_profile`,
`a_writable_managed_volume_leases_under_every_granting_profile`,
`restrictive_profile_refuses_read_write_launch`,
`the_embedder_host_leases_a_writable_managed_volume_under_standard`,
`the_embedder_host_refuses_a_writable_managed_volume_under_restrictive`, and
`launch_attaches_a_writable_managed_volume_under_standard_only_when_granted`,
`machine_start_leases_a_writable_registered_volume_under_the_spec_profile`, and
`a_writable_registration_against_a_restrictive_machine_is_refused_up_front`.
The profile table tests moved with the table. The existing CLI volume tests now
pass the dev profile explicitly and are otherwise unchanged.

**Docs.** The policy-profiles guide, the CLI reference's volume section, the
exec guide, and the persistent-workspaces guide describe the rule. The reference's volume table also stops describing managed volumes as
virtio-fs mounts and drops a `--host-backed` flag that `machine volume create`
does not have.

The filesystem page's managed-volume example mounted at `--guest /cache`, which
the mount allow-list refuses; it now mounts at `/data/cache`, and the page says
which roots are allowed. The docs-coverage ledger was regenerated: the `/cache`
form left `covered` because no page documents it any more, and the
`/data/cache` form was already covered.
