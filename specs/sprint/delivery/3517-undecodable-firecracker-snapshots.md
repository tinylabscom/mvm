# Name an undecodable Firecracker snapshot, and drop a standby that has one

Issue #3517, found landing #3493 (Firecracker v1.14.1 → v1.17.0).

A Firecracker snapshot is readable only by a Firecracker that writes the same
snapshot format, and the format changes between releases. Upgrading a host's
Firecracker leaves every snapshot the old one took unrestorable. Nothing said
so: the restore failed with Firecracker's raw API error, and a warm-pool claim
against such a parent returned it to rotation, so every later launch paid a
failed fork until the standby's TTL.

## What the live box showed

On the Hetzner KVM box, a snapshot taken by v1.14.1 and read by v1.17.0:

- `firecracker --snapshot-version`: `v8.0.0` (1.14.1) and `v12.0.0` (1.17.0).
- `firecracker --describe-snapshot` (1.17.0): `bitcode error`. The newer binary
  cannot read even the header of the older snapshot, so a snapshot's format
  cannot be asked for after the fact.
- `PUT /snapshot/load` (1.17.0): HTTP 400, `Failed to get snapshot state from
  file: Failed to load snapshot state from file: ... bitcode error`.

That ruled out the first design (compare the file's format with the binary's
before loading). What remains dependable is Firecracker's own taxonomy: every
failure to decode the state file (foreign encoding, format version, magic,
checksum, short read) is reported under `Failed to load snapshot state from
file`, unchanged from v1.14.1 to v1.17.0 and distinct from failing to open the
file. That is a property of the snapshot, permanent on this host.

## What changed

- `fc::snapshot_decode` classifies a failed `PUT /snapshot/load` as
  `UndecodableSnapshot` when Firecracker could not decode the state, and says
  so with the running Firecracker's version (`GET /version` on the socket the
  load already holds) and the remedy: capture it again. It runs only after a
  load has failed, so the restore latency path is untouched, and it adds no
  `sudo` shell. Any other failure keeps its own error.
- `StandbyError::Unrestorable` is the claim-side form. The Firecracker driver
  maps an undecodable fork restore to it, and the claim drops that parent from
  the pool instead of releasing it, while still cleaning up the child dir and
  any paused child.
- `WarmClaimLease` moved to `workload_runner/runner/claim_lease.rs`, which keeps
  `runner.rs` under the file-size cap.
- `capabilities::running_version` factors the `GET /version` read out of
  `FcCapabilities::probe`, which both now use.

## What this does not do

- It does not make an old snapshot restorable; nothing can, short of keeping
  the old Firecracker.
- It does not pre-empt the failure. A snapshot's writer is not recorded, and the
  file cannot be read by a newer binary, so the refusal still comes from the
  load. It is named, and for the pool it is not repeated.
- Template snapshot restore on Firecracker is refused outright
  (`restore_from_template_snapshot`), so the unused `SnapshotCompatibility`
  contract on `SnapshotInfo` protects nothing and was left alone.

## Validation

`cargo fmt --all -- --check`; `RUSTFLAGS="-D warnings" just check-gated`;
workspace clippy; `cargo nextest run -p mvm-contract -p mvm-core -p mvm-vmm -p
mvm-backends -p mvm-runtime -p mvm-cli -p mvm-client` (7633 passed);
`cargo test --workspace --doc`; `xtask check-all`; the `test-support` library
lane (4809 passed). The classifier is tested against the exact message
Firecracker v1.17.0 returned on the box.
