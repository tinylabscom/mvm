# Image administration boundary

`prepare_image(&PrepareImageRequest, Option<&mut dyn Read>, &TransferProgress)`
explicitly acquires and publishes registry, archive, stdin, or local-directory
inputs, and exposes typed transfer counters through the progress handle;
frontends format and display them.

`resolve_prepared_image(&ResolveImageRequest)` never acquires or repairs an
image. It checks the prepared guest-runtime identity, cache identity and
completion/verity artifacts. Production additionally requires a digest pin,
the current registry/signature policy, a host-signed verification receipt
bound to the resolved digest and semantic policy, a sealed guest profile, and
the recorded base-image vulnerability gate. It does not run cosign on launch.

Local sources remain development-only. Stdin belongs to the caller; the service
accepts a reader and does not access process stdin. Published local entries are
resolved by supplied source identity without rereading the original source.
Rootfs directories retain their explicitly unverified development provenance;
they do not gain registry trust through cache publication.

This is a privileged native client surface, not an SDK/host-ABI registration.
The old client OCI convenience helpers are not used as a substitute for this
verified policy.

## Pending helper-lifecycle integration

The CLI pull adapter still performs the existing best-effort orphan-helper
sweep. Direct client preparation needs the helper-domain owner's configured-home
sweep API wired into `prepare_image` before runtime preparation or
materialization. Preserve non-fatal sweep failures and once-before-spawn
behavior. Do not put this sweep on `resolve_prepared_image`: cache-only launches
must not pay for process discovery or spawn helpers.

This seam is handed to the parent integrator because the helper service is being
migrated independently. Until it is wired, direct client preparation does not
perform the old CLI orphan-helper cleanup.

## Test mapping from the CLI

All tests formerly under `commands::image::<module>::tests` retain their names
under `image_admin::<module>::tests`, except the progress-formatting test which
belongs to CLI rendering:

| Original CLI module | Client tests retained | Mapping |
| --- | ---: | --- |
| `base_image` | 5 | `image_admin::base_image::tests` |
| `materialize` | 22 | `image_admin::materialize::tests` |
| `pull_core` | 26 | `image_admin::pull_core::tests` |
| `cache` | 29 | `image_admin::cache::tests` |
| `ingest` | 11 | `image_admin::ingest::tests` |
| `oci_types` | 1 | `image_admin::oci_types::tests` |
| `trust_policy` | 8 | `image_admin::trust_policy::tests` |
| `trust` | 4 | `image_admin::trust::tests` |
| `source` | 9 | `image_admin::source::tests` |

`pull_progress_reads_as_bytes_of_total_with_a_percentage` moved from
`commands::image::pull_core::tests` to `commands::image::pull::tests`.

New public-service regression fixtures cover:

- valid prepared production receipt, tampered signature, semantic policy drift,
  formatting-only policy changes, and resolution that leaves evidence unchanged;
- local rootfs preparation/publication, resolution after removing the original
  source, and refusal after removing the cached verity artifact;
- rejection of local production inputs and absent stdin readers before acquisition;
- cold-cache refusal without network acquisition or new cache state.

Run the client tests with `cargo test -p mvm-client image_admin::`; run the
progress rendering test with
`cargo test -p mvm-cli pull_progress_reads_as_bytes_of_total_with_a_percentage`.
These commands are handed to the parent warm validation environment; no real
registry pulls, Nix builds, or VMs are required by the new fixtures.
