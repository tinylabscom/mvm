# Release E2E fetches the signed builder image; cold source bootstrap moves to a nightly witness

Backing: shipped-source
Validation: cargo nextest run --test github_actions_extended_e2e

The Linux documented-surface lane built the builder VM image from source before
any of its 313 scenarios ran. On the 2026-09-15 and 2026-09-16 nightlies that
preparation took 37 and 38 minutes of a two-hour job; the builder image itself
is examined by no scenario. On the 2026-09-16 release dry run the second Stage 0
of that preparation hung for its full two-hour builder timeout, and the job was
cancelled at 180 minutes before the suite started.

## What changed

- `e2e-docs-linux` sets `MVM_BOOT_IMAGE: fetch` and names
  `MVM_BUILDER_BACKEND: firecracker`, matching the macOS lane. The Stage 0
  grants (readable `/boot` kernel, vhost-vsock ownership, QEMU and virtiofsd)
  are gone from that job, so a lane that drifts back into a source bootstrap
  fails in seconds instead of spending the budget.
- `scripts/e2e-documented-surface.sh` bootstraps the builder image with the
  embedded, verifier-carrying binary **before** the SDK sidecar build. The
  sidecar is still built from the tree, through the unembedded binary; the
  helper that binary re-executes finds the image ready rather than being asked
  to fetch it without the verifier compiled in.
- Firecracker joins HVF in building the source-matched SDK sidecar as a shell
  job inside the builder image it already has. Previously every non-HVF backend
  ran a separate Stage 0 for the sidecar regardless of `MVM_BOOT_IMAGE`, which
  would have kept the Linux lane paying for Stage 0 after the fetch.
- Extended CI gains `source-bootstrap-linux`, running
  `scripts/e2e-source-bootstrap.sh` (`just e2e-source-bootstrap`) nightly
  against a cold home with a read-only token: the unembedded sidecar hand-off,
  a from-source `mvmctl bootstrap`, and a user flake build through the result.
  Every step is fatal, and the script refuses a warm home or
  `MVM_BOOT_IMAGE=fetch`.
- Both harnesses emit `[phase] name=<phase> seconds=<n>` lines and a summary
  table (also written to the GitHub step summary) through
  `scripts/e2e-phase-timings.sh`, including on a failed or interrupted run.

## Fetch verification, made fail-closed where it was not

The published-image fetch already refused a digest mismatch, a missing asset,
and a missing or malformed signature bundle. It did not refuse the rest:

- **Partial installs.** Artifacts were downloaded straight into the live cache,
  so a failure after the kernel and rootfs verified left a cache the bootstrap
  treated as ready. The fetch now stages every artifact beside the cache and
  swaps the directory in only after every check passes; a failed swap restores
  the previous cache.
- **Architecture.** Nothing compared the image to the host. A foreign-arch
  request is refused before any network I/O, and the image's own
  `manifest.json` must declare `<arch>-linux` and pin the same kernel and rootfs
  digests (and sizes) as the signed checksum manifest.
- **Provenance.** A fetched image now records `source_kind`, the boot-image tag
  and the acquisition time in its provenance sidecar, and prints
  `Builder VM image source: fetched (<tag>), signature and digests verified` —
  or names the waiver env var when verification was waived.
- **Wrong signing identity.** A real `v0.18.0-rc.1` bundle signed by the CLI
  release workflow is committed as a fixture; it verifies offline under the CLI
  train and is refused by the boot-image train.

Revocation is **not** added here. Boot images have no published revocation
channel: the `revocations` release that `revocations.yml` would publish does
not exist, so a fail-closed check would refuse every fetch. The plan assigns
revocation negative tests to W3 (#3365), where the image-set manifest and its
revocation channel are defined.

## Live evidence

On the x86_64 KVM host (8 cores, rotational disks), against a cold home with
`MVM_BOOT_IMAGE=fetch` and the Firecracker builder, running this change:

| Step | Seconds | Result |
|---|---:|---|
| `mvmctl bootstrap` (fetch + verify the pinned image) | 399 | `Builder VM image source: fetched (boot-image/v0.1.5), signature and digests verified` |
| unembedded `build sdk-sidecar build`, cold Nix store | 1466 | glibc and musl built as Firecracker shell jobs; no Stage 0 cache created |
| `machine build --flake examples/exit_code` (earlier run, same image) | 869 | built through the fetched image |

The sidecar figure splits into about 4 minutes rebuilding the embedded
bootstrap helper, 13 minutes for the glibc image and 7 for musl. That cost was
already inside the baseline's 37 minutes — the Stage 0 sidecar build on the
2026-09-16 release dry run took 24 — so what this change removes is the
from-source builder image bootstrap, not the sidecar.

## What to expect from the measurement

**Measured (2026-09-17 dispatch and the 2026-09-18 nightly), 313 scenarios
passing in both:** the job went from 118 minutes to 92 and 106. Image
preparation fell from 37 minutes to 30.0 and 34.2, of which the fetched builder
image is 6.6 and 7.7 and the source-matched SDK sidecar is 23.4 and 26.5. The
25-minute target is met by one run and missed by the other, so the hypothesis
is rejected as stated and the sidecar build is what remains.

The prediction below held.

The release-lane speedup was not claimed in advance. Two things were known
before the measurement:

- The failure it prevents is the larger effect: a Stage 0 hang cost the whole
  180-minute budget and a release dry run, and the lane no longer runs one.
- On a healthy night the saving may fall short of the 25-minute target, because
  the source-matched SDK sidecar build is now the dominant preparation cost. If
  the measurement confirms that, the next candidate is acquiring the published
  signed sidecar when its source fingerprint matches the tree — a change to what
  the release gate proves, and a decision to take on its own.
