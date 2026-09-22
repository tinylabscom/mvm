# Admission reads the tier recorded with the image it boots

Backing: shipped-source
Validation: cargo nextest run -p mvm-client -p mvm-build -p mvm-cli -E 'test(admission) | test(recorded_tier) | test(image_source) | test(production_admission)'

Slice W5k of the sibling-checkout workflow (#3364). A production admission
boots only verified released images — however the local bytes were selected.
W5a refused while the selector was set; this refuses what the boot actually
resolved, so a locally built image already sitting in a managed cache is
caught with the selector unset, and so is an in-tree Stage 0 builder or a
pair-installed default image.

## What changed

- `image_source::recorded_tier_for(path)` answers the tier recorded with a
  managed image cache entry: the default image's sidecar `source`
  (`fetched` → verified-release; `built-local`, `local-pair`, or anything
  unrecognized → local-dev), and the builder cache's provenance
  `source_kind` (only an explicit `fetched` verifies; Stage 0, pair installs,
  and unrecognized kinds are local). Unmanaged paths — an operator-named
  `--image` — record nothing and return `None`: their admission stays the
  digest pin. Both readers fail closed on unrecognized values.
- Admission (`admit_plan_for_boot`) refuses a recorded local-dev tier under
  `Variant::Prod`, after the existing variable-set refusal and before any
  hashing or signing. The two refusals are complementary: one keys on the
  selector, the other on the bytes.
- Ordinary boots read the tier too: `ensure_default_microvm_image` and
  `image boot update` report what the image they resolved records, so a
  local-dev boot is visible in the log without running `doctor`.
- The `doctor` image-source line adds the installed default image's rootfs
  sha256 (inside the identities segment — the three-segment line shape is a
  tested contract), corrects its stale "image builds do not consume this
  selection yet" note, and stays absent rather than guessed when nothing is
  cached.

## Evidence

- New tests: the tier readers (fetched/local/unrecognized/missing for both
  caches; unmanaged paths answer `None`); a production admission refuses a
  locally built cached image with the selector unset and before signing; a
  development admission accepts the same image; a production admission
  accepts a fetched one; the doctor line carries the digest prefix, keeps
  its segment shape, and the existing doctor/admission suites still pass.
- `cargo nextest run --workspace`: 14752 passed, zero failures.
- Workspace clippy with warnings denied: clean; `just check-gated` clean;
  every xtask gate clean.

## Not done

- W5l — contributor documentation, the two-repository example change, and a
  paired-change CI job checking out both repositories at explicit SHAs.
- W5m — the acceptance witnesses: cache reuse and single-sided
  invalidation, two concurrent pairs, stale manifest, wrong architecture, a
  live boot from a sibling checkout, and the same pair-built base image
  booted by every Linux-direct backend.
