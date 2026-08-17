# `mvmctl run npm test` picks the image

**Plan:** `specs/plans/329-run-first-cli-and-upstream-adoption.md`, Phase 2.

## What shipped

`mvm_core::runtime_catalog` — a curated, in-tree table mapping commands and
project files to OCI images, modelled on the existing `Catalog`/`CatalogEntry`
(same `search`/`find` shape, same `schema_version`) rather than inventing a
second catalog idiom. Six runtimes: python, node, rust, go, ruby, shell.

One resolver, `resolve_run_source`, shared by both verbs. The order is the
contract:

1. an explicit `--image`/`--manifest`/`--flake`/`--deployment`/`--runtime-pack`
2. `--runtime <name>` — an unknown name refuses and lists the known ones
3. `--no-detect`, or a verb that only takes explicit sources
4. an `mvm.toml` in or above the working directory
5. the command, then a project file
6. the bundled default

## What it reuses rather than reinvents

Step 4 is `mvm_core::domain::manifest::discover_manifest_from_dir` — the same
Cargo-style walk-up, stopping at the same `.git` boundary, that `mvmctl build`
already used. The project config file `mvm.toml` already existed and already
carried an image; it was simply never consulted by a run. No second config idiom
was added.

## Two decisions worth recording

**Detection picks a source, never a posture.** An inferred run admits through the
same signed `ExecutionPlan`, with the same `--profile standard` and the same
deny-all egress, as one that named its image. Pinned by
`a_detected_run_is_still_deny_all_and_standard_profile`, mutation-checked by
making the detection branch also set `net = true`.

**Inference is `run`-only.** `machine run` creates a named, possibly persistent
machine. Inferring its base image from the working directory meant that
`machine run` inside any Rust checkout silently chose `rust:1-alpine` — caught by
running it in this repo, where a BDD scenario asserting the no-source error went
red for the wrong reason. The split is one `Inference` enum passed to the one
resolver, so the verbs cannot drift on anything else.

## Honesty about the pins

The catalog's refs are tags, not digests. That is a dev-tier convenience, and it
is safe because `--prod` refuses a mutable reference before any network fetch: a
production run cannot inherit a detected tag, it has to name a digest.

An inferred source announces itself on stderr every time
(`[mvm] detected node from the command `npm` — booting node:22-alpine`), not
through `ui::info`, which is opt-in chatter shown only under `--verbose`. A boot
whose image the user did not choose has to say so, or the first they learn of it
is a "command not found" from a guest they never picked. stderr keeps `--json`
stdout machine-readable.
