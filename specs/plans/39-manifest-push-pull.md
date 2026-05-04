# Plan 39 — `mvmctl manifest push` / `pull`

> Spun out of plan 38 slice 8c. Plan 38 ships `mvmctl manifest verify`
> (local checksums, slice 8b shipped) and `prune` (orphan sweep,
> slice 8a shipped). Push and pull are deferred here because they
> have a real semantic question — "where does pull install the slot
> when the source manifest_path doesn't resolve on the target?" —
> that warrants its own focused design.

## Context

Plan 38 made the registry slot path-keyed: a built artifact lives at
`~/.mvm/templates/<sha256(canonical_manifest_path)>/`. That's clean
on a single machine — every project has a stable identity tied to
where its `mvm.toml` lives.

The ambiguity surfaces at *transfer time*. If Alice on machine A
runs `mvmctl manifest push openclaw` (publishing the slot for her
`/Users/alice/work/openclaw/mvm.toml`), and Bob on machine B runs
`mvmctl manifest pull openclaw`, **what canonical path should Bob's
slot key off?** Bob doesn't have `/Users/alice/work/openclaw/`.
Three answers:

1. **Preserve source identity** — install to
   `~/.mvm/templates/<alice's-slot-hash>/` on Bob's machine. Bob's
   `mvmctl up` on that slot would error because the manifest path
   it records doesn't exist locally.
2. **Bob provides destination** — `mvmctl manifest pull openclaw
   --to /Users/bob/projects/openclaw`. Bob writes a fresh
   `mvm.toml` at the destination (or pull writes one), the slot is
   keyed off that new canonical path. Slots are deterministic on
   each machine, but identity isn't preserved across the network.
3. **Hybrid: pull writes the manifest** — `mvmctl manifest pull
   openclaw [DIR]`. Pull fetches the bundled manifest (`mvm.toml`
   contents shipped in the channel), writes it to `DIR/mvm.toml`,
   computes Bob's local slot hash from that canonical path, and
   installs the artifacts there. Bob ends up with a runnable
   `cd DIR && mvmctl up`. Source identity is recorded in
   `provenance.original_manifest_path` for audit but doesn't drive
   the slot key.

Recommendation: **option 3.** It's the only one where Bob can
actually use the pulled artifacts immediately, and it makes the
source's `manifest_path` an audit field rather than a runtime
identifier.

## Approach

### Push (`mvmctl manifest push [PATH] [--revision <hash>]`)

Producer side. Adapts `template_push` from `mvm-runtime` (which
exists today, name-keyed) to operate on slot hashes.

- Resolve PATH → slot_hash (same logic as other manifest verbs).
- S3 channel key: derived from `persisted.name` if set
  (e.g. `openclaw`), otherwise fallback to the slot_hash. Push
  refuses if `persisted.name` is set AND the remote channel
  already points at a different slot, unless `--force-channel`
  passed.
- Bundle layout uploaded to `<prefix>/manifests/<channel>/revisions/<rev>/`:
  - `manifest.json` — the persisted slot record (slice 2 schema +
    `provenance`).
  - `mvm.toml` — the source manifest contents (so pull can rehydrate
    on the target).
  - `vmlinux`, `rootfs.ext4`, `fc-base.json`, `revision.json` — the
    artifacts.
  - `checksums.json` — sha256 over each file in the bundle (also
    written locally so `manifest verify` works offline).
- After successful upload, write `<prefix>/manifests/<channel>/current`
  pointing at the new revision.

### Pull (`mvmctl manifest pull <CHANNEL-OR-HASH> [DIR] [--revision <hash>]`)

Consumer side. Option-3 design.

- Resolve `<CHANNEL-OR-HASH>`:
  - 64-hex value → fetch by slot hash (`<prefix>/slots/<hash>/...`
    bypasses the channel layer; provenance-preserving rare path).
  - Otherwise → channel name; fetch
    `<prefix>/manifests/<channel>/current` to learn the revision.
- Resolve `DIR`:
  - If supplied → use it as the destination directory.
  - If omitted → default to `./<channel>` (or `./<short-hash>` for
    hash pulls). Refuses if the directory exists and isn't empty
    unless `--force` passed.
- Download bundle to a tempdir.
- Verify checksums before installing (refuse on mismatch — would
  mean tampering or transport corruption).
- Write `<DIR>/mvm.toml` from the bundle.
- Compute local slot hash from `canonical(<DIR>/mvm.toml)`.
- Install artifacts under `~/.mvm/templates/<local-slot-hash>/...`,
  with the persisted manifest's `manifest_path` set to the local
  canonical path. Provenance retains `original_manifest_path`,
  `pulled_from_channel`, and `pulled_from_hash` for audit.
- Print: "Pulled `openclaw` revision `abc123…` to `./openclaw`. Run:
  `mvmctl up ./openclaw`."

### Channel collision rules

| Producer state | Remote `current` | Push behaviour |
|---|---|---|
| Manifest has no `name` | n/a | Always pushes by slot_hash; no channel collision possible |
| Has `name = "openclaw"`, channel doesn't exist | absent | Creates channel, pushes |
| Has `name = "openclaw"`, channel matches our slot | matches | Pushes new revision, updates current |
| Has `name = "openclaw"`, channel points at different slot | conflicts | Refuses unless `--force-channel`. Error includes the conflicting slot's hash and a hint to rename. |

This is the same naming-collision logic plan 38 §"Edge cases" §"Push
channel collisions" already specified.

### Cosign hook (deferred but designed)

When plan 36 (sealed-signed-builder-image) lands, push gains a
`--sign` flag that signs the bundle's `checksums.json` with the
project's signing key; pull verifies via `--check-signature`.
Until plan 36 ships, the flag is reserved (errors with a clear
"not yet wired" message — same pattern as `verify
--check-signature` shipped in slice 8b).

### Registry transport

Reuses `mvm-runtime::vm::template::registry::TemplateRegistry`
(OpenDAL-backed, S3-or-equivalent). The path layout differs between
slot-keyed and channel-keyed bundles:

```
<prefix>/manifests/<channel>/current                  → revision hex
<prefix>/manifests/<channel>/revisions/<rev>/<file>   → bundled artifacts
<prefix>/slots/<slot_hash>/revisions/<rev>/<file>     → hash-keyed pulls (rare)
```

Channel-keyed is the primary user-facing path. Slot-hash-keyed is for
operators who want to pull a specific provenance hash regardless of
what `current` points at on the channel.

## Critical files to modify

| File | Change |
|---|---|
| `crates/mvm-runtime/src/vm/template/lifecycle.rs` | New `template_push_slot(slot_hash, revision, channel_override)` and `template_pull_slot_to_dir(channel_or_hash, dst_dir, revision)` functions. Reuse the existing `TemplateRegistry` + `Checksums` infrastructure. |
| `crates/mvm-runtime/src/vm/template/registry.rs` | Add `key_channel_revision_file`, `key_channel_current`, `key_slot_revision_file` helpers (channel-vs-slot-hash path layout). |
| `crates/mvm-cli/src/commands/manifest/push.rs` (new) | Clap action: `mvmctl manifest push [PATH] [--revision] [--force-channel]`. |
| `crates/mvm-cli/src/commands/manifest/pull.rs` (new) | Clap action: `mvmctl manifest pull <CHANNEL-OR-HASH> [DIR] [--revision] [--force]`. |
| `crates/mvm-cli/src/commands/manifest/mod.rs` | Wire `Push`/`Pull` into the `ManifestAction` enum. |
| `crates/mvm-core/src/domain/manifest.rs` | Extend `Provenance` with `original_manifest_path: Option<String>`, `pulled_from_channel: Option<String>`, `pulled_from_hash: Option<String>`. |

## Verification

1. `cargo test --workspace` — new tests cover:
   - Channel name collision detection.
   - Hash-vs-name resolution in `mvmctl manifest pull`.
   - DIR-already-exists rejection / `--force` override.
   - `provenance.original_manifest_path` round-trip.
2. `cargo clippy --workspace -- -D warnings` clean.
3. Manual smoke (with a real S3 endpoint or `localstack`):
   - `mvmctl init /tmp/openclaw && mvmctl build /tmp/openclaw`
   - `mvmctl manifest push /tmp/openclaw`
   - On a second machine: `mvmctl manifest pull openclaw /tmp/openclaw-pulled`
   - `mvmctl up /tmp/openclaw-pulled` boots the pulled image.
4. Channel collision smoke: push a second project with `name = "openclaw"`; expect refusal + clear error pointing at `--force-channel`.
5. Hash pull: `mvmctl manifest pull <slot_hash> /tmp/by-hash` resolves to the bundle without going through channel `current`.

## Out of scope

- **Cosign integration.** Reserved as `--sign` / `--check-signature`
  flags; implementation lands when plan 36 ships.
- **OCI registry support.** Reusing OpenDAL gets us OCI for free
  later, but slice 8c stays focused on the dominant S3-compatible
  path. OCI is a follow-up if/when there's demand.
- **Bundle compression.** Today's artifacts are uploaded raw; gzip
  or zstd is a small win and a separate optimization.
