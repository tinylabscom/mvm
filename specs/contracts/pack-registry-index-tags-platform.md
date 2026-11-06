# Pack registry index: tags, platform and size

Status: client implemented; producer emission pending in mvm-packs.

This contract extends the registry `index.json` (`schema_version` 2) with
optional per-version fields so `mvmctl pack search` can list tag, platform,
digest and size, and `mvmctl pull` can warn about an architecture mismatch
before it downloads anything. The extension is additive and the schema
version does not change.

## Trust

The index is untrusted discovery data. Nothing in the new fields grants trust
or admission:

- The signed manifest and its signature decide what is installed. The index
  digest only has to match the fetched manifest bytes; a mismatch is refused.
- A tag points at one exact version and carries no digest of its own. The
  digest is the `manifest_sha256` of that version. A tag can never select a
  different digest than the signed manifest.
- `guest_arch` and `size_bytes` are advisory. The authenticated manifest's
  architecture is re-checked after verification.
- Every index string is escaped for control characters before it is printed.

## Fields

Each object in `packs[].versions[]` keeps `version` and `manifest_sha256` and
may add:

| Field        | Type          | Meaning                                                              |
| ------------ | ------------- | -------------------------------------------------------------------- |
| `tags`       | array of text | Aliases for this exact version. `latest` is the only one `pull` accepts. |
| `guest_arch` | text          | Guest architecture in `GuestArch` spelling: `x86_64` or `aarch64`.   |
| `size_bytes` | integer       | Size of the version's bundle archive in bytes.                       |

The displayed platform is `linux/<guest_arch>`. A missing field means
"not advertised": no tags, no architecture, no size. A missing
`guest_arch` is never treated as a mismatch.

Unknown fields stay refused (`deny_unknown_fields`, as today). Consequently a
client that predates this contract rejects an index that uses the new
fields; publish them only after the supported client floor has moved.

## Rules

1. A tag names at most one version of a pack. A tag listed under two versions
   makes the index invalid.
2. Versions stay unique per pack. Each version has one manifest and therefore
   one architecture; a pack built for both architectures publishes distinct
   versions.
3. An unpinned request (`ns/name` or `ns/name:latest`) resolves to the highest
   semantic version whose `guest_arch` is absent or equals the host. The
   `latest` tag is a display hint and does not override that ordering. If no
   version matches the host, resolution falls back to the highest version
   overall and `pull` warns before download.
4. Tags are immutable per version: once a version carries a tag, the producer
   does not move it to another version except `latest`, which always follows
   rule 3's ordering for its architecture.

## What the producer must emit

mvm-packs `build-packs.py` must, for each published version:

- add `guest_arch` from the pack's application descriptor;
- add `size_bytes` from the bundle archive it publishes;
- add `tags: ["latest"]` on exactly one version of each pack, the highest
  non-revoked version; omit revoked versions from tagging;
- keep `tags` absent or empty on every other version.

Nothing in this repository claims the producer emits these today. Until it
does, the client prints `-` for each missing field.
