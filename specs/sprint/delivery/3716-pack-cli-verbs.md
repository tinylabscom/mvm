# Signed pack operator surface: search / pull / pack registry / policy pack references

The registry-pack substrate (lockfile, signed manifests, payload verification,
atomic install) shipped without a way to fetch or consume packs. This slice
adds the operator surface, all fail-closed:

- **`mvmctl search [QUERY]`** lists the registry index (`MVM_PACK_REGISTRY`,
  defaulting to the mvm-templates source; `file://` works for tests and
  mirrors), marking installed packs.
- **`mvmctl pull ns/name[@version]`** resolves the version from the index,
  downloads the manifest, sigstore bundle, and every declared payload file
  into a staging directory (paths from the unverified manifest are refused
  before they join a URL or path), then verifies, installs, and pins. An
  already-pinned version is re-verified lock-first (digest drift refuses);
  a newer published version is adopted and replaces the pin. The pin is
  written only after installation succeeds, and there is deliberately no
  verification-bypass switch.
- **`mvmctl pack registry ls|rm|update`** manages installed packs under the
  existing `pack` verb (whose other subcommands stay the attested-pack cache).
- **`run --policy ns/name[@version]`** (the plan's `run --profile ns/name`
  shape, on the flag PS-05 chose) resolves pack profiles and groups:
  `PolicyStore::load` re-reads the locked sidecars, re-verifies the exact
  payload, and reads the declared `pack/profile.toml` or `pack/group.toml`
  with `LayerOrigin::Pack` — escape hatches stay refused.

## Testing

- `mvm_core::registry_pack_store`: 12 tests — lockfile round trip, upsert and
  remove semantics, fail-closed missing publisher policy, adopt+install+pin
  composition, re-verification on open (tampered payload and version drift
  refuse), removal, declared-document reads.
- `mvmctl pack_registry`: index search and version resolution.
- `tests/cli.rs`: verb help surfaces, `search --json` against a `file://`
  registry, `pull` reaching signature verification and refusing with no pin
  recorded (default builds carry no verifier; the happy path is covered in
  mvm-core with injected checkers — an end-to-end signed fixture arrives with
  the mvm-templates publication workflow), empty `pack registry ls`, and the
  unpinned-rm no-op.
- s29 doc-tier gates: new verbs tiered (`pull`/`search` parse with the reason
  recorded; the parse-tier pin rises 70 → 72 with the justification in the
  conformance source).

## Remaining for #3716

Publisher-policy bootstrap UX, the mvm-templates publication workflow with
real signed packs (and the signed end-to-end witness it enables), policy
composition rules audited for pack origins, admission binding of pack
profiles to the signed plan, and the initial agent/runtime packs.
