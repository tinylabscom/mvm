# PackSpec v1 conformance inputs

These language-neutral JSON documents describe authored intent only. They do
not resolve, install, copy, build, boot, sign, or publish anything. In particular,
`claude-style.json` describes argv and a proposed local file; it neither supplies
nor demonstrates installation, redistribution permission, authentication, or
execution of Claude Code.

`minimal.json` needs one generic package and no language dependencies.
`python.json` separately declares generic packages and ordered Python manifest
and lockfile references. The existing Workload IR `PythonTool` vocabulary is
reused. No language runtime is inferred from `.package(name, version=...)`.

## Wire rules

- `schema` is exactly `mvm.pack-spec/v1`. All top-level fields are required;
  empty lists mean none. Unknown fields and source/dependency kinds fail.
- Identity names contain lowercase ASCII letters, digits and hyphens, begin
  with a letter, and are at most 128 bytes. Release versions have exactly three
  unsigned 32-bit decimal components with no leading zeroes.
- Targets are explicit `aarch64-linux` or `x86_64-linux`; never host defaults.
- Generic package names and optional version tokens are at most 128 ASCII bytes,
  start alphanumeric, and otherwise use alphanumeric characters or `-_.+`.
  Versions are requests for an exact spelling, not ranges or resolved hashes;
  omission or null delegates selection to future resolution. `scope` is required:
  `build` or `runtime`. Nothing here proves a catalog can supply a package.
- The only source is a local tree relative to the spec directory. Dependency
  manifests/lockfiles and copy sources are relative to that tree. `.` names the
  tree root only for source/copy, not dependency files. Copy destinations are
  guest-absolute and cannot be `/`. Paths are at most 4096 UTF-8 bytes, contain
  no empty, `.` or `..` components, control characters, backslashes or colons.
  Materialization must separately enforce filesystem containment and symlink
  safety; lexical validation is not a filesystem authority check.
- Entrypoint is nonempty argv with a non-whitespace executable and no NUL in
  any argument. Empty subsequent arguments are meaningful. No shell evaluation.
- CPU cores are integers in `1..=65535`; memory MB in `1..=4294967295`. These
  match existing IR numeric widths, prevent zero and overflow, and are advisory
  requests, not evidence of capacity or admission grants.

## Normalization and validation

`PackSpec::canonical_json()` validates, omits absent/null package versions,
sorts every object's keys, emits compact UTF-8 JSON with no trailing newline,
and preserves every list's order, duplicates, and string contents. Paths are
rejected rather than repaired. Object key/input whitespace differences do not
change the result. This is an authored representation, not a signed format,
resolved lock digest or build cache key.

Run the Rust witnesses with:

```sh
cargo test -p mvm-contract --test pack_spec --features schema
cargo run -p mvm-contract --features schema --bin emit_pack_spec_schema
```

The feature-gated schema describes the closed structural vocabulary and basic
scalar constraints. Semantic validation remains required (including path
traversal rejection, version component bounds, and argv NUL checks); accepting
a document against JSON Schema alone is not contract validation.

## Boundaries

PackSpec is **authored** intent. A future **resolved/locked** record must bind
source content, package selections, dependency files, target, compiler and base
image digests. Future **build results** must carry actual artifact hashes and
witnesses. **Release** metadata supplies publisher identity, protected signing,
provenance, SBOM, revocation and admission bindings; no credentials or signing
authority belong in authored input.

Downstream work must lower into `mvm-contract` Workload IR and use the existing
`mvm-sdk` compiler, `mvm-build` jobs, `mvm-client` and `mvm-bundler`. This slice
does not implement that lowering, launch behavior, scenarios, OCI materialization,
network policy, secrets, SDK language bindings, or new lightweight-pack behavior.
