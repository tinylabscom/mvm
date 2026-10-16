# Gitoxide optional-cache source patches

These two local Cargo patches let `mvm` retain Git attributes, excludes,
SHA-1, and signing APIs without enabling two performance-only caches.
No fingerprint, parsing, signing, object lookup, or cache implementation
is changed. `deny.toml` is unchanged.

## Immutable source origin

Both packages originate at https://github.com/GitoxideLabs/gitoxide and
are licensed `MIT OR Apache-2.0`. Both original `LICENSE-MIT` and
`LICENSE-APACHE` files are retained byte-for-byte in each package.

| Package | Published archive SHA-256 | Upstream revision recorded in `.cargo_vcs_info.json` |
| --- | --- | --- |
| `gix 0.87.1` | `fdefc1465d8631807deaf504dacdeff628b978de515653b47976ca7c28ab2a7a` | `3ebca8b66017ab2dd02a38f75f78f485bee1ded8` |
| `gix-object 0.64.1` | `56fef799ca40cdeab4de5a3e74a696d8fa9b9c6264592646bf022e026f13ce2c` | `e52fe9d03e82437a25bdfb1098e7046ec7e1b558` |

Canonical archives:

- https://static.crates.io/crates/gix/gix-0.87.1.crate
- https://static.crates.io/crates/gix-object/gix-object-0.64.1.crate

The import used the local Cargo archive cache, verified each SHA-256
against both this table and the pre-patch registry entry in `Cargo.lock`,
and rejected links and escaping archive paths before copying files.
It imported only these two published packages: 204 files / 1,485,145 bytes
and 36 files / 281,219 bytes respectively. This is not a Gitoxide
workspace checkout and does not vendor its dependency tree.

## Complete upstream delta

- `gix/Cargo.toml` and `gix/Cargo.toml.orig`: move
  `gix-pack/object-cache-dynamic` from the unconditional dependency into
  the new `object-cache-dynamic` feature; enable it in `default`.
  Enable existing `hp-tempfile-registry` in `default` to retain the
  registry implementation formerly enabled transitively by signing.
  `command` selects `gix-object/signature-basic` instead of `signature`.
- `gix-object/Cargo.toml` and `gix-object/Cargo.toml.orig`: add
  `signature-basic` containing the existing command and tempfile
  dependencies, with tempfile default features disabled. Preserve
  existing `signature` as `signature-basic` plus
  `gix-tempfile/hp-hashmap`.
- `gix-object/src/signature/mod.rs`: change exactly the two module
  gates from `signature` to `signature-basic`. Existing `signature`
  enables this feature, preserving its API and performance behavior.
  No implementation body changes.
- `gix/src/object/mod.rs`: gate the private dynamic-cache re-export.
  `gix/src/repository/init.rs`: gate dynamic object-cache setup independently
  of pack-cache setup. `gix/src/repository/cache.rs`: retain both public
  cache-size methods; without the dynamic-cache feature, requesting a cache
  leaves object caching disabled. Object reads still use the same database.

Every other imported file is byte-identical to its published archive.
Both manifests are edited because Cargo consumes the normalized manifest
while an upstream submission should use the original manifest.

The upstream default behavior and existing `gix-object/signature` behavior
are preserved. Deliberately cache-free `gix` consumers retain all signing
APIs through the new basic feature. Both caches can still be explicitly
selected. The registry's standard-library implementation still provides
temporary-file tracking and cleanup. No optional-package weak forwarding
is needed: `gix` already has an unconditional `gix-tempfile` dependency.

Updating `clru` or `dashmap` to another hashbrown generation would change
cache dependency compatibility and retain code this consumer does not
need. Feature selection is the narrower, upstreamable rule.

## Reconciliation and validation

After applying this source packet, reconcile only these package identities:

```sh
cargo update --offline -p gix@0.87.1 -p gix-object@0.64.1
cargo metadata --offline --locked --format-version 1
cargo tree --offline --locked -i hashbrown
cargo deny --locked check
```

Review the lock diff: these two packages become path packages; cache-only
dependencies should disappear if no other consumer enables them. Preserve
the separate `mvm-macho-sign` package and all its direct dependencies.
Do not change policy to accommodate a remaining duplicate.

Compilation and Git identity/attribute/exclude behavior tests must run
under the parent task's coordinated validation. Source provenance checks
alone do not establish a green dependency gate or working compilation.
Remove these patches when upstream releases equivalent feature control
and the workspace can advance to those versions.
