# 2553 — the machine declaration names a rootfs source, not a string

2544 put the parse at the client boundary; `MachineSpec.image` itself stayed a
`String`, so the declaration was only authoritative from that boundary inward.
A caller could hand the DTO a string that meant nothing — `""`, `"path:"`, a
value pasted with a trailing newline — and construction succeeded. The mock
backend, which never parses anything, would run such a machine to completion.

`RootfsSource` now lives in `mvm-core` (`crates/mvm-core/src/rootfs_source.rs`)
and `MachineSpec.image` names it. `mvm-runtime`'s `artifacts::spec` re-exports
it so the build spec keeps its call sites unchanged.

## Where the type went, and why not `mvm-contract`

`mvm-contract` was the other candidate — the issue noted the enum is
"no_std-shaped already", and `ImageReference` already lives there. It does not
fit: `RootfsSource::LocalPath` carries a `PathBuf`, which `core` + `alloc` has
no equivalent of, and the crate must keep building for
`wasm32-unknown-unknown`. Demoting the arm to `String` to fit would restore the
stringly-typed representation this change exists to remove, and a host
filesystem path has no meaning on the browser target that crate serves.
`mvm-core` is std, sits below both `mvm-client` and `mvm-runtime`, and already
hosts the DTO — so `dto.rs` names the type with no dependency inversion.

## Persisted specs

Nothing persisted deserializes as this type. The on-disk record at
`~/.mvm/machines/<name>/machine.json` is a *different* `MachineSpec`
(`mvm_runtime::machine::persist`, `image: Option<String>`), untouched here;
`save_machine_spec`/`overwrite_machine_spec` are its only writers. The DTO
reaches no file, no test fixture, and no JSON corpus, and even the gateway wire
copies `&spec.image` into a separate `CreateSandboxBody` rather than sending
the DTO. So the migration question has no live state behind it.

The serialized form stays the flat string anyway, and not for compatibility:
the same value reaches a guest as `--image <string>` argv — what both language
SDKs emit and what the drift-locked `tests/machine-fixtures/create-image.argv`
pins — so a tagged enum would make the DTO's field and the argv two spellings
of one declaration. `Display` writes the shortest form that re-parses to the
value, decided by re-parsing rather than by a second copy of the shape rules,
so `alpine:3.20` and `/var/lib/rootfs.ext4` keep their exact bytes.

## `Flake` in a boot declaration

Kept in the one type rather than split into a narrower boot-side enum. The
string grammar gained `flake:<ref>#<attr>` (nix's own spelling), which makes
`FromStr`/`Display` total — no variant is unwritable, so serialization can
never fail — and leaves the refusal where it belongs: the in-process backend
cannot build a flake, which is a backend capability limit, not a malformed
declaration. A second enum would have duplicated the grammar and pre-empted a
backend that later can.

## Follow-on

`LaunchRequest.image` is typed too, which deleted its `image source must not be
empty` runtime check (unrepresentable now) and the redundant re-parse in
`resolve_local_rootfs`. `mvm-sdk`'s two `spec.image.is_empty()` guards went the
same way.

Not done: `RootfsSource::Oci` still carries a `String`, not the
`ImageReference` the plan resolves it to downstream. That would change the
build spec's serialized form and touch the nix builder, and is a separate
change.
