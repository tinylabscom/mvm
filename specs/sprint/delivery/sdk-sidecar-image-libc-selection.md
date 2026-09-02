# The sidecar variant comes from the image, not from the catalog

#3044 selected the SDK sidecar from the libc a catalogued runtime *declares*,
and said so plainly in its own commit message: "an arbitrary `--image`
reference is still `Unknown` … probing it before materialization is the
remaining half of the selection work."

That remaining half is what this closes. On main before it,

```
mvmctl run --image python:3.12-alpine --host-service host.kv.v1 -- python ...
```

is refused for an unknown libc — the image is plainly musl, the musl sidecar is
cached, and the command is the one the issue was originally reported against.
`resolve_run_source` returns `Explicit` before the catalog is ever consulted, so
`detected_libc` never leaves `Unknown` for an image the user names themselves.

## Select from what was observed, not what was declared

The libc is already detected when the OCI layers are unpacked and recorded in
the image's `mvm-meta.json`. That recording is the only thing the host can still
read once the tree is an ext4 blob, and it is a fact about *this* image rather
than about the table that pinned a reference to it.

So the selection moves to `resolve_launch`, immediately after
`resolve_image_artifacts` returns and before `build_start_config`. That is the
first point at which the guest exists.

What makes it safe rather than a reshuffle is that it is still *one*
resolution. The attachment feeds the launch config directly, and the same value
reaches admission through `AdmitInputs` — which is why that callback grew from
three positional arguments into a struct. The plan grant and the attached volume
cannot describe different bytes because they are the same object. The
alternative — admit the binding, resolve the artifact later, have admission
check the two agree — adds a seam whose only job is to prevent a disagreement
this shape makes unrepresentable.

`resolve_bindings_and_sidecar` is gone; `--host-service` parsing is validation
again, which is all a command layer can honestly do before an image exists.

## The declaration keeps a job worth having

`RuntimeEntry::libc` no longer selects, but deleting it would throw away the
only *independent* statement about a catalogued image's libc. It is now
cross-checked against what the materialized rootfs records, and a disagreement
refuses.

That case is not hypothetical: a catalog entry pins a mutable tag, and an
upstream `:alpine` image rebuilt on a different base makes the declaration
quietly wrong about every guest booted from it. Selection would still be
correct — it reads the observed value — so nothing else would ever notice.
`Unknown` on either side is not a disagreement: no declaration is the ordinary
`--image` case, and no recorded libc is refused later by the resolver with a
message about what to do.

## The artifact proves its own libc

Main identifies a cached sidecar's libc from the directory it was filed under.
That is the one signal this issue's history showed to be untrustworthy. Twice
during this work a build named a `*-linux-musl` target, linked through the host
`cc`, exited zero with both C ABI symbols exported — and produced a **glibc**
object. Filed under `musl/`, the path, the filename and the build log all agree
and are all wrong together; the guest reports it as a relocation error from
inside `dlopen`.

`crates/mvm-fs/src/elf.rs` reads the object's `DT_NEEDED` list — little-endian
ELF64, program headers, `PT_DYNAMIC`, the string table resolved through the
`PT_LOAD` map — and `validate_sidecar_payload` refuses a payload whose libc
soname is not the one its slot claims. `libc.so` is a prefix of `libc.so.6`, so
the comparison is exact; both directions are tested.

Every sidecar fixture in the workspace now carries a real ELF object naming the
libc of the slot it is filed under, and the libc is an explicit argument at each
call site rather than defaulted. Threading it that way immediately caught three
fixtures that had been staging a musl object into a glibc slot — which had been
invisible, and which is exactly the mistake the check exists to find.

## Verification

`mvmctl run --image python:3.12-alpine --host-service host.kv.v1` selects and
attaches the musl variant and the workload round-trips a key through the broker.
The `host_kv.feature` `@live` scenarios pass on a home whose cache holds both
variants, and the negative one asserts the broker's own `not_bound` code on
stderr — where a failing workload's diagnostic actually goes.
