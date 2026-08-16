# 2544 — the boot path reads a declared rootfs source, not a probed one

`classify_image` decided what a `spec.image` string meant by asking the
filesystem: `is_file()` → materialized rootfs, `is_dir()` → unpacked tree,
anything else → registry reference. The fallthrough arm answered two different
questions with one variant — "this is a reference" and "I could not classify
this" — so a mistyped path (`rootfs.ext5`) left the local arm entirely and was
handed to the OCI client, which turned it into a live registry GET whose 404
named neither the typo nor the path. The mirror case followed from the same
probe: a relative reference colliding with a cwd entry was silently
reinterpreted as a local file.

The three arms take different verification routes, so probing made the route a
function of the caller's working directory rather than of what they declared.

`RootfsSource` (`mvm-runtime`, already the build side's typed answer to this
question) gained a filesystem-free `FromStr`: an absolute / `./` / `../` / `~/`
path — or an explicit `path:` — is `LocalPath`, and everything else — or an
explicit `oci:` — is `Oci`. `mvm-client`'s duplicate `ImageSource` is gone; the
boot path now parses the declaration, then plans the work
(`RootfsPlan::{Materialized, UnpackedDir, Pull}`). The filesystem is consulted
only to tell a blob from a tree, and only after the caller declared the source
local; an absent declared path is an `InvalidSpec` naming the path, and `Pull`
— the only variant that reaches a registry — is unreachable from it. A bad
reference is also parsed at plan time, before the staging dir, and hints at the
`./` form when a same-named entry exists.

Left alone deliberately: `mvm-cli::exec::ImageSource` shares the name but not
the question — its variants are resolved boot artifacts (template, pinned
revision, prebuilt kernel+rootfs paths, wasm module), downstream of this
decision. Folding it in would conflate declaration with resolution. Typing
`MachineSpec.image` itself is the remaining step and needs `RootfsSource`
hoisted below `mvm-client`; tracked separately.
