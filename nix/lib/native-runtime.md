# Application-layer GNU ELF runtime

`mkGuest` keeps its default `packages = []` static. Explicitly including the
flake-pinned `pkgs.glibc` in `packages` opts that application into native GNU
runtime aliases. The recipe API `.package("glibc")` selects this same package;
there is no workload-specific image or proprietary binary transformation.

For `aarch64-linux`, the interpreter is `/lib/ld-linux-aarch64.so.1`.
For `x86_64-linux`, it is `/lib64/ld-linux-x86-64.so.2`.
Other systems are refused when this capability is selected.

The factory retains the explicitly selected pinned glibc library output and its
transitive store closure through its existing ext4 materializer. Top-level `lib/*.so*`
ELF files from that glibc closure receive `/lib` aliases, including their declared
SONAMEs. Duplicate filenames and SONAMEs are accepted only when they resolve
to the same file. Missing transitive `DT_NEEDED` names, wrong-architecture files,
dangling links, links outside that closure, symlinked library directories,
and collisions with application-owned destinations fail the build.
Bounded unversioned text linker scripts are not runtime libraries and are skipped.
The upstream application bytes and the existing `extraFiles` source/mode
mechanism are unchanged.

Symlink components are visited in filesystem order: a link is resolved before
a following `..`. Every visited hop must stay in a declared closure output,
even if lexical normalization would put the final path back inside. At most
40 symlinks are followed; dangling links and non-directory intermediate
components fail.

The metadata reader supports only ELF64 little-endian `ET_DYN` objects for the
selected machine, with current identification/header versions, a 64-byte ELF
header, and ordinary 56-byte program headers (no extended program-header
count). The nonempty program-header table must fit in the file. Unused
`PT_NULL` entries are ignored, including their undefined fields. Segment file
ranges, virtual-address bounds, alignment and load/dynamic file versus memory
sizes are checked. Exactly one nonempty, load-mapped `PT_DYNAMIC` with whole
16-byte entries and a `DT_NULL` terminator is required. Conflicting duplicate
`DT_STRTAB`/`DT_STRSZ` tags fail. The nonempty string table must fit entirely
within exactly one file-backed `PT_LOAD`, with no overlapping load mapping.
Dynamic names must be nonempty, NUL-terminated ASCII basenames.

Every aliased object, both a library and the GNU dynamic loader, must declare
a SONAME. Neither role is required to have `DT_NEEDED`: a legitimate glibc
loader can have a SONAME and dynamic metadata without dependencies. Missing
dynamic data or missing SONAME is not treated as an empty dependency list.
This is a deliberately limited metadata validator, not a complete ELF linker
or proof of executable compatibility. Tests use structurally valid synthetic
objects and malformed mutations; they do not confirm actual pinned glibc bytes.

This is not a general distribution compatibility promise: the selected glibc
must provide the binary's required symbol versions. The helper inspects the
glibc closure's internal library dependencies, not arbitrary application data
or entrypoint files. No general external-library `DT_NEEDED` satisfaction is
guaranteed. Nix glibc's compiled default store path is preserved by the same
guest store closure; the factory does not alias arbitrary additional selected
packages or claim that `/lib` would make them discoverable. Additional
non-glibc requirements need a separately selected, validated search-path/cache
mechanism. GNU search-path behavior, GLIBC symbol versions and external ELF
execution require builder/native validation; mock alias tests alone do not
establish them. No guest NIC, SSH path, canonical base-image
change, trust change or separate application renderer is introduced.

Host-only mock validation:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s nix/tests -p 'test_native_runtime.py'
```

Nix evaluation/build and open-source native ELF boot probes for both guest
architectures must run on the authorized existing builder, not the host.
