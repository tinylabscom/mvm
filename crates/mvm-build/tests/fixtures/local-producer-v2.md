# Local producer reference data (PS-21)

These JSON files are inert data, never executable configuration, importable
Python, bytecode, or a command description. Rust tests do not discover or
execute an interpreter, Git, utilities, mvmctl, a builder or a VMM.

## Independent reference

The canonical producer is **mvm-images** revision
`f5ed15188114f2e3b7e27717640f0cbd37f53914`, not mvm source. Its
`scripts/emit-local-manifest.py` SHA-256 is
`45b93439cdebeba9c2d84749ec7c9afcfbe2c46802a756d84febb8b441583387`.
The Python-owned runner `scripts/reference-tests/test_local_producer_pair.py`
records the exact hashes of its five source dependencies and compares fresh
independent producer outputs with these files. It accepts neutral JSON paths,
not an mvm source checkout. Exporting these three data files suffices; it imports
no Rust code and requires no mvm executable.

- `local-producer-v2.json`: packet version 1, the four literal V2 framing
  vectors and deterministic repository identity. Binary fields are hex, modes
  are decimal Git modes. The real repository commits `a.txt = tracked\n`,
  then changes it to `tracked\nchanged\n`, creates `u.txt = untracked\n`
  and `link -> a.txt`. Actor/time/message are the existing deterministic
  repository fixture's values. The Rust unit test passes the neutral inputs
  through the actual Rust fingerprint encoder, not an extra reference encoder.
- `local-producer-manifests.json`: eight complete Python output documents,
  clean/dirty × x86_64/aarch64 × default/rootless. The input is the canonical
  Python `images_checkout(boot_abi="2\n")` metadata fixture; dirty changes
  `flake.nix` to `changed\n`. Contract 1, cache protocol fixture 1,
  `SOURCE_DATE_EPOCH=1`, no mvm checkout.
- `local-producer-rootfs.json`: one inert zlib/hex artifact generated once by
  the existing `supported_rootfs()` fixture through real
  `mvm_fs::ext4::build_image`. Both producers consume these **same bytes**.
  The compressed input is exactly 285 bytes; decompression is bounded to
  36,865 bytes and must yield exactly 36,864. Packet, compressed and original
  SHA-256 values are pinned; no declared size can raise the bound.

The independent runner regenerated all four vector hashes, observed the real
Dulwich repository, emitted all eight manifests, inspected the shared real
ext4 fixture and matched the committed outputs. No producer or parser was
rewritten to create these captures.

## Exact boundary of evidence

Rust constructs its repositories in-process with the existing fixture encoder,
and observes them with gix. It builds rootfs bytes with `mvm_fs::ext4`, emits
with the real Rust producer and admits them with the actual strict consumer.
Both architectures and both profiles are exercised in clean and dirty states.
Schema 3, images-only local_checkouts and base-image contract 1 are not
normalized. Historical dirty V1 refuses; V2 fields and framing are preserved.
The real symlink repository parity case is Unix-only (`cfg(unix)`); neutral
encoder vectors and the eight-case producer matrix are not Unix-gated.

**Manifest comparison is complete same-subject semantic JSON equality.**
There is no normalization or replacement of any expected manifest field,
including artifact `sha256` and `size`. Rust independently computes both from
the decoded neutral artifact, checks the neutral bytes still equal its
deterministic mvm_fs fixture, and verifies staged bytes and the 0444 `1\n`
marker through the strict consumer. Python independently decodes the identical
neutral artifact, verifies its hashes/bounds and inspects it through the
canonical producer's marker reader. JSON whitespace/key order is not a wire
contract, so serialized formatting is not compared. This is not
installed-runtime boot evidence.

## Preparation and validation

The attached mvm-images checkout was an older schema-2 working tree. No branch
was switched and no product files or pins were imported. Only these five
f5ed151 source files were extracted using `git show` into a private scratch
`reference/scripts/` tree:

```
emit-local-manifest.py
local_ext4_contract.py
ext4_contract.py
tests/test_local_mvm.py
tests/ext4_fixture.py
```

The separately authorized dependency preparation, inside attached mvm-images:

```
python3 -m venv .mvm-test/fixture-venv
.mvm-test/fixture-venv/bin/python -m pip install dulwich==0.24.10 ext4==1.4.1
.mvm-test/fixture-venv/bin/python -m pip install urllib3==2.6.3
```

All packages came from the existing cache. Final environment:
`dulwich==0.24.10`, `ext4==1.4.1`, `urllib3==2.6.3`,
`cachetools==7.1.1`, `crcmod==1.7`. No global install or production fallback.

Standalone verification (source and data are explicitly supplied paths):

```
python scripts/reference-tests/test_local_producer_pair.py \
  PREPARED_SCRIPTS LOCAL_PRODUCER_V2_JSON LOCAL_PRODUCER_MANIFESTS_JSON \
  LOCAL_PRODUCER_ROOTFS_JSON
```

This command passed. Capture used the same runner with `--capture`; its
complete output was compared to the committed JSON. Initial stdlib-only
AST extraction checked two hashes during exploration; it is not the final
independent-manifest evidence.

### Same-subject artifact generation

An explicitly authorized scratch-only generator extracted `supported_rootfs`
unchanged from fixture source v3
`1003715b42a875d1d9a45c246362b76c7a2aa35c6834d179b43d4bcac72cf032`.
It added only a `main` that writes those bytes to the caller's scratch path.
It linked existing mvm_fs and dependency outputs without Cargo or a rebuild:

```
rustc --edition=2024 SCRATCH/generate.rs \
  --extern mvm_fs=TARGET/debug/build/mvm-fs/e469942f842351b4/out/libmvm_fs-e469942f842351b4.rmeta \
  --extern mvm_fs=TARGET/debug/build/mvm-fs/e469942f842351b4/out/libmvm_fs-e469942f842351b4.rlib \
  -o SCRATCH/generate-rootfs \
  [one -L dependency=DIR for each existing TARGET/debug/build/*/*/out]
SCRATCH/generate-rootfs SCRATCH/rootfs.ext4
```

`TARGET` was `/tmp/mvm-4413-validation-1f8555755bf3/target`.
Successful compile plus execution took 0.659 seconds. The initial invocation
using only `.rlib` failed because these outputs use split metadata; adding the
corresponding `.rmeta` was the only correction. The packet preserves the full
successful argv and scratch generator source as generation metadata.

The resulting original SHA-256 is
`17a0d044d997f556f231fed641fbe41ccf82638857aa11fdb6cc9a48f11765f9`;
zlib level 9 yielded 285 bytes with SHA-256
`f0ec33287174cad091375c671830d9ad1db9d835b25584f6c380bec42052526b`.
The Python runner then freshly emitted every manifest from those exact bytes;
the capture was installed verbatim, not edited to inject a desired digest.

Rust gates, **not run** without the shared build slot:

```
cargo test -p mvm-build --test local_producer_pair
cargo test -p mvm-build --lib neutral_python_reference_vectors_exercise_rust_encoder
```

No Cargo, dependency/native rebuild, VM, cryptographic acceptance suite or
installed-runtime test was run by the fixture worker for this update. The
bounded scratch generator compile/run above is the sole Rust execution here.
Parent reported the earlier v3 four-test Rust pair suite passed on macOS
arm64; that result predates the same-subject update and does not validate it.
Formatting/source parsing and the independent Python check are separate evidence.
