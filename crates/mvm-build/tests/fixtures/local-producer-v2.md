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
  The same packet also carries the shared real-repository observation matrix
  below, not just hashes copied between independent language-specific tests.
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

## Shared observation matrix

`observation_cases` contains finite file/index-state recipes: initial file
bytes, subsequent file bytes/types, a staging flag, linked-worktree posture
and independently captured complete `RepoIdentity` outputs. Paths/bodies are
hex bytes. Neither language treats the data as code, imports, commands,
shell arguments or a Git configuration. Both create actual repositories
in-process with the existing deterministic actor/time/message. Python uses
Dulwich; Rust uses the existing repository fixture and actual gix observer.

| Case | Actual observations |
| --- | --- |
| `ignored-files` | Clean; ignored file added; ignored bytes changed; negated ignore added. First three identities equal; last differs. |
| `staged-and-unstaged` | Clean; index/worktree staged; unstaged working edit; working bytes restored to HEAD while staged index differs. Adjacent identities differ. |
| `linked-worktree` | Separate administrative HEAD/index plus commondir; linked clean then edited. Common checkout remains unchanged. |
| `symlink-targets` | Clean; link to tracked file; changed dangling target. Adjacent identities differ. Unix-only. |
| `binary-file` | Clean; `00ff0a` untracked bytes; changed `00ff0a00` bytes. Adjacent identities differ. |
| `non-utf8-name` | Unix-only clean state, actual `78ff0a` file with `00ff0a` bytes, then `ff000a` bytes. Independent Linux capture contains all three distinct identities. |

Expected identities carry only commit and versioned worktree state; no
absolute/canonical fixture root is accepted as fingerprint authority.
All successful states are compared against independently captured Python
outputs, unchanged. The matrix is split into portable and `cfg(unix)` Rust
tests; unsupported Windows symlink/raw-name cases are not represented as
passed observations.

The canonical packet now contains 19 independent Linux matrix observations,
including all three raw-name states and no unsupported marker. Both readers
require that complete supported shape before observing the raw-name case.
Supporting filesystems must match every state, not a truncated reference.
On this Darwin filesystem, actual raw-name creation raises EILSEQ: both
readers verify the completed clean prefix against the Linux reference, then
explicitly report the remaining raw-name observations unsupported. EILSEQ is
accepted only at the first raw-name creation, not as a blind platform skip.
Darwin's raw-name prefix/EILSEQ witness is not a raw-name parity pass.

`mutation` supplies one identical tracked `flake.nix` edit and captured
post-edit identity for both implementations. Python applies the actual edit
from a copy callback during each real producer emit, observes the identity
change, and requires refusal plus staging cleanup. Rust applies the same
edit after production, compares the actual observed identity to that capture,
and requires the actual strict consumer to refuse the stale set. These are
producer-mutation and stale-consumer refusal witnesses respectively, not a
claim that the two APIs are identical. Same-subject eight-manifest output
comparison remains untouched.

### Independent Linux reference adoption

The canonical observation packet is the **unchanged output** of successful
[mvm-images run 38845610324](https://github.com/tinylabscom/mvm-images/actions/runs/38845610324),
capture job `116795334623`, artifact
`ps21-linux-reference-38845610324-1/linux-observations.json`:

`d447325e8bf9e4c6a55cb266a04dd2b6268cacae0bac7b90f679367dff84fcbd`

The workflow checkout was add-only commit
`62a792afe3ec4017abe246f3f0a3251d8111c8a5` over producer revision f5ed151.
Coordinator review verified its six additions and unchanged existing workflow
bytes, and verified the sole push run/capture job succeeded. No such GitHub
query or Linux execution is attributed to the fixture worker.

The artifact's source-provenance records runner SHA-256
`49e5ca6a11b624859e51129a27f57f0e247f965776dbd5cab61fdd1c3ddd4a6f`,
the five canonical producer/test source hashes, and input packet hashes
`d622678f8d8288aa2b124ee589b0979b086ed302efc2e907ad8ed0dd877cb40b`,
`9057fd0265d35d547ae8d0bad0f6e8f2d0d1783434941701f3f9044806ad635f`,
and `d9855dd4f4e5bf1d9005fc553c750a0b9ca31a325c9d8a1c2d151ffe70108a96`.
It records Python 3.12.3, Linux x86_64/glibc 2.39 and the five pinned
dependencies (plus pip 24.0).

The fixture worker independently checked the local JSON artifact's SHA-256,
all four entries in `provenance.sha256`, the three distinct raw-name states
with no unsupported marker, and that every other recipe, observation,
mutation result and literal vector was unchanged. It adopted the original
artifact bytes without editing or normalizing an expected field. Capture
itself intentionally re-observed and rewrote expected outputs; it was not a
byte-copy operation.

Evidence limits: pip used exact versions but **not `--require-hashes`**;
public package/source-distribution provenance was recorded post hoc, not
preauthorized by content hash. The job passed its eight complete-manifest
assertions, but did not retain those manifest bodies in its artifact; this is
not a claim of a later independent inspection of Linux-emitted bodies.
The ZIP SHA-256
`e0bb14b1fb7748b65c1dc9963dc1869953361e945df1d4170067cbd2e6d2b4b5`
is owner-reported, not independently ZIP-verified by the fixture worker.
The JSON/provenance checks above are independent local checks.

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

### Reproducible standalone observation capture

The image-owned runner now exposes **`--capture-observations`** explicitly.
Unlike `--capture` (which prints only fresh manifests), this mode recreates
every observation recipe and prints a complete updated `local-producer-v2`
packet to stdout. It also performs all eight same-subject manifest comparisons
and actual producer-mutation refusal checks. It never overwrites its input.
The generated packet's SHA-256 is reported to stderr. Normal verification
does not update or normalize any expected field.

All modes enforce the five exact source hashes, producer revision and source
hash, all three input packet hashes, Python >= 3.12 and the five exact package
versions listed above. The admitted packet requires three supported raw-name
observations and no unsupported marker. Capture records the actual new
filesystem result only in its output, after verifying completed observations
against that reference. On supporting Linux it emits all three raw-name
identities; on this Darwin filesystem the standalone mode emits the old
partial/EILSEQ packet hash
`d622678f8d8288aa2b124ee589b0979b086ed302efc2e907ad8ed0dd877cb40b`
and reported actual EILSEQ.

The Linux operator needs only:

- An independently available Linux runner and filesystem supporting raw Unix
  filenames; Python 3.12+ with venv and the pinned packages.
- The mvm-images Git object for f5ed151 and this image-owned runner file.
- Exported copies of the **three neutral JSON files**, not mvm source,
  executables, a Cargo workspace, a VMM or a container daemon.
- A bounded manual phase: one CPU, 512 MiB memory and a five-minute time limit
  are sufficient resource allowances, not a measured Linux result.

From an existing mvm-images checkout, with the three exported JSON files in
`INPUTS`, a standalone Linux recapture phase is:

```sh
set -eu
REV=f5ed15188114f2e3b7e27717640f0cbd37f53914
INPUTS=.mvm-test/reference-input
mkdir -p .mvm-test
RUN=$(mktemp -d .mvm-test/linux-reference.XXXXXX)
mkdir -p "$RUN/scripts/tests"
for name in emit-local-manifest.py local_ext4_contract.py ext4_contract.py \
  tests/test_local_mvm.py tests/ext4_fixture.py
do
  git show "$REV:scripts/$name" > "$RUN/scripts/$name"
done
printf '%s  %s\n' \
  bd8d2773abbc9ad0eca9483b27c4f378d47f911d733d5749936919adfe17cfde \
  scripts/reference-tests/test_local_producer_pair.py | sha256sum -c -
python3 -m venv "$RUN/venv"
PURE=1 "$RUN/venv/bin/python" -m pip install --no-binary=dulwich \
  dulwich==0.24.10 ext4==1.4.1 urllib3==2.6.3 cachetools==7.1.1 crcmod==1.7
"$RUN/venv/bin/python" scripts/reference-tests/test_local_producer_pair.py \
  "$RUN/scripts" "$INPUTS/local-producer-v2.json" \
  "$INPUTS/local-producer-manifests.json" \
  "$INPUTS/local-producer-rootfs.json" \
  --capture-observations > "$RUN/linux-observations.json"
"$RUN/venv/bin/python" - "$RUN/linux-observations.json" <<'PY'
import json, pathlib, platform, sys
assert sys.platform.startswith("linux"), "not Linux evidence"
packet = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
raw = next(c for c in packet["observation_cases"] if c["name"] == "non-utf8-name")
assert "unsupported_on_capture" not in raw, "filesystem did not support raw names"
assert len(raw["expected"]) == 3, "missing actual raw-name observations"
assert len({json.dumps(v, sort_keys=True) for v in raw["expected"]}) == 3
print(platform.platform(), platform.python_version(), "three actual raw-name states")
PY
sha256sum "$RUN/linux-observations.json"
```

The output format is the existing version-1 JSON observation packet, with
`observation_cases[*].expected` freshly observed and `mutation.after` freshly
observed. No hashes are fabricated for raw names. Freeze and review the output
plus its reported hash before adopting it and updating the admitted packet
hashes in both tests/runners. The actual independent Linux capture above
supersedes v6's Linux-reference HOLD. Adoption does not assert a new Rust
pass: parent coordinates the updated seven-test suite and independent review.

No Linux execution, daemon/VM start, or workflow edit was performed by the
fixture worker for adoption. The separately coordinated image-owned capture
remains independent of mvm's merge queue: no mvm source/process, image build,
publication, signing or lock change is introduced here. Its published
workflow and neutral input copies remain untouched historical evidence.

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
Parent subsequently reported v4 four-test PASS and no review findings; that
predates this shared-matrix extension and does not validate its new tests.
Formatting/source parsing and the independent Python check are separate evidence.
