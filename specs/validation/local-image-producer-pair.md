# Local Linux image producer pairing

## Contract and reference inputs

The Rust producer and the independently runnable `mvm-images` reference runner
consume neutral, hash-pinned data. The Rust tests do not launch Git, Python, a
builder, or a VMM, and do not import executable reference sources.

The [fixture provenance](../../crates/mvm-build/tests/fixtures/local-producer-v2.md)
records the exact image-producer revision, source inventory, dependency versions,
capture commands, and neutral artifact hashes. Reference output comes from the
real Python producer, not a Rust reimplementation of its output.

The shared rootfs was generated with `mvm_fs::ext4::build_image`. Both producers
consume those identical bytes. The Rust test independently verifies its digest,
size, deterministic reconstruction, and base-image marker before comparing every
manifest field. No expected digest, size, or other field is substituted.

## Run the Rust pairing

From `mvm`:

```sh
cargo test --locked -p mvm-build --test local_producer_pair -- --test-threads=1
```

This is an ordinary integration test, not an ignored opt-in test. It requires
neither a Python environment nor `MVM_IMAGES_PAIR_CHECKOUT` /
`MVM_IMAGES_PAIR_PYTHON`.

Coverage includes:

- The canonical V2 encoding vectors through the actual Rust encoder.
- An actual in-process repository compared with independently observed reference
  identity, including a subsequent working-tree mutation.
- Eight manifest combinations: clean/dirty checkout, x86_64/aarch64, and
  default-tenant/rootless-tenant rootfs roles.
- Complete schema-3/base-contract-1 manifest value equality over the same artifact.
- Actual strict consumer admission, artifact digest/size, architecture, checkout
  freshness, path/inventory restrictions, and marker contents/mode.
- Refusal of V1 dirty identities and tampered reference packets.

The separate image-repository reference runner verifies or recaptures the neutral
data using its own pinned source and dependency environment. Its invocation is
documented in the fixture provenance. It is not a Rust test subprocess or a
product runtime prerequisite.

## Supporting regression commands

```sh
cargo test --locked -p mvm-core --lib --features test-support image_set
cargo test --locked -p mvm-build --lib --features test-support image_source
cargo test --locked -p mvm-build --lib --features test-support published_image_set
cargo clippy --locked -p mvm-build --all-targets --features test-support -- -D warnings
```

These commands supplement the required workspace and platform gates; a focused
pass does not imply that the full workspace or another platform passed.

## Acceptance boundaries

- Manifest architecture selection is not a cross-architecture boot witness.
- The neutral rootfs exercises the supported ext4 layout, not every ext4 format.
- Local-set admission is not signed-release authentication or runtime authority.
- The matrix covers single-rootfs local sets, not a complete published image set.
- Native Linux/Windows checks, signed-release verification, installed boots, and
  publication remain separate gates.
- No image lock, protected release pin, or canonical image recipe is changed by
  this test.
