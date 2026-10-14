# Local Linux image producer pairing

## Pinned inputs

The acceptance test pairs the Rust producer with `mvm-images` commit
`1249f1606fc1f15218a8ea15d0b3f08e0bac60dc`. The Rust integration starts from
consumer commit `10237ac0b9ae7cf2ee74c9ccee1b60325122da5a` and preserves the
reviewed V2 observer from `e18a211aae1582beb9c203d237a2b0500d813ee4`.

The reference interpreter must come from the isolated environment described in
the pinned image repository's README. The test checks the critical Dulwich and
ext4 dependency versions, the producer HEAD, and every Python source file's
inventory and bytes against the pinned commit before executing reference code.
Reference modules run from a private source-only tree, not from the checkout's
bytecode caches. Python uses isolated mode and a controlled environment.

Normal local image production does not require Git system-control environment
variables. The explicit paths below are acceptance-test inputs, not new product
configuration requirements.

## Execute the pairing

For sibling `mvm` and `mvm-images` checkouts, run from `mvm` after preparing the
image repository's isolated environment:

```sh
export MVM_IMAGES_PAIR_CHECKOUT="$(cd ../mvm-images && pwd)"
export MVM_IMAGES_PAIR_PYTHON="$MVM_IMAGES_PAIR_CHECKOUT/.venv/bin/python"
cargo test --locked -p mvm-build --features test-support \
  --test local_producer_pair -- --ignored --nocapture
```

When the checkouts are not siblings, set those two variables to the actual
checkout and interpreter paths. The test intentionally refuses a different
producer commit. An ordinary test invocation that leaves these tests ignored
is not interoperability evidence.

The two executed tests cover:

- Eight combinations: clean/dirty checkout, x86_64/aarch64, and
  default-tenant/rootless-tenant single-rootfs sets.
- Exact checkout identities and full schema-3/base-contract-1 manifest equality.
- Strict Rust manifest, architecture, identity, artifact digest/size and marker
  admission with the compiled payload-capable protocol range.
- Refusal of modified or untracked Python reference sources, and safe execution
  in the presence of poisoned unchecked-hash bytecode in the admitted checkout.

Both producers read the same real ext4 bytes, generated in process by the
existing `mvm-fs` writer. Emission inspects copied, hashed staged bytes. Supplied
invalid roots never fall back to source compatibility; only a partial set
without workload roots may use the source declaration.

## Supporting regression commands

```sh
cargo test --locked -p mvm-core --lib --features test-support image_set
cargo test --locked -p mvm-build --lib --features test-support image_source
cargo test --locked -p mvm-build --lib --features test-support published_image_set
cargo clippy --locked -p mvm-build --all-targets --features test-support -- -D warnings
```

The initial Darwin acceptance passed 210 core image-set tests, 173 image-source
tests, 37 published-image tests, both explicitly executed pairing tests, and the
Clippy command. Raw-byte filename and directory sub-witnesses reported APFS
`EILSEQ`; portable witnesses and fixed raw-byte encoding vectors still ran.
These counts describe the scoped integration, not the entire workspace.

## Acceptance boundaries

- The existing Rust reader rejects the legacy 128-byte-inode Python fixture.
  Pairing uses the supported 256-byte-inode writer; it does not establish
  support for every ext4 format.
- A payload-less library process must still refuse builder boot ABI 2.
  The test asserts that refusal. Its explicit compiled protocol range exercises
  format admission, not installation or usability of a signed runtime.
- The test covers single-rootfs local sets, not complete 17-member publication.
- It starts no builder, VMM, `mvmctl`, Nix build or installed guest.
- Native Linux/Windows consumer validation, signed release verification,
  post-publication Firecracker/HVF installed boots, and image publication remain
  separate gates. No image lock or protected release pin is advanced by this
  acceptance test.
