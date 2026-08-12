# Persistent machine README contract

**Status:** COMPLETE

The documented persistent-machine workflow used a positional machine name,
while `machine create` alone required `--name`. The first command therefore
failed in argument parsing and none of the remaining lifecycle examples could
operate on the missing machine.

## Contract

`mvmctl machine create [NAME] --image IMAGE` is the canonical form. `NAME`
remains optional so the existing automatic-name behavior is preserved. There
is no compatibility alias for `--name`: the CLI, SDKs, fixtures, and docs share
one syntax.

## Delivery

- [x] Add a parser regression covering the complete persistent-machine README
      workflow before changing the CLI contract.
- [x] Accept the optional machine name positionally and verify the real binary
      persists the requested name, image, CPU count, and memory size.
- [x] Update Rust, Python, and TypeScript SDK argv generation and shared
      language fixtures.
- [x] Update BDD scenarios, recovery guidance, and website documentation to the
      canonical positional form.
- [x] Run formatting, workspace check, host all-target Clippy, the serialized
      workspace unit and integration tests, all three SDK suites, all 173 BDD
      scenarios, and the 131-page documentation build.
- [x] Run Linux-native all-target Clippy, Linux/conformance, feature coverage,
      release-profile tests, and the complete workspace suite (including
      doctests) in CI.
