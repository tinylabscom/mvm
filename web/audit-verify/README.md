# Browser audit-log verifier (ADR-001)

A serverless, static page that verifies an mvm chain-signed audit log
in the browser — the same Ed25519 chain check `mvmctl audit verify` runs
on the host, compiled to WebAssembly. The verification logic lives in
the workspace crate [`mvm-verify`](../../crates/mvm-verify); this
directory is only the `#[wasm_bindgen]` shim plus the page.

This crate is **excluded from the main Cargo workspace** (see the root
`Cargo.toml`) so `wasm-bindgen` and the `wasm32` target never enter
`cargo build --workspace` or CI. The verifier's tests run as part of the
normal workspace via `mvm-verify`.

## Build

The wasm artifact is **not built by default and not shipped**. It is not
needed to use or test the verifier — all of the logic lives in the
`mvm-verify` crate and is covered by the normal workspace test run.

If you ever do want the browser bundle, build it **inside the builder/dev
VM** (`mvmctl dev`), never with a host toolchain — same invariant as
every other build in this repo: builder tools never live on the host
(ADR-004, ADR-007). The wasm32 target + `wasm-pack` belong in that guest,
not on a contributor's machine. The output (`pkg/*.js` + `…_bg.wasm`) is
what `index.html` imports; serve the directory statically and the page is
fully offline after load — nothing you paste leaves the tab.

## Inputs

- **Public key**: the host signer's Ed25519 public key as 64 hex chars
  (the private key lives at `~/.mvm/keys/host-signer.ed25519`, mode 0600).
  There is no CLI subcommand to print the public half yet — a small
  `mvmctl audit pubkey` printer is the obvious follow-up (noted in
  ADR-001). Until then, derive it from the keypair.
- **Audit log**: the contents of a per-tenant `~/.mvm/audit/<tenant>.jsonl`
  stream (paste, or pick the file).

## What it proves

Byte-for-byte the same thing `mvm_supervisor::verify_audit_chain` proves:
every line's `prev_hash` links the chain and every signature verifies
under the key. Any reordering, edit, or deletion fails. The equivalence
is pinned by `mvm-supervisor`'s `mvm_verify_matches_supervisor_chain`
test, so if the audit entry shape drifts, CI fails before the browser
tool can silently disagree.

## Merkle inclusion proofs

Three further exports let a browser verify an `O(log n)` transparency-log
inclusion proof (from `mvmctl trust audit prove`) against a host-signed
Merkle root (`mvmctl trust audit publish-root`) without downloading the
whole chain:

- `verify_inclusion(proof_json)` — folds a proof to its own embedded root.
  This is only half a membership check.
- `verify_signed_root(root_json, pubkey_hex)` — checks the root's Ed25519
  signature under the trusted host key.
- `verify_membership(proof_json, root_json, pubkey_hex, tenant)` — the full
  check: verifies the signed root, checks it is for the intended `tenant`,
  verifies the proof, and binds root + tree_size. This is the exact
  composition `mvmctl trust audit verify-inclusion` enforces host-side, so a
  root signed for a different tenant, or a self-consistent proof over an
  unsigned root, is rejected. `index.html` wiring for this flow is a
  follow-up.
