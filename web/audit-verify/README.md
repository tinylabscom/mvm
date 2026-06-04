# Browser audit-log verifier (ADR-069)

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
(ADR-013, ADR-046). The wasm32 target + `wasm-pack` belong in that guest,
not on a contributor's machine. The output (`pkg/*.js` + `…_bg.wasm`) is
what `index.html` imports; serve the directory statically and the page is
fully offline after load — nothing you paste leaves the tab.

## Inputs

- **Public key**: the host signer's Ed25519 public key as 64 hex chars
  (the private key lives at `~/.mvm/keys/host-signer.ed25519`, mode 0600).
  There is no CLI subcommand to print the public half yet — a small
  `mvmctl audit pubkey` printer is the obvious follow-up (noted in
  ADR-069). Until then, derive it from the keypair.
- **Audit log**: the contents of a per-tenant `~/.mvm/audit/<tenant>.jsonl`
  stream (paste, or pick the file).

## What it proves

Byte-for-byte the same thing `mvm_supervisor::verify_audit_chain` proves:
every line's `prev_hash` links the chain and every signature verifies
under the key. Any reordering, edit, or deletion fails. The equivalence
is pinned by `mvm-supervisor`'s `mvm_verify_matches_supervisor_chain`
test, so if the audit entry shape drifts, CI fails before the browser
tool can silently disagree.
