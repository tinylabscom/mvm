# Sigstore optional-client source patches

These two local Cargo patches let `mvm` verify Sigstore bundles offline
without compiling the Rekor and timestamp-authority HTTP clients. Verification
is unchanged: the patch only makes the `reqwest`-based `client` modules
optional. Upstream compiles them unconditionally, which pulled `reqwest`,
`hyper`, `hyper-util`, `tower`, `tower-http` and friends into every `mvmctl`
that links the verifier, although `mvm` verifies against an embedded trust root
and the bundle's inline proofs and never calls a Sigstore service.

## Immutable source origin

Both packages originate at https://github.com/prefix-dev/sigstore-rust and are
licensed `Apache-2.0` per their manifests. Their published archives carry no
separate license files.

| Package | Published archive SHA-256 (equals the `Cargo.lock` checksum) | Upstream revision recorded in `.cargo_vcs_info.json` |
| --- | --- | --- |
| `sigstore-rekor 0.11.0` | `9b97c5a866f849a9445ae657bef0caa2db053a82827e6dae3a2b3de9c15a6a1a` | `ef17cacdbd357befea4c1c768ef02ed9bf52672c` |
| `sigstore-tsa 0.11.0` | `b58fe92d4d8cf4b7215b927b70bc1245b6e0d70d801febdfe0cd265ad97ebf8b` | `ef17cacdbd357befea4c1c768ef02ed9bf52672c` |

## What differs from the published archives

Exactly four files, and nothing else (`.cargo-ok` and the crate-local
`Cargo.lock` are not carried):

- `Cargo.toml` of each package: `reqwest` becomes `optional = true`, a new
  `client = ["dep:reqwest"]` feature owns it, and `rustls` and `native-tls`
  now also enable `client`. `default = ["rustls"]` is unchanged, so an
  unpatched consumer sees the same default behaviour.
- `src/lib.rs` of each package: `pub mod client;` and its `pub use` are behind
  `#[cfg(feature = "client")]`. No other module referenced `reqwest`.

No parsing, hashing, signature, certificate, Merkle-proof or timestamp logic
is touched.

## How `mvm` selects them

`mvm-core` depends on `sigstore-verify` with `default-features = false` and no
TLS feature, so the clients stay off. The `sigstore-network` feature of
`mvm-core` enables `sigstore-verify/rustls`, which turns the clients (and the
TUF fetch in `sigstore-trust-root`) back on for an embedder that wants them.
No shipped `mvmctl` surface enables it.

## Removal

Delete the two `[patch.crates-io]` entries and these directories once the
upstream crates make the client optional. `sigstore-verify` and `-bundle`
already take `default-features = false` on both, so nothing else changes.
