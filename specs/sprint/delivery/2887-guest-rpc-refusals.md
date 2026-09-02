# 2887 — Guest RPC refusal handling and explicit SDK dev profile

Backing: shipped-source
Validation: check-sprint-append

## What shipped

Filesystem and process RPC helpers now use the shared unary-response contract.
Valid universal refusals such as `VerbNotAuthorized` and
`UnsupportedInProfile` therefore remain typed errors instead of being reported
as an unmatched response variant.

The runtime SDK's live transport also carries an explicitly selected outer run
profile into its nested `machine run`. `mvmctl run --mode live --profile dev`
sets the Rust-owned `MVM_SDK_RUN_PROFILE` contract, and both language SDKs
validate and lower it to `machine run --profile dev`. A direct SDK launch with
no profile remains on the CLI's secure standard default; unknown values fail
before a VM is booted.

The Python and TypeScript live fixtures now exercise the explicit dev profile,
produce the same golden argv, and retain the sealed-machine refusal witness.

## Verification

- `cargo test -p mvm-agentd rpc_surfaces_`: 2 passed
- `cargo test -p mvm-sdk env::tests`: 5 passed
- `cargo check -p mvm-cli`: passed
- Python live Sandbox suite: 58 passed
- TypeScript SDK suite: 151 passed
- SDK BDD live argv scenarios passed in both languages; the reviewed surface
  divergence check passed after verifying the generated root export in both
  built artifacts
- generated SDK environment bindings refreshed from the Rust registry
