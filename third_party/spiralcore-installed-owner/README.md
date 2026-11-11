# Installed resource ownership component

This MIT-licensed component is imported from SpiralCore. The full copyright
notice is preserved in `LICENSE-MIT`; `provenance.json` records the source
revision, paths, exact imported hashes and integration-test import edit.

The original owner holds an exclusive owner lock. Every participating resource
retains its own shared holder lease for the original installation/profile/epoch.
Recovery requires a fresh, separately opened exclusive holder lock; it does not
infer cleanup from a PID, timeout or metadata assertion. Drop never publishes a
clean epoch. Stable descriptor identities, private local storage and durable
publication barriers remain mandatory.

The import preserves the fixed 176-byte record and checksum domain. It uses
MVM's already locked SHA-256 dependency and adds no package version. The record
checksum is damage detection, not authentication or a FIPS-validation claim.

`mvm-vmm::host::installed_owner` is a Unix resource-lifetime primitive. Its
successful retirement proves exclusion only of resources that actually retain
the lease. It neither grants mailbox/boot authority nor proves original Child
collection. Host-agent, signer, helper and cleanup-job participation must be
integrated and tested before it can qualify installed-service recovery.

Focused Linux validation commands (serial subprocess fixtures):

```sh
cargo test --release --locked -p mvm-vmm --test installed_owner -- --test-threads=1
cargo test --release --locked -p mvm-vmm --lib host::installed_owner -- --test-threads=1
cargo clippy --release --locked -p mvm-vmm --lib --test installed_owner -- -D warnings
```

These commands exercise the imported production module. They boot no MVM and
do not establish native macOS, Windows, WAN, durable mailbox or fleet acceptance.
