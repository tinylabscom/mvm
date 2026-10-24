# sigstore-rekor

Rekor transparency log client for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides a client for Rekor, Sigstore's transparency log. Rekor provides an immutable, append-only ledger of signed software artifacts, enabling verification that signatures were created at a specific time and have not been tampered with.

## Features

- **Log entry creation**: Submit signatures and attestations to Rekor
- **Entry retrieval**: Fetch log entries by UUID, log index, or search criteria
- **Entry types**: Support for HashedRekord and DSSE entry types
- **Inclusion proofs**: Retrieve cryptographic proofs of log inclusion
- **Log info**: Query current log state and checkpoints

## Entry Types

| Type | Description |
|------|-------------|
| `hashedrekord` | Hash and signature over arbitrary content |
| `dsse` | DSSE envelope with in-toto attestations |

## Usage

```rust
use sigstore_rekor::RekorClient;

let client = RekorClient::production();

// Create a log entry
let entry = client.create_entry(&hashedrekord).await?;

// Retrieve an entry
let entry = client.get_entry_by_uuid(&uuid).await?;

// Search for entries
let entries = client.search_by_hash(&artifact_hash).await?;
```

## Related Crates

Used by:

- [`sigstore-sign`](../sigstore-sign) - Submits entries during signing
- [`sigstore-verify`](../sigstore-verify) - Verifies log inclusion

## License

BSD-3-Clause
