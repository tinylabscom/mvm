# sigstore-tsa

RFC 3161 Time-Stamp Protocol client for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate implements the Time-Stamp Protocol as specified in RFC 3161. It provides functionality to request timestamps from Time-Stamp Authorities (TSAs) and verify timestamp responses.

Timestamps provide trusted third-party evidence of when a signature was created, which is essential for verifying signatures after the signing certificate has expired.

## Features

- **Timestamp requests**: Create and send RFC 3161 timestamp requests
- **Response parsing**: Parse and validate timestamp responses
- **Timestamp verification**: Verify timestamp tokens against TSA certificates
- **Multiple TSAs**: Built-in support for Sigstore TSA and FreeTSA

## Usage

```rust
use sigstore_tsa::TimestampClient;

// Get a timestamp from the Sigstore TSA
let client = TimestampClient::sigstore();
let timestamp_token = client.timestamp_sha256(&digest).await?;

// Or use the convenience function
let token = sigstore_tsa::timestamp_sigstore(&digest).await?;
```

## ASN.1 Types

The crate provides ASN.1/DER types for RFC 3161 structures:

- `TimeStampReq` - Timestamp request
- `TimeStampResp` - Timestamp response
- `TstInfo` - Timestamp token info
- `Asn1MessageImprint` - Hash algorithm and digest (ASN.1 format)

## Related Crates

Used by:

- [`sigstore-sign`](../sigstore-sign) - Requests timestamps during signing
- [`sigstore-verify`](../sigstore-verify) - Verifies timestamps in bundles

## License

BSD-3-Clause
