# Kernel pin freshness remediation

Issue: #1839

Status: COMPLETE

## Scope

Update the two deliberately synchronized Linux 6.12 kernel pins from 6.12.97
to the published 6.12.98 point release. Both pins use the same upstream
tarball and must carry the same verified Nix SRI hash.

## Delivery checklist

- [x] Update the `libkrunfw` tarball URL and hash.
- [x] Update the custom workload/builder kernel version and hash.
- [x] Add or update focused coverage for synchronized kernel pins.
- [x] Run formatting, workspace check, tests, and clippy gates.
- [ ] Publish the verified branch as a pull request.

The verified branch is ready for publication as a pull request.

## Source verification

The upstream `linux-6.12.98.tar.xz` SHA-256 is
`a62b6a2d207ff72510e5f47156b7078e1e71797357412411b8e4fff97fc8f4c7`, which
converts to the Nix SRI hash
`sha256-pitqLSB/9yUQ5fRxVrcHjh5xeXNXQSQRuOT/+X/I9Mc=`.
