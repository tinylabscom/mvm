---
title: Seven CI claims
description: The security claims that must stay backed by tests and documentation.
---

The public security model is claim-gated. A claim should be presented as a
guarantee only when implementation, tests, and docs agree.

## Current claim set

| # | Claim | Evidence path |
| --- | --- | --- |
| 1 | No host filesystem access beyond explicit shares. | Guest profile, seccomp, mount policy, docs examples. |
| 2 | Guest binaries cannot elevate to uid 0. | `no_new_privs`, readonly account files, launch tests. |
| 3 | Tampered rootfs fails where verified boot is supported. | dm-verity/root hash tests and backend caveats. |
| 4 | Production guest agent excludes development exec handlers. | Symbol checks and profile-gated request refusal. |
| 5 | Vsock framing is fuzzed and closed over known messages. | Fuzz targets, `deny_unknown_fields`, protocol tests. |
| 6 | Prebuilt dev images are hash-verified. | Manifest verification before use. |
| 7 | Supply-chain dependencies are audited on every PR. | `cargo audit`, dependency policy, CI gates. |

## How to use this page

When writing docs, link strong claims to the [Security claim ledger](/security/claim-ledger/)
or [Matryoshka model](/security/matryoshka/). If the behavior is backend-specific,
name the backend.

## What not to claim

- Do not claim the dev/test QEMU backend carries the same claims as Firecracker (claim 3 partial; Tier 2 dev/test only).
- Do not claim secret non-leakage for manual file mounts.
- Do not claim cold-start numbers without a published benchmark.
- Do not imply Windows local runtime support is shipped.
