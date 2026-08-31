# Plan 2026-08-31: RustCrypto 0.11 migration and aws-lc-rs removal (B4/C1)

Backing: shipped-source
Validation: none

## Gate that unblocked this plan

This plan was gated on two upstream crates shipping STABLE (non-RC) releases:

- **aes-gcm 0.11** — required for the RustCrypto 0.11 trait line unification
- **ed25519-dalek 3.0** — required for the 0.11 digest/signature ecosystem

ADR-002 forbids RC crypto in the shipped closure. Both gates cleared on
2026-08-21 (aes-gcm 0.11.1) and 2026-08-?? (ed25519-dalek 3.0.0). This plan
documents the work done once both were confirmed stable.

## What was already done

When the gates cleared, the workspace was inspected and found to have already
advanced the RustCrypto 0.11 line in `[workspace.dependencies]`:

| Crate | Workspace spec | Lock file |
|---|---|---|
| aes-gcm | `"0.11"` | 0.11.0 → **0.11.1** (this PR) |
| sha2 | `"0.11"` | 0.11.0 (+ 0.10.9 optional) |
| digest | (via sha2/hmac) | 0.11.3 (+ 0.10.7 optional) |
| hmac | `"0.13"` | 0.13.0 |
| hkdf | (via hmac) | 0.13.0 |
| ed25519-dalek | `"3"` | 3.0.0 |
| x25519-dalek | `"3"` | 3.0.0 |

The workspace-level migration was complete before this plan ran. The
0.10.9/0.10.7 versions in the lock file are **read-only transitive entries**
from `sigstore-crypto 0.11.0` (the latest release as of 2026-08-31), which
unconditionally depends on the 0.10 digest line. They are gated behind the
optional `manifest-verify` feature and never enter the default shipped closure.

## What this PR does

- Bumps `aes-gcm` in `Cargo.lock` from 0.11.0 to **0.11.1** (the first stable
  release; `cargo update -p aes-gcm`).

## aws-lc-rs status

`aws-lc-rs` is present in `Cargo.lock` but is NOT in the default shipped
closure. Dependency chain:

- Default closure: no aws-lc-rs path (confirmed — `mvm-http` uses
  `reqwest` with `rustls-no-provider` and no `http3` feature; no quinn pulled
  in on the default path).
- `user` feature (manifest-verify → sigstore-verify → sigstore-crypto 0.11.0):
  aws-lc-rs **is** reachable. sigstore-crypto 0.11.0 is the latest upstream
  release and unconditionally depends on aws-lc-rs. This cannot be removed
  without an upstream sigstore-crypto update.
- `template-registry-s3` feature (object_store 0.14.1): aws-lc-rs **is**
  reachable. This is an optional feature used only by the S3 template registry
  backend and also blocked on upstream.

## C1 note (oci-client rustls-tls-no-provider)

The originally anticipated C1 step — applying the oci-client
`rustls-tls-no-provider` feature (oras-project/rust-oci-client#274) — does not
apply to this workspace. The workspace has no `oci-client` dependency; OCI
operations go through `mvm-fs`'s own OCI layer implementation. No action needed.

## What remains (blocked upstream)

| Item | Blocked on |
|---|---|
| Remove sha2 0.10.9 / digest 0.10.7 from lock | sigstore-crypto > 0.11.0 shipping a digest-0.11 build |
| Remove aws-lc-rs from lock (manifest-verify path) | same |
| Remove aws-lc-rs from lock (object_store path) | object_store shipping without aws-lc-rs default |

When sigstore-crypto releases a version that uses the 0.11 digest line and
removes the aws-lc-rs dep, running `cargo update -p sigstore-crypto` will
clear all three items in one operation.

## Checklist

- [x] B4 — RustCrypto 0.11 workspace migration (workspace specs were already updated; aes-gcm bumped to 0.11.1 in lockfile)
- [x] C1 — oci-client rustls-tls-no-provider (not applicable — no oci-client dep in workspace)
- [ ] D2 ratchet — `cargo tree -i aws-lc-rs` empty in default closure (already true for default; blocked for `manifest-verify` path on sigstore-crypto upstream)
