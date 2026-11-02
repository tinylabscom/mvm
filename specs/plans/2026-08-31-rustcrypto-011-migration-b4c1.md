# Plan 2026-08-31: RustCrypto 0.11 migration and aws-lc-rs removal (B4/C1)

Backing: shipped-source
Validation: none

## Gate that unblocked this plan

This plan was gated on two upstream crates shipping STABLE (non-RC) releases:

- **aes-gcm 0.11** — required for the RustCrypto 0.11 trait line unification
- **ed25519-dalek 3.0** — required for the 0.11 digest/signature ecosystem

ADR-002 forbids RC crypto in the shipped closure. Both gates cleared on
2026-08-21 (aes-gcm 0.11.1) and 2026-10-26 (ed25519-dalek 3.0.0). This plan
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
0.10.9/0.10.7 versions in the lock file were **read-only transitive entries**
from `sigstore-crypto 0.11.0`, which unconditionally depended on the 0.10
digest line. Those entries are gone as of the D2 upgrade below.

## What B4 did

- Bumps `aes-gcm` in `Cargo.lock` from 0.11.0 to **0.11.1** (the first stable
  release; `cargo update -p aes-gcm`).

## What D2 did (2026-11-02)

sigstore-crypto 0.15.1 (released 2026-10-xx) moved aws-lc-rs to an optional
feature (`default = ["aws-lc-rs"]` but `aws-lc-rs` behind `dep:aws-lc-rs`).
sigstore-tsa and sigstore-rekor 0.15.x adopted the client-optional approach
upstream, so the workspace patches in `third_party/sigstore-{tsa,rekor}-0.11.0`
are no longer needed and have been removed.

Changes in this step:
- `mvm-core` sigstore-verify/trust-root/types upgraded from `"0.11"` to `"0.15"`
- `[patch.crates-io]` entries for sigstore-rekor and sigstore-tsa removed
- `third_party/sigstore-{tsa,rekor}-0.11.0/` directories deleted
- `third_party/sigstore-patches.md` deleted (described the now-removed patches)
- `image_verify.rs`: `VerificationPolicy::default()` → `any_identity()`;
  `result.identity` → `result.identity().to_string()`; `result.issuer` → `result.issuer()`
- `cargo tree -i aws-lc-rs` returns exit 101 (not found) for the whole workspace

**Collateral dependency upgrades required to resolve pem/base64 conflicts:**

sigstore-types 0.15.1 introduced `pem 4.0.0`, which requires `base64 ^0.23`.
The following packages were on `pem ^3` / `base64 ^0.22` and had to be
upgraded to avoid new `xtask check-duplicate-majors` failures:

| Package | Before | After |
|---|---|---|
| rcgen | 0.14.7 | 0.14.10 |
| plist | 1.10.0 | 1.10.3 |
| reqwest | 0.13.4 | 0.13.5 |
| hyper-util | 0.1.20 | 0.1.21 |

All four require Rust 1.88, so the workspace MSRV was bumped from **1.85 →
1.88** in `Cargo.toml`. Rust 1.88 stabilises let-chains and introduces two new
lints (`manual_is_multiple_of`, `collapsible_if` with let-chains) that required
mechanical fixes across several crates.

**Net result:** 5 previously allowlisted duplicates removed (`rand`, `rand_core`,
`sha2`, `signature`, `untrusted`); workspace drops from 20 to 15 allowlisted
duplicate-major crates.

`digest 0.10.7` remains in the lock file via `sha1 0.10.6 ← gix`; that is
unrelated to sigstore and is tracked separately.

## aws-lc-rs status (after D2)

`aws-lc-rs` is **not** in `Cargo.lock`. `cargo tree -i aws-lc-rs` errors
"package ID specification did not match any packages" for the workspace.

## C1 note (oci-client rustls-tls-no-provider)

The originally anticipated C1 step — applying the oci-client
`rustls-tls-no-provider` feature (oras-project/rust-oci-client#274) — does not
apply to this workspace. The workspace has no `oci-client` dependency; OCI
operations go through `mvm-fs`'s own OCI layer implementation. No action needed.

## Checklist

- [x] B4 — RustCrypto 0.11 workspace migration (workspace specs were already updated; aes-gcm bumped to 0.11.1 in lockfile)
- [x] C1 — oci-client rustls-tls-no-provider (not applicable — no oci-client dep in workspace)
- [x] D2 ratchet — `cargo tree -i aws-lc-rs` empty across all features (cleared 2026-11-02 by upgrading sigstore-* to 0.15.1)
