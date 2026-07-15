---
title: "ADR-027: Iroh-aware encryption layering"
status: Proposed
date: 2026-05-07
related: ADR-002 (security posture), ADR-005 (libkrun pivot), plan 60-mvm-libkrun-migration
---

## Status

Proposed. Implementation across Phases 2 (volumes/snapshots), 6 (mTLS for hostd, attestation), and ongoing.

## Context

mvmd uses **iroh** (https://iroh.computer) for its P2P agent transport. iroh provides QUIC with TLS 1.3 native, ALPN-tagged streams, and relay-mediated NAT traversal. The naive instinct was to layer additional mTLS on top of iroh for the mvmd↔mvm-agent hop "to be safe." This is wasteful (re-encryption costs CPU and adds bugs) and structurally confused (iroh's TLS already authenticates both ends via NodeIDs).

Separately, the **mvmd-agent ↔ mvm-hostd** hop is a *different* boundary — same machine, different process, communicating over a Unix domain socket. Here, mTLS *does* belong, because the agent is unprivileged and the hostd is root; mutual authentication is the safety mechanism.

And separately again, the **host ↔ guest** hop (vsock) needs its own auth model — vsock has no TLS by design.

The encryption story therefore decomposes into four independent boundaries, each with the right primitive for the threat at that layer.

## Decision

Encryption layers, named explicitly:

| Hop | Transport | Security | Owner |
|---|---|---|---|
| mvmd-coordinator ↔ mvmd-agent | iroh QUIC + relay | TLS 1.3 native to iroh; ALPN `/mvmd/agent/1` | iroh — **we do NOT layer extra TLS** |
| mvmd-agent ↔ mvm-hostd | Unix domain socket | mTLS via `rustls` + `rcgen`; certs per-node 7-day rotation | mvm (this repo) |
| host ↔ guest | virtio-vsock | `AuthenticatedFrame` (HMAC + X25519 ephemeral session keys for forward secrecy) | mvm-guest (this repo) |
| host process ↔ keystore | OS API (Keychain / Cred Mgr / Secret Service) | platform-native; HSM/TPM where available | OS + our `Keystore` trait |
| volume bytes at rest | LUKS2 (Linux) / APFS-encrypted (macOS) / BitLocker (Windows) | AES-XTS | OS + our `Keystore` wrap |
| snapshot bytes at rest | AEAD: AES-256-GCM (preferred) / ChaCha20-Poly1305 | per-snapshot DEK wrapped by tenant KEK | mvm (this repo) |

Each layer rotates independently (see plan 60 §"Encryption and key rotation design").

## Consequences

**Positive**:
- No double-encryption at the iroh hop (CPU, latency saved).
- Each layer's key material is scoped to its threat (no master-key compromise across layers).
- Layer documentation matches code structure — each `mvm/src/security/<name>.rs` aligns with one row in the table.

**Negative**:
- Operators must understand the layering to debug cert / key issues. Mitigated by a runbook (`specs/runbooks/key-management.md`, Phase 2).
- Cross-layer key derivation (e.g., a tenant KEK derived from a node identity key) requires careful documentation.

## Alternatives considered

- **Add mTLS over iroh**: rejected. Wasteful CPU; iroh already authenticates both ends via Ed25519 NodeIDs.
- **Plaintext over iroh and rely on the network**: rejected. iroh's QUIC is the security primitive; we just don't *double*-secure.
- **One unified key hierarchy**: deferred. Useful for compliance reporting (single root → many DEKs) but not load-bearing for security; revisit in Phase 9.

## Threat model impact

The four-boundary model maps cleanly onto STRIDE per layer. Each threat (Spoofing, Tampering, Information Disclosure, Elevation of Privilege) is addressed by the layer that owns the boundary, not by all layers redundantly.

## Compliance impact

- SOC 2: positive — encryption-in-transit and at-rest are both covered with explicit owners.
- PCI: positive — segments cardholder data flow from operational flow.
- HIPAA: positive — Transmission Security (§164.312(e)) is satisfied per-layer with documented mechanisms.


## Consolidated from ADR-042 — Encryption substrate — where AES-GCM lives, what HKDF is for, and how key rotation works

## Status

Accepted. Plan 63 W1–W6 shipped the full mvm-side encryption substrate in commits b9e4e64 (W2), 1ea9352 (W3), f7e39a7 (W1), a30f866 (W4), 6fc798d (W5), and this commit (W6). The plan-60 §"Security model" claim "tenant data encryption keys can be rotated without downtime" went from substrate-only to user-observably true.

## Context

Plan 60's Phase 2 calls for "encryption everywhere" — at-rest encryption for volumes, snapshots, and secrets, plus key rotation without re-encrypting data. Plan 45 §D5 decided that the *bulk* encryption code (the `EncryptedBackend<B>` decorator, AES-SIV for deterministic volume keys, HKDF for per-volume key derivation, the `opendal` object-store path) lives **in mvmd, not in mvm**. mvm provides the substrate the mvmd-side path needs:

- AES-256-GCM primitives over byte slices (`snapshot_crypto`).
- AES-256-GCM primitives over file paths in 1 MiB chunks (`snapshot_encryption`).
- HMAC-SHA256 envelope over arbitrary file groups with monotonic-epoch replay defence (`snapshot_hmac`).
- `KeyProvider` trait + three impls (env, file, OS-keyring) returning `SecretBox<Vec<u8>>`.
- `SecretStore` trait + two impls (file, OS-keyring) for the multi-key tenant secret case.
- Versioned master-key store with manifest, atomic rotation, and DEK re-wrap.
- LUKS2 keyslot rotation via cryptsetup shell-out (mode-0600 tempfiles, never argv).
- Snapshot KEK rolling via verify-under-old + reseal-under-new + atomic rename.

Until plan 63 shipped, the substrate was incomplete in three load-bearing ways:

1. **No key rotation.** Tenants couldn't roll their master key without re-encrypting every DEK by hand.
2. **No multi-key secret store.** `KeyProvider` is single-key-per-tenant (the master DEK); there was nowhere to put `api_token`, `webhook_secret`, etc.
3. **Snapshots weren't encrypted at rest.** HMAC-SHA256 protected integrity but the memory image was readable by anyone who could read `~/.mvm/`.

ADR-042 documents the closed shape: what lives where, which algorithms are pinned, what the rotation invariants are, and the secrets-in-types contract.

## Decision

### Algorithm choices

| Primitive | Algorithm | Where it lives | Rationale |
|---|---|---|---|
| At-rest authenticated encryption | AES-256-GCM | `mvm-security::snapshot_crypto` (slices) + `snapshot_encryption` (files) | Hardware-accelerated on every supported host; 96-bit nonce + 128-bit tag is the conventional packaging; the FIPS 140-3 module ecosystem certifies AES-256-GCM widely. |
| Sealed-bundle integrity | HMAC-SHA256 | `mvm-security::snapshot_hmac` | Stripped to the minimum — separate from the encryption layer so a corrupted ciphertext fails the HMAC check *before* AEAD decryption is attempted. Defense-in-depth, not just a tag we already get from GCM. |
| Per-tenant DEK wrap | AES-256-GCM (`Aes256Gcm` variant) | `mvm-security::key_rotation::rewrap_dek` | Re-uses `snapshot_crypto`, no new primitive. Fresh nonce per re-wrap, plaintext DEK held in `SecretBox` for the duration of the unwrap → re-wrap window. |
| Tenant DEK wrap (mvmd-side) | AES-KWP (NIST SP 800-38F / RFC 5649) | mvmd's `EncryptedBackend<B>` | The deterministic-key wrap path mvmd uses for volume DEKs; mvm refuses to handle this variant in-crate and points at mvmd. |
| Snapshot HMAC key derivation | host-local random 32 bytes | `~/.mvm/snapshot.key` mode 0600 | Single-host posture; key is a per-host secret, not tenant-scoped. |
| Tenant master key | host-local random 32 bytes per version | `<active_dir>/v<N>.bin` mode 0600 | Versioned; the manifest tracks the lifecycle (`Active → Legacy → Revoked`). |

### Key-rotation invariants

`mvm-security::key_rotation` ships five primitives, each with a hard invariant:

1. **`rewrap_dek(wrapped, old_master, new_master, new_version)` is resumable-safe.** Idempotent against the (new_version, wrapped) pair: re-running on an already-migrated record is the caller's responsibility (the `migrate_wrapped_keys` bulk path checks `master_key_version` and returns `Skipped`).
2. **`rotate_master_key(active_dir, &org_id)` is *not* idempotent — it always produces a fresh version.** Callers that want "rotate only if no fresh-enough key exists" consult `load_manifest` first. Marking prior `Active → Legacy` and the manifest write happen atomically via `.tmp + rename`; an interrupted call leaves the previous manifest intact.
3. **`migrate_wrapped_keys` converges on retry.** Records already at `to_version` are `Skipped`; records at neither `from_version` nor `to_version` fail loudly rather than guess. Caller commits each record's storage in its own transaction; on host crash, the next invocation picks up where it left off.
4. **`rotate_luks_slot` never puts passphrases on argv.** Both old and new passphrases stage through mode-0600 tempfiles auto-unlinked on drop.
5. **`reseal_snapshot` advances the epoch.** Verifies under old key at the current epoch, then advances the `EpochStore` and re-seals under the new key at epoch+1. Tampered snapshots fail the old-key verify and the seal is left untouched.

### Secrets-in-types contract (W2)

Every secret-carrying type in mvm-security wraps `secrecy::SecretBox<T>`:

- `KeyProvider::get_data_key` returns `SecretBox<Vec<u8>>`.
- `SecretStore::get` returns `SecretBox<String>`.
- `snapshot_hmac::load_or_init_key` returns `SecretBox<[u8; HMAC_KEY_BYTES]>`.
- `key_rotation::rewrap_dek` holds the unwrapped DEK in `SecretBox<Vec<u8>>` for the duration of the re-wrap.
- `key_rotation::load_master_key` returns `SecretBox<[u8; MASTER_KEY_BYTES]>`.

The xtask `check-no-display-on-secret-types` lint walks `crates/*/src/**/*.rs` via `syn` and rejects any `derive(Debug)` or `impl Display` on a type whose name contains `Secret|Key|Password|Token` (case-insensitive). Conservative — opt-out is `// allow(secret-debug): <reason>` directly above the type. Two opt-outs exist today, both documented:

- `WrappedKey` in `mvm-core::domain::volume` carries ciphertext (not key bytes); the hand-written `Debug` redacts the field to `<N bytes>`.
- `MasterKeyManifest` in `mvm-security::key_rotation` carries metadata only (`org_id`, `version`, `created_at`, `state`); deriving Debug helps operators read audit trails.

The lint runs on every PR via `cargo run -p xtask -- check-no-display-on-secret-types`.

### Snapshot encryption shape

`mvmctl pause` transparently encrypts the snapshot artifacts when a tenant DEK is configured. The lifecycle:

```
mvmctl pause <vm>
  ↓ FirecrackerIO::create_snapshot → vmstate.bin + mem.bin
  ↓ tighten file modes to 0600
  ↓ if keystore::default_provider().get_data_key("local") is Ok:
      encrypt_file_in_place(vmstate.bin, dek)  # MVSE magic
      encrypt_file_in_place(mem.bin, dek)
  ↓ EpochStore::next()  → monotonic epoch
  ↓ snapshot_hmac::seal(dir, files, epoch, version, hmac_key)
  ↓ ~/.mvm/instances/<vm>/snapshot/integrity.json now covers
    whichever shape we just wrote (encrypted or not).

mvmctl resume <vm>
  ↓ snapshot_hmac::verify(...) — fails fast on tamper or replay
  ↓ probe(vmstate.bin):
      encrypted + DEK available → decrypt_file_in_place
      encrypted + DEK missing   → refuse with "run `mvmctl secret put`"
      unencrypted + DEK present → refuse (downgrade defence);
                                  MVM_ALLOW_UNENCRYPTED_SNAPSHOT=1
                                  is the one-time migration escape
      unencrypted + no DEK      → resume normally (pre-W5 shape)
  ↓ FirecrackerIO::load_snapshot
```

Chunked wire format (24-byte header + N chunks of nonce(12) + ciphertext_with_tag(chunk_size + 16)) handles snapshots into multi-GB territory without holding the whole image in memory. Default chunk size is 1 MiB; tests inject a 64-byte chunk size to exercise multi-chunk paths cheaply.

### Operator-facing surface

- `mvmctl secret put <name> --tenant <T> [--value V | --value - | --value-file PATH]` — stores or replaces a value. With no explicit source, prompts with hidden terminal input when stdin is a TTY, or reads piped stdin otherwise. Inline / stdin / file remain supported. Never logs the value. File-backed records are AES-256-GCM encrypted at rest.
- `mvmctl secret get <name> --tenant <T>` — verifies that the secret exists and prints only presence metadata. It never emits the raw value; secrets can be replaced with `put` but not viewed after storage.
- `mvmctl secret ls --tenant <T>` — names only.
- `mvmctl secret rm <name> --tenant <T>`.
- Audit emissions for every CRUD operation appear at `~/.mvm/audit/secrets.jsonl` carrying `(timestamp, action, tenant, name, outcome, pid, error?)`. Values are never recorded.

Provisioning the tenant DEK happens out-of-band (today) via `MVM_TENANT_KEY_LOCAL=<hex>` for `EnvKeyProvider`, `/var/lib/mvm/keys/local.key` for `FileKeyProvider`, or `keyring set mvm local <hex>` for `KeyringProvider`. A future polish workstream may add a `mvmctl key rotate` CLI surface; the plan-63 W1 substrate (`rotate_master_key` + `migrate_wrapped_keys`) is the foundation.

### What lives where — convergence rule

Per plan 45 §D5 / plan 63 §"Convergence rule":

| Concern | mvm-security | mvmd | Why |
|---|---|---|---|
| AES-256-GCM (slices, files) | ✅ owned | uses | Both halves need it |
| HMAC-SHA256 (snapshot integrity) | ✅ owned | uses | Both halves need it |
| AES-KWP (RFC 5649 DEK wrap) | ❌ refuse | ✅ owned | Deterministic-wrap path mvmd uses for volume keys |
| AES-SIV (deterministic encryption) | ❌ absent | ✅ owned | Object-store volume keys need deterministic ciphertexts |
| HKDF (per-volume key derivation) | ❌ absent | ✅ owned | Volume-specific key derivation lives at the EncryptedBackend layer |
| KeyProvider / SecretStore | ✅ owned | uses | OS-keystore + file-based key provisioning is per-host concern |
| key_rotation primitives | ✅ owned | uses | Substrate; mvmd orchestrates fleet-wide rotation atop |
| EncryptedBackend<B> decorator | ❌ absent | ✅ owned | mvmd-side per Path C |
| Object-store volume encryption | ❌ absent | ✅ owned | Path C, opendal-backed |

mvm-side `make_backend` returns `VolumeError::UnsupportedBackend` for `ObjectStore`, redirecting callers to `mvmctl --remote` which proxies through mvmd.

## Consequences

### Positive

- **Tenant DEK can rotate without re-encrypting data.** `rewrap_dek` unwraps under the prior master, re-wraps under the new master, preserves the underlying DEK plaintext. Idempotent on retry after a crash.
- **Snapshots are encrypted at rest** when a tenant DEK is configured, transparently — no new CLI surface required. Pre-W5 unencrypted snapshots keep working until the operator opts into the migration via `MVM_ALLOW_UNENCRYPTED_SNAPSHOT=1`.
- **Tenant secrets have a real home.** `mvmctl secret put/get/ls/rm` works on every supported host; OS keyring when reachable, AES-256-GCM encrypted files with a mode-0600 local store key otherwise. Auto mode keeps file-backed entries visible when the OS keyring is reachable, so backend probe changes do not hide existing secrets. Values never appear in logs.
- **Compile-time guard against accidental secret logging.** `SecretBox<T>` makes `Debug`/`Display` a compile error; the xtask lint catches the few types whose name contains `Key|Secret|Password|Token` even when the wrap isn't explicit.
- **Convergence rule keeps the surface small.** mvm provides primitives; mvmd composes them. The "where does AES-KWP live?" / "where is HKDF wired?" ambiguity that haunted Phase 1 is closed.

### Negative / honest deferrals

- **No hardware key attestation.** Tenant DEKs live as software-managed keys on the host filesystem or OS keyring. TPM2 / SEV-SNP / TDX integration is plan 60 Phase 6's territory.
- **No per-volume DEK on the mvm side.** The `Volume` type in `mvm-core::domain::volume` doesn't carry a `WrappedKey` field — that's mvmd's `EncryptedBackend<B>` concern per plan 45 §D5. mvm-security's `migrate_wrapped_keys` operates on a caller-supplied slice; mvmd owns the storage-side enumeration.
- **No cross-host secret replication.** Single-host posture only. mvmd's secret service handles fleet-wide distribution.
- **`mvmctl key rotate` CLI is a future polish.** The W1 primitives (`rotate_master_key`, `migrate_wrapped_keys`) are callable but operator-driven rotation hasn't been wired through a user-facing verb yet.
- **Migration escape exists.** Pre-W5 unencrypted snapshots can be resumed under a key-configured tenant via `MVM_ALLOW_UNENCRYPTED_SNAPSHOT=1`. This is a one-time bypass — the next pause encrypts. Documented for the v0.14 → v0.15 cut.
- **File-store key custody is local-host only.** The file backend encrypts values at rest with a mode-0600 local store key. This is single-host protection, not cross-host replication or hardware-backed attestation.

### Out of scope (named in plan 63's non-goals)

- Object-store encryption (mvmd, Path C).
- TPM2 / SEV-SNP / TDX hardware attestation.
- End-to-end network encryption (plan 60 Phase 3).
- Per-volume LUKS at the host level (mvmd's `StorageBucket` ↔ filesystem volume convergence).

## References

- `specs/plans/63-phase-2-encryption-everywhere.md` — full sprint plan for plan 63, with per-workstream status.
- `specs/plans/60-mvm-libkrun-migration.md` Phase 2 — the cornerstone this ADR documents the closing of.
- `specs/plans/45-filesystem-volumes.md` §D5 / Path C — convergence rule for where `EncryptedBackend<B>` lives.
- ADR-002 (`specs/adrs/002-microvm-security-posture.md`) — the security claims the substrate underpins.
- ADR-027 (`specs/adrs/027-iroh-aware-encryption-layering.md`) — broader encryption layering across iroh + on-disk surfaces.
- `crates/mvm-core/src/domain/volume.rs` — `WrappedKey`, `MasterKeyRef`, `WrapAlgorithm::{AesKwp, Aes256Gcm}`.
- `crates/mvm-security/src/snapshot_crypto.rs` — AES-256-GCM over slices.
- `crates/mvm-security/src/snapshot_encryption.rs` — AES-256-GCM over files (chunked).
- `crates/mvm-security/src/snapshot_hmac.rs` — HMAC-SHA256 + `SecretBox<[u8; 32]>`.
- `crates/mvm-security/src/keystore.rs` — `KeyProvider` + Env/File/Keyring impls.
- `crates/mvm-security/src/secret_store.rs` — `SecretStore` + File/Keyring impls.
- `crates/mvm-security/src/key_rotation.rs` — rotation primitives + `MasterKeyManifest`.
- `crates/mvm-cli/src/commands/ops/secret.rs` — `mvmctl secret` subcommand surface.
- `crates/mvm/src/vm/instance_snapshot.rs` — pause/resume pipeline with W5 integration.
- `xtask/src/check_no_display_on_secret_types.rs` — the CI lint enforcing the `SecretBox<T>` contract.
