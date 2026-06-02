# Plan 122 — Encryption + key lifecycle

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the at-rest encryption story on both platforms, give every key a defined lifecycle (rotation + zeroize + rebuild-rekey), make snapshot artifacts content-addressed and signed, and reseed the guest CSPRNG on resume so two clones of a snapshot can't reuse key material. Reuse the crypto already in the tree; add no new dependencies.

**Architecture:** The pieces exist. AES-256-GCM at-rest (`snapshot_encryption.rs`, `snapshot_crypto.rs`), a DEK/KEK envelope (`key_rotation.rs::rewrap_dek` + `keystore.rs`), OS-keyring storage, LUKS2 volumes on Linux, and `SecretBox` zeroize are all present in `mvm-security` (→ `mvm-core` after plan 121). This plan closes the gaps: the macOS volume path, the 90-day KEK rotation timer, the per-rebuild DEK binding, content-addressed + signed snapshots, and VMGenID-driven reseed. The crypto engine lives in `mvm-core`; the `encrypted` `StorageProvider` that wraps volume bytes is plan 123's job, consuming this engine.

**Tech Stack:** existing deps only — `aes-gcm`, `ed25519-dalek`, `x25519-dalek`, `sha2`, `hmac`, `keyring`, `zeroize`, `getrandom`. No `snow`, no `chacha20poly1305`, no `hkdf`, no `libcryptsetup-sys` (see the design note).

**Prereq:** plan 121 folds `mvm-security` into `mvm-core`. This plan works in that post-121 module; it writes `mvm_core::crypto::*` for the new code (121 B3 settles whether the fold lands as `mvm_core::security` or `mvm_core::crypto` — use whichever it picked).

**Boundary:** the `encrypted` volume `StorageProvider` impl → plan 123 (calls this engine). Egress TLS + the mvmd-hop transport → mvmd. The **no-raw-secrets-to-guest** invariant (ADR-066 §5) is a separate workstream — ADR-062 dropped the old `host.secrets.v1` substitution, so it must be re-designed and built on its own (the brief's secrets plan + its ADR). This plan's channel carries opaque handles, never raw secret bytes; Task A0 only adds the seam that a future untrusted-boundary channel would encrypt over.

---

## Design note — dropping in-flight channel encryption (revises ADR-066 §5)

ADR-066 §5 specified Noise (`snow`) on the vsock channel and mTLS on the agent↔hostd UDS. Reconsidered against the dependency budget and ADR-002's trust model, both are low-value:

- The host is in the TCB and reads guest RAM directly. The vsock channel and the host-side UDS are local, between endpoints the model already trusts. Encrypting them protects plaintext from an observer that can read the plaintext anyway.
- The frames are already Ed25519-authenticated (`AuthenticatedFrame`, `SessionHello`/`Ack` in `mvm-core/src/policy/security.rs:38`). Authenticity is the property that matters here — it stops a compromised guest from forging host messages, and vice versa. Keep it.
- Confidentiality belongs on channels that cross an untrusted boundary. Those are egress and the mvmd hop, which already use TLS / iroh.

So this plan keeps authenticated cleartext framing and adds no `snow`. If a future channel does cross an untrusted boundary inside mvm, add Noise then, scoped to that channel. **This reverses an approved ADR decision — veto if you want Noise kept, and I'll restore it.** ADR-066 §1 (pluggable encryption stage) + §5 (authenticated cleartext on host-local channels) are already reconciled to this; the pluggable seam is built in Task A0.

---

## Existing surface (build on, do not reinvent)

| Concern | Where | What it gives |
|---|---|---|
| AEAD primitive | `mvm-security/src/snapshot_crypto.rs:28,54` | `encrypt(pt,key)`/`decrypt(ct,key)`, AES-256-GCM, `[nonce‖ct‖tag]` |
| File-at-rest | `mvm-security/src/snapshot_encryption.rs:96,229` | `encrypt_file_in_place(path,key)` chunked AES-256-GCM |
| DEK/KEK envelope | `mvm-security/src/key_rotation.rs:104` | `rewrap_dek(wrapped, old_master, new_master, version)` → `WrappedKey` |
| Master-key store + rotate | `key_rotation.rs:243,315` | `rotate_master_key`, `migrate_wrapped_keys` (resumable), manifest |
| Snapshot reseal | `key_rotation.rs:417` | `reseal_snapshot(dir, old, new, version)` + epoch counter |
| Per-tenant DEK store | `mvm-security/src/keystore.rs:57` | `KeyProvider::get_data_key(tenant) -> SecretBox<Vec<u8>>`, keyring/file/env |
| LUKS2 volume (Linux) | `mvm/src/security/encryption.rs:11,34` | `create_encrypted_volume`, `open_encrypted_volume` (cryptsetup shell-out) |
| Snapshot HMAC | `mvm-security/src/snapshot_hmac.rs` | `load_or_init_key`, integrity tag |
| Channel auth | `mvm-core/src/policy/security.rs:38` | `AuthenticatedFrame`, Ed25519 `SessionHello`/`Ack` |

Gaps this plan fills: macOS volume-at-rest, 90-day rotation timer, per-rebuild DEK binding, snapshot content-address + signature, VMGenID reseed.

---

## Phase A — one AEAD, both platforms

### Task A0: pluggable channel layering (the encryption seam)

`core::framing` (built in plan 121 B4) frames `FramedMessage<T>` with a pluggable auth stage. Add a second pluggable stage — an optional encryption transform — so a Noise/AEAD layer can wrap an untrusted-boundary channel later without touching callers. Ship the identity (no-op) transform only; nothing is encrypted on a host-local channel today (see the design note).

**Files:** `crates/mvm-core/src/framing.rs`.

- [ ] **Step 1:** Failing test — a frame round-trips through `Identity` unchanged, and through a stub transform it returns equal after `encode`→`decode`.
  ```rust
  // Applied to the serialized frame body after the Ed25519 auth step. Identity
  // ships today; a Noise/AEAD impl is the future drop-in for a channel that
  // crosses an untrusted boundary (none today — see the design note).
  trait Transform {
      fn encode(&self, body: &[u8]) -> Vec<u8>;
      fn decode(&self, wire: &[u8]) -> Result<Vec<u8>, FramingError>;
  }
  ```
- [ ] **Step 2:** Implement `Identity` (returns its input) and thread the transform through `FramedMessage` encode/decode after auth. The default channel uses `Identity`.
- [ ] **Step 3:** Tests green; commit. No new dep — the seam is structure, not crypto.

### Task A1: collapse the AEAD call sites into `mvm_core::crypto::aead`

`snapshot_crypto` and `snapshot_encryption` both reach for `Aes256Gcm` directly. Give them one typed entry point so key handling and the wire format live in one place.

**Files:** `crates/mvm-core/src/crypto/aead.rs` (new, post-121); the two existing modules become callers.

- [ ] **Step 1:** Write `aead.rs` with a typed key and the existing wire format. The `Key` newtype exists so a 32-byte buffer can't be passed where a signing key is wanted, and to carry the zeroize impl in one spot.
  ```rust
  /// AES-256-GCM with a random 96-bit nonce per call. Wire: nonce ‖ ct ‖ tag.
  /// Nonce reuse under one key is catastrophic for GCM, so we never accept a
  /// caller-supplied nonce — each seal draws a fresh one from the OS CSPRNG.
  pub struct Key([u8; 32]); // zeroized on drop via the SecretBox it's stored in

  pub fn seal(key: &Key, plaintext: &[u8]) -> Vec<u8>;
  pub fn open(key: &Key, framed: &[u8]) -> Result<Vec<u8>, AeadError>; // AeadError on tag mismatch / short input
  ```
- [ ] **Step 2:** Failing test — roundtrip and tamper.
  ```rust
  #[test]
  fn seal_open_roundtrip_and_reject_tamper() {
      let k = Key::random();
      let mut ct = seal(&k, b"snapshot bytes");
      assert_eq!(open(&k, &ct).unwrap(), b"snapshot bytes");
      ct[20] ^= 1; // flip one ciphertext byte
      assert!(open(&k, &ct).is_err()); // GCM tag must catch it
  }
  ```
- [ ] **Step 3:** Implement over `aes-gcm` (already a dep), nonce from `getrandom`.
- [ ] **Step 4:** Re-point `snapshot_crypto::{encrypt,decrypt}` and `snapshot_encryption` at `aead::{seal,open}`; keep their public signatures so callers don't churn. `cargo test -p mvm-core aead snapshot` green.
- [ ] **Step 5:** Commit.

### Task A2: macOS volume-at-rest path

LUKS2 is Linux-only. macOS volumes have no at-rest encryption today. Add a per-file AES-256-GCM volume encryptor for non-Linux so the StorageProvider (123) has both arms.

**Files:** `crates/mvm-core/src/crypto/volume.rs` (new) or extend `aead.rs`; cfg-gated.

- [ ] **Step 1:** Failing test — a directory sealed on macOS opens back to identical bytes, and the on-disk form is ciphertext (no plaintext marker survives).
- [ ] **Step 2:** Implement `seal_dir`/`open_dir` over `aead::seal` per file (the volume is small app-deps content, not a block device, so per-file AEAD is adequate and avoids a loopback/dm dependency on macOS).
- [ ] **Step 3:** `#[cfg(not(target_os = "linux"))]` for this path; Linux keeps `create_encrypted_volume` (LUKS2). The selection is the StorageProvider's (123) — this task only provides the macOS arm. Test green on the dev host.
- [ ] **Step 4:** Commit.

## Phase B — key lifecycle

### Task B1: 90-day KEK rotation timer

`rotate_master_key` exists but is only ever called by hand. Add the policy that decides when.

**Files:** `crates/mvm-core/src/crypto/rotation_policy.rs` (new); reads the master-key manifest.

- [ ] **Step 1:** Failing test — a KEK whose `created_at` is older than the interval is due; a fresh one is not.
  ```rust
  #[test]
  fn kek_due_for_rotation_past_interval() {
      let manifest = manifest_with_active_age(Duration::from_days(91));
      assert!(rotation_due(&manifest, DEFAULT_INTERVAL)); // 90d default
      let fresh = manifest_with_active_age(Duration::from_days(10));
      assert!(!rotation_due(&fresh, DEFAULT_INTERVAL));
  }
  ```
- [ ] **Step 2:** Implement `rotation_due(&MasterKeyManifest, interval) -> bool` (interval configurable, default 90d) and `rotate_if_due()` that calls `rotate_master_key` then sweeps with `migrate_wrapped_keys`. Time comes in as a parameter — no wall-clock read inside the pure check, so it stays testable.
- [ ] **Step 3:** Wire `rotate_if_due` into the host startup path (where the supervisor already loads keys). KEK rotation only re-wraps DEKs, so it's cheap and safe to run on boot.
- [ ] **Step 4:** Tests green; commit.

### Task B2: per-rebuild DEK binding

ADR-066 §5: a per-volume DEK rides the rebuild cycle and binds to the artifact content-hash + signed plan + audit chain, so a DEK can't be lifted onto a different artifact.

**Files:** extend `WrappedKey` metadata in `key_rotation.rs`; the admit path that already verifies plans (`mvm-cli` up / supervisor).

- [ ] **Step 1:** Failing test — a `WrappedKey` whose bound `content_hash` differs from the volume it's presented with is refused at admit.
- [ ] **Step 2:** Add `bound: { content_hash, plan_id, audit_head }` to `WrappedKey`; mint a fresh DEK per rebuild and record the binding. Verify it in the admit path next to the existing plan check.
- [ ] **Step 3:** Tests green; commit.

## Phase C — snapshots content-addressed + signed

`reseal_snapshot` protects integrity with an HMAC + epoch. ADR-066 §7 wants snapshots treated like signed bundles (claim 9): content-addressed and Ed25519-signed, because a file CRC/HMAC is integrity, not authentication — anyone with the HMAC key can forge.

**Files:** `key_rotation.rs::reseal_snapshot` and the snapshot seal path; reuse `ed25519-dalek` + the host signer at `~/.mvm/keys/host-signer.ed25519`.

- [ ] **Step 1:** Failing tests — a sealed snapshot carries `{ sha256, signature }`; verify passes; a flipped byte fails the content-address; a signature from the wrong key fails verify.
- [ ] **Step 2:** On seal, compute `sha256` over the sealed bytes and sign `(sha256 ‖ epoch)` under the host signer. Keep the HMAC for cheap local integrity if useful, but make the Ed25519 signature the authentication gate at admit.
- [ ] **Step 3:** Verify at resume admit (next to the existing snapshot epoch/replay check). Tests green; commit.

## Phase D — VMGenID reseed on resume

Resuming two copies of one snapshot leaves both guests with identical CSPRNG state, so they generate the same nonces/keys — a real key-reuse break. The guest must notice the clone and reseed. Hardware VMGenID exists on Firecracker but not libkrun/Vz, so carry a generation token over the config/vsock path we already have; that covers every backend.

**Files:** the resume path in the backend/supervisor (host side); `crates/mvm-guest` agent (guest side).

- [ ] **Step 1 (host):** On every resume, emit a fresh 16-byte generation token bound to the snapshot's content-address (Phase C) so it can't be replayed onto a different snapshot. Failing test: two resumes of the same snapshot get distinct tokens.
- [ ] **Step 2 (guest):** Failing test — the agent reseeds and drops its session when the token changes, and does nothing when it's unchanged.
  ```rust
  #[test]
  fn changed_genid_forces_reseed_and_session_reset() {
      let mut a = Agent::with_genid([1u8; 16]);
      assert!(!a.on_genid([1u8; 16])); // unchanged -> no reseed
      assert!(a.on_genid([2u8; 16]));  // changed  -> reseed + drop session
  }
  ```
- [ ] **Step 3 (guest):** On a changed token, reseed the CSPRNG (`getrandom` → the agent's RNG) and drop the current vsock session so a fresh Ed25519 handshake runs (new session keys, no carried sequence numbers). Tests green; commit.

## Phase E — reconcile the ADR

- [ ] **Step 1:** Edit ADR-066 §5: replace the "Noise vsock + mTLS" paragraph with the trust-model reasoning from the design note above (authenticated cleartext on host-local channels; confidentiality only across untrusted boundaries). Record VMGenID reseed as a numbered claim candidate in the §7/claims area. Commit.

## Acceptance

- [ ] One AEAD entry point (`mvm_core::crypto::aead`); both platforms have an at-rest volume path (LUKS2 Linux, per-file AES-256-GCM macOS).
- [ ] KEK rotation runs on a 90-day policy; per-rebuild DEKs bind to content-hash + plan + audit head and are refused on mismatch.
- [ ] Snapshots are content-addressed + Ed25519-signed; a flipped byte or wrong-key signature is rejected at resume admit.
- [ ] A changed VMGenID token reseeds the guest CSPRNG and resets the vsock session; unchanged is a no-op.
- [ ] `cargo test --workspace`, `clippy -D warnings`, `fmt --check` green. **No new dependency** entered any `Cargo.toml` (diff the lockfile; the only deltas should be features already pulled).
- [ ] ADR-066 §5 matches the shipped channel posture.

### deferred follow-ups

- [ ] `encrypted` volume `StorageProvider` impl (selects LUKS2 vs the macOS arm) → plan 123.
- [ ] `libcryptsetup-sys` FFI to replace the `cryptsetup` shell-out — only if the shell-out proves insufficient; not worth a native dep now (dep budget).
- [ ] Hardware VMGenID device per backend (Firecracker ACPI table) → backend plan; the token path covers all backends in the meantime.
- [ ] Re-add Noise to any future channel that crosses an untrusted boundary inside mvm (none today).

## Self-review

- **Spec coverage (brief 122):** envelope DEK/KEK (exists; B2 binds it per-rebuild), both-platform AEAD (A1/A2), 90-day KEK rotation (B1), snapshot-at-rest + content-address + sign (C), VMGenID claim candidate (D). "Noise vsock, mTLS/TLS" is deliberately dropped with rationale (design note + E) — the one open decision for you.
- **Dependencies:** zero added — every task names an existing crate. The lockfile-diff check is in acceptance.
- **Grounding:** every "exists" cites the real file:line + signature from the current tree; the new code shows the actual entry points, not sketches.
- **Voice:** comments mark the non-obvious (GCM nonce-reuse hazard, why time is a parameter, why HMAC isn't authentication, why a clone must reseed) and skip narrating the calls.
