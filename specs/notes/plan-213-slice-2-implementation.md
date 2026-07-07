# Plan 213 Slice 2 (Units 1–2) Implementation Plan — keyless pack verifier + embedded trust root

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. Each task is one fresh subagent + two-stage review.

**Goal:** Un-inert the attested-pack path on installed binaries by adding a keyless (cosign/Sigstore) pack verifier and a compiled-in release-identity trust root, so a stock `mvmctl` verifies public release packs with no hand-placed config — while the existing ed25519 `pack-trust.json` path stays untouched as the operator/fleet lane.

**Architecture:** Two authorities, one shared pipeline (ADR-097 §9). The ed25519 `verify_pack_at` is unchanged. A new `verify_pack_keyless_at` reuses `mvm_core::crypto::image_verify::verify_signed_payload` (already vendored, `manifest-verify`-gated, offline) to check a detached cosign bundle sidecar over the manifest bytes against an exact-match identity built from a compiled-in template + the binary's version, then runs the *same* structural/hash/policy/revocation middle. `pack_cache::PackVerifyCtx` gains a keyless strategy so `resolve_pack`/`promote` are authority-agnostic.

**Tech Stack:** Rust, `ed25519-dalek`, `sha2`, `serde`, the vendored `sigstore-verify`/`sigstore-trust-root`/`sigstore-types` (behind `manifest-verify`).

## Global Constraints

- No spec refs in CODE comments (CI-gated): no `Plan N`, `ADR-\d+`, `#NNNN`, `W\d.` in `//` comments. Reword to the concept. (Fine in this doc and in spec markdown.)
- No AI-tool attribution in commits; no `Co-Authored-By` trailer.
- No new external crates without ADR-002 justification — reuse `ed25519-dalek` + the `manifest-verify` sigstore stack.
- No placeholder pubkeys / no dead constants: every embedded template names the real release workflow identity.
- Source-checkout builds stay a no-op on the pack path; the embedded root must not change source-checkout behavior.
- `mvm-core` default build stays runtime-free: the keyless verifier is `#[cfg(feature = "manifest-verify")]`; the no-feature fallback fails closed.
- The keyless verifier lives in `mvm-core` with trust inputs as parameters (no `mvm-cli` dependency), so mvmd reaches it by enabling `manifest-verify`.
- Verify locally with `MVM_SKIP_EMBED_BINARIES=1` (this box's zig cross-compile cache is broken); run `cargo nextest run -p mvm-core` and `-p mvm-cli`, plus `cargo clippy -p <crate> --all-targets -- -D warnings` on the *default* feature set AND with `--features manifest-verify`.

---

## Task 1: `KeyId::from_identity`

**Files:**
- Modify: `crates/mvm-core/src/plan/bundle.rs` (add `KeyId::from_identity` next to `from_pubkey`)
- Test: same file `#[cfg(test)]` module

**Interfaces:**
- Produces: `KeyId::from_identity(identity: &str) -> KeyId` — sha256(identity) truncated to 32 lowercase hex, `is_well_formed()`-true. A stable, well-formed id for a keyless signer (used for revocation keying + audit); it is NOT a pubkey hash and is never used to look up a verifying key.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn key_id_from_identity_is_well_formed_and_stable() {
    let id = "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.17.0";
    let a = KeyId::from_identity(id);
    let b = KeyId::from_identity(id);
    assert_eq!(a, b, "same identity yields same id");
    assert!(a.is_well_formed(), "32 lowercase hex");
    assert_ne!(a, KeyId::from_identity("other"), "different identity differs");
}
```

- [ ] **Step 2: Run it, confirm it fails** — `cargo test -p mvm-core --lib key_id_from_identity` → FAIL (`from_identity` not found).
- [ ] **Step 3: Implement** — mirror `from_pubkey` but hash the identity string bytes:

```rust
/// Derive a stable, well-formed `KeyId` from a signer *identity* string (a
/// keyless OIDC subject). Distinct from `from_pubkey`: there is no key here, so
/// this id is only an identifier for revocation keying and audit, never a lookup
/// into a key store.
pub fn from_identity(identity: &str) -> Self {
    let digest = Sha256::digest(identity.as_bytes());
    Self(format!("{digest:x}")[..32].to_string())
}
```

- [ ] **Step 4: Run it, confirm it passes.**
- [ ] **Step 5: Commit** — `feat(mvm-core): KeyId::from_identity for keyless signer ids`

---

## Task 2: `SignatureFormat::Sigstore` variant

**Files:**
- Modify: `crates/mvm-core/src/packs.rs` (`SignatureFormat` enum, ~line 301)
- Test: `packs.rs` tests

**Interfaces:**
- Produces: `SignatureFormat::Sigstore` (serde `snake_case` → `"sigstore"`). Declares a pack's signing authority; a `Sigstore` pack carries an empty `signatures` vec (the detached sidecar is authoritative).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn signature_format_sigstore_serde_snake_case() {
    assert_eq!(serde_json::to_string(&SignatureFormat::Sigstore).unwrap(), "\"sigstore\"");
    let back: SignatureFormat = serde_json::from_str("\"sigstore\"").unwrap();
    assert_eq!(back, SignatureFormat::Sigstore);
}
```

- [ ] **Step 2: Run it, confirm it fails** (variant missing).
- [ ] **Step 3: Implement** — add `Sigstore` to `SignatureFormat`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFormat {
    Ed25519,
    Sigstore,
}
```

- [ ] **Step 4: Run it + `cargo nextest run -p mvm-core`** — the existing `validate_signature_bundle` already rejects non-`Ed25519` formats, so no existing test should regress.
- [ ] **Step 5: Commit** — `feat(mvm-core): SignatureFormat::Sigstore authority variant`

---

## Task 3: factor `validate_manifest_structural` out of `validate_manifest`

**Files:**
- Modify: `crates/mvm-core/src/packs.rs` (`validate_manifest`, ~line 393)
- Test: `packs.rs` tests (existing suite must stay green + one new)

**Interfaces:**
- Produces: `pub fn validate_manifest_structural(manifest, policy) -> Result<(), PackVerifyError>` — everything current `validate_manifest` does *except* the final `validate_signature_bundle(...)` call. `validate_manifest` becomes `validate_manifest_structural(...)?; validate_signature_bundle(manifest)` so `verify_pack_at` is byte-for-byte behavior-preserving.

- [ ] **Step 1: Write the failing test** (structural check accepts an empty ed25519 bundle, which the full `validate_manifest` would reject):

```rust
#[test]
fn structural_validation_ignores_signature_bundle_shape() {
    let mut f = fixture(PackKind::Runtime);
    f.manifest.provenance.signature_bundle.signatures.clear();
    // Full validate_manifest would fail on the empty bundle; structural must not.
    validate_manifest_structural(&f.manifest, &f.policy).expect("structural passes");
    assert!(matches!(
        validate_manifest(&f.manifest, &f.policy),
        Err(PackVerifyError::SignatureBundleEmpty)
    ));
}
```

- [ ] **Step 2: Run it, confirm it fails** (`validate_manifest_structural` undefined).
- [ ] **Step 3: Implement** — extract the body; keep `validate_manifest` as the composed pair:

```rust
pub fn validate_manifest(manifest: &PackManifest, policy: &LocalPackPolicy) -> Result<(), PackVerifyError> {
    validate_manifest_structural(manifest, policy)?;
    validate_signature_bundle(manifest)
}

/// Everything `validate_manifest` checks except the ed25519 signature-bundle
/// shape, so both the ed25519 and the keyless verifier share one structural gate.
pub fn validate_manifest_structural(manifest: &PackManifest, policy: &LocalPackPolicy) -> Result<(), PackVerifyError> {
    // ... existing body: schema, arch, backend, host caps, policy_hash, channel,
    // trust expiry, validate_required_outputs, validate_oci_inputs, validate_file_paths ...
    Ok(())
}
```

- [ ] **Step 4: Run `cargo nextest run -p mvm-core`** — full existing suite green + new test.
- [ ] **Step 5: Commit** — `refactor(mvm-core): split validate_manifest_structural from signature-bundle shape`

---

## Task 4: keyless signature-shape validation + `verify_pack_keyless_at`

**Files:**
- Modify: `crates/mvm-core/src/packs.rs` (new `KeylessTrust`, `verify_pack_keyless_at`, keyless shape check, new `PackVerifyError` variants, `COSIGN_BUNDLE_FILE_NAME`)
- Test: `packs.rs` tests

**Interfaces:**
- Consumes: `image_verify::verify_signed_payload(payload, bundle, identity, issuer) -> VerifyResult<()>` (Task-independent, already exists); `validate_manifest_structural` (Task 3); `KeyId::from_identity` (Task 1); `SignatureFormat::Sigstore` (Task 2).
- Produces:
  - `pub const COSIGN_BUNDLE_FILE_NAME: &str = "manifest.cosign.bundle";`
  - `pub struct KeylessTrust { pub accepted_identities: Vec<String>, pub issuer: String }`
  - `#[cfg(feature = "manifest-verify")] pub fn verify_pack_keyless_at(manifest: &PackManifest, root: &Path, policy: &LocalPackPolicy, cosign_bundle: &[u8], keyless: &KeylessTrust, revocations: &dyn PackRevocationChecker) -> Result<VerifiedPack, PackVerifyError>`
  - `PackVerifyError::KeylessSignatureInvalid(String)`, `PackVerifyError::WrongSignatureAuthority { expected: SignatureFormat, found: SignatureFormat }`

**Design notes:**
- Keyless shape gate (`validate_signature_bundle_keyless`): require `format == Sigstore`, `payload == ManifestV1`, `signatures.is_empty()`, and `trust.signing_key_id.is_well_formed()`. Reject `format == Ed25519` with `WrongSignatureAuthority`.
- The signature step succeeds if `verify_signed_payload(manifest.signature_payload_bytes(), bundle, id, &keyless.issuer)` returns `Ok` for **any** `id` in `keyless.accepted_identities` (exact-match; try in order). Sign/verify the same bytes the ed25519 path signs — `signature_payload_bytes()` (manifest with signatures cleared) — so producer and verifier agree on the covered bytes.
- Then `validate_manifest_structural` + `verify_files` + `verify_pack_hash` + `verify_revocation` (the shared middle). Return `VerifiedPack { pack_hash, file_count, signer_key_id: manifest.trust.signing_key_id.clone() }`.
- Positive keyless-signature testing needs a *real* cosign bundle (can't mint offline), exactly as `image_verify` has no positive unit test for the signature step. Cover the signature step here only via negative/shape paths; the end-to-end positive proof is Unit 3's pipeline lane (or a committed real-bundle fixture if one is captured). Do NOT fake a passing bundle.

- [ ] **Step 1: Write failing tests** (offline-only; shape + authority + negative signature + shared middle):

```rust
#[cfg(feature = "manifest-verify")]
mod keyless {
    use super::*;

    fn sigstore_manifest(dir: &TempDir) -> PackManifest { /* like produced_hvf_builder_pack but: */
        // build via PackBuilder, then rewrite for keyless:
        //   m.provenance.signature_bundle.format = SignatureFormat::Sigstore;
        //   m.provenance.signature_bundle.signatures.clear();
        //   m.trust.signing_key_id = KeyId::from_identity(IDENTITY);
        //   m.outputs.pack_hash = m.computed_pack_hash().unwrap();
        unimplemented!("assembled in Step 3")
    }

    const IDENTITY: &str = "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.17.0";
    const ISSUER: &str = "https://token.actions.githubusercontent.com";

    fn trust() -> KeylessTrust {
        KeylessTrust { accepted_identities: vec![IDENTITY.into()], issuer: ISSUER.into() }
    }

    #[test]
    fn ed25519_pack_rejected_by_keyless_verifier() {
        let dir = TempDir::new().unwrap();
        let m = produced_hvf_builder_pack(&dir); // ed25519 authority
        let err = verify_pack_keyless_at(&m, dir.path(), &hvf_policy(), b"bundle", &trust(),
            &StaticRevocation { status: RevocationStatus::Good }).expect_err("wrong authority");
        assert!(matches!(err, PackVerifyError::WrongSignatureAuthority { .. }));
    }

    #[test]
    fn garbage_bundle_is_keyless_signature_invalid() {
        let dir = TempDir::new().unwrap();
        let m = sigstore_manifest(&dir);
        let err = verify_pack_keyless_at(&m, dir.path(), &hvf_policy(), b"not a bundle", &trust(),
            &StaticRevocation { status: RevocationStatus::Good }).expect_err("bad bundle");
        assert!(matches!(err, PackVerifyError::KeylessSignatureInvalid(_)));
    }
}
```

(Also add: `sigstore_manifest` with a non-empty `signatures` vec → shape error; a `format == Ed25519` but routed keyless → `WrongSignatureAuthority`.)

- [ ] **Step 2: Run, confirm fail.**
- [ ] **Step 3: Implement** `COSIGN_BUNDLE_FILE_NAME`, `KeylessTrust`, the shape gate, the error variants, and `verify_pack_keyless_at` (+ a `#[cfg(not(feature = "manifest-verify"))]` fallback returning `KeylessSignatureInvalid("manifest-verify disabled")`). Fill in `sigstore_manifest`.
- [ ] **Step 4: Run** `cargo nextest run -p mvm-core --features manifest-verify` (+ default-feature build stays green via the fallback).
- [ ] **Step 5: Commit** — `feat(mvm-core): keyless pack verifier (verify_pack_keyless_at)`

---

## Task 5: embedded release-identity templates + version interpolation

**Files:**
- Create: `crates/mvm-core/src/release_trust.rs`
- Modify: `crates/mvm-core/src/lib.rs` (`pub mod release_trust;`)
- Test: `release_trust.rs` tests

**Interfaces:**
- Produces:
  - `pub const RELEASE_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";`
  - `const RELEASE_IDENTITY_TEMPLATES: &[&str] = &["https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"];`
  - `pub fn accepted_release_identities(version: &str) -> Vec<String>` — one entry per template, `{version}` replaced.
  - `pub fn release_keyless_trust(version: &str) -> KeylessTrust` — `{ accepted_identities: accepted_release_identities(version), issuer: RELEASE_OIDC_ISSUER.into() }`.

> Confirm the exact org/repo/workflow-filename against `.github/workflows/release.yml`'s `on:` triggers and the repo slug used in existing cosign identities (grep `image_verify` callers / `release.yml` for the current SAN) before hardcoding — the template must match what the signing job actually asserts.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn templates_interpolate_version_exactly() {
    let ids = accepted_release_identities("0.17.0");
    assert!(!ids.is_empty());
    assert!(ids.iter().all(|i| i.contains("@refs/tags/v0.17.0") && !i.contains("{version}")));
    assert!(ids.iter().any(|i| i.contains(".github/workflows/release.yml")));
}

#[test]
fn keyless_trust_carries_issuer_and_ids() {
    let t = release_keyless_trust("0.17.0");
    assert_eq!(t.issuer, RELEASE_OIDC_ISSUER);
    assert_eq!(t.accepted_identities, accepted_release_identities("0.17.0"));
}
```

- [ ] **Step 2–4: Run/implement/pass.**
- [ ] **Step 5: Commit** — `feat(mvm-core): embedded release-identity templates + keyless trust builder`

---

## Task 6: `pack_cache` keyless strategy

**Files:**
- Modify: `crates/mvm-core/src/pack_cache.rs` (`PackVerifyCtx`, `MANIFEST_FILE_NAME` sibling sidecar handling)
- Test: `pack_cache.rs` tests

**Interfaces:**
- Change `PackVerifyCtx` from a struct to a strategy enum so `promote`/`resolve_pack` stay authority-agnostic:

```rust
pub enum PackVerifyCtx<'a> {
    Ed25519 { policy: &'a LocalPackPolicy, trust: &'a dyn PackTrustStore, revocations: &'a dyn PackRevocationChecker },
    #[cfg(feature = "manifest-verify")]
    Keyless { policy: &'a LocalPackPolicy, keyless: &'a KeylessTrust, revocations: &'a dyn PackRevocationChecker },
}

impl<'a> PackVerifyCtx<'a> {
    pub fn ed25519(policy, trust, revocations) -> Self { ... }  // replaces `new`
    #[cfg(feature = "manifest-verify")]
    pub fn keyless(policy, keyless, revocations) -> Self { ... }

    fn verify(&self, manifest: &PackManifest, root: &Path) -> Result<VerifiedPack, PackVerifyError> {
        match self {
            Self::Ed25519 { policy, trust, revocations } => verify_pack_at(manifest, root, policy, *trust, *revocations),
            #[cfg(feature = "manifest-verify")]
            Self::Keyless { policy, keyless, revocations } => {
                let bundle = std::fs::read(root.join(COSIGN_BUNDLE_FILE_NAME))
                    .map_err(|e| PackVerifyError::KeylessSignatureInvalid(format!("reading cosign bundle: {e}")))?;
                verify_pack_keyless_at(manifest, root, policy, &bundle, keyless, *revocations)
            }
        }
    }
}
```

- The keyless bundle sidecar (`COSIGN_BUNDLE_FILE_NAME`) must be treated like `MANIFEST_FILE_NAME`: reserved (a declared pack file may not collide with it) and carried through `promote` into the content-addressed dir so `resolve_pack`'s re-verify finds it.
- Update the existing call sites: `PackVerifyCtx::new(...)` → `PackVerifyCtx::ed25519(...)` in `dev_vz.rs` and all `pack_cache`/`packs` tests.

- [ ] **Step 1: Write failing test** — a keyless-strategy promote/resolve round-trip using a synthetic Sigstore manifest whose signature step is stubbed via a test-only `KeylessTrust` that the `verify_signed_payload` path accepts *only if a real fixture bundle exists*; otherwise assert the reserved-sidecar + `ed25519` rename path still works and that `PackVerifyCtx::keyless` reads the sidecar (missing sidecar → `KeylessSignatureInvalid`). Keep the offline-provable behavior: missing-bundle → error; reserved-name collision → `ReservedFileName`.

```rust
#[cfg(feature = "manifest-verify")]
#[test]
fn keyless_ctx_missing_bundle_sidecar_is_signature_invalid() {
    // promote path with Keyless ctx and no sidecar on disk must fail closed.
    // (build a Sigstore manifest dir without the sidecar; expect KeylessSignatureInvalid)
}
```

- [ ] **Step 2–4:** implement the enum + sidecar reservation + carry-through; fix all call sites; `cargo nextest run -p mvm-core` (default + `--features manifest-verify`).
- [ ] **Step 5: Commit** — `refactor(mvm-core): PackVerifyCtx gains a keyless strategy`

---

## Task 7: un-inert the installed pack path (host wiring)

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/dev_vz.rs` (`attested_builder_pack` module: `host_pack_verify_inputs`, `attempt_attested_builder_pack`)
- Modify: `crates/mvm-cli/Cargo.toml` / root `Cargo.toml` only if `manifest-verify` isn't already reachable in the CLI build (it is, via the `user` feature bundle — confirm)
- Test: `dev_vz.rs` `attested_builder_pack_tests`

**Behavior:**
- Under `#[cfg(feature = "manifest-verify")]`: build a keyless `PackVerifyCtx` from `release_keyless_trust(env!("CARGO_PKG_VERSION"))` + the host `LocalPackPolicy` + the on-disk `PackTrustConfig` (still the revocation checker), and resolve the installed builder pack through it. The embedded root is always active → `resolve_pack` now returns `Some` for a correctly keyless-signed release pack instead of always `None`. Keep the ed25519 `pack-trust.json` publishers additive (still consulted for operator packs and revocations).
- Without `manifest-verify`: unchanged — ed25519-only, inert without config.
- Unchanged: source-checkout no-op (`find_builder_vm_flake().is_ok()`), the `MVM_BUILDER_PACK` gate, and fail-open to the plain download when resolution yields `None`.

- [ ] **Step 1: Write failing test** — with `manifest-verify`, `host_pack_verify_inputs(arch)` yields a ctx whose accepted identities include the interpolated `CARGO_PKG_VERSION` and whose issuer is `RELEASE_OIDC_ISSUER`; the source-checkout no-op and flag-off predicates still hold. Mirror the existing `attested_builder_pack_tests` env-isolation helpers.
- [ ] **Step 2–4:** implement, run `cargo nextest run -p mvm-cli` (with `MVM_SKIP_EMBED_BINARIES=1`) default + `--features manifest-verify`; clippy both.
- [ ] **Step 5: Commit** — `feat(mvm-cli): un-inert the installed builder-pack path via the embedded keyless root`

---

## Self-review checklist (run before handing off Unit 2)

1. **Spec coverage:** Unit 1 = Tasks 1–4 (authority shape, structural split, keyless verifier). Unit 2 = Tasks 5–7 (embedded templates, cache strategy, host un-inert). Release pipeline (Unit 3) + network fetch (Unit 4) are separate, later.
2. **No fake positives:** the keyless *signature* positive path is deliberately not unit-tested offline (no mintable bundle) — proven in the pipeline lane; do not stub a passing `verify_signed_payload`.
3. **Type consistency:** `KeylessTrust { accepted_identities, issuer }`, `verify_pack_keyless_at(...)`, `COSIGN_BUNDLE_FILE_NAME`, `PackVerifyCtx::{ed25519,keyless}`, `release_keyless_trust(version)`, `accepted_release_identities(version)`, `KeyId::from_identity` — used identically across tasks.
4. **Feature gating:** every keyless entry point is `manifest-verify`-gated with a fail-closed no-feature fallback; the default `mvm-core` build stays runtime-free.
5. **Downgrade safety:** ed25519 verifier rejects `Sigstore` format (existing `validate_signature_bundle`); keyless verifier rejects `Ed25519` (`WrongSignatureAuthority`).
