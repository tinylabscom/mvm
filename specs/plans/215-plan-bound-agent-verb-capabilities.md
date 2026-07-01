# Plan-bound Agent Verb Capabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a signed `ExecutionPlan` attenuate which guest-agent control verbs a workload may receive, enforced guest-side, strictly narrowing (never widening) the existing class/profile gate.

**Architecture:** A new optional `agent_verbs` field on `ExecutionPlan` names the verbs a workload needs. At admission the supervisor mints a `VerbGrant` — a host-signer-signed, session-bound, time-bound token — and delivers it to the guest at the `ProtocolHello` handshake. The agent verifies the grant against the host-signer verifying key, pins it for the session, and refuses any non-baseline verb outside the set (after the class gate). Denials audit to the chain-signed log.

**Tech Stack:** Rust, `ed25519-dalek` (already a workspace dep), `serde`/`serde_json`, `chrono` (`DateTime<Utc>`). Tests via `cargo nextest`.

## Global Constraints

- **Reuse first.** `VerbGrant` verification reuses `ed25519_dalek::VerifyingKey`/`Verifier` (already imported in `crates/mvm-guest/src/vsock.rs:7`). Signing reuses the host signer at `crates/mvm-hostd/src/host_signer/keystore.rs:69` (`pub fn sign(&self, bytes: &[u8]) -> SignResult`). Do not add a JCS/canonicalization crate — sign a fixed-field-order struct (no maps) via `serde_json::to_vec`, which is byte-deterministic.
- **No schema-bump ceremony.** `agent_verbs` is additive with `#[serde(default)]`; do NOT bump `SCHEMA_VERSION` (`crates/mvm-core/src/plan/execution_plan.rs:54`, currently `6`).
- **Strictly subtractive.** The grant may only narrow what `GuestRequest::allowed_in(profile)` (`crates/mvm-guest/src/vsock.rs:884`) already permits. The class gate runs first and is the hard outer bound.
- **Key separation is load-bearing (ADR-103).** The `VerbGrant` MUST be signed by the host-signer/admission authority and verified by the guest against that authority's verifying key — distinct from the per-session `AuthenticatedFrame` key. A collapse of the two keys silently defeats the feature.
- **`#[serde(deny_unknown_fields)]`** on every new host↔guest wire type, matching the repo's fail-closed convention.
- **Dev unaffected.** A plan with `agent_verbs == None` behaves exactly as today (class-gate only). Verify this explicitly (Task 4).
- **No spec/PR/ADR citations in code comments** (repo rule). Reasoning stays here; code carries only why-comments.
- **Docs upkeep:** on completion, tick this plan in `specs/REFACTOR-STATUS.md` and reflect status in `specs/SPRINT.md` in the same change.

---

### Task 1: `VerbId` newtype in mvm-core

**Files:**
- Create: `crates/mvm-core/src/plan/verb.rs`
- Modify: `crates/mvm-core/src/plan/mod.rs` (add `pub mod verb;` + re-export)
- Test: inline `#[cfg(test)]` in `verb.rs`

**Interfaces:**
- Produces: `VerbId(String)` with `VerbId::new(&str) -> Result<VerbId, VerbIdError>`, `VerbId::as_str(&self) -> &str`, `impl Display`, `Serialize`/`Deserialize` (transparent string). A `VerbId` is a `GuestRequest::kind_name()` value (`crates/mvm-guest/src/vsock.rs:555`) — the kebab-case identifier, a non-empty token `[a-z][a-z0-9-]*`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/mvm-core/src/plan/verb.rs  (bottom)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_id_accepts_kebab_and_rejects_junk() {
        assert_eq!(VerbId::new("run-entrypoint").unwrap().as_str(), "run-entrypoint");
        assert_eq!(VerbId::new("ping").unwrap().as_str(), "ping");
        assert!(VerbId::new("").is_err());
        assert!(VerbId::new("Run_Entrypoint").is_err()); // caps + underscore
        assert!(VerbId::new("-lead").is_err());
        assert!(VerbId::new("has space").is_err());
    }

    #[test]
    fn verb_id_serde_is_transparent_string() {
        let v = VerbId::new("worker-status").unwrap();
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"worker-status\"");
        let back: VerbId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn verb_id_deserialize_rejects_invalid() {
        assert!(serde_json::from_str::<VerbId>("\"BAD\"").is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-core verb_id`
Expected: FAIL — `verb.rs` / `VerbId` does not exist.

- [ ] **Step 3: Write minimal implementation**

```rust
// crates/mvm-core/src/plan/verb.rs  (top)
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// A guest-agent control-verb identifier: the stable `kind_name()` token
/// (non-empty kebab-case). Validated at construction so an `agent_verbs`
/// grant can never carry an unparseable verb.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct VerbId(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerbIdError {
    #[error("verb id is empty")]
    Empty,
    #[error("verb id '{0}' is not lowercase kebab-case ([a-z][a-z0-9-]*)")]
    Shape(String),
}

impl VerbId {
    pub fn new(s: &str) -> Result<Self, VerbIdError> {
        if s.is_empty() {
            return Err(VerbIdError::Empty);
        }
        let mut chars = s.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !first_ok || !rest_ok {
            return Err(VerbIdError::Shape(s.to_string()));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VerbId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for VerbId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        VerbId::new(&s).map_err(serde::de::Error::custom)
    }
}
```

Add to `crates/mvm-core/src/plan/mod.rs` (near the other `pub mod` lines around `:33`):

```rust
pub mod verb;
pub use verb::{VerbId, VerbIdError};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-core verb_id`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/plan/verb.rs crates/mvm-core/src/plan/mod.rs
git commit -m "feat(core): add VerbId newtype for agent verb grants"
```

---

### Task 2: `agent_verbs` field on `ExecutionPlan` + synthesis wiring

**Files:**
- Modify: `crates/mvm-core/src/plan/execution_plan.rs` (add field near `services`/`nonce`, ~`:120`–`:157`)
- Modify: `crates/mvm-cli/src/commands/vm/plan_builder.rs:169` (`synthesize_plan`) + its `SynthesisInput`
- Test: inline in `execution_plan.rs` and a synthesis test alongside existing `synthesize_plan` tests

**Interfaces:**
- Consumes: `VerbId` (Task 1).
- Produces: `ExecutionPlan.agent_verbs: Option<Vec<VerbId>>`. `SynthesisInput` gains `agent_verbs: Option<Vec<VerbId>>`, threaded verbatim into the built plan.

- [ ] **Step 1: Write the failing test**

```rust
// crates/mvm-core/src/plan/execution_plan.rs  (in existing #[cfg(test)] mod)
#[test]
fn agent_verbs_defaults_none_and_roundtrips() {
    let plan = sample_plan(); // existing test helper in this module
    assert!(plan.agent_verbs.is_none(), "field must default to None");

    // Absent in JSON => None (serde default), preserving old plans.
    let mut v = serde_json::to_value(&plan).unwrap();
    v.as_object_mut().unwrap().remove("agent_verbs");
    let back: ExecutionPlan = serde_json::from_value(v).unwrap();
    assert!(back.agent_verbs.is_none());

    // Present => preserved.
    let mut with = plan.clone();
    with.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap(), VerbId::new("ping").unwrap()]);
    let round: ExecutionPlan = serde_json::from_str(&serde_json::to_string(&with).unwrap()).unwrap();
    assert_eq!(round.agent_verbs, with.agent_verbs);
}
```

> If `sample_plan()` does not exist in this module, use the module's existing plan-construction test helper (grep `fn ` in the `#[cfg(test)]` block); do not invent one.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-core agent_verbs_defaults_none_and_roundtrips`
Expected: FAIL — no field `agent_verbs`.

- [ ] **Step 3: Write minimal implementation**

In `ExecutionPlan` (place after `nonce`, `crates/mvm-core/src/plan/execution_plan.rs:157`):

```rust
    /// Per-workload agent verb allow-list. `None` (or absent) → the
    /// guest applies the class/profile gate only (current behavior).
    /// `Some(set)` → the guest also requires each control verb to be a
    /// baseline verb or present in this set. Strictly subtractive: this
    /// can only narrow, never widen, the class gate.
    #[serde(default)]
    pub agent_verbs: Option<Vec<VerbId>>,
```

Add the import at the top of the file:

```rust
use crate::plan::VerbId;
```

Thread through synthesis — in `SynthesisInput` (`crates/mvm-cli/src/commands/vm/plan_builder.rs`, struct above `:169`) add:

```rust
    pub agent_verbs: Option<Vec<mvm_core::plan::VerbId>>,
```

and in `synthesize_plan` where the `ExecutionPlan { .. }` literal is built, set:

```rust
        agent_verbs: input.agent_verbs.clone(),
```

Fix every other `SynthesisInput { .. }` construction the compiler flags (tests, callers) by adding `agent_verbs: None`.

- [ ] **Step 4: Run test + build**

Run: `cargo nextest run -p mvm-core agent_verbs_defaults_none_and_roundtrips && cargo build -p mvm-cli`
Expected: PASS; `mvm-cli` builds (all `SynthesisInput` sites updated).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/plan/execution_plan.rs crates/mvm-cli/src/commands/vm/plan_builder.rs
git commit -m "feat(core): add optional agent_verbs to ExecutionPlan and synthesis"
```

---

### Task 3: `VerbGrant` type — sign + verify (mvm-core), mint (mvm-hostd)

**Files:**
- Create: `crates/mvm-core/src/plan/verb_grant.rs`
- Modify: `crates/mvm-core/src/plan/mod.rs` (`pub mod verb_grant;` + re-export)
- Create mint helper: `crates/mvm-hostd/src/host_signer/verb_grant_mint.rs` (+ `mod` line in `host_signer/mod.rs`)
- Test: inline in both new files

**Interfaces:**
- Consumes: `VerbId` (Task 1), `Nonce` (`crates/mvm-core/src/plan/types.rs:421`, API: `from_bytes([u8;16])`, `from_hex`, `as_hex`), `ed25519_dalek::{SigningKey, VerifyingKey}`.
- Produces:
  - `VerbGrant { session_id: String, plan_nonce: Nonce, not_after: DateTime<Utc>, verbs: Vec<VerbId>, sig: Vec<u8> }`.
  - `VerbGrant::signing_bytes(&self) -> Vec<u8>` (deterministic; excludes `sig`).
  - `VerbGrant::verify(&self, key: &VerifyingKey, session_id: &str, plan_nonce: &Nonce, now: DateTime<Utc>) -> Result<(), VerbGrantError>`.
  - `mint_verb_grant(signer: &HostSigner, session_id: &str, plan_nonce: &Nonce, not_after: DateTime<Utc>, verbs: Vec<VerbId>) -> Result<VerbGrant>` (mvm-hostd).

- [ ] **Step 1: Write the failing test (core: sign/verify roundtrip + rejections)**

```rust
// crates/mvm-core/src/plan/verb_grant.rs  (bottom)
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey { SigningKey::from_bytes(&[7u8; 32]) }
    fn nonce() -> Nonce { Nonce::from_bytes([1u8; 16]) }

    fn signed(now: DateTime<Utc>, verbs: Vec<&str>) -> (VerbGrant, SigningKey) {
        let k = key();
        let mut g = VerbGrant {
            session_id: "sess-A".into(),
            plan_nonce: nonce(),
            not_after: now + Duration::minutes(10),
            verbs: verbs.into_iter().map(|v| VerbId::new(v).unwrap()).collect(),
            sig: vec![],
        };
        g.sig = k.sign(&g.signing_bytes()).to_bytes().to_vec();
        (g, k)
    }

    #[test]
    fn valid_grant_verifies() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        assert!(g.verify(&k.verifying_key(), "sess-A", &nonce(), now).is_ok());
    }

    #[test]
    fn forged_key_rejected() {
        let now = Utc::now();
        let (g, _) = signed(now, vec!["run-entrypoint"]);
        let attacker = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(matches!(g.verify(&attacker, "sess-A", &nonce(), now), Err(VerbGrantError::BadSignature)));
    }

    #[test]
    fn wrong_session_rejected() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        assert!(matches!(g.verify(&k.verifying_key(), "sess-B", &nonce(), now), Err(VerbGrantError::SessionMismatch)));
    }

    #[test]
    fn wrong_nonce_rejected() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        let other = Nonce::from_bytes([2u8; 16]);
        assert!(matches!(g.verify(&k.verifying_key(), "sess-A", &other, now), Err(VerbGrantError::NonceMismatch)));
    }

    #[test]
    fn expired_rejected() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        let later = g.not_after + Duration::seconds(1);
        assert!(matches!(g.verify(&k.verifying_key(), "sess-A", &nonce(), later), Err(VerbGrantError::Expired)));
    }

    #[test]
    fn signing_bytes_are_stable_and_exclude_sig() {
        let now = Utc::now();
        let (mut g, _) = signed(now, vec!["ping"]);
        let a = g.signing_bytes();
        g.sig = vec![0xAA; 64]; // mutate sig only
        assert_eq!(a, g.signing_bytes(), "signing_bytes must not depend on sig");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-core verb_grant`
Expected: FAIL — `verb_grant` module absent.

- [ ] **Step 3: Write minimal implementation (core)**

```rust
// crates/mvm-core/src/plan/verb_grant.rs  (top)
use crate::plan::{Nonce, VerbId};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Host-signer-signed, session- and time-bound capability granting a
/// workload a subset of agent control verbs. Signed by the admission
/// authority, verified by the guest — deliberately a different key from
/// the per-session frame-signing key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerbGrant {
    pub session_id: String,
    pub plan_nonce: Nonce,
    pub not_after: DateTime<Utc>,
    pub verbs: Vec<VerbId>,
    /// Ed25519 signature over `signing_bytes()`.
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerbGrantError {
    #[error("verb grant session id mismatch")]
    SessionMismatch,
    #[error("verb grant nonce mismatch")]
    NonceMismatch,
    #[error("verb grant expired")]
    Expired,
    #[error("verb grant signature invalid")]
    BadSignature,
}

/// Fixed-field-order, map-free struct: `serde_json::to_vec` is
/// byte-deterministic, so it needs no external canonicalizer.
#[derive(Serialize)]
struct VerbGrantSigned<'a> {
    session_id: &'a str,
    plan_nonce: &'a str,
    not_after: String,
    verbs: Vec<&'a str>,
}

impl VerbGrant {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let body = VerbGrantSigned {
            session_id: &self.session_id,
            plan_nonce: self.plan_nonce.as_hex(),
            not_after: self.not_after.to_rfc3339(),
            verbs: self.verbs.iter().map(VerbId::as_str).collect(),
        };
        serde_json::to_vec(&body).expect("VerbGrantSigned serializes")
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        session_id: &str,
        plan_nonce: &Nonce,
        now: DateTime<Utc>,
    ) -> Result<(), VerbGrantError> {
        if self.session_id != session_id {
            return Err(VerbGrantError::SessionMismatch);
        }
        if self.plan_nonce.as_hex() != plan_nonce.as_hex() {
            return Err(VerbGrantError::NonceMismatch);
        }
        if now > self.not_after {
            return Err(VerbGrantError::Expired);
        }
        let sig = Signature::from_slice(&self.sig).map_err(|_| VerbGrantError::BadSignature)?;
        key.verify(&self.signing_bytes(), &sig).map_err(|_| VerbGrantError::BadSignature)
    }

    /// Baseline verbs are always answerable regardless of the grant set,
    /// mirroring the broker's implicit `host.audit.v1`. `protocol-hello`
    /// is the handshake itself and is pinned before any grant exists.
    pub fn permits(&self, verb: &str) -> bool {
        const BASELINE: &[&str] = &["protocol-hello", "ping", "readiness-status"];
        BASELINE.contains(&verb) || self.verbs.iter().any(|v| v.as_str() == verb)
    }
}
```

Register in `crates/mvm-core/src/plan/mod.rs`:

```rust
pub mod verb_grant;
pub use verb_grant::{VerbGrant, VerbGrantError};
```

Ensure `serde_bytes` is a dep of `mvm-core` (grep `serde_bytes` in `crates/mvm-core/Cargo.toml`; if absent, add `serde_bytes = "0.11"` — it is already used elsewhere in the workspace).

- [ ] **Step 4: Run core tests**

Run: `cargo nextest run -p mvm-core verb_grant`
Expected: PASS (6 tests).

- [ ] **Step 5: Write the failing mint test (mvm-hostd)**

```rust
// crates/mvm-hostd/src/host_signer/verb_grant_mint.rs  (bottom)
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use mvm_core::plan::{Nonce, VerbId};

    #[test]
    fn minted_grant_verifies_under_signer_key() {
        let dir = tempfile::tempdir().unwrap();
        let signer = HostSigner::load_or_init_at(dir.path()).unwrap(); // confirm exact ctor at keystore.rs
        let now = Utc::now();
        let nonce = Nonce::from_bytes([3u8; 16]);
        let grant = mint_verb_grant(
            &signer,
            "sess-Z",
            &nonce,
            now + Duration::minutes(5),
            vec![VerbId::new("run-entrypoint").unwrap()],
        ).unwrap();

        grant.verify(&signer.verifying_key(), "sess-Z", &nonce, now).unwrap();
    }
}
```

> Confirm the exact host-signer constructor and verifying-key accessor at `crates/mvm-hostd/src/host_signer/keystore.rs:69` and nearby (`load_or_init_at`, `verifying_key`) — the repo already tests `host_signer::load_or_init_at` (CLAUDE.md claim 8). Match those names; do not invent.

- [ ] **Step 6: Implement mint helper**

```rust
// crates/mvm-hostd/src/host_signer/verb_grant_mint.rs  (top)
use crate::host_signer::HostSigner; // confirm path/name at host_signer/mod.rs
use anyhow::Result;
use chrono::{DateTime, Utc};
use mvm_core::plan::{Nonce, VerbGrant, VerbId};

/// Mint a session-bound verb grant signed by the host-signer authority.
pub fn mint_verb_grant(
    signer: &HostSigner,
    session_id: &str,
    plan_nonce: &Nonce,
    not_after: DateTime<Utc>,
    verbs: Vec<VerbId>,
) -> Result<VerbGrant> {
    let mut grant = VerbGrant {
        session_id: session_id.to_string(),
        plan_nonce: plan_nonce.clone(),
        not_after,
        verbs,
        sig: vec![],
    };
    grant.sig = signer.sign(&grant.signing_bytes())?.into(); // adapt to SignResult's accessor
    Ok(grant)
}
```

> `signer.sign(..)` returns `SignResult` (keystore.rs:69). Read that type and convert its signature bytes to `Vec<u8>` (e.g. `.signature_bytes().to_vec()` or `.as_bytes()`); adjust the `.into()` above to the real accessor.

Add `mod verb_grant_mint;` + `pub use verb_grant_mint::mint_verb_grant;` to `crates/mvm-hostd/src/host_signer/mod.rs`.

- [ ] **Step 7: Run mint test**

Run: `cargo nextest run -p mvm-hostd verb_grant`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/mvm-core/src/plan/verb_grant.rs crates/mvm-core/src/plan/mod.rs \
        crates/mvm-hostd/src/host_signer/verb_grant_mint.rs crates/mvm-hostd/src/host_signer/mod.rs
git commit -m "feat: VerbGrant type with host-signer mint and session/time-bound verify"
```

---

### Task 4: Guest-side enforcement + `VerbNotAuthorized` response

**Files:**
- Modify: `crates/mvm-guest/src/vsock.rs` — add `GuestResponse::VerbNotAuthorized` (near `UnsupportedInProfile`, `:941`), register it in `enum ResponseVariant` (`:1106`) and `response_contract`/variant-mapping (`:813`, `:1157`, `:1216`).
- Modify: `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — add the grant intersection right after the `allowed_in` gate (`:2055`). The agent holds an `Option<VerbGrant>` pinned for the session (delivered in Task 5; for this task, thread it in as a parameter/field defaulting to `None`).
- Test: inline in `vsock.rs` tests (sibling to the class-gate tests at `:5418`/`:5578`).

**Interfaces:**
- Consumes: `VerbGrant::permits` (Task 3), `GuestRequest::kind_name` (`:555`), `allowed_in` (`:884`).
- Produces: `GuestResponse::VerbNotAuthorized { verb: String }`; a helper `fn enforce_verb_grant(req: &GuestRequest, grant: Option<&VerbGrant>) -> Option<GuestResponse>` returning `Some(VerbNotAuthorized)` when denied, `None` when allowed.

- [ ] **Step 1: Write the failing test**

```rust
// crates/mvm-guest/src/vsock.rs  (in #[cfg(test)] mod)
#[test]
fn grant_denies_unlisted_but_allows_listed_and_baseline() {
    let now = chrono::Utc::now();
    let grant = VerbGrant {
        session_id: "s".into(),
        plan_nonce: Nonce::from_bytes([0u8; 16]),
        not_after: now + chrono::Duration::minutes(1),
        verbs: vec![VerbId::new("run-entrypoint").unwrap()],
        sig: vec![],
    };
    // listed => allowed
    let run = GuestRequest::RunEntrypoint { /* fill minimal fields */ };
    assert!(enforce_verb_grant(&run, Some(&grant)).is_none());
    // baseline => allowed even though not listed
    assert!(enforce_verb_grant(&GuestRequest::Ping, Some(&grant)).is_none());
    // ProdSafe but unlisted => denied
    let idle = GuestRequest::UpdateIdleTimeout { /* fill minimal fields */ };
    match enforce_verb_grant(&idle, Some(&grant)) {
        Some(GuestResponse::VerbNotAuthorized { verb }) => assert_eq!(verb, idle.kind_name()),
        other => panic!("expected VerbNotAuthorized, got {other:?}"),
    }
}

#[test]
fn no_grant_is_class_gate_only() {
    let idle = GuestRequest::UpdateIdleTimeout { /* fill minimal fields */ };
    assert!(enforce_verb_grant(&idle, None).is_none(), "None grant must not deny anything");
}
```

> Fill the `RunEntrypoint`/`UpdateIdleTimeout` struct fields from their real definitions in this file; use the module's existing request-construction test helpers if present.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-guest grant_denies_unlisted`
Expected: FAIL — `enforce_verb_grant` / `VerbNotAuthorized` absent.

- [ ] **Step 3: Implement**

Add the response variant (after `UnsupportedInProfile`, `:941`):

```rust
    /// The pinned verb grant does not authorize this verb for the
    /// workload. Wire-stable. Universal — may answer any request.
    VerbNotAuthorized { verb: String },
```

Register it in `ResponseVariant` (`:1108` list), in the `GuestResponse -> ResponseVariant` match (`:1223` area), and treat it like `UnsupportedInProfile` in the universal-rejection set (`:1127`) so the response-contract test stays green.

Add the enforcement helper:

```rust
/// Grant intersection, applied AFTER `allowed_in`. `None` grant => no
/// restriction (class gate only). Baseline/listed verbs pass.
pub fn enforce_verb_grant(req: &GuestRequest, grant: Option<&VerbGrant>) -> Option<GuestResponse> {
    match grant {
        None => None,
        Some(g) if g.permits(req.kind_name()) => None,
        Some(_) => Some(GuestResponse::VerbNotAuthorized { verb: req.kind_name().to_string() }),
    }
}
```

Wire it into the dispatch in `mvm-guest-agent.rs` immediately after the existing `allowed_in` block (`:2055`):

```rust
    if let Some(resp) = enforce_verb_grant(&req, boot_state.verb_grant.as_ref()) {
        write_response(&mut file, &resp);
        return;
    }
```

For this task add `verb_grant: Option<VerbGrant>` to the agent's boot/session state struct, defaulting to `None` (Task 5 populates it).

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-guest grant_ && cargo nextest run -p mvm-guest response_contract`
Expected: PASS (new tests + the existing response-contract test still green).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-guest/src/vsock.rs crates/mvm-guest/src/bin/mvm-guest-agent.rs
git commit -m "feat(guest): enforce plan-bound verb grant after the class gate"
```

---

### Task 5: Deliver + verify the grant at the ProtocolHello handshake

> **Reshaped for the 5-B decision (real key separation) into 5a–5d; only 5a landed on the core branch. 5b (guest mounts config drive), 5c (supervisor mints grant + provisions host-signer pubkey via config drive), 5d (deliver grant over ProtocolHello + thread supervisor→caller) and Task 6 (audit) are deferred to a follow-on branch validated on a live boot.**

**Files:**
- Modify guest read side: `crates/mvm-guest/src/vsock.rs` handshake (`ProtocolHello` / the hello-read path around `:2211`–`:2322`) to carry an optional `verb_grant` and the host-signer verifying key.
- Modify host write side: the agent client that performs the handshake — `crates/mvm-cli/src/commands/shared/vsock.rs` and `crates/mvm-cli/src/commands/machine/mod.rs` (the `ProtocolHello` senders; masked in grep — open these files to find the exact hello-construction call).
- Provision the host-signer verifying key into the guest via the SAME mechanism the guest already uses to obtain its frame-verifying key (read `vsock.rs:2211`–`:2322` first).
- Test: inline handshake tests in `vsock.rs`.

**Interfaces:**
- Consumes: `VerbGrant::verify` (Task 3), the pinned `verb_grant` slot on session state (Task 4).
- Produces: after a successful handshake, session state carries `verb_grant: Option<VerbGrant>` verified against the host-signer key, bound to this session id + the plan nonce.

- [ ] **Step 1: Read the current handshake key-provisioning**

Run: `sed -n '2200,2325p' crates/mvm-guest/src/vsock.rs`
Confirm how the guest obtains `host_verifying_key` + `session_id` today and where the plan `nonce` is (or must be) made available guest-side. Decide the provisioning point for the host-signer verifying key (baked rootfs key file vs. passed at boot) and record it in the plan's task notes before coding.

- [ ] **Step 2: Write the failing handshake test**

```rust
// crates/mvm-guest/src/vsock.rs  (#[cfg(test)] mod)
#[test]
fn handshake_pins_valid_grant_and_rejects_forged() {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let session = "sess-H";
    let nonce = Nonce::from_bytes([4u8; 16]);
    let now = chrono::Utc::now();

    let mut good = VerbGrant {
        session_id: session.into(), plan_nonce: nonce.clone(),
        not_after: now + chrono::Duration::minutes(1),
        verbs: vec![VerbId::new("ping").unwrap()], sig: vec![],
    };
    good.sig = { use ed25519_dalek::Signer; signer.sign(&good.signing_bytes()).to_bytes().to_vec() };

    // Accepts a grant signed by the trusted key, bound to this session+nonce.
    assert!(pin_verb_grant(Some(&good), &signer.verifying_key(), session, &nonce, now).unwrap().is_some());

    // Rejects one signed by a different key.
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
    let mut forged = good.clone();
    forged.sig = { use ed25519_dalek::Signer; attacker.sign(&forged.signing_bytes()).to_bytes().to_vec() };
    assert!(pin_verb_grant(Some(&forged), &signer.verifying_key(), session, &nonce, now).is_err());

    // Replay onto a different session id is refused.
    assert!(pin_verb_grant(Some(&good), &signer.verifying_key(), "other", &nonce, now).is_err());
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo nextest run -p mvm-guest handshake_pins_valid_grant`
Expected: FAIL — `pin_verb_grant` absent.

- [ ] **Step 4: Implement `pin_verb_grant` + wire into handshake**

```rust
/// Verify an incoming grant against the host-signer key and the live
/// session binding; returns the grant to pin, or an error that aborts
/// the handshake. `None` in => `None` out (grant-less workloads).
pub fn pin_verb_grant(
    grant: Option<&VerbGrant>,
    host_signer_key: &ed25519_dalek::VerifyingKey,
    session_id: &str,
    plan_nonce: &Nonce,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<VerbGrant>> {
    match grant {
        None => Ok(None),
        Some(g) => {
            g.verify(host_signer_key, session_id, plan_nonce, now)
                .map_err(|e| anyhow::anyhow!("verb grant rejected at handshake: {e}"))?;
            Ok(Some(g.clone()))
        }
    }
}
```

Extend the `ProtocolHello` payload with `verb_grant: Option<VerbGrant>` (`#[serde(default)]`), call `pin_verb_grant` during the hello handler, and store the result into the session state's `verb_grant` slot (Task 4). On the host write side, populate `verb_grant` from the admitted plan by calling `mint_verb_grant` (Task 3) with the session id, `plan.nonce`, and a `not_after` clamped to `plan.valid_until`.

- [ ] **Step 5: Run tests + guest build**

Run: `cargo nextest run -p mvm-guest handshake_pins_valid_grant && cargo build -p mvm-guest -p mvm-cli`
Expected: PASS; both crates build.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-guest/src/vsock.rs crates/mvm-cli/src/commands/shared/vsock.rs crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "feat: deliver and verify the verb grant at the ProtocolHello handshake"
```

---

### Task 6: Audit denials to the chain-signed log

**Files:**
- Modify: `crates/mvm-hostd/src/audit/emitter.rs` — add `emit_verb_denied` beside `emit_oci_provenance` (`:206`).
- Modify: the host caller that receives `GuestResponse::VerbNotAuthorized` (the agent client in `crates/mvm-cli/src/commands/machine/mod.rs`) to call the emitter.
- Test: inline in `emitter.rs` (model on the existing emitter tests) + a verify-chain assertion.

**Interfaces:**
- Consumes: `AuditEmitter` (`crates/mvm-hostd/src/audit/emitter.rs`), `verify_audit_chain` (mvm-hostd).
- Produces: `AuditEmitter::emit_verb_denied(&self, plan: &ExecutionPlan, verb: &str) -> Result<()>` emitting category `"verb_denied"`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/mvm-hostd/src/audit/emitter.rs  (#[cfg(test)] mod, mirror existing emitter tests)
#[test]
fn verb_denied_entry_is_chained_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let key = test_signing_key();           // reuse this module's existing helper
    let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
    let plan = sample_plan();               // reuse existing helper

    emitter.emit_admitted(&plan, "signer-1").unwrap();
    emitter.emit_verb_denied(&plan, "update-idle-timeout").unwrap();

    // The chain still verifies, and the denial is present.
    verify_chain_for(&plan, dir.path()).unwrap();   // reuse the module's verify helper
    let log = std::fs::read_to_string(chain_path_for(&plan, dir.path())).unwrap();
    assert!(log.contains("verb_denied"));
    assert!(log.contains("update-idle-timeout"));
}
```

> Use this module's existing test helpers (grep the `#[cfg(test)]` block for the emitter/verify/sample-plan helpers used by `emit_oci_provenance`'s tests); do not invent new ones.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-hostd verb_denied_entry_is_chained`
Expected: FAIL — `emit_verb_denied` absent.

- [ ] **Step 3: Implement the emitter method**

```rust
    /// Emit a `verb_denied` entry: the agent refused a control verb the
    /// workload's grant did not authorize. Chained like every other entry.
    pub fn emit_verb_denied(&self, plan: &ExecutionPlan, verb: &str) -> Result<()> {
        // Model the body/labels on emit_oci_provenance (:206). category = "verb_denied",
        // labels carry { verb }. No payload bytes.
        self.emit_entry(plan, "verb_denied", serde_json::json!({ "verb": verb }))
    }
```

> Match the private helper `emit_oci_provenance` uses to append+chain an entry (read `:206`–`:238`); reuse it rather than re-implementing chaining.

Wire the call in the agent client: on `GuestResponse::VerbNotAuthorized { verb }`, call `emitter.emit_verb_denied(&plan, &verb)` before surfacing the error.

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-hostd verb_denied && cargo nextest run -p mvm-hostd verify_audit_chain`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-hostd/src/audit/emitter.rs crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "feat(audit): emit chain-signed verb_denied entries on grant refusal"
```

---

### Task 7 (OPTIONAL — host-side outer layer; skip if descoped)

Close the `services_bindings: vec![]` hardcode at `crates/mvm-backend/src/host_agent_spawn.rs:208` and add a symmetric host-side verb pre-check at the daemon so an unauthorized verb is refused before the frame reaches the guest. This is defense-in-depth per ADR-103; the guest check (Tasks 4–5) is the load-bearing line and this task is not required for correctness. Gate inclusion on the maintainer's answer to the ADR-103 review question. If included, follow the same TDD shape: failing daemon test that an unbound verb is refused host-side → thread `agent_verbs` into `RegisterVm` → enforce → commit.

---

## Full-suite gate (after the last included task)

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo nextest run --workspace`
- [ ] `cargo test --workspace --doc`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] Update `specs/REFACTOR-STATUS.md` (tick Plan 215) and `specs/SPRINT.md` in the same commit.
- [ ] Update `specs/adrs/103-plan-bound-agent-verb-capabilities.md` `Sequenced by:` to point at this plan; flip Status `Proposed → Accepted` if the maintainer approves.

## Self-Review

- **Spec coverage:** ADR-103 decision (optional signed field → handshake token → guest intersect after class gate) = Tasks 2/3/5/4. Subtractive invariant = Task 4 (`no_grant_is_class_gate_only` + class gate untouched). Key separation = Tasks 3/5 (`forged_key_rejected`, handshake forged/replay). Freshness = Task 3 (`expired`, `wrong_nonce`, `wrong_session`). Baseline verbs = Task 3 `permits` + Task 4. Audit parity = Task 6. Host-side outer layer = Task 7 (optional, matching the ADR's "in-scope-optional"). Alternatives/threat-model are rationale, no task needed.
- **Placeholders:** the `/* fill minimal fields */` markers in Tasks 4/5 are explicit instructions to read the real struct defs in the same file, not hand-waving; every new type/fn is fully specified. Masked existing symbols (host-signer accessors, hello senders, emitter chain helper) are pinned by `file:line` with a "read + match, don't invent" instruction — required because the grep output masked those tokens.
- **Type consistency:** `VerbId`, `VerbGrant { session_id, plan_nonce, not_after, verbs, sig }`, `VerbGrant::{signing_bytes, verify, permits}`, `mint_verb_grant`, `enforce_verb_grant`, `pin_verb_grant`, `GuestResponse::VerbNotAuthorized { verb }`, `emit_verb_denied` are used identically across tasks. `Nonce` API (`from_bytes`/`as_hex`) matches `types.rs:421`.
