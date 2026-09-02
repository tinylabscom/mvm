//! Verb-grant trust and enforcement: verifying a host-signed
//! `VerbGrant` against the boot-pinned host-signer anchor, re-pinning
//! it across a snapshot restore, and the per-call gate that refuses an
//! unlisted verb.

use super::*;

/// Grant intersection, applied AFTER `allowed_in`. `None` grant => no
/// restriction (class gate only). Baseline/listed verbs pass.
pub fn enforce_verb_grant(
    req: &GuestRequest,
    grant: Option<&mvm_core::plan::VerbGrant>,
) -> Option<GuestResponse> {
    match grant {
        None => None,
        Some(g) if g.permits(req.kind_name()) => None,
        Some(_) => Some(GuestResponse::VerbNotAuthorized {
            verb: req.kind_name().to_string(),
        }),
    }
}
/// Well-known guest path where `/init` copies the host-signer's Ed25519
/// public key from the read-only config drive.
/// Absent on grant-less boots.
pub const HOST_SIGNER_PUBKEY_PATH: &str = "/run/mvm/host-signer.pub";

/// Decode a 64-char lowercase-hex string to an Ed25519 `VerifyingKey`.
///
/// Returns `Err` on wrong length, invalid hex chars, or a byte sequence that
/// is not a valid compressed Ed25519 point.
pub fn verifying_key_from_hex(hex: &str) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
    let hex = hex.trim_ascii();
    if hex.len() != 64 {
        anyhow::bail!(
            "host-signer pubkey must be exactly 64 hex chars, got {}",
            hex.len()
        );
    }
    let mut bytes = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(pair[0]).ok_or_else(|| {
            anyhow::anyhow!(
                "host-signer pubkey has invalid hex char {:?}",
                pair[0] as char
            )
        })?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| {
            anyhow::anyhow!(
                "host-signer pubkey has invalid hex char {:?}",
                pair[1] as char
            )
        })?;
        bytes[i] = hi * 16 + lo;
    }
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("host-signer pubkey is not a valid Ed25519 key: {e}"))
}

/// Load the host-signer verifying key from `path`.
///
/// - File absent  -> `Ok(None)`   (grant-less boot; no key to verify against)
/// - File present, valid raw 32-byte Ed25519 key -> `Ok(Some(key))`
/// - File present, valid 64-char hex of a 32-byte Ed25519 key -> `Ok(Some(key))`
/// - File present but malformed -> `Err`  (fail closed; do not silently ignore)
pub fn load_host_signer_verifying_key(
    path: &std::path::Path,
) -> anyhow::Result<Option<ed25519_dalek::VerifyingKey>> {
    let raw = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("failed to read host-signer pubkey: {e}")),
    };
    if raw.len() == 32 {
        let key_bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .expect("length checked before converting host-signer pubkey");
        return ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("host-signer pubkey is not a valid Ed25519 key: {e}"));
    }
    let raw = std::str::from_utf8(&raw).map_err(|e| {
        anyhow::anyhow!("host-signer pubkey is neither raw bytes nor UTF-8 hex: {e}")
    })?;
    verifying_key_from_hex(raw.trim_ascii()).map(Some)
}

/// Kernel-cmdline token carrying the host-signer's Ed25519 public key as hex.
///
/// A vsock-only guest has no config drive to copy the key off, so the launcher
/// rides it here instead.
pub const HOST_SIGNER_PUB_CMDLINE_KEY: &str = "mvm.host_signer_pub";

/// The `mvm.host_signer_pub=<hex>` value in a kernel cmdline, if present.
pub fn host_signer_pub_token(cmdline: &str) -> Option<&str> {
    let prefix = format!("{HOST_SIGNER_PUB_CMDLINE_KEY}=");
    cmdline
        .split_whitespace()
        .find_map(|part| part.strip_prefix(prefix.as_str()))
}

/// Write the host-signer anchor to [`HOST_SIGNER_PUBKEY_PATH`] under `root`.
///
/// The token is decoded and validated as an Ed25519 key *before* anything is
/// written, so a file that exists is always a usable anchor and a malformed
/// token leaves the guest anchorless — refusing control connections — rather
/// than holding a key that fails to parse later.
///
/// `root` is a test seam; production passes `/`.
pub fn write_host_signer_anchor(root: &std::path::Path, hex: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let key = verifying_key_from_hex(hex)?;
    // Derive from the constant so the writer and the reader can never drift.
    let path = root.join(HOST_SIGNER_PUBKEY_PATH.trim_start_matches('/'));
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("host-signer anchor path has no parent directory"))?;
    std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("mkdir {}: {e}", dir.display()))?;
    std::fs::write(&path, key.to_bytes())
        .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| anyhow::anyhow!("chmod {}: {e}", path.display()))?;
    Ok(())
}

/// Provision the anchor from a kernel cmdline into the live root.
///
/// Returns `Ok(false)` when the cmdline carries no token — a launch that ships
/// no anchor is a valid (if unreachable) boot, not an error. Requires `/proc`
/// to be mounted, so PID 1 must read `/proc/cmdline` after its early mounts.
pub fn provision_host_signer_anchor_from_cmdline(
    cmdline: &str,
    root: &std::path::Path,
) -> anyhow::Result<bool> {
    let Some(hex) = host_signer_pub_token(cmdline) else {
        return Ok(false);
    };
    write_host_signer_anchor(root, hex)?;
    Ok(true)
}

/// Decode a single ASCII hex nibble ('0'-'9', 'a'-'f') to its value.
/// Returns `None` for any other character (including uppercase).
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Verify an incoming grant against the provisioned host-signer key and the
/// live session binding, returning the grant to pin.
///
/// - `grant` `None`                        -> `Ok(None)` (workload shipped no grant; class gate only)
/// - `grant` `Some` but `host_signer_key` `None` -> `Err` (fail closed — a grant arrived but
///   we have no key to trust it against; letting it silently pass would disable enforcement)
/// - `grant` `Some` + `key` `Some`         -> `verify(session_id, plan_nonce, now)`; `Ok(Some(clone))` or `Err`
pub fn pin_verb_grant(
    grant: Option<&mvm_core::plan::VerbGrant>,
    host_signer_key: Option<&ed25519_dalek::VerifyingKey>,
    session_id: &str,
    plan_nonce: &mvm_core::plan::Nonce,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Option<mvm_core::plan::VerbGrant>> {
    match (grant, host_signer_key) {
        (None, _) => Ok(None),
        (Some(_), None) => anyhow::bail!(
            "verb grant present but no host-signer key provisioned — cannot verify; \
             rejecting to prevent unverifiable grant from bypassing enforcement"
        ),
        (Some(g), Some(key)) => {
            g.verify(key, session_id, plan_nonce, now)
                .map_err(|e| anyhow::anyhow!("verb grant verification failed: {e}"))?;
            Ok(Some(g.clone()))
        }
    }
}

/// Verify a `VerbGrantEnvelope` against a caller-supplied host-signer trust
/// anchor and return the pinned grant, or `None` on any failure.
///
/// Shared verification core used by both boot-time `load_pinned_verb_grant`
/// (resolves the anchor from disk) and restore-time `re_pin_verb_grant`
/// (receives the anchor already resolved). Neither caller reads the verifying
/// key from the envelope: the key that rides inside the envelope
/// (`envelope.pubkey_hex`) is self-attested and is never trusted for
/// verification. Logs a warning and returns `None` on any error so callers
/// never crash on a bad envelope.
fn verify_envelope_with_anchor(
    envelope: &mvm_core::protocol::vm_backend::VerbGrantEnvelope,
    host_signer_key: &ed25519_dalek::VerifyingKey,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<mvm_core::plan::VerbGrant> {
    let plan_nonce = match mvm_core::plan::Nonce::from_hex(&envelope.plan_nonce_hex) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("mvm-guest-agent: verb-grant plan_nonce_hex invalid, skipping grant: {e}");
            return None;
        }
    };
    match pin_verb_grant(
        Some(&envelope.grant),
        Some(host_signer_key),
        &envelope.grant.session_id,
        &plan_nonce,
        now,
    ) {
        Ok(pinned) => pinned,
        Err(e) => {
            eprintln!("mvm-guest-agent: verb-grant verification failed, skipping grant: {e}");
            None
        }
    }
}

/// Re-pin a verb grant delivered over vsock at restore time (plain resume sends
/// no envelope; a fork sends a fresh host-signed one).
///
/// Trust derives from the boot-pinned host-signer anchor the guest holds at
/// `HOST_SIGNER_PUBKEY_PATH`, passed in as `host_signer_key` — NOT from the key
/// embedded in the envelope. A prior version verified against
/// `envelope.pubkey_hex`, which is self-attested: any party able to deliver a
/// `PostRestore` envelope could forge its own keypair and mint an arbitrary
/// grant. Binding to the boot anchor closes that bypass.
///
/// A fork legitimately mints a fresh host-signed envelope carrying the child's
/// new `session_id`/`plan_nonce` and MAY widen the verb set (it runs a newly
/// admitted plan), so re-pin does NOT require the boot session/nonce to match;
/// the sole invariant is that the grant is signed by the host-signer anchor.
pub fn re_pin_verb_grant(
    envelope: &mvm_core::protocol::vm_backend::VerbGrantEnvelope,
    current_grant: Option<&mvm_core::plan::VerbGrant>,
    host_signer_key: &ed25519_dalek::VerifyingKey,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<mvm_core::plan::VerbGrant> {
    if let Some(current) = current_grant {
        let predecessor_session = envelope.predecessor_session_id.as_deref()?;
        let predecessor_nonce_hex = envelope.predecessor_plan_nonce_hex.as_deref()?;
        if predecessor_session != current.session_id
            || predecessor_nonce_hex != current.plan_nonce.as_hex()
        {
            eprintln!("mvm-guest-agent: PostRestore grant lineage mismatch, refusing re-pin");
            return None;
        }
    }
    verify_envelope_with_anchor(envelope, host_signer_key, now)
}

/// Read the pinned verb grant written by `/init` and verify it before use.
///
/// The grant's trust derives from the host-signer pubkey provisioned through
/// the read-only config drive. The envelope's embedded pubkey is retained for
/// wire compatibility and diagnostics, but is not trusted for verification.
///
/// Returns:
/// - `Some(grant)` when the file is present and the grant verifies.
/// - `None` when `grant_path` is absent (no-grant boot; class gate only).
/// - `None` when the envelope is malformed or the grant fails verification
///   (logs a warning; does not crash the agent).
pub fn load_pinned_verb_grant(
    grant_path: &std::path::Path,
    host_signer_pubkey_path: &std::path::Path,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<mvm_core::plan::VerbGrant> {
    // Grant file absent → no grant on this boot.
    let raw = match read_grant_bytes(grant_path) {
        Ok(Some(b)) => b,
        Ok(None) => return None,
        Err(e) => {
            eprintln!("mvm-guest-agent: could not read verb-grant file: {e}");
            return None;
        }
    };
    let envelope: mvm_core::protocol::vm_backend::VerbGrantEnvelope =
        match serde_json::from_slice(&raw) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("mvm-guest-agent: verb-grant.json malformed, booting without grant: {e}");
                return None;
            }
        };
    let host_key = match load_host_signer_verifying_key(host_signer_pubkey_path) {
        Ok(Some(key)) => key,
        Ok(None) => {
            eprintln!(
                "mvm-guest-agent: verb-grant present but host-signer pubkey is absent, booting without grant"
            );
            return None;
        }
        Err(e) => {
            eprintln!("mvm-guest-agent: host-signer pubkey invalid, booting without grant: {e}");
            return None;
        }
    };
    verify_envelope_with_anchor(&envelope, &host_key, now)
}

fn read_grant_bytes(path: &std::path::Path) -> anyhow::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow::anyhow!("read {}: {error}", path.display())),
    }
}

/// Well-known guest path for the dm-verity-measured verb-trust policy baked
/// into a sealed image's rootfs. Absent on dev/OCI boots.
pub const VERB_TRUST_POLICY_PATH: &str = "/etc/mvm/verb-trust.json";

/// The guest's grant-trust decision, derived from the measured policy and
/// whether a valid grant is pinned. `ObserveGap` serves but flags the gap
/// (observe mode); `FailClosed` refuses control RPCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    Serve,
    ObserveGap,
    FailClosed,
}

/// Read the dm-verity-measured verb-trust policy from `path`. Absent,
/// unreadable, or malformed returns `None` (no requirement — the dev/OCI
/// permissive default). A real sealed image carries this file under
/// dm-verity, so a malformed policy there cannot occur without breaking
/// the verity seal (claim 3).
pub fn load_verb_trust_policy(path: &std::path::Path) -> Option<mvm_core::plan::VerbTrustPolicy> {
    let raw = std::fs::read(path).ok()?;
    match serde_json::from_slice(&raw) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("mvm-guest-agent: verb-trust.json malformed, treating as no policy: {e}");
            None
        }
    }
}

/// Returns `true` if `verb` is in the baseline set (`mvm_core::plan::VERB_GRANT_BASELINE`)
/// that is always allowed regardless of grant or trust-policy state.
pub fn is_verb_trust_baseline(verb: &str) -> bool {
    mvm_core::plan::VERB_GRANT_BASELINE.contains(&verb)
}

/// Pure trust decision. `Attested` key source is treated as fail-closed
/// whenever the grant is not present, never a silent downgrade.
/// `launch_requires_grant` is derived from the `mvm.require_grant=1`
/// kernel-cmdline token set by the host when it delivered a verb grant.
pub fn trust_decision(
    policy: Option<&mvm_core::plan::VerbTrustPolicy>,
    grant_present: bool,
    launch_requires_grant: bool,
) -> TrustDecision {
    use mvm_core::plan::GrantKeySource;
    if grant_present {
        return TrustDecision::Serve;
    }
    let policy_requires = policy.map(|p| p.require_grant).unwrap_or(false);
    let attested = policy
        .map(|p| matches!(p.grant_key_source, GrantKeySource::Attested))
        .unwrap_or(false);
    if launch_requires_grant || policy_requires || attested {
        return TrustDecision::FailClosed;
    }
    if policy.is_some() {
        TrustDecision::ObserveGap
    } else {
        TrustDecision::Serve
    }
}

/// Whether the kernel cmdline carries the launcher's `mvm.require_grant=1`
/// enforcement assertion.
pub fn parse_require_grant_cmdline(cmdline: &str) -> bool {
    cmdline
        .split_whitespace()
        .any(|tok| tok == "mvm.require_grant=1")
}

/// Return whether enforcement is launch-asserted for `cmdline`.
pub fn launch_requires_grant(cmdline: &str) -> bool {
    parse_require_grant_cmdline(cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- enforce_verb_grant ----

    #[test]
    fn grant_denies_unlisted_but_allows_listed_and_baseline() {
        use mvm_core::plan::{Nonce, VerbGrant, VerbId};
        let now = chrono::Utc::now();
        let grant = VerbGrant {
            session_id: "s".into(),
            plan_nonce: Nonce::from_bytes([0u8; 16]),
            not_after: now + chrono::Duration::minutes(1),
            verbs: vec![VerbId::new("run-entrypoint").unwrap()],
            sig: vec![],
        };
        // listed => allowed
        let run = GuestRequest::RunEntrypoint {
            stdin: vec![],
            timeout_secs: 1,
            env: vec![],
            stream_input: false,
        };
        assert!(enforce_verb_grant(&run, Some(&grant)).is_none());
        // baseline => allowed even though not listed
        assert!(enforce_verb_grant(&GuestRequest::Ping, Some(&grant)).is_none());
        // ProdSafe but unlisted => denied
        let idle = GuestRequest::UpdateIdleTimeout { secs: 0 };
        let idle_name = idle.kind_name();
        match enforce_verb_grant(&idle, Some(&grant)) {
            Some(GuestResponse::VerbNotAuthorized { verb }) => assert_eq!(verb, idle_name),
            other => panic!("expected VerbNotAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn no_grant_is_class_gate_only() {
        let idle = GuestRequest::UpdateIdleTimeout { secs: 0 };
        assert!(
            enforce_verb_grant(&idle, None).is_none(),
            "None grant must not deny anything"
        );
    }

    #[test]
    fn prod_safe_grant_refuses_all_dev_only_requests() {
        use mvm_core::plan::{Nonce, VerbGrant, VerbId};

        let grant = VerbGrant {
            session_id: "s".into(),
            plan_nonce: Nonce::from_bytes([0u8; 16]),
            not_after: chrono::Utc::now() + chrono::Duration::minutes(1),
            verbs: GuestRequest::prod_safe_verb_names()
                .iter()
                .map(|name| VerbId::new(name).expect("the prod-safe catalog contains valid verbs"))
                .collect(),
            sig: vec![],
        };
        let requests = [
            GuestRequest::Exec {
                command: "id".into(),
                stdin: None,
                timeout_secs: Some(1),
            },
            GuestRequest::ConsoleOpen {
                cols: 80,
                rows: 24,
                env: vec![],
                argv: vec![],
            },
            GuestRequest::ConsoleClose { session_id: 1 },
            GuestRequest::ConsoleResize {
                session_id: 1,
                cols: 80,
                rows: 24,
            },
            GuestRequest::ExecBatch {
                stages: vec![],
                commands: vec![],
                timeout_secs: Some(1),
            },
            GuestRequest::RunCode {
                code: "print(1)".into(),
                timeout_secs: Some(1),
            },
            GuestRequest::RunDetached {
                argv: vec!["/bin/true".into()],
                env: vec![],
            },
            GuestRequest::ProcStart {
                argv: vec!["/bin/true".into()],
                env: Default::default(),
                cwd: None,
                stdin: vec![],
                timeout_secs: Some(1),
            },
            GuestRequest::ProcList,
            GuestRequest::ProcSignal {
                pid_token: "test".into(),
                signum: 15,
            },
            GuestRequest::ProcSendInput {
                pid_token: "test".into(),
                bytes: vec![],
            },
            GuestRequest::ProcWait {
                pid_token: "test".into(),
                timeout_secs: Some(1),
            },
            GuestRequest::ProcKill {
                pid_token: "test".into(),
            },
        ];

        for request in requests {
            assert_eq!(request.class(), RequestClass::DevOnly);
            assert!(request.allowed_in(mvm_core::security::AgentProfile::Dev));
            assert!(matches!(
                enforce_verb_grant(&request, Some(&grant)),
                Some(GuestResponse::VerbNotAuthorized { .. })
            ));
        }
    }

    // ---- load_host_signer_verifying_key ----

    #[test]
    fn load_host_signer_key_absent_missing_malformed() {
        let dir = tempfile::tempdir().unwrap();
        // absent -> Ok(None)
        assert!(
            load_host_signer_verifying_key(&dir.path().join("nope"))
                .unwrap()
                .is_none()
        );
        // valid -> Ok(Some)
        let k = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let rawpath = dir.path().join("ok.raw.pub");
        std::fs::write(&rawpath, k.verifying_key().to_bytes()).unwrap();
        let loaded = load_host_signer_verifying_key(&rawpath).unwrap().unwrap();
        assert_eq!(loaded.to_bytes(), k.verifying_key().to_bytes());

        // valid hex -> Ok(Some)
        let hexpath = dir.path().join("ok.pub");
        let hex: String = k
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(&hexpath, format!("{hex}\n")).unwrap(); // trailing newline tolerated
        let loaded = load_host_signer_verifying_key(&hexpath).unwrap().unwrap();
        assert_eq!(loaded.to_bytes(), k.verifying_key().to_bytes());
        // malformed -> Err
        let bad = dir.path().join("bad.pub");
        std::fs::write(&bad, "not-hex").unwrap();
        assert!(load_host_signer_verifying_key(&bad).is_err());

        let directory = dir.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(
            load_host_signer_verifying_key(&directory).is_err(),
            "an unreadable host-signer path must not be treated as absent"
        );
    }

    #[test]
    fn verifying_key_hex_roundtrip_combines_high_and_low_nibbles() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);
        let hex = signer
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let parsed = verifying_key_from_hex(&hex).expect("a signer key round-trips from hex");
        assert_eq!(parsed, signer.verifying_key());
    }

    #[test]
    fn provisioning_helper_handles_missing_and_valid_cmdline_tokens() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!provision_host_signer_anchor_from_cmdline("console=ttyS0", dir.path()).unwrap());
        assert!(
            !dir.path()
                .join(HOST_SIGNER_PUBKEY_PATH.trim_start_matches('/'))
                .exists()
        );

        let signer = ed25519_dalek::SigningKey::from_bytes(&[18u8; 32]);
        let hex = signer
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(
            provision_host_signer_anchor_from_cmdline(
                &format!("mvm.host_signer_pub={hex}"),
                dir.path()
            )
            .unwrap()
        );
        let path = dir
            .path()
            .join(HOST_SIGNER_PUBKEY_PATH.trim_start_matches('/'));
        assert_eq!(
            std::fs::read(path).unwrap(),
            signer.verifying_key().to_bytes()
        );
    }

    // ---- pin_verb_grant ----

    #[test]
    fn pin_verb_grant_valid_forged_replay_expired_and_no_key() {
        use mvm_core::plan::{Nonce, VerbGrant, VerbId};
        let signer = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let session = "sess-H";
        let nonce = Nonce::from_bytes([4u8; 16]);
        let now = chrono::Utc::now();
        let mut good = VerbGrant {
            session_id: session.into(),
            plan_nonce: nonce.clone(),
            not_after: now + chrono::Duration::minutes(1),
            verbs: vec![VerbId::new("ping").unwrap()],
            sig: vec![],
        };
        good.sig = {
            use ed25519_dalek::Signer;
            signer.sign(&good.signing_bytes()).to_bytes().to_vec()
        };

        // valid, key present -> Some
        assert!(
            pin_verb_grant(
                Some(&good),
                Some(&signer.verifying_key()),
                session,
                &nonce,
                now
            )
            .unwrap()
            .is_some()
        );
        // no grant -> None regardless of key
        assert!(
            pin_verb_grant(None, Some(&signer.verifying_key()), session, &nonce, now)
                .unwrap()
                .is_none()
        );
        // grant present but NO key provisioned -> Err (fail closed)
        assert!(pin_verb_grant(Some(&good), None, session, &nonce, now).is_err());
        // forged key -> Err
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        assert!(
            pin_verb_grant(
                Some(&good),
                Some(&attacker.verifying_key()),
                session,
                &nonce,
                now
            )
            .is_err()
        );
        // replay onto other session -> Err
        assert!(
            pin_verb_grant(
                Some(&good),
                Some(&signer.verifying_key()),
                "other",
                &nonce,
                now
            )
            .is_err()
        );
        // expired -> Err
        let later = good.not_after + chrono::Duration::seconds(1);
        assert!(
            pin_verb_grant(
                Some(&good),
                Some(&signer.verifying_key()),
                session,
                &nonce,
                later
            )
            .is_err()
        );
    }

    // ---- load_pinned_verb_grant ----

    /// Build a signed VerbGrant + VerbGrantEnvelope in a tempdir and write the
    /// signer pubkey as the config-drive key source.
    #[cfg(test)]
    fn write_grant_fixture(
        dir: &std::path::Path,
        signer: &ed25519_dalek::SigningKey,
        session: &str,
        nonce: &mvm_core::plan::Nonce,
        verbs: &[&str],
        valid_minutes: i64,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        use mvm_core::plan::{VerbGrant, VerbId};
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
        let now = chrono::Utc::now();
        let mut grant = VerbGrant {
            session_id: session.into(),
            plan_nonce: nonce.clone(),
            not_after: now + chrono::Duration::minutes(valid_minutes),
            verbs: verbs.iter().map(|v| VerbId::new(v).unwrap()).collect(),
            sig: vec![],
        };
        grant.sig = {
            use ed25519_dalek::Signer;
            signer.sign(&grant.signing_bytes()).to_bytes().to_vec()
        };
        let pubkey_hex: String = signer
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let envelope = VerbGrantEnvelope {
            pubkey_hex: pubkey_hex.clone(),
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant,
        };
        let grant_path = dir.join("verb-grant.json");
        std::fs::write(&grant_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let pubkey_path = dir.join("host-signer.pub");
        std::fs::write(&pubkey_path, format!("{pubkey_hex}\n")).unwrap();
        (grant_path, pubkey_path)
    }

    #[test]
    fn load_pinned_verb_grant_valid_returns_some() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([8u8; 16]);
        let (grant_path, pubkey_path) =
            write_grant_fixture(dir.path(), &signer, "sess-valid", &nonce, &["ping"], 10);
        let now = chrono::Utc::now();
        let result = load_pinned_verb_grant(&grant_path, &pubkey_path, now);
        assert!(
            result.is_some(),
            "valid grant + matching key must return Some"
        );
        let g = result.unwrap();
        assert_eq!(g.session_id, "sess-valid");
    }

    #[test]
    fn load_pinned_verb_grant_ignores_envelope_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([11u8; 16]);
        use mvm_core::plan::{VerbGrant, VerbId};
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
        let now = chrono::Utc::now();
        let mut grant = VerbGrant {
            session_id: "sess-wrong-key".into(),
            plan_nonce: nonce.clone(),
            not_after: now + chrono::Duration::minutes(10),
            verbs: vec![VerbId::new("ping").unwrap()],
            sig: vec![],
        };
        grant.sig = {
            use ed25519_dalek::Signer;
            signer.sign(&grant.signing_bytes()).to_bytes().to_vec()
        };
        let attacker_pubkey_hex: String = attacker
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let envelope = VerbGrantEnvelope {
            pubkey_hex: attacker_pubkey_hex,
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant,
        };
        let grant_path = dir.path().join("verb-grant.json");
        std::fs::write(&grant_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let signer_pubkey_hex: String = signer
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let pubkey_path = dir.path().join("host-signer.pub");
        std::fs::write(&pubkey_path, format!("{signer_pubkey_hex}\n")).unwrap();
        let result = load_pinned_verb_grant(&grant_path, &pubkey_path, now);
        assert!(
            result.is_some(),
            "config-drive pubkey must be trusted instead of envelope.pubkey_hex"
        );
    }

    #[test]
    fn load_pinned_verb_grant_wrong_config_key_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([14u8; 16]);
        let (grant_path, pubkey_path) =
            write_grant_fixture(dir.path(), &signer, "sess-wrong-key", &nonce, &["ping"], 10);
        let attacker_pubkey_hex: String = attacker
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(&pubkey_path, format!("{attacker_pubkey_hex}\n")).unwrap();
        let now = chrono::Utc::now();
        let result = load_pinned_verb_grant(&grant_path, &pubkey_path, now);
        assert!(
            result.is_none(),
            "grant signed by a different key than config-drive pubkey must return None"
        );
    }

    #[test]
    fn load_pinned_verb_grant_malformed_config_pubkey_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[15u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([16u8; 16]);
        let (grant_path, pubkey_path) = write_grant_fixture(
            dir.path(),
            &signer,
            "sess-bad-pubkey",
            &nonce,
            &["ping"],
            10,
        );
        std::fs::write(&pubkey_path, "not-valid-hex\n").unwrap();
        let result = load_pinned_verb_grant(&grant_path, &pubkey_path, chrono::Utc::now());
        assert!(
            result.is_none(),
            "malformed config-drive pubkey must return None"
        );
    }

    #[test]
    fn grant_file_reader_distinguishes_absent_from_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-grant.json");
        assert_eq!(read_grant_bytes(&missing).unwrap(), None);

        let directory = dir.path().join("grant-directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(read_grant_bytes(&directory).is_err());
    }

    /// The vsock-only payoff: when the host-signer pubkey is present (as the
    /// cmdline-delivered trust anchor now provides on the OCI/vsock path), a
    /// valid pinned grant enforces its verb list SELECTIVELY — the listed verb
    /// (and baseline verbs) are served while an unlisted verb is refused —
    /// instead of collapsing to a deny-all posture. Drives the real per-verb
    /// gate `enforce_verb_grant` against the pinned grant, not just a
    /// grant-present shortcut.
    #[test]
    fn present_host_signer_pub_enforces_verb_list_selectively() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([22u8; 16]);
        // List a single non-baseline verb so "listed" is distinguishable from
        // the always-answerable baseline set.
        let (grant_path, pubkey_path) = write_grant_fixture(
            dir.path(),
            &signer,
            "sess-selective",
            &nonce,
            &["update-idle-timeout"],
            10,
        );
        let now = chrono::Utc::now();

        // Anchor present ⇒ grant pins, carrying the listed verb.
        let pinned = load_pinned_verb_grant(&grant_path, &pubkey_path, now)
            .expect("anchor present ⇒ valid grant must pin");
        assert!(
            pinned
                .verbs
                .iter()
                .any(|v| v.as_str() == "update-idle-timeout"),
            "listed verb must survive into the pinned grant"
        );

        // Listed, non-baseline verb ⇒ enforce_verb_grant permits (no refusal).
        let listed = GuestRequest::UpdateIdleTimeout { secs: 0 };
        assert!(
            enforce_verb_grant(&listed, Some(&pinned)).is_none(),
            "listed verb must be served under the pinned grant"
        );
        // Baseline verb ⇒ permitted even though absent from the verb list.
        assert!(
            enforce_verb_grant(&GuestRequest::Ping, Some(&pinned)).is_none(),
            "baseline verb must be served regardless of the verb list"
        );
        // Unlisted, non-baseline verb ⇒ refused. This is what proves selective
        // enforcement rather than deny-all or serve-all.
        let unlisted = GuestRequest::WorkerStatus;
        let unlisted_name = unlisted.kind_name();
        match enforce_verb_grant(&unlisted, Some(&pinned)) {
            Some(GuestResponse::VerbNotAuthorized { verb }) => assert_eq!(verb, unlisted_name),
            other => panic!("unlisted verb must be refused, got {other:?}"),
        }

        // Anchor absent ⇒ no grant pins ⇒ launch-asserted enforcement fails closed.
        let missing_anchor = dir.path().join("no-host-signer.pub");
        assert!(
            load_pinned_verb_grant(&grant_path, &missing_anchor, now).is_none(),
            "absent anchor is the current OCI/vsock regression: grant cannot pin"
        );
        assert_eq!(
            trust_decision(None, false, true),
            TrustDecision::FailClosed,
            "no grant under launch-asserted enforcement is the deny-all path"
        );
    }

    /// The shipped anchor form: [`write_host_signer_anchor`] writes
    /// `host-signer.pub` as the RAW 32 pubkey bytes, not hex. Exercise that byte
    /// layout end-to-end through the reader into `load_pinned_verb_grant`.
    #[test]
    fn load_pinned_verb_grant_accepts_raw_32_byte_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([24u8; 16]);
        let (grant_path, pubkey_path) =
            write_grant_fixture(dir.path(), &signer, "sess-raw", &nonce, &["ping"], 10);
        // Replace the hex fixture pubkey with the raw 32-byte form.
        std::fs::write(&pubkey_path, signer.verifying_key().to_bytes()).unwrap();
        assert_eq!(std::fs::read(&pubkey_path).unwrap().len(), 32);
        let result = load_pinned_verb_grant(&grant_path, &pubkey_path, chrono::Utc::now());
        assert!(
            result.is_some(),
            "raw 32-byte host-signer pubkey must pin the grant (not the anchor-absent None path)"
        );
        assert_eq!(result.unwrap().session_id, "sess-raw");
    }

    /// A real Firecracker cmdline carries the anchor among a dozen other
    /// tokens, and the value must be lifted out of exactly the right one.
    #[test]
    fn host_signer_pub_token_is_lifted_out_of_a_full_cmdline() {
        let hex = "c5".repeat(32);
        let cmdline = format!(
            "console=ttyS0 reboot=k panic=1 root=/dev/vda rw \
             {HOST_SIGNER_PUB_CMDLINE_KEY}={hex} mvm.require_grant=1 init=/init"
        );
        assert_eq!(host_signer_pub_token(&cmdline), Some(hex.as_str()));
        assert_eq!(
            host_signer_pub_token("console=ttyS0 root=/dev/vda rw"),
            None,
            "a launch that ships no anchor must not be mistaken for one that does"
        );
        // A token that merely *contains* the key name is not the key.
        assert_eq!(
            host_signer_pub_token(&format!("not.{HOST_SIGNER_PUB_CMDLINE_KEY}=deadbeef")),
            None
        );
    }

    /// The writer must land the anchor at exactly the path the reader opens,
    /// in the raw byte form the reader accepts.
    #[test]
    fn write_host_signer_anchor_round_trips_through_the_reader() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[41u8; 32]);
        let hex: String = signer
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        write_host_signer_anchor(dir.path(), &hex).unwrap();

        let path = dir
            .path()
            .join(HOST_SIGNER_PUBKEY_PATH.trim_start_matches('/'));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            signer.verifying_key().to_bytes(),
            "the anchor is written as raw key bytes"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            load_host_signer_verifying_key(&path).unwrap(),
            Some(signer.verifying_key()),
            "the reader must accept exactly what the writer produced"
        );
    }

    /// Fail closed: a malformed token leaves no file behind, so the guest stays
    /// anchorless and keeps refusing control rather than holding a key that
    /// cannot be parsed at the point it is needed.
    #[test]
    fn write_host_signer_anchor_refuses_a_malformed_token_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(HOST_SIGNER_PUBKEY_PATH.trim_start_matches('/'));

        for bad in ["", "zz", &"ab".repeat(31), &"ab".repeat(33)] {
            assert!(
                write_host_signer_anchor(dir.path(), bad).is_err(),
                "{bad:?} must be refused"
            );
            assert!(
                !path.exists(),
                "a refused token must never leave an anchor behind ({bad:?})"
            );
        }
    }

    /// The universal initramfs makes the agent itself PID 1, so no
    /// the init runs to copy the anchor off a config drive. If PID-1
    /// early setup does not provision it, `host_signer_key()` stays `None`,
    /// every control connection is refused, and the run dies at
    /// `ActivateEnvironment` — its first RPC. That shipped.
    ///
    /// Asserted against the source because the real path needs to be PID 1
    /// inside a guest, which no unit test can be.
    #[test]
    fn pid1_early_setup_provisions_the_host_signer_anchor() {
        let src = include_str!("../bin/mvm-guest-agent/init.rs");
        let body = src
            .split("pub(crate) fn early_setup")
            .nth(1)
            .expect("early_setup must exist")
            .split("\nfn ")
            .next()
            .expect("function body is delimited by the next item");

        let mounted = body
            .find("mount_early_filesystems")
            .expect("early setup must mount /proc");
        let provisioned = body
            .find("provision_host_signer_anchor")
            .expect("PID-1 early setup must provision the host-signer anchor from the cmdline");
        assert!(
            mounted < provisioned,
            "the anchor is read off /proc/cmdline, so /proc must be mounted first"
        );
    }

    /// Firecracker's serial console is synchronous and every byte requires a
    /// guest exit. Normal-path boot progress is already observable through the
    /// authenticated readiness response, so only failures should use stderr
    /// before the control plane can serve requests.
    #[test]
    fn pid1_success_path_stays_quiet_until_control_requests_are_served() {
        let agent = include_str!("../bin/mvm-guest-agent.rs");
        let main = agent
            .split("fn main()")
            .nth(1)
            .expect("the agent main function must exist");
        let before_accept_loop = main
            .split("loop {")
            .next()
            .expect("the control accept loop must exist");
        for message in [
            "mvm-guest-agent: profile=",
            "mvm-guest-agent: starting on vsock",
            "mvm-guest-agent: control plane ready",
            "mvm-guest-agent: listening on vsock",
        ] {
            assert!(
                !before_accept_loop.contains(message),
                "normal boot must not synchronously write {message:?} before serving control requests"
            );
        }

        let init = include_str!("../bin/mvm-guest-agent/init.rs");
        for message in [
            "running as PID 1",
            "host-signer anchor provisioned",
            "activation complete",
        ] {
            assert!(
                !init.contains(message),
                "normal activation must not synchronously write {message:?} before its ACK"
            );
        }
        assert!(
            init.contains("FATAL (PID 1)"),
            "failure diagnostics must remain on the serial console"
        );
        assert!(
            init.contains("control stays closed"),
            "fail-closed signer diagnostics must remain on the serial console"
        );

        let background_boot = include_str!("../bin/mvm-guest-agent/boot.rs");
        for message in [
            "entrypoint validated",
            "no per-call entrypoint wrapper baked",
        ] {
            assert!(
                !background_boot.contains(message),
                "normal background discovery must not contend for the serial console during activation"
            );
        }
        assert!(
            background_boot.contains("entrypoint validation failed"),
            "entrypoint failure diagnostics must remain on the serial console"
        );
    }

    #[test]
    fn load_pinned_verb_grant_malformed_envelope_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let grant_path = dir.path().join("verb-grant.json");
        let pubkey_path = dir.path().join("host-signer.pub");
        std::fs::write(&pubkey_path, "00".repeat(32)).unwrap();
        std::fs::write(&grant_path, b"this is not json").unwrap();
        let result = load_pinned_verb_grant(&grant_path, &pubkey_path, chrono::Utc::now());
        assert!(
            result.is_none(),
            "malformed envelope JSON must return None (fail-closed)"
        );
    }

    #[test]
    fn load_pinned_verb_grant_absent_grant_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let missing_grant = dir.path().join("no-grant.json");
        let missing_pubkey = dir.path().join("no-host-signer.pub");
        let result = load_pinned_verb_grant(&missing_grant, &missing_pubkey, chrono::Utc::now());
        assert!(
            result.is_none(),
            "absent grant file must return None (no-op boot)"
        );
    }

    // ---- re_pin_verb_grant ----

    #[test]
    fn re_pin_verb_grant_valid_returns_some() {
        // Grant signed by the host anchor, envelope pubkey = anchor, called with
        // the anchor: verifies and re-pins. A host-signed re-pin MAY widen the
        // served verb set (a fork runs a newly admitted plan), so we assert the
        // full listed set comes back.
        let host = ed25519_dalek::SigningKey::from_bytes(&[20u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([21u8; 16]);
        let now = chrono::Utc::now();
        let envelope = self_signed_envelope(
            &host,
            "sess-repin",
            &nonce,
            &["run-entrypoint", "update-idle-timeout"],
            now + chrono::Duration::minutes(10),
        );
        let result = re_pin_verb_grant(&envelope, None, &host.verifying_key(), now);
        let grant = result.expect("valid host-signed envelope must yield Some from re_pin");
        assert_eq!(grant.session_id, "sess-repin");
        assert!(grant.permits("run-entrypoint"));
        assert!(grant.permits("update-idle-timeout"));
    }

    #[test]
    fn re_pin_verb_grant_wrong_key_returns_none() {
        // Envelope is self-consistent (grant signed by `signer`, pubkey_hex =
        // signer), but the boot-pinned anchor is a DIFFERENT key. Because re-pin
        // verifies against the anchor and ignores the embedded pubkey, an
        // envelope not signed by the anchor is rejected — this is exactly the
        // property the old embedded-pubkey path lacked.
        let signer = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
        let anchor = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([24u8; 16]);
        let now = chrono::Utc::now();
        let envelope = self_signed_envelope(
            &signer,
            "sess-wrong",
            &nonce,
            &["ping"],
            now + chrono::Duration::minutes(10),
        );
        let result = re_pin_verb_grant(&envelope, None, &anchor.verifying_key(), now);
        assert!(
            result.is_none(),
            "grant not signed by the boot-pinned anchor must return None"
        );
    }

    // ---- PostRestore grant_envelope default + roundtrip ----

    #[test]
    fn post_restore_grant_envelope_defaults_absent_and_roundtrips() {
        use mvm_core::crypto::vmgenid::GENID_BYTES;

        // A PostRestore frame that omits grant_envelope deserializes with it as
        // None. That is the `#[serde(default)]` rule this repo applies to every
        // new optional field, not a shim for an older wire format.
        let old = r#"{"token":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#;
        let g: GuestRequest =
            serde_json::from_str(&format!(r#"{{"PostRestore":{}}}"#, old)).unwrap();
        match g {
            GuestRequest::PostRestore { grant_envelope, .. } => assert!(
                grant_envelope.is_none(),
                "absent grant_envelope must default to None"
            ),
            _ => panic!("expected PostRestore"),
        }

        // A frame with an explicit null also deserializes correctly.
        let with_null =
            r#"{"PostRestore":{"token":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"grant_envelope":null}}"#;
        match serde_json::from_str::<GuestRequest>(with_null).unwrap() {
            GuestRequest::PostRestore { grant_envelope, .. } => assert!(grant_envelope.is_none()),
            _ => panic!("expected PostRestore"),
        }

        // A frame without both token and grant_envelope defaults both.
        match serde_json::from_str::<GuestRequest>(r#"{"PostRestore":{}}"#).unwrap() {
            GuestRequest::PostRestore {
                token,
                grant_envelope,
                ..
            } => {
                assert_eq!(token, [0u8; GENID_BYTES]);
                assert!(grant_envelope.is_none());
            }
            _ => panic!("expected PostRestore"),
        }
    }

    // ---- trust_decision + load_verb_trust_policy ----

    #[test]
    fn trust_decision_covers_policy_matrix() {
        use mvm_core::plan::{GrantKeySource, VerbTrustPolicy};
        let require = |req| VerbTrustPolicy {
            version: 1,
            require_grant: req,
            grant_key_source: GrantKeySource::LaunchProvisioned,
        };
        // No policy (dev/OCI): always serve regardless of launch flag.
        assert_eq!(trust_decision(None, false, false), TrustDecision::Serve);
        assert_eq!(trust_decision(None, false, true), TrustDecision::FailClosed);
        assert_eq!(trust_decision(None, true, false), TrustDecision::Serve);
        assert_eq!(trust_decision(None, true, true), TrustDecision::Serve);
        // Policy + grant present: serve regardless of launch flag.
        assert_eq!(
            trust_decision(Some(&require(true)), true, false),
            TrustDecision::Serve
        );
        assert_eq!(
            trust_decision(Some(&require(true)), true, true),
            TrustDecision::Serve
        );
        // Policy present, grant absent, require=false, launch=false: observe (mvmd-safe case).
        assert_eq!(
            trust_decision(Some(&require(false)), false, false),
            TrustDecision::ObserveGap
        );
        // Policy present, grant absent, require=false, launch=true: fail closed (mvmctl grant-delivering launch).
        assert_eq!(
            trust_decision(Some(&require(false)), false, true),
            TrustDecision::FailClosed
        );
        // Policy present, grant absent, require=true: fail closed regardless of launch.
        assert_eq!(
            trust_decision(Some(&require(true)), false, false),
            TrustDecision::FailClosed
        );
        assert_eq!(
            trust_decision(Some(&require(true)), false, true),
            TrustDecision::FailClosed
        );
        // No policy, no grant, launch=true: fail closed.
        assert_eq!(trust_decision(None, false, true), TrustDecision::FailClosed);
        // No policy, no grant, launch=false: serve.
        assert_eq!(trust_decision(None, false, false), TrustDecision::Serve);
        // Attested + no grant is treated as fail-closed regardless of launch.
        let attested = VerbTrustPolicy {
            version: 1,
            require_grant: false,
            grant_key_source: GrantKeySource::Attested,
        };
        assert_eq!(
            trust_decision(Some(&attested), false, false),
            TrustDecision::FailClosed
        );
        assert_eq!(
            trust_decision(Some(&attested), false, true),
            TrustDecision::FailClosed
        );
    }

    #[test]
    fn parse_require_grant_cmdline_exact_match() {
        // Token present: true.
        assert!(parse_require_grant_cmdline(
            "console=hvc0 mvm.require_grant=1 quiet"
        ));
        assert!(parse_require_grant_cmdline("mvm.require_grant=1"));
        // Token absent: false.
        assert!(!parse_require_grant_cmdline("console=hvc0 quiet"));
        assert!(!parse_require_grant_cmdline(""));
        // mvm.require_grant=0 is not the exact token: false.
        assert!(!parse_require_grant_cmdline("mvm.require_grant=0"));
        // Substring of another token does not match: false.
        assert!(!parse_require_grant_cmdline("foo=mvm.require_grant=1bar"));
        assert!(!parse_require_grant_cmdline("xmvm.require_grant=1"));
        assert!(launch_requires_grant("mvm.require_grant=1 quiet"));
        assert!(!launch_requires_grant("quiet"));
    }

    #[test]
    fn load_verb_trust_policy_absent_is_none_malformed_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("verb-trust.json");
        assert!(load_verb_trust_policy(&p).is_none()); // absent
        std::fs::write(&p, b"{ not json").unwrap();
        assert!(load_verb_trust_policy(&p).is_none()); // malformed => None (dev-default)

        let policy = mvm_core::plan::VerbTrustPolicy {
            version: 1,
            require_grant: true,
            grant_key_source: mvm_core::plan::GrantKeySource::LaunchProvisioned,
        };
        std::fs::write(&p, serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(load_verb_trust_policy(&p), Some(policy));
    }

    // ---- PostRestore re-pin adversarial (resume-path authority) ----

    /// Build a `VerbGrantEnvelope` self-signed by `signer`, carrying `signer`'s
    /// own pubkey. Mirrors what the launcher would ship, but usable with any key
    /// so an adversarial (non-host) signer can be substituted.
    fn self_signed_envelope(
        signer: &ed25519_dalek::SigningKey,
        session: &str,
        nonce: &mvm_core::plan::Nonce,
        verbs: &[&str],
        not_after: chrono::DateTime<chrono::Utc>,
    ) -> mvm_core::protocol::vm_backend::VerbGrantEnvelope {
        use ed25519_dalek::Signer;
        use mvm_core::plan::{VerbGrant, VerbId};
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
        let mut grant = VerbGrant {
            session_id: session.into(),
            plan_nonce: nonce.clone(),
            not_after,
            verbs: verbs.iter().map(|v| VerbId::new(v).unwrap()).collect(),
            sig: vec![],
        };
        grant.sig = signer.sign(&grant.signing_bytes()).to_bytes().to_vec();
        let pubkey_hex: String = signer
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        VerbGrantEnvelope {
            pubkey_hex,
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant,
        }
    }

    /// A stale (expired) envelope delivered at restore must not re-pin: replaying
    /// an old-but-once-valid grant cannot revive authority past its expiry.
    #[test]
    fn re_pin_verb_grant_expired_envelope_returns_none() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[30u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([31u8; 16]);
        let issued = chrono::Utc::now();
        let envelope = self_signed_envelope(
            &signer,
            "sess-stale",
            &nonce,
            &["run-entrypoint"],
            issued + chrono::Duration::minutes(5),
        );
        // Restore happens one minute after expiry. Anchor matches the signer, so
        // the ONLY reason to reject is the elapsed validity window.
        let later = issued + chrono::Duration::minutes(6);
        assert!(
            re_pin_verb_grant(&envelope, None, &signer.verifying_key(), later).is_none(),
            "an expired envelope must not re-pin at restore"
        );
    }

    /// Verbs appended to the grant AFTER signing (a widened set the signer never
    /// authorized) break the Ed25519 signature and must not re-pin.
    #[test]
    fn re_pin_verb_grant_verbs_widened_after_signing_returns_none() {
        use mvm_core::plan::VerbId;
        let signer = ed25519_dalek::SigningKey::from_bytes(&[32u8; 32]);
        let nonce = mvm_core::plan::Nonce::from_bytes([33u8; 16]);
        let now = chrono::Utc::now();
        let mut envelope = self_signed_envelope(
            &signer,
            "sess-widen",
            &nonce,
            &["update-idle-timeout"],
            now + chrono::Duration::minutes(10),
        );
        // Tamper: append a broader verb after the signature was computed.
        envelope
            .grant
            .verbs
            .push(VerbId::new("run-entrypoint").unwrap());
        // Anchor matches the signer, so rejection is purely the broken signature
        // over the tampered (widened) verb set.
        assert!(
            re_pin_verb_grant(&envelope, None, &signer.verifying_key(), now).is_none(),
            "verbs appended after signing must fail signature verification and not re-pin"
        );
    }

    /// ADVERSARIAL (resume path). A `PostRestore` envelope self-signed by a key
    /// that is NOT the boot-pinned host signer must not install a grant. Re-pin
    /// verifies against the host-signer trust anchor pinned at boot — the same
    /// anchor `load_pinned_verb_grant` uses and
    /// `load_pinned_verb_grant_ignores_envelope_pubkey` proves the boot path
    /// binds to (rather than trusting `envelope.pubkey_hex`). A self-attested
    /// envelope key carries no authority.
    #[test]
    fn post_restore_self_signed_envelope_must_not_widen_authority() {
        // Boot pins a host-signed grant limited to a single non-baseline verb.
        let dir = tempfile::tempdir().unwrap();
        let host = ed25519_dalek::SigningKey::from_bytes(&[40u8; 32]);
        let boot_nonce = mvm_core::plan::Nonce::from_bytes([41u8; 16]);
        let now = chrono::Utc::now();
        let (grant_path, pubkey_path) = write_grant_fixture(
            dir.path(),
            &host,
            "sess-boot",
            &boot_nonce,
            &["update-idle-timeout"],
            10,
        );
        let pinned = load_pinned_verb_grant(&grant_path, &pubkey_path, now)
            .expect("boot grant must pin under the host anchor");
        assert!(
            !pinned.permits("run-entrypoint"),
            "run-entrypoint is forbidden at boot"
        );

        // Adversary crafts a restore envelope self-signed by a NON-host key,
        // listing a broadened verb set, carrying its own pubkey.
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let evil_nonce = mvm_core::plan::Nonce::from_bytes([43u8; 16]);
        let evil_env = self_signed_envelope(
            &attacker,
            "attacker",
            &evil_nonce,
            &["run-entrypoint", "update-idle-timeout"],
            now + chrono::Duration::minutes(10),
        );

        // Verified against the boot-pinned HOST anchor (not the envelope's
        // self-attested pubkey), the non-host-signed envelope is rejected
        // outright — no grant, and certainly no widening to the boot-forbidden
        // verb.
        let result = re_pin_verb_grant(&evil_env, Some(&pinned), &host.verifying_key(), now);
        assert!(
            result.is_none(),
            "SECURITY: a PostRestore envelope self-signed by a non-host key must \
             not re-pin any grant — it is not signed by the boot host-signer anchor"
        );
    }

    /// A host-signed grant for a sibling VM must not re-pin over this VM's
    /// current grant unless it proves lineage from the grant already pinned in
    /// the snapshot.
    #[test]
    fn re_pin_verb_grant_cross_vm_host_signed_requires_matching_lineage() {
        let host = ed25519_dalek::SigningKey::from_bytes(&[44u8; 32]);
        let current_nonce = mvm_core::plan::Nonce::from_bytes([46u8; 16]);
        let other_vm_nonce = mvm_core::plan::Nonce::from_bytes([45u8; 16]);
        let now = chrono::Utc::now();
        let current = self_signed_envelope(
            &host,
            "current-vm-session",
            &current_nonce,
            &["update-idle-timeout"],
            now + chrono::Duration::minutes(10),
        )
        .grant;
        // Host-signed, but for some other VM's session/nonce.
        let mut envelope = self_signed_envelope(
            &host,
            "some-other-vm-session",
            &other_vm_nonce,
            &["run-entrypoint"],
            now + chrono::Duration::minutes(10),
        );
        envelope.predecessor_session_id = Some("sibling-vm-session".into());
        envelope.predecessor_plan_nonce_hex = Some(other_vm_nonce.as_hex().to_string());
        let result = re_pin_verb_grant(&envelope, Some(&current), &host.verifying_key(), now);
        assert!(
            result.is_none(),
            "a host-signed grant for another VM must not re-pin when its \
             predecessor lineage does not match the currently pinned grant"
        );
    }

    #[test]
    fn re_pin_verb_grant_rejects_each_lineage_component_independently() {
        let host = ed25519_dalek::SigningKey::from_bytes(&[50u8; 32]);
        let current_nonce = mvm_core::plan::Nonce::from_bytes([51u8; 16]);
        let next_nonce = mvm_core::plan::Nonce::from_bytes([52u8; 16]);
        let now = chrono::Utc::now();
        let current = self_signed_envelope(
            &host,
            "current-session",
            &current_nonce,
            &["update-idle-timeout"],
            now + chrono::Duration::minutes(10),
        )
        .grant;

        let mut wrong_session = self_signed_envelope(
            &host,
            "child-session",
            &next_nonce,
            &["run-entrypoint"],
            now + chrono::Duration::minutes(10),
        );
        wrong_session.predecessor_session_id = Some("wrong-session".into());
        wrong_session.predecessor_plan_nonce_hex = Some(current.plan_nonce.as_hex().to_string());
        assert!(
            re_pin_verb_grant(&wrong_session, Some(&current), &host.verifying_key(), now).is_none()
        );

        let mut wrong_nonce = self_signed_envelope(
            &host,
            "child-session",
            &next_nonce,
            &["run-entrypoint"],
            now + chrono::Duration::minutes(10),
        );
        wrong_nonce.predecessor_session_id = Some(current.session_id.clone());
        wrong_nonce.predecessor_plan_nonce_hex = Some(next_nonce.as_hex().to_string());
        assert!(
            re_pin_verb_grant(&wrong_nonce, Some(&current), &host.verifying_key(), now).is_none()
        );
    }

    #[test]
    fn re_pin_verb_grant_matching_lineage_allows_host_signed_rotation() {
        let host = ed25519_dalek::SigningKey::from_bytes(&[47u8; 32]);
        let current_nonce = mvm_core::plan::Nonce::from_bytes([48u8; 16]);
        let next_nonce = mvm_core::plan::Nonce::from_bytes([49u8; 16]);
        let now = chrono::Utc::now();
        let current = self_signed_envelope(
            &host,
            "parent-vm-session",
            &current_nonce,
            &["update-idle-timeout"],
            now + chrono::Duration::minutes(10),
        )
        .grant;
        let mut envelope = self_signed_envelope(
            &host,
            "child-vm-session",
            &next_nonce,
            &["run-entrypoint", "update-idle-timeout"],
            now + chrono::Duration::minutes(10),
        );
        envelope.predecessor_session_id = Some(current.session_id.clone());
        envelope.predecessor_plan_nonce_hex = Some(current.plan_nonce.as_hex().to_string());
        let result = re_pin_verb_grant(&envelope, Some(&current), &host.verifying_key(), now);
        let grant = result.expect("matching lineage must allow a host-signed grant rotation");
        assert_eq!(grant.session_id, "child-vm-session");
        assert!(grant.permits("run-entrypoint"));
    }
}
