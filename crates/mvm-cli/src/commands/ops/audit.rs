//! `mvmctl audit` subcommand handlers.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

use crate::ui;

use mvm_core::user_config::MvmConfig;
use mvm_hostd::supervisor::{SignedEnvelope, verify_audit_chain};

use super::super::vm::audit_chain::{audit_path_for_tenant, default_audit_dir};
use super::super::vm::host_signer;
use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: AuditAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum AuditAction {
    /// Show the last N audit events (default: 20). Reads the legacy
    /// `~/.mvm/log/audit.jsonl` LocalAudit stream; pass `--chain` to
    /// follow the plan-64 chain at `~/.mvm/audit/<tenant>.jsonl`.
    Tail {
        /// Number of lines to show
        #[arg(long, short = 'n', default_value = "20")]
        lines: usize,
        /// Follow log output (poll every 500 ms until Ctrl-C)
        #[arg(long, short = 'f')]
        follow: bool,
        /// Read the plan-64 chain (`~/.mvm/audit/<tenant>.jsonl`) instead
        /// of the legacy LocalAudit log.
        #[arg(long)]
        chain: bool,
        /// Tenant whose chain to tail when `--chain` is set.
        /// Defaults to `"local"` (one-host = one-tenant per ADR-002).
        #[arg(long, default_value = "local")]
        tenant: String,
    },
    /// Verify the plan-64 audit chain. Returns nonzero exit on any
    /// signature or chain-link failure.
    Verify {
        /// Tenant whose chain to verify. Defaults to `"local"`.
        #[arg(long, default_value = "local")]
        tenant: String,
    },
    /// Show every audit chain entry bound to a specific plan_id.
    Show {
        /// The plan_id (UUIDv4) to filter by.
        plan_id: String,
        /// Tenant whose chain to search. Defaults to `"local"`.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Emit matching entries as a JSON array to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Run a read-only security-posture self-test. Reports the live
    /// state of plan-65 + plan-7a mitigations on this host (host
    /// signer present, audit chain verifiable, allowlists populated,
    /// overlay root 0700, TLS minimum pinned, …) so an operator
    /// can confirm their config without reading source.
    ///
    /// Read-only: makes no network calls, writes no files, mutates
    /// no state.
    Posture {
        /// Emit a machine-readable JSON object to stdout instead of
        /// the human-readable summary. Useful for monitoring +
        /// configuration-drift detection.
        #[arg(long)]
        json: bool,
    },
    /// Verify a destruction certificate (or array of certificates)
    /// produced by overlay erasure tooling. Designed for use by an
    /// off-host auditor — the verifier needs only the certificate
    /// file + (optionally) the operator's host identity pubkey
    /// + (optionally) the operator's audit chain file.
    ///
    /// Plan 60 Phase 7a Slice D. Each certificate carries an
    /// Ed25519 signature over the destruction receipt fields; this
    /// command checks the signature and refuses tampered fields.
    /// When `--chain` is also supplied, cross-references each cert
    /// against the chain's `lifecycle.tenant.destroyed` entries by
    /// SHA-256 fingerprint — the third axis of the three-axis
    /// verification matrix (signature + pubkey + chain anchor).
    VerifyCert {
        /// Path to the certificate file. Pass `-` to read from
        /// stdin. Accepts either a single `SignedDestructionReceipt`
        /// object or a JSON array of them.
        cert: String,
        /// Optional path to the operator's host identity pubkey.
        /// When supplied, each certificate's embedded signer_pubkey
        /// must match byte-for-byte. The file is the URL-safe-no-pad
        /// base64 form of the 32-byte Ed25519 public key (the same
        /// shape `~/.mvm/keys/host-signer.pub` encodes; pass it
        /// through `cat host-signer.pub | base64`).
        #[arg(long)]
        pubkey: Option<std::path::PathBuf>,
        /// Optional path to the operator's audit chain file (the
        /// `~/.mvm/audit/<tenant>.jsonl` file). When supplied, each
        /// cert's `cert_fingerprint` (SHA-256 of canonical compact
        /// JSON) is matched against the
        /// `lifecycle.tenant.destroyed` entries in the chain. The
        /// auditor sees per-cert match / missing / mismatch
        /// alongside the signature verdict.
        #[arg(long)]
        chain: Option<std::path::PathBuf>,
        /// Emit verified receipts as a JSON array on stdout (for
        /// downstream tooling). Human summary still goes to stderr.
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        AuditAction::Tail {
            lines,
            follow,
            chain,
            tenant,
        } => {
            if chain {
                audit_tail_chain(&tenant, lines, follow)
            } else {
                audit_tail(lines, follow)
            }
        }
        AuditAction::Verify { tenant } => audit_verify(&tenant),
        AuditAction::Show {
            plan_id,
            tenant,
            json,
        } => audit_show(&tenant, &plan_id, json),
        AuditAction::Posture { json } => super::audit_posture::run(json),
        AuditAction::VerifyCert {
            cert,
            pubkey,
            chain,
            json,
        } => verify_cert(&cert, pubkey.as_deref(), chain.as_deref(), json),
    }
}

// ─────────────────────────────────────────────────────────────────
// Plan 60 Phase 7a Slice D — auditor-side verify-cert
// ─────────────────────────────────────────────────────────────────

/// Axis-3 chain-cross-reference outcome per certificate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum ChainMatch {
    /// Certificate's fingerprint found in the chain. Cross-
    /// referenced; auditor's strongest outcome.
    Matched,
    /// No matching chain entry. The operator emitted a cert
    /// without an audit-chain anchor — suspicious.
    Missing,
    /// Chain has an entry for this tenant/workload but the
    /// `cert_fingerprint` label differs — the operator swapped a
    /// cert post-emission.
    Mismatched,
    /// `--chain` wasn't supplied; this axis was skipped.
    Skipped,
}

fn verify_cert(
    cert: &str,
    pubkey_path: Option<&std::path::Path>,
    chain_path: Option<&std::path::Path>,
    json: bool,
) -> Result<()> {
    use base64::Engine;
    use mvm::vm::overlay::{
        SignedDestructionReceipt, cert_fingerprint, verify_destruction_receipt,
    };

    // 1. Slurp the cert. `-` reads from stdin so an auditor can
    //    `cat certs.json | mvmctl audit verify-cert -`.
    let raw = if cert == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("reading certificate from stdin")?;
        buf
    } else {
        std::fs::read_to_string(cert).with_context(|| format!("reading {cert}"))?
    };

    // 2. Parse — accept both shapes (batch tools emit an array; the
    //    Rust API + runbook snippet show single objects).
    let certs: Vec<SignedDestructionReceipt> = if raw.trim_start().starts_with('[') {
        serde_json::from_str(&raw).context("decoding certificate array")?
    } else {
        let one: SignedDestructionReceipt =
            serde_json::from_str(&raw).context("decoding certificate")?;
        vec![one]
    };

    // 3. Optional expected pubkey. The file is the base64 form
    //    `~/.mvm/keys/host-signer.pub | base64` produces.
    let expected_pubkey = match pubkey_path {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("reading pubkey file {}", p.display()))?;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(raw.trim().as_bytes())
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD.decode(raw.trim().as_bytes())
                })
                .with_context(|| format!("decoding base64 pubkey from {}", p.display()))?;
            if bytes.len() != 32 {
                anyhow::bail!(
                    "pubkey file {} contains {} bytes; expected 32",
                    p.display(),
                    bytes.len()
                );
            }
            let array: [u8; 32] = bytes.as_slice().try_into().unwrap();
            Some(ed25519_dalek::VerifyingKey::from_bytes(&array).context("parsing pubkey")?)
        }
        None => None,
    };

    // 4. Verify each. Fail fast on the first refusal so the
    //    operator sees a clear error per cert.
    let mut verified: Vec<&mvm::vm::overlay::DestructionReceipt> = Vec::with_capacity(certs.len());
    for (i, signed) in certs.iter().enumerate() {
        let receipt =
            verify_destruction_receipt(signed, expected_pubkey.as_ref()).with_context(|| {
                format!(
                    "verifying certificate {} ({}/{})",
                    i + 1,
                    signed.receipt.tenant,
                    signed.receipt.workload,
                )
            })?;
        verified.push(receipt);
    }

    // 5. Chain cross-reference (the third verification axis).
    //    When `--chain` is supplied, build a fingerprint → entry
    //    map from `lifecycle.tenant.destroyed` events and check
    //    each cert.
    let chain_index = match chain_path {
        Some(p) => Some(load_chain_fingerprint_index(p)?),
        None => None,
    };
    let chain_matches: Vec<ChainMatch> = certs
        .iter()
        .zip(verified.iter())
        .map(|(signed, receipt)| match chain_index.as_ref() {
            None => ChainMatch::Skipped,
            Some(index) => {
                let fp = cert_fingerprint(signed);
                let key = (receipt.tenant.clone(), receipt.workload.clone());
                match index.get(&key) {
                    Some(chain_fp) if *chain_fp == fp => ChainMatch::Matched,
                    Some(_) => ChainMatch::Mismatched,
                    None => ChainMatch::Missing,
                }
            }
        })
        .collect();

    // Fail if any chain check is Missing or Mismatched. Skipped
    // is informational only — auditor opted not to check the
    // chain axis.
    let chain_failure = chain_matches
        .iter()
        .any(|m| matches!(m, ChainMatch::Missing | ChainMatch::Mismatched));

    // 6. Render. Human summary to stderr always; receipts JSON to
    //    stdout when --json.
    eprintln!(
        "mvmctl audit verify-cert: {} certificate(s) verified",
        verified.len()
    );
    for (r, chain_match) in verified.iter().zip(chain_matches.iter()) {
        let chain_sigil = match chain_match {
            ChainMatch::Matched => " [chain ✓]",
            ChainMatch::Missing => " [chain ✗ MISSING ENTRY]",
            ChainMatch::Mismatched => " [chain ✗ FINGERPRINT MISMATCH]",
            ChainMatch::Skipped => "",
        };
        eprintln!(
            "  ✓ {}/{}: {} file(s), {} byte(s) wiped at {}{}",
            r.tenant, r.workload, r.files_wiped, r.bytes_wiped, r.destroyed_at, chain_sigil
        );
    }
    if json {
        // Emit { receipts, chain_matches } so downstream tooling
        // can introspect both verdicts.
        let output = serde_json::json!({
            "receipts": verified,
            "chain_matches": chain_matches,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    }
    if chain_failure {
        anyhow::bail!(
            "chain cross-reference failed for one or more certificate(s); \
             see the per-cert ✗ markers above. The cert's signature is \
             valid but the audit chain does not corroborate it."
        );
    }
    Ok(())
}

/// Read a chain file and return a map from
/// `(tenant, workload)` to `cert_fingerprint` for every
/// `lifecycle.tenant.destroyed` entry. Lines we can't parse
/// are skipped silently — the chain may contain entries from
/// other event categories.
fn load_chain_fingerprint_index(
    chain_path: &std::path::Path,
) -> Result<std::collections::HashMap<(String, String), String>> {
    use std::io::BufRead;
    let file = std::fs::File::open(chain_path)
        .with_context(|| format!("opening chain file {}", chain_path.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut index = std::collections::HashMap::new();
    for line in reader.lines() {
        let line = line.with_context(|| format!("reading {}", chain_path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        // Each line is a `SignedEnvelope { entry, prev_hash,
        // signature }`. We only need `entry.event` + `entry.labels`.
        let Ok(envelope) = serde_json::from_str::<mvm_hostd::supervisor::SignedEnvelope>(&line)
        else {
            continue;
        };
        if envelope.entry.event != "lifecycle.tenant.destroyed" {
            continue;
        }
        let labels = &envelope.entry.labels;
        let (Some(tenant), Some(workload), Some(fingerprint)) = (
            labels.get("tenant"),
            labels.get("workload"),
            labels.get("cert_fingerprint"),
        ) else {
            continue;
        };
        index.insert((tenant.clone(), workload.clone()), fingerprint.clone());
    }
    Ok(index)
}

fn audit_tail_chain(tenant: &str, lines: usize, follow: bool) -> Result<()> {
    let dir = default_audit_dir()?;
    let path = audit_path_for_tenant(&dir, tenant);
    if !path.exists() {
        ui::info(&format!(
            "No plan-64 audit chain found for tenant '{tenant}'. \
             Events appear at {} after the next `mvmctl up`.",
            path.display()
        ));
        return Ok(());
    }
    print_last_n_chain_lines(&path, lines)?;
    if !follow {
        return Ok(());
    }
    let mut pos = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !path.exists() {
            continue;
        }
        let new_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if new_len > pos {
            use std::io::{BufRead, Seek, SeekFrom};
            let mut file = std::fs::File::open(&path)?;
            file.seek(SeekFrom::Start(pos))?;
            let reader = std::io::BufReader::new(&file);
            for line in reader.lines() {
                let line = line?;
                print_chain_line(&line);
            }
            pos = new_len;
        }
    }
}

fn print_last_n_chain_lines(path: &std::path::Path, n: usize) -> Result<()> {
    use std::io::BufRead;
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    let start = lines.len().saturating_sub(n);
    for line in &lines[start..] {
        print_chain_line(line);
    }
    Ok(())
}

fn print_chain_line(line: &str) {
    match serde_json::from_str::<SignedEnvelope>(line) {
        Ok(env) => {
            // Render the inner AuditEntry as a single human-readable
            // line. Operators who want the full envelope still have
            // the raw file at `~/.mvm/audit/<tenant>.jsonl`.
            let labels = if env.entry.labels.is_empty() {
                String::new()
            } else {
                let pairs: Vec<String> = env
                    .entry
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                format!("  [{}]", pairs.join(" "))
            };
            println!(
                "{ts}  {event}  plan={plan}  workload={workload}{labels}",
                ts = env.entry.timestamp,
                event = env.entry.event,
                plan = env.entry.plan_id.0,
                workload = env.entry.image_name,
            );
        }
        Err(_) => println!("{line}"),
    }
}

fn audit_verify(tenant: &str) -> Result<()> {
    let dir = default_audit_dir()?;
    let path = audit_path_for_tenant(&dir, tenant);
    if !path.exists() {
        ui::info(&format!(
            "No audit chain found for tenant '{tenant}' at {}. Nothing to verify.",
            path.display()
        ));
        return Ok(());
    }
    let signer =
        host_signer::load_or_init().context("loading host signer to verify audit chain")?;
    let vk = signer.verifying;
    match verify_audit_chain(&path, &vk) {
        Ok(count) => {
            ui::success(&format!(
                "audit chain '{}' verifies clean: {count} entries",
                path.display()
            ));
            Ok(())
        }
        Err(e) => {
            // Print a clear error AND propagate so the process exits
            // nonzero. `mvmctl audit verify` is meant for scripting.
            anyhow::bail!("audit chain verify failed: {e}");
        }
    }
}

fn audit_show(tenant: &str, plan_id: &str, json: bool) -> Result<()> {
    let dir = default_audit_dir()?;
    let path = audit_path_for_tenant(&dir, tenant);
    if !path.exists() {
        if json {
            crate::json_out::emit_json(&Vec::<SignedEnvelope>::new())?;
        } else {
            ui::info(&format!(
                "No audit chain found for tenant '{tenant}' at {}.",
                path.display()
            ));
        }
        return Ok(());
    }
    use std::io::BufRead;
    let file = std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut matched: Vec<SignedEnvelope> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Ok(env) = serde_json::from_str::<SignedEnvelope>(&line)
            && env.entry.plan_id.0 == plan_id
        {
            if json {
                matched.push(env);
            } else {
                print_chain_line(&line);
            }
        }
    }
    if json {
        crate::json_out::emit_json(&matched)?;
    } else if matched.is_empty() {
        ui::info(&format!(
            "No audit entries found for plan_id '{plan_id}' in tenant '{tenant}'."
        ));
    }
    Ok(())
}

fn audit_tail(lines: usize, follow: bool) -> Result<()> {
    let log_path = mvm_core::audit::default_audit_log();
    let path = std::path::Path::new(&log_path);

    if !path.exists() {
        ui::info(&format!(
            "No audit log found. Events are recorded at {log_path}."
        ));
        return Ok(());
    }

    print_last_n_lines(path, lines)?;

    if !follow {
        return Ok(());
    }

    // Tail -f: track file position and poll for new content.
    let mut pos = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !path.exists() {
            continue;
        }
        let new_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if new_len > pos {
            let mut file = std::fs::File::open(path)?;
            use std::io::{BufRead, Seek, SeekFrom};
            file.seek(SeekFrom::Start(pos))?;
            let reader = std::io::BufReader::new(&file);
            for line in reader.lines() {
                let line = line?;
                print_audit_line(&line);
            }
            pos = new_len;
        }
    }
}

fn print_last_n_lines(path: &std::path::Path, n: usize) -> Result<()> {
    use std::io::BufRead;
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    let start = lines.len().saturating_sub(n);
    for line in &lines[start..] {
        print_audit_line(line);
    }
    Ok(())
}

fn print_audit_line(line: &str) {
    match serde_json::from_str::<mvm_core::audit::LocalAuditEvent>(line) {
        Ok(event) => {
            let kind = serde_json::to_string(&event.kind)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            let vm = event
                .vm_name
                .as_deref()
                .map(|n| format!("  [{n}]"))
                .unwrap_or_default();
            let detail = event
                .detail
                .as_deref()
                .map(|d| format!("  {d}"))
                .unwrap_or_default();
            println!("{ts}  {kind}{vm}{detail}", ts = event.timestamp);
        }
        Err(_) => {
            // Non-local-audit line — print as-is (fleet AuditEntry, etc.)
            println!("{line}");
        }
    }
}

#[cfg(test)]
mod verify_cert_tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use mvm::vm::overlay::{
        DestructionReceipt, SignedDestructionReceipt, sign_destruction_receipt,
    };
    use tempfile::tempdir;

    fn sample_receipt() -> DestructionReceipt {
        DestructionReceipt {
            tenant: "acme".to_string(),
            workload: "build".to_string(),
            destroyed_at: chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0)
                .unwrap(),
            files_wiped: 5,
            bytes_wiped: 1024,
        }
    }

    fn sign(receipt: &DestructionReceipt) -> (SignedDestructionReceipt, SigningKey) {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signed = sign_destruction_receipt(receipt, &key);
        (signed, key)
    }

    fn write_cert_file(signed: &SignedDestructionReceipt) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cert.json");
        std::fs::write(&path, serde_json::to_string_pretty(signed).unwrap()).unwrap();
        dir
    }

    fn write_pubkey_file(key: &SigningKey, dir: &std::path::Path) -> std::path::PathBuf {
        let pubkey = key.verifying_key();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey.to_bytes());
        let path = dir.join("pubkey.b64");
        std::fs::write(&path, b64).unwrap();
        path
    }

    #[test]
    fn verify_cert_accepts_valid_single_cert() {
        let (signed, _key) = sign(&sample_receipt());
        let dir = write_cert_file(&signed);
        verify_cert(
            dir.path().join("cert.json").to_str().unwrap(),
            None,
            None,
            false,
        )
        .unwrap();
    }

    #[test]
    fn verify_cert_accepts_array_form() {
        let (signed1, _k1) = sign(&sample_receipt());
        let (signed2, _k2) = sign(&DestructionReceipt {
            workload: "test".to_string(),
            ..sample_receipt()
        });
        let dir = tempdir().unwrap();
        let path = dir.path().join("certs.json");
        let arr = vec![signed1, signed2];
        std::fs::write(&path, serde_json::to_string_pretty(&arr).unwrap()).unwrap();
        verify_cert(path.to_str().unwrap(), None, None, false).unwrap();
    }

    #[test]
    fn verify_cert_rejects_tampered_field() {
        let (mut signed, _key) = sign(&sample_receipt());
        signed.receipt.tenant = "evil".to_string();
        let dir = write_cert_file(&signed);
        let err = verify_cert(
            dir.path().join("cert.json").to_str().unwrap(),
            None,
            None,
            false,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("SignatureInvalid") || msg.contains("verifying certificate"),
            "{msg}"
        );
    }

    #[test]
    fn verify_cert_with_matching_pubkey_succeeds() {
        let (signed, key) = sign(&sample_receipt());
        let dir = write_cert_file(&signed);
        let pubkey_path = write_pubkey_file(&key, dir.path());
        verify_cert(
            dir.path().join("cert.json").to_str().unwrap(),
            Some(&pubkey_path),
            None,
            false,
        )
        .unwrap();
    }

    #[test]
    fn verify_cert_with_mismatched_pubkey_rejects() {
        let (signed, _signer_key) = sign(&sample_receipt());
        let dir = write_cert_file(&signed);
        // Plant a DIFFERENT pubkey on disk.
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey_path = write_pubkey_file(&other, dir.path());
        let err = verify_cert(
            dir.path().join("cert.json").to_str().unwrap(),
            Some(&pubkey_path),
            None,
            false,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("PubkeyMismatch") || msg.contains("verifying certificate"),
            "{msg}"
        );
    }

    #[test]
    fn verify_cert_rejects_malformed_pubkey_file_size() {
        let (signed, _key) = sign(&sample_receipt());
        let dir = write_cert_file(&signed);
        // Plant a short pubkey file — base64-decodes to wrong
        // length.
        let path = dir.path().join("bad-pubkey.b64");
        std::fs::write(&path, "AAAA").unwrap(); // 3 bytes decoded
        let err = verify_cert(
            dir.path().join("cert.json").to_str().unwrap(),
            Some(&path),
            None,
            false,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("32"), "{msg}");
    }

    #[test]
    fn verify_cert_rejects_unparseable_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.json");
        std::fs::write(&path, "this is not json").unwrap();
        let err = verify_cert(path.to_str().unwrap(), None, None, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("decoding") || msg.contains("EOF"), "{msg}");
    }

    // ──────────────────────────────────────────────────────────────
    // Chain cross-reference (the third verification axis)
    //
    // Build a synthetic chain file containing one
    // `lifecycle.tenant.destroyed` SignedEnvelope per planted
    // cert, then exercise the chain-axis logic. The SignedEnvelope
    // chain-signing happens via FileAuditSigner so the file's
    // shape matches the overlay erasure chain-anchor format.
    // ──────────────────────────────────────────────────────────────

    use mvm::vm::overlay::cert_fingerprint;
    use mvm_core::plan::{PlanId, TenantId};
    use mvm_hostd::supervisor::{AuditEntry, AuditSigner, FileAuditSigner};
    use std::collections::BTreeMap;

    fn write_chain_with_entries(
        dir: &std::path::Path,
        tenant: &str,
        entries: &[(&str, &str, &str)],
    ) -> std::path::PathBuf {
        // entries are (workload, fingerprint, tenant_label). The
        // tenant_label is what we plant in the labels (operator-
        // visible tenant id) — usually the same as the chain's
        // own tenant.
        let chain_dir = dir.join("audit");
        std::fs::create_dir_all(&chain_dir).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let signer = FileAuditSigner::open(signing_key, &chain_dir).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (workload, fingerprint, tenant_label) in entries {
            let mut labels = BTreeMap::new();
            labels.insert("tenant".to_string(), tenant_label.to_string());
            labels.insert("workload".to_string(), workload.to_string());
            labels.insert("cert_fingerprint".to_string(), fingerprint.to_string());
            let entry = AuditEntry {
                timestamp: chrono::Utc::now(),
                tenant: TenantId(tenant.to_string()),
                plan_id: PlanId(mvm_hostd::supervisor::UNBOUND_PLAN_ID.to_string()),
                plan_version: 0,
                bundle_id: None,
                bundle_version: None,
                image_name: mvm_hostd::supervisor::UNBOUND_IMAGE_NAME.to_string(),
                image_sha256: mvm_hostd::supervisor::UNBOUND_IMAGE_SHA256.to_string(),
                event: "lifecycle.tenant.destroyed".to_string(),
                labels,
            };
            rt.block_on(signer.sign_and_emit(&entry)).unwrap();
        }
        chain_dir.join(format!("{tenant}.jsonl"))
    }

    #[test]
    fn chain_match_finds_matching_fingerprint() {
        let (signed, _key) = sign(&sample_receipt());
        let fp = cert_fingerprint(&signed);
        let cert_dir = write_cert_file(&signed);

        // Plant a chain entry with the matching fingerprint.
        let chain_path =
            write_chain_with_entries(cert_dir.path(), "local", &[("build", &fp, "acme")]);

        // Must succeed AND the chain check (per stderr) is matched.
        verify_cert(
            cert_dir.path().join("cert.json").to_str().unwrap(),
            None,
            Some(&chain_path),
            false,
        )
        .unwrap();
    }

    #[test]
    fn chain_match_fails_when_no_chain_entry_for_cert() {
        // Cert has a fingerprint, but the chain has NO matching
        // `lifecycle.tenant.destroyed` entry. Auditor sees Missing.
        // We plant the chain with a DIFFERENT tenant's entry so the
        // chain file exists but lookup misses on the cert's
        // (tenant, workload) key.
        let (signed, _key) = sign(&sample_receipt());
        let cert_dir = write_cert_file(&signed);
        let chain_path = write_chain_with_entries(
            cert_dir.path(),
            "local",
            &[("other-workload", "other-fingerprint", "other-tenant")],
        );

        let err = verify_cert(
            cert_dir.path().join("cert.json").to_str().unwrap(),
            None,
            Some(&chain_path),
            false,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("chain cross-reference failed"), "{msg}");
    }

    #[test]
    fn chain_match_fails_when_fingerprint_mismatches() {
        // The chain HAS an entry for the cert's tenant/workload,
        // but the fingerprint label is different — operator
        // swapped a cert post-emission.
        let (signed, _key) = sign(&sample_receipt());
        let cert_dir = write_cert_file(&signed);
        let chain_path = write_chain_with_entries(
            cert_dir.path(),
            "local",
            &[("build", "deadbeef-wrong-fingerprint", "acme")],
        );

        let err = verify_cert(
            cert_dir.path().join("cert.json").to_str().unwrap(),
            None,
            Some(&chain_path),
            false,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("chain cross-reference failed"), "{msg}");
    }

    #[test]
    fn chain_axis_skipped_when_no_chain_arg() {
        // Sanity: with no --chain, the chain check is skipped.
        // The existing tests cover this implicitly; this test
        // pins it explicitly so a future refactor that defaults
        // --chain to a real path breaks loudly.
        let (signed, _key) = sign(&sample_receipt());
        let cert_dir = write_cert_file(&signed);
        verify_cert(
            cert_dir.path().join("cert.json").to_str().unwrap(),
            None,
            None,
            false,
        )
        .unwrap();
    }

    #[test]
    fn load_chain_index_extracts_lifecycle_destroyed_entries_only() {
        // The helper must skip non-destruction events so the
        // index isn't polluted by other categories on the same
        // chain file.
        let dir = tempdir().unwrap();
        let chain_dir = dir.path().join("audit");
        std::fs::create_dir_all(&chain_dir).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let signer = FileAuditSigner::open(signing_key, &chain_dir).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // One destruction event.
        let mut labels = BTreeMap::new();
        labels.insert("tenant".to_string(), "acme".to_string());
        labels.insert("workload".to_string(), "build".to_string());
        labels.insert("cert_fingerprint".to_string(), "fp1".to_string());
        let destroy_entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: TenantId("local".to_string()),
            plan_id: PlanId(mvm_hostd::supervisor::UNBOUND_PLAN_ID.to_string()),
            plan_version: 0,
            bundle_id: None,
            bundle_version: None,
            image_name: mvm_hostd::supervisor::UNBOUND_IMAGE_NAME.to_string(),
            image_sha256: mvm_hostd::supervisor::UNBOUND_IMAGE_SHA256.to_string(),
            event: "lifecycle.tenant.destroyed".to_string(),
            labels,
        };
        rt.block_on(signer.sign_and_emit(&destroy_entry)).unwrap();

        // One unrelated event.
        let mut other_labels = BTreeMap::new();
        other_labels.insert("verb".to_string(), "up".to_string());
        let other_entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: TenantId("local".to_string()),
            plan_id: PlanId(mvm_hostd::supervisor::UNBOUND_PLAN_ID.to_string()),
            plan_version: 0,
            bundle_id: None,
            bundle_version: None,
            image_name: mvm_hostd::supervisor::UNBOUND_IMAGE_NAME.to_string(),
            image_sha256: mvm_hostd::supervisor::UNBOUND_IMAGE_SHA256.to_string(),
            event: "cmd.up.completed".to_string(),
            labels: other_labels,
        };
        rt.block_on(signer.sign_and_emit(&other_entry)).unwrap();

        let path = chain_dir.join("local.jsonl");
        let index = load_chain_fingerprint_index(&path).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(
            index
                .get(&("acme".to_string(), "build".to_string()))
                .map(String::as_str),
            Some("fp1")
        );
    }
}
