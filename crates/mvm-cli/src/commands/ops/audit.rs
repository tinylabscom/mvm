//! `mvmctl audit` subcommand handlers.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

use crate::ui;

use ed25519_dalek::VerifyingKey;
use mvm_core::user_config::MvmConfig;
use mvm_hostd::audit_signer::verify::verify_workload_chain;
use mvm_hostd::supervisor::{SignedEnvelope, verify_audit_chain};
use mvm_protocol::merkle::{InclusionProof, SignedAuditRoot, verify_inclusion, verify_signed_root};

use super::super::vm::audit_chain::{AuditEmitter, audit_path_for_tenant, default_audit_dir};
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
    /// follow the chain-signed log at `~/.mvm/audit/<tenant>.jsonl`.
    Tail {
        /// Number of lines to show
        #[arg(long, short = 'n', default_value = "20")]
        lines: usize,
        /// Follow log output (poll every 500 ms until Ctrl-C)
        #[arg(long, short = 'f')]
        follow: bool,
        /// Read the chain-signed log (`~/.mvm/audit/<tenant>.jsonl`)
        /// instead of the legacy LocalAudit log.
        #[arg(long)]
        chain: bool,
        /// Tenant whose chain to tail when `--chain` is set.
        /// Defaults to `"local"` (one-host = one-tenant).
        #[arg(long, default_value = "local")]
        tenant: String,
    },
    /// Verify the chain-signed audit log. Returns nonzero exit on any
    /// signature or chain-link failure.
    Verify {
        /// Tenant whose chain to verify. Defaults to `"local"`.
        #[arg(long, default_value = "local")]
        tenant: String,
    },
    /// Show every audit chain entry bound to a specific plan_id.
    Show {
        /// The plan_id (`sha256:<hex>` content-address) to filter by.
        plan_id: String,
        /// Tenant whose chain to search. Defaults to `"local"`.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Emit matching entries as a JSON array to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Run a read-only security-posture self-test. Reports the live
    /// state of the host's mitigations (host
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
    /// Each certificate carries an
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
    /// Build, sign, and publish a Merkle transparency-log root over the
    /// tenant's chain-signed audit log (host-side). The signed root at
    /// `~/.mvm/audit/<tenant>.root.json` lets an external auditor pin the
    /// log's state without replaying the whole chain. The root is only
    /// built over a chain that verifies clean.
    PublishRoot {
        /// Tenant whose chain to publish a root for. Defaults to `"local"`.
        #[arg(long, default_value = "local")]
        tenant: String,
    },
    /// Emit an inclusion proof that one audit line is a leaf of the log,
    /// paired with the current signed root, as JSON. The selector picks the
    /// line: a numeric 0-based index, a `plan_id`, or `sha256:<hex>` of the
    /// exact line. A selector matching more than one line is refused as
    /// ambiguous (fail closed).
    Prove {
        /// Line selector: numeric index, a plan_id, or `sha256:<hex>` of the
        /// exact audit line.
        selector: String,
        /// Tenant whose chain to prove against. Defaults to `"local"`.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Emit the proof + current signed root as a JSON object to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Verify an inclusion proof against a host-signed root — the full
    /// membership check. Verifies the signed root under the trusted host
    /// key, checks it is for `--tenant`, verifies the proof, and binds the
    /// two (root_hash + tree_size must match). Nonzero exit naming the
    /// failed check on any failure; a genuinely-signed root for a different
    /// tenant, or a self-consistent proof over an unsigned root, is rejected.
    VerifyInclusion {
        /// Path to the inclusion-proof JSON, or `-` to read from stdin.
        #[arg(long)]
        proof: String,
        /// Path to the signed-root JSON. Defaults to
        /// `~/.mvm/audit/<tenant>.root.json`.
        #[arg(long)]
        root: Option<std::path::PathBuf>,
        /// Path to the trusted host public key. Defaults to
        /// `~/.mvm/keys/host-signer.pub`. Accepts the raw 32-byte key, hex,
        /// or base64.
        #[arg(long)]
        pubkey: Option<std::path::PathBuf>,
        /// Tenant the signed root must be bound to (and whose default root
        /// path is used when `--root` is omitted).
        #[arg(long, default_value = "local")]
        tenant: String,
    },
    /// Opt-in forensic network transcript capture: arm / disarm / list /
    /// export. Off by default; separate from the metadata-only flow audit.
    Transcript {
        #[command(subcommand)]
        action: super::transcript::TranscriptAction,
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
        AuditAction::Transcript { action } => super::transcript::run(action),
        AuditAction::VerifyCert {
            cert,
            pubkey,
            chain,
            json,
        } => verify_cert(&cert, pubkey.as_deref(), chain.as_deref(), json),
        AuditAction::PublishRoot { tenant } => audit_publish_root(&tenant),
        AuditAction::Prove {
            selector,
            tenant,
            json,
        } => audit_prove(&tenant, &selector, json),
        AuditAction::VerifyInclusion {
            proof,
            root,
            pubkey,
            tenant,
        } => audit_verify_inclusion(&proof, root.as_deref(), pubkey.as_deref(), &tenant),
    }
}

// ─────────────────────────────────────────────────────────────────
// auditor-side verify-cert
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
    use mvm_runtime::vm::overlay::{
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
    let mut verified: Vec<&mvm_runtime::vm::overlay::DestructionReceipt> =
        Vec::with_capacity(certs.len());
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

// ─────────────────────────────────────────────────────────────────
// Merkle transparency log: publish-root / prove / verify-inclusion
// ─────────────────────────────────────────────────────────────────

/// Build, sign, and publish a Merkle root over the tenant's audit chain.
fn audit_publish_root(tenant: &str) -> Result<()> {
    let signer =
        host_signer::load_or_init().context("loading host signer to publish audit root")?;
    let emitter = AuditEmitter::new(signer.signing).context("opening host audit emitter")?;
    let signed = emitter
        .publish_root(tenant)
        .with_context(|| format!("publishing Merkle root for tenant '{tenant}'"))?;
    let path = mvm_core::config::audit_root_path(tenant);
    ui::success(&format!(
        "published Merkle root for tenant '{tenant}': root {root} over {n} entries -> {path}",
        root = signed.root_hash,
        n = signed.tree_size,
        path = path.display(),
    ));
    Ok(())
}

/// Build an inclusion proof for the selector-resolved leaf and print it
/// (paired with the current signed root) as JSON, or a one-line summary.
fn audit_prove(tenant: &str, selector: &str, json: bool) -> Result<()> {
    use mvm_protocol::merkle::build_inclusion_proof;

    let signer =
        host_signer::load_or_init().context("loading host signer to build inclusion proof")?;
    let dir = default_audit_dir()?;
    // Read the verified leaf set once; the selector resolves against exactly
    // the leaves the proof is built over, so indices can't drift.
    let leaves = mvm_hostd::audit::merkle::read_leaves(&dir, tenant, &signer.verifying)
        .with_context(|| format!("reading the verified audit chain for tenant '{tenant}'"))?;
    let index = resolve_selector(&leaves, selector)?;
    let proof = build_inclusion_proof(&leaves, index)
        .map_err(|e| anyhow::anyhow!("building inclusion proof for leaf {index}: {e}"))?;

    // Pair the proof with the currently-published signed root, if any, so a
    // downstream `verify-inclusion` has both halves of the membership check.
    let root_path = mvm_core::config::audit_root_path(tenant);
    let signed_root: Option<SignedAuditRoot> = if root_path.exists() {
        let raw = std::fs::read_to_string(&root_path)
            .with_context(|| format!("reading signed root {}", root_path.display()))?;
        Some(
            serde_json::from_str(&raw)
                .with_context(|| format!("decoding signed root {}", root_path.display()))?,
        )
    } else {
        None
    };

    if json {
        let out = serde_json::json!({ "proof": proof, "signed_root": signed_root });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        ui::info(&format!(
            "inclusion proof: leaf {idx} of {n} (root {root})",
            idx = proof.leaf_index,
            n = proof.tree_size,
            root = proof.root,
        ));
        if signed_root.is_none() {
            ui::warn(&format!(
                "no published root at {}; run `mvmctl trust audit publish-root` first \
                 so `verify-inclusion` has a signed root to bind against.",
                root_path.display()
            ));
        }
    }
    Ok(())
}

/// Resolve a `prove` selector to a 0-based leaf index over `leaves`.
///
/// Accepts a numeric line index, a `plan_id`, or `sha256:<hex>` of the exact
/// audit line. Every non-numeric interpretation is collected across all
/// lines; a selector matching more than one line is refused as ambiguous so
/// the resolution is fail-closed.
fn resolve_selector(leaves: &[String], selector: &str) -> Result<usize> {
    use sha2::{Digest, Sha256};

    // 1. numeric 0-based line index.
    if let Ok(idx) = selector.parse::<usize>() {
        if idx >= leaves.len() {
            anyhow::bail!(
                "line index {idx} out of range: the chain has {} entries",
                leaves.len()
            );
        }
        return Ok(idx);
    }

    // 2 & 3. a `sha256:<hex>` line hash and/or a plan_id. Collect every match.
    let line_hash_want = selector
        .strip_prefix("sha256:")
        .map(str::to_ascii_lowercase);
    let mut matches: Vec<usize> = Vec::new();
    for (i, line) in leaves.iter().enumerate() {
        let mut matched = false;
        if let Some(want) = &line_hash_want {
            let got = hex::encode(Sha256::digest(line.as_bytes()));
            if &got == want {
                matched = true;
            }
        }
        if !matched
            && let Ok(env) = serde_json::from_str::<SignedEnvelope>(line)
            && env.entry.plan_id.0 == selector
        {
            matched = true;
        }
        if matched {
            matches.push(i);
        }
    }

    match matches.as_slice() {
        [] => anyhow::bail!("selector '{selector}' matched no audit line in the chain"),
        [only] => Ok(*only),
        many => anyhow::bail!(
            "selector '{selector}' is ambiguous: it matches {} lines (indices {many:?}); \
             use a numeric line index or a `sha256:<hex>` line hash to disambiguate",
            many.len()
        ),
    }
}

/// Verify an inclusion proof against a host-signed root — the full
/// membership check. Loads the proof, the signed root, and the trusted host
/// key, then enforces the composition via [`run_verify_inclusion`].
fn audit_verify_inclusion(
    proof_arg: &str,
    root_path: Option<&std::path::Path>,
    pubkey_path: Option<&std::path::Path>,
    tenant: &str,
) -> Result<()> {
    // 1. load the inclusion proof (file or stdin).
    let proof_raw = if proof_arg == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("reading inclusion proof from stdin")?;
        buf
    } else {
        std::fs::read_to_string(proof_arg)
            .with_context(|| format!("reading inclusion proof {proof_arg}"))?
    };
    let proof: InclusionProof =
        serde_json::from_str(&proof_raw).context("decoding inclusion-proof JSON")?;

    // 2. load the signed root (default: ~/.mvm/audit/<tenant>.root.json).
    let root_path = root_path
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| mvm_core::config::audit_root_path(tenant));
    let root_raw = std::fs::read_to_string(&root_path)
        .with_context(|| format!("reading signed root {}", root_path.display()))?;
    let signed_root: SignedAuditRoot =
        serde_json::from_str(&root_raw).context("decoding signed-root JSON")?;

    // 3. load the trusted host verifying key (default: host-signer.pub).
    let vk = match pubkey_path {
        Some(p) => load_verifying_key(p)?,
        None => {
            host_signer::load_or_init()
                .context("loading host signer public key")?
                .verifying
        }
    };

    // 4-7: the composition. Fail closed naming the failed check.
    let message = run_verify_inclusion(&proof, &signed_root, &vk, tenant)?;
    ui::success(&message);
    Ok(())
}

/// The full inclusion-membership check as a pure function, so the security
/// composition is unit-testable without touching the filesystem.
///
/// Enforces, in order and fail-closed:
///   1. the signed root verifies under the trusted host key;
///   2. the signed root is for the tenant the caller intended
///      (`signed_root.tenant == expected_tenant`) — a genuinely-signed root
///      for a different tenant is not evidence for this one;
///   3. the inclusion proof is internally consistent (folds to its own root);
///   4. the proof binds to THIS signed root — `root_hash` and `tree_size`
///      must match.
///
/// Only when all hold does it return the success message. A proof that
/// self-verifies but whose embedded root differs from the host-signed root is
/// rejected at step 4 — self-consistency is not membership.
fn run_verify_inclusion(
    proof: &InclusionProof,
    signed_root: &SignedAuditRoot,
    vk: &VerifyingKey,
    expected_tenant: &str,
) -> Result<String> {
    verify_signed_root(signed_root, vk)
        .map_err(|e| anyhow::anyhow!("signed-root verification failed: {e}"))?;
    if signed_root.tenant != expected_tenant {
        anyhow::bail!(
            "tenant binding failed: signed root is for tenant '{}', expected '{}'",
            signed_root.tenant,
            expected_tenant
        );
    }
    verify_inclusion(proof)
        .map_err(|e| anyhow::anyhow!("inclusion-proof verification failed: {e}"))?;
    if proof.root != signed_root.root_hash {
        anyhow::bail!(
            "root binding failed: proof root {} does not match the host-signed root {}",
            proof.root,
            signed_root.root_hash
        );
    }
    if proof.tree_size != signed_root.tree_size {
        anyhow::bail!(
            "tree-size binding failed: proof tree_size {} does not match the host-signed \
             tree_size {}",
            proof.tree_size,
            signed_root.tree_size
        );
    }
    Ok(format!(
        "verified: entry at index {idx} of {n} is in the host-signed log (root {root})",
        idx = proof.leaf_index,
        n = proof.tree_size,
        root = signed_root.root_hash,
    ))
}

/// Load a trusted Ed25519 verifying key from a file. Accepts the raw
/// 32-byte form (`~/.mvm/keys/host-signer.pub`), 64-char hex, or base64.
fn load_verifying_key(path: &std::path::Path) -> Result<VerifyingKey> {
    let raw =
        std::fs::read(path).with_context(|| format!("reading pubkey file {}", path.display()))?;
    // Raw 32-byte key half — the on-disk host-signer.pub shape.
    if raw.len() == 32 {
        let arr: [u8; 32] = raw.as_slice().try_into().expect("length checked");
        return VerifyingKey::from_bytes(&arr)
            .with_context(|| format!("parsing raw pubkey {}", path.display()));
    }
    // Otherwise the file is text: hex (64 chars) or base64.
    let text = String::from_utf8(raw).with_context(|| {
        format!(
            "pubkey file {} is neither 32 raw bytes nor UTF-8 text",
            path.display()
        )
    })?;
    let text = text.trim();
    let bytes = hex::decode(text)
        .ok()
        .filter(|b| b.len() == 32)
        .or_else(|| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .ok()
                .or_else(|| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(text)
                        .ok()
                })
                .filter(|b| b.len() == 32)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "pubkey file {} did not contain a 32-byte Ed25519 key (raw, hex, or base64)",
                path.display()
            )
        })?;
    let arr: [u8; 32] = bytes.as_slice().try_into().expect("length checked");
    VerifyingKey::from_bytes(&arr).with_context(|| format!("parsing pubkey {}", path.display()))
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
    let lifecycle_path = audit_path_for_tenant(&dir, tenant);
    let workload_paths = workload_chain_paths(&dir, tenant)?;

    if !lifecycle_path.exists() && workload_paths.is_empty() {
        ui::info(&format!(
            "No audit chain found for tenant '{tenant}' under {}. Nothing to verify.",
            dir.display()
        ));
        return Ok(());
    }

    // Both chain kinds are signed under the host key; load it once.
    let signer =
        host_signer::load_or_init().context("loading host signer to verify audit chain")?;
    let vk = signer.verifying;

    // The host-lifecycle chain (`<tenant>.jsonl`, SignedEnvelope format).
    if lifecycle_path.exists() {
        match verify_audit_chain(&lifecycle_path, &vk) {
            Ok(count) => ui::success(&format!(
                "audit chain '{}' verifies clean: {count} entries",
                lifecycle_path.display()
            )),
            // Print a clear error AND propagate so the process exits
            // nonzero. `mvmctl audit verify` is meant for scripting.
            Err(e) => anyhow::bail!("audit chain verify failed: {e}"),
        }
    }

    // The per-VM workload-emitted chains (`<tenant>.<vm>.workload.jsonl`,
    // OnDiskEntry/JCS). Each per-VM signer owns its own file (single-writer),
    // so a tenant can have several; verify every one.
    for workload_path in &workload_paths {
        match verify_workload_chain(workload_path, &vk) {
            Ok(count) => ui::success(&format!(
                "workload audit chain '{}' verifies clean: {count} entries",
                workload_path.display()
            )),
            Err(e) => anyhow::bail!(
                "workload audit chain verify failed ({}): {e}",
                workload_path.display()
            ),
        }
    }

    Ok(())
}

/// Enumerate a tenant's per-VM workload audit chains
/// (`<tenant>.<vm>.workload.jsonl`) in the audit dir, sorted for stable
/// output. The naming convention lives in `mvm-core::config` so the writer
/// (the backend spawn) and this reader can't drift.
fn workload_chain_paths(dir: &std::path::Path, tenant: &str) -> Result<Vec<std::path::PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // No audit dir yet ⇒ no workload chains.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading audit dir {}", dir.display())),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading audit dir {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if mvm_core::config::workload_audit_vm_name(name, tenant).is_some() {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
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
    use mvm_runtime::vm::overlay::{
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let other = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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

    use mvm_core::plan::{PlanId, TenantId};
    use mvm_hostd::supervisor::{AuditEntry, AuditSigner, FileAuditSigner};
    use mvm_runtime::vm::overlay::cert_fingerprint;
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
        let signing_key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
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
        let signing_key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
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

// ──────────────────────────────────────────────────────────────────
// Merkle transparency-log verbs: publish-root / prove / verify-inclusion
// ──────────────────────────────────────────────────────────────────
#[cfg(test)]
mod merkle_verb_tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use mvm_protocol::merkle::{build_inclusion_proof, merkle_root, root_signing_bytes};

    fn fresh_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn lines(n: usize) -> Vec<String> {
        (0..n).map(|i| format!(r#"{{"line":{i}}}"#)).collect()
    }

    /// Sign a root over `leaves` exactly the way `publish_root` does.
    fn sign_root(key: &SigningKey, tenant: &str, leaves: &[String]) -> SignedAuditRoot {
        sign_root_fields(
            key,
            tenant,
            leaves.len() as u64,
            &hex::encode(merkle_root(leaves)),
        )
    }

    /// Sign a root over caller-chosen `tree_size` / `root_hash` (to isolate the
    /// tree_size-binding check, which needs a validly-signed-but-mismatched root).
    fn sign_root_fields(
        key: &SigningKey,
        tenant: &str,
        tree_size: u64,
        root_hash: &str,
    ) -> SignedAuditRoot {
        let timestamp = "2026-07-26T00:00:00Z".to_string();
        let payload = root_signing_bytes(tenant, tree_size, root_hash, &timestamp).unwrap();
        let sig = key.sign(&payload);
        SignedAuditRoot {
            tenant: tenant.to_string(),
            tree_size,
            root_hash: root_hash.to_string(),
            timestamp,
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            signer_pubkey: hex::encode(key.verifying_key().to_bytes()),
        }
    }

    // ---- run_verify_inclusion composition ----

    #[test]
    fn composition_accepts_valid_proof_against_signed_root() {
        let key = fresh_key();
        let vk = key.verifying_key();
        let leaves = lines(5);
        let signed = sign_root(&key, "local", &leaves);
        let proof = build_inclusion_proof(&leaves, 2).unwrap();
        let msg = run_verify_inclusion(&proof, &signed, &vk, "local").unwrap();
        assert!(msg.contains("index 2 of 5"), "{msg}");
        assert!(msg.contains(&signed.root_hash), "{msg}");
    }

    #[test]
    fn composition_rejects_self_consistent_proof_over_a_different_root() {
        // THE CRUX: a proof that self-verifies (verify_inclusion Ok) with the
        // SAME tree_size as the signed root, but whose embedded root differs.
        // Self-consistency is not membership — it must be rejected at the
        // root-binding step.
        let key = fresh_key();
        let vk = key.verifying_key();
        let signed = sign_root(&key, "local", &lines(5)); // root A, size 5
        let foreign_leaves: Vec<String> = (0..5).map(|i| format!(r#"{{"forged":{i}}}"#)).collect(); // root B, size 5
        let proof = build_inclusion_proof(&foreign_leaves, 2).unwrap();
        // Sanity: the forged proof self-verifies and its size matches.
        assert!(verify_inclusion(&proof).is_ok());
        assert_eq!(proof.tree_size, signed.tree_size);
        assert_ne!(proof.root, signed.root_hash);

        let err = run_verify_inclusion(&proof, &signed, &vk, "local").unwrap_err();
        assert!(
            format!("{err:#}").contains("root binding failed"),
            "{err:#}"
        );
    }

    #[test]
    fn composition_rejects_tampered_signed_root() {
        // Tamper the signed root's root_hash: the signature no longer covers
        // it, so verify_signed_root refuses before the proof is even folded.
        let key = fresh_key();
        let vk = key.verifying_key();
        let leaves = lines(5);
        let mut signed = sign_root(&key, "local", &leaves);
        let proof = build_inclusion_proof(&leaves, 0).unwrap();
        signed.root_hash = hex::encode([0xabu8; 32]);
        let err = run_verify_inclusion(&proof, &signed, &vk, "local").unwrap_err();
        assert!(
            format!("{err:#}").contains("signed-root verification failed"),
            "{err:#}"
        );
    }

    #[test]
    fn composition_rejects_signed_root_under_wrong_key() {
        // The signed root is valid, but we hand verify the WRONG trusted key.
        let key = fresh_key();
        let leaves = lines(4);
        let signed = sign_root(&key, "local", &leaves);
        let proof = build_inclusion_proof(&leaves, 1).unwrap();
        let wrong_vk = fresh_key().verifying_key();
        let err = run_verify_inclusion(&proof, &signed, &wrong_vk, "local").unwrap_err();
        assert!(
            format!("{err:#}").contains("signed-root verification failed"),
            "{err:#}"
        );
    }

    #[test]
    fn composition_rejects_wrong_entry_proof() {
        // A proof for a real tree whose leaf_index is re-pointed folds to a
        // different root → verify_inclusion fails before any binding check.
        let key = fresh_key();
        let vk = key.verifying_key();
        let leaves = lines(8);
        let signed = sign_root(&key, "local", &leaves);
        let mut proof = build_inclusion_proof(&leaves, 3).unwrap();
        proof.leaf_index = 4;
        let err = run_verify_inclusion(&proof, &signed, &vk, "local").unwrap_err();
        assert!(
            format!("{err:#}").contains("inclusion-proof verification failed"),
            "{err:#}"
        );
    }

    #[test]
    fn composition_rejects_tree_size_mismatch() {
        // Isolate the tree_size binding: sign a root that claims the SAME
        // root_hash the proof folds to, but a different tree_size. The
        // signature is valid and the proof self-verifies, so only the
        // tree_size bind can catch it.
        let key = fresh_key();
        let vk = key.verifying_key();
        let leaves = lines(5);
        let proof = build_inclusion_proof(&leaves, 0).unwrap();
        let signed = sign_root_fields(&key, "local", 99, &proof.root);
        let err = run_verify_inclusion(&proof, &signed, &vk, "local").unwrap_err();
        assert!(
            format!("{err:#}").contains("tree-size binding failed"),
            "{err:#}"
        );
    }

    #[test]
    fn composition_rejects_root_for_a_different_tenant() {
        // A genuinely-signed root+proof for tenant `beta` must NOT count as
        // evidence for tenant `acme` — the signed `tenant` field is checked
        // against the caller's intent, fail closed. Same key, same valid
        // signature: only the tenant binding catches the mix-up.
        let key = fresh_key();
        let vk = key.verifying_key();
        let leaves = lines(5);
        let signed = sign_root(&key, "beta", &leaves);
        let proof = build_inclusion_proof(&leaves, 2).unwrap();

        let err = run_verify_inclusion(&proof, &signed, &vk, "acme").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("tenant binding failed"), "{msg}");
        assert!(msg.contains("beta") && msg.contains("acme"), "{msg}");

        // The same root+proof verifies when the intended tenant matches.
        let ok = run_verify_inclusion(&proof, &signed, &vk, "beta").unwrap();
        assert!(ok.contains("index 2 of 5"), "{ok}");
    }

    // ---- resolve_selector ----

    /// Seed a real chain of SignedEnvelope lines via `FileAuditSigner`,
    /// returning the verified leaf set. `plan_ids` names each entry's plan_id.
    fn seed_leaves(plan_ids: &[&str]) -> (tempfile::TempDir, Vec<String>) {
        use mvm_hostd::supervisor::{AuditEntry, AuditSigner, FileAuditSigner};
        use std::collections::BTreeMap;

        let dir = tempfile::tempdir().unwrap();
        let chain_dir = dir.path().join("audit");
        std::fs::create_dir_all(&chain_dir).unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, &chain_dir).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (i, plan_id) in plan_ids.iter().enumerate() {
            let entry = AuditEntry {
                timestamp: chrono::Utc::now(),
                tenant: mvm_core::plan::TenantId("local".to_string()),
                plan_id: mvm_core::plan::PlanId(plan_id.to_string()),
                plan_version: 1,
                bundle_id: None,
                bundle_version: None,
                image_name: "img".to_string(),
                image_sha256: "abc".to_string(),
                event: format!("e-{i}"),
                labels: BTreeMap::new(),
            };
            rt.block_on(signer.sign_and_emit(&entry)).unwrap();
        }
        let leaves = mvm_hostd::audit::merkle::read_leaves(&chain_dir, "local", &vk).unwrap();
        (dir, leaves)
    }

    #[test]
    fn resolve_selector_numeric_index() {
        let leaves = lines(4);
        assert_eq!(resolve_selector(&leaves, "0").unwrap(), 0);
        assert_eq!(resolve_selector(&leaves, "3").unwrap(), 3);
    }

    #[test]
    fn resolve_selector_numeric_out_of_range_refused() {
        let leaves = lines(3);
        let err = resolve_selector(&leaves, "3").unwrap_err();
        assert!(format!("{err:#}").contains("out of range"), "{err:#}");
    }

    #[test]
    fn resolve_selector_line_hash() {
        use sha2::{Digest, Sha256};
        let leaves = lines(4);
        let want = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(leaves[2].as_bytes()))
        );
        assert_eq!(resolve_selector(&leaves, &want).unwrap(), 2);
    }

    #[test]
    fn resolve_selector_no_match_refused() {
        let leaves = lines(3);
        let err = resolve_selector(&leaves, "sha256:deadbeef").unwrap_err();
        assert!(
            format!("{err:#}").contains("matched no audit line"),
            "{err:#}"
        );
    }

    #[test]
    fn resolve_selector_unique_plan_id() {
        let (_dir, leaves) = seed_leaves(&["plan-a", "plan-b", "plan-c"]);
        assert_eq!(resolve_selector(&leaves, "plan-b").unwrap(), 1);
    }

    #[test]
    fn resolve_selector_ambiguous_plan_id_refused() {
        // Two lines carry the same plan_id → the selector is ambiguous and
        // must be refused (fail closed) rather than silently proving one.
        let (_dir, leaves) = seed_leaves(&["plan-x", "plan-dup", "plan-dup"]);
        let err = resolve_selector(&leaves, "plan-dup").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ambiguous"), "{msg}");
    }

    #[test]
    fn prove_selector_to_verify_inclusion_round_trip() {
        // End-to-end over real SignedEnvelope leaves: resolve a plan_id, build
        // the proof over the exact leaf bytes, sign a matching root, and run
        // the full composition. The leaf bytes fold to `merkle_root(leaves)`
        // independent of which key signed the chain, so signing the root with
        // a fresh key exercises the proof↔root binding faithfully.
        let (_dir, leaves) = seed_leaves(&["plan-a", "plan-b", "plan-c", "plan-d"]);
        let key = fresh_key();
        let idx = resolve_selector(&leaves, "plan-c").unwrap();
        assert_eq!(idx, 2);
        let proof = build_inclusion_proof(&leaves, idx).unwrap();
        let signed = sign_root(&key, "local", &leaves);
        let msg = run_verify_inclusion(&proof, &signed, &key.verifying_key(), "local").unwrap();
        assert!(msg.contains("index 2 of 4"), "{msg}");
    }

    // ---- load_verifying_key ----

    #[test]
    fn load_verifying_key_raw_32_bytes() {
        let key = fresh_key();
        let vk = key.verifying_key();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-signer.pub");
        std::fs::write(&path, vk.to_bytes()).unwrap();
        let loaded = load_verifying_key(&path).unwrap();
        assert_eq!(loaded.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn load_verifying_key_hex_text() {
        let key = fresh_key();
        let vk = key.verifying_key();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pub.hex");
        std::fs::write(&path, format!("{}\n", hex::encode(vk.to_bytes()))).unwrap();
        let loaded = load_verifying_key(&path).unwrap();
        assert_eq!(loaded.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn load_verifying_key_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.pub");
        std::fs::write(&path, "not-a-key").unwrap();
        assert!(load_verifying_key(&path).is_err());
    }
}
