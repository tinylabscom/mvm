//! Writer for `.mvmev` evidence archives.
//!
//! An archive is a plain tar carrying one run's evidence: the signed
//! execution receipts, an inclusion proof per receipt against a single
//! host-signed audit root, the raw chain lines, a citation for every in-scope
//! entry with no receipt mapping, and the host public key needed to check all
//! of it. No gzip — the members are JSON, and the format mirrors the
//! `.mvmpkg` manifest-plus-signature shape in `mvm_core::plan::bundle`.
//!
//! # Why one root
//!
//! Every proof in an archive binds to `manifest.audit_root`. Building a root
//! per receipt would let two receipts from the same run attest different
//! trees, and a reader could not tell which one the archive was actually
//! about.
//!
//! # Completeness follows the scope
//!
//! A tenant-scoped archive carries every leaf, so a reader compares
//! `leaves.len()` against the root's `tree_size` and derives coverage. A
//! plan-scoped archive is a subsequence, and a subsequence carries nothing
//! that would attest its own completeness — the host asserts it, and the
//! manifest records that it is an assertion.

use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use mvm_core::did_key::DidKey;
use mvm_core::plan::bundle::ensure_safe_path;
use mvm_core::receipt_archive::{
    ArchiveScope, Completeness, EVIDENCE_MANIFEST_SCHEMA_VERSION, EvidenceManifest, LeafCitation,
    SignedEvidenceManifest, TranscriptCitation,
};
use sha2::{Digest, Sha256};

use crate::audit::receipt_export::{CitedEntry, ExportedEvidence, export_evidence};
use crate::supervisor::audit::PlanAuditEntry;
use crate::supervisor::audit::{
    LABEL_CAPTURE_ID, LABEL_CHUNK_COUNT, LABEL_TRANSCRIPT_ROOT, LABEL_VM_NAME,
    TRANSCRIPT_SEALED_EVENT,
};
use crate::supervisor::audit_file::verify_audit_chain_entries;

/// Archive member holding the signed manifest.
pub const MANIFEST_MEMBER: &str = "manifest.json";
/// Archive member holding the detached manifest signature.
pub const SIGNATURE_MEMBER: &str = "manifest.sig";
/// Archive member holding the raw 32-byte host verifying key.
pub const HOST_PUBKEY_MEMBER: &str = "host.pub";
/// Archive member holding the host `did:key` as text.
pub const HOST_DID_MEMBER: &str = "host.did";

/// Archive-relative path of the inclusion proof for leaf `index`.
///
/// Keyed by leaf index rather than by receipt id so *every* leaf has a proof
/// under the same rule -- a citation with no proof would sit in the manifest
/// bound to nothing but the host's signature over it.
#[must_use]
pub fn proof_member_for(index: u64) -> String {
    format!("proofs/leaf-{index}.json")
}

/// What to put in an archive.
///
/// A params struct rather than positional arguments: the fields are three
/// strings and two flags, which is exactly the shape that transposes silently.
#[derive(Debug, Clone)]
pub struct ArchiveRequest {
    /// Directory holding the tenant's chain-signed audit log.
    pub audit_dir: PathBuf,
    /// Tenant whose chain to read.
    pub tenant: String,
    /// What the archive covers.
    pub scope: ArchiveScope,
    /// Embed sealed transcript ciphertext, rather than only citing its root.
    pub with_transcripts: bool,
}

impl ArchiveRequest {
    /// Start building a request. Every value is set by name.
    #[must_use]
    pub fn builder() -> ArchiveRequestBuilder {
        ArchiveRequestBuilder::default()
    }

    /// The plan id this archive is filtered to, if any.
    fn plan_filter(&self) -> Option<&str> {
        match &self.scope {
            ArchiveScope::Plan { plan_id } => Some(plan_id.as_str()),
            ArchiveScope::Tenant => None,
        }
    }

    /// Completeness the scope implies.
    fn completeness(&self) -> Completeness {
        match self.scope {
            ArchiveScope::Plan { .. } => Completeness::Attested,
            ArchiveScope::Tenant => Completeness::Derivable,
        }
    }
}

/// Builder for [`ArchiveRequest`]. Required fields are checked by
/// [`ArchiveRequestBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
#[derive(Debug, Default)]
pub struct ArchiveRequestBuilder {
    audit_dir: Option<PathBuf>,
    tenant: Option<String>,
    scope: Option<ArchiveScope>,
    with_transcripts: bool,
}

impl ArchiveRequestBuilder {
    /// Directory holding the tenant's chain-signed audit log.
    #[must_use]
    pub fn audit_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.audit_dir = Some(dir.into());
        self
    }

    /// Tenant whose chain to read.
    #[must_use]
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// What the archive covers.
    #[must_use]
    pub fn scope(mut self, scope: ArchiveScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Embed sealed transcript ciphertext rather than only citing its root.
    #[must_use]
    pub fn with_transcripts(mut self, yes: bool) -> Self {
        self.with_transcripts = yes;
        self
    }

    /// Finish, or report which field was never set.
    pub fn build(self) -> Result<ArchiveRequest> {
        Ok(ArchiveRequest {
            audit_dir: self
                .audit_dir
                .context("archive request needs an audit_dir")?,
            tenant: self.tenant.context("archive request needs a tenant")?,
            scope: self.scope.context("archive request needs a scope")?,
            with_transcripts: self.with_transcripts,
        })
    }
}

/// Build a `.mvmev` archive and return its bytes.
///
/// The caller writes them out; keeping the bytes in memory means the on-disk
/// archive and the thing that was signed are the same object.
pub fn write_archive(req: &ArchiveRequest, signing_key: &SigningKey) -> Result<Vec<u8>> {
    let evidence = export_evidence(&req.audit_dir, &req.tenant, req.plan_filter(), signing_key)
        .with_context(|| format!("exporting evidence for tenant '{}'", req.tenant))?;

    let audit_root =
        crate::audit::merkle::sign_root_in(&req.audit_dir, &req.tenant, signing_key)
            .with_context(|| format!("signing the audit root for tenant '{}'", req.tenant))?;

    let path = crate::audit::emitter::audit_path_for_tenant(&req.audit_dir, &req.tenant);
    let entries = verify_audit_chain_entries(&path, &signing_key.verifying_key())
        .with_context(|| format!("re-reading the verified chain for tenant '{}'", req.tenant))?;

    let mut parts = ArchiveParts::default();

    let receipt_leaves = receipt_leaf_indices(&entries, req.plan_filter());
    if receipt_leaves.len() != evidence.receipts.len() {
        bail!(
            "internal: {} receipts but {} mapped leaves — the exporter and the archive \
             disagree about which entries map",
            evidence.receipts.len(),
            receipt_leaves.len()
        );
    }

    add_receipt_members(
        &ReceiptPass {
            evidence: &evidence,
            receipt_leaves: &receipt_leaves,
            entries: &entries,
            req,
            signing_key,
        },
        &mut parts,
    )?;
    add_cited_members(&evidence, req, signing_key, &mut parts)?;
    add_chain_members(&req.audit_dir, &req.tenant, &mut parts.members)?;

    let transcripts = collect_transcripts(&entries, req.with_transcripts)?;

    parts.leaves.sort_by_key(|l| l.index);

    let manifest = EvidenceManifest {
        schema_version: EVIDENCE_MANIFEST_SCHEMA_VERSION,
        archive_id: String::new(),
        tenant: req.tenant.clone(),
        scope: req.scope.clone(),
        host_did: DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key(),
        audit_root,
        leaves: parts.leaves,
        counts_by_event: parts.counts,
        transcripts,
        members: digest_map(&parts.members),
        completeness: req.completeness(),
    };

    let signed =
        SignedEvidenceManifest::sign(manifest, signing_key, chrono::Utc::now().to_rfc3339())
            .map_err(|e| anyhow::anyhow!("signing the evidence manifest: {e}"))?;

    emit_tar(&signed, signing_key, parts.members)
}

/// Leaf indices, in chain order, of the in-scope entries that map to receipts.
///
/// Recomputed here rather than threaded out of the exporter so the archive's
/// idea of which leaf a receipt came from is derived from the same chain the
/// proofs are built over.
fn receipt_leaf_indices(entries: &[PlanAuditEntry], plan_filter: Option<&str>) -> Vec<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, e)| plan_filter.is_none_or(|f| e.plan_id.0 == f))
        .filter(|(_, e)| {
            matches!(
                crate::audit::receipt_export::map_event(&e.event),
                crate::audit::receipt_export::EntryMapping::Receipt { .. }
            )
        })
        .map(|(i, _)| i)
        .collect()
}

/// What the archive accumulates as it walks the evidence: the byte members,
/// the leaf citations, and the per-event tally.
///
/// One value rather than three `&mut` parameters threaded through every
/// helper — the three always move together, and a helper that took two of
/// them would be a helper that forgot to count something.
#[derive(Default)]
struct ArchiveParts {
    members: Vec<(String, Vec<u8>)>,
    leaves: Vec<LeafCitation>,
    counts: BTreeMap<String, u64>,
}

impl ArchiveParts {
    /// Record one leaf: its member bytes, its citation, and its tally.
    fn push_leaf(&mut self, member: String, bytes: Vec<u8>, citation: LeafCitation) {
        *self.counts.entry(citation.event.clone()).or_default() += 1;
        self.members.push((member, bytes));
        self.leaves.push(citation);
    }
}

/// Everything the receipt pass needs, grouped so it stays one argument.
struct ReceiptPass<'a> {
    evidence: &'a ExportedEvidence,
    receipt_leaves: &'a [usize],
    entries: &'a [PlanAuditEntry],
    req: &'a ArchiveRequest,
    signing_key: &'a SigningKey,
}

fn add_receipt_members(ctx: &ReceiptPass<'_>, parts: &mut ArchiveParts) -> Result<()> {
    for (n, signed) in ctx.evidence.receipts.iter().enumerate() {
        let leaf_index = ctx.receipt_leaves[n];
        let entry = &ctx.entries[leaf_index];
        let member = format!("receipts/{n:04}-{}.json", signed.payload.receipt_type);

        let proof = crate::audit::merkle::build_inclusion_in(
            &ctx.req.audit_dir,
            &ctx.req.tenant,
            &ctx.signing_key.verifying_key(),
            leaf_index,
        )
        .with_context(|| format!("building an inclusion proof for leaf {leaf_index}"))?;
        parts.members.push((
            proof_member_for(leaf_index as u64),
            serde_json::to_vec_pretty(&proof).context("serializing an inclusion proof")?,
        ));

        let digest = crate::audit::evidence::audit_entry_digest_hex(entry)
            .with_context(|| format!("digesting audit entry '{}'", entry.event))?;
        parts.push_leaf(
            member.clone(),
            serde_json::to_vec_pretty(signed).context("serializing a receipt member")?,
            LeafCitation {
                index: leaf_index as u64,
                digest: format!("sha256:{digest}"),
                event: entry.event.clone(),
                member,
            },
        );
    }
    Ok(())
}

fn add_cited_members(
    evidence: &ExportedEvidence,
    req: &ArchiveRequest,
    signing_key: &SigningKey,
    parts: &mut ArchiveParts,
) -> Result<()> {
    for cited in &evidence.cited {
        let member = format!("cited/{}.json", cited.leaf_index);
        // A citation gets the same proof a receipt does. Without one it would
        // be bound to nothing a verifier could check independently of the
        // host's signature over the manifest.
        let proof = crate::audit::merkle::build_inclusion_in(
            &req.audit_dir,
            &req.tenant,
            &signing_key.verifying_key(),
            cited.leaf_index as usize,
        )
        .with_context(|| format!("building an inclusion proof for leaf {}", cited.leaf_index))?;
        parts.members.push((
            proof_member_for(cited.leaf_index),
            serde_json::to_vec_pretty(&proof).context("serializing an inclusion proof")?,
        ));
        parts.push_leaf(
            member.clone(),
            serde_json::to_vec_pretty(&CitedJson::from(cited))
                .context("serializing a citation member")?,
            LeafCitation {
                index: cited.leaf_index,
                digest: cited.digest.clone(),
                event: cited.event.clone(),
                member,
            },
        );
    }
    Ok(())
}

/// On-wire form of a citation. Mirrors [`CitedEntry`] rather than reusing it so
/// the archive's wire shape is not hostage to an internal type's field order.
#[derive(serde::Serialize, serde::Deserialize)]
struct CitedJson {
    leaf_index: u64,
    digest: String,
    event: String,
    plan_id: String,
    timestamp: String,
}

impl From<&CitedEntry> for CitedJson {
    fn from(c: &CitedEntry) -> Self {
        Self {
            leaf_index: c.leaf_index,
            digest: c.digest.clone(),
            event: c.event.clone(),
            plan_id: c.plan_id.clone(),
            timestamp: c.timestamp.clone(),
        }
    }
}

/// Copy the raw chain files in, so the archive re-verifies standalone.
fn add_chain_members(
    audit_dir: &Path,
    tenant: &str,
    members: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    let live = crate::audit::emitter::audit_path_for_tenant(audit_dir, tenant);
    if live.exists() {
        members.push((
            format!("audit/{tenant}.jsonl"),
            std::fs::read(&live)
                .with_context(|| format!("reading chain file {}", live.display()))?,
        ));
    }
    // Retired segments, so a root spanning a rotation is reproducible.
    let dir = std::fs::read_dir(audit_dir)
        .with_context(|| format!("listing audit dir {}", audit_dir.display()))?;
    let mut segments: Vec<PathBuf> = dir
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&format!("{tenant}.seg-")) && n.ends_with(".jsonl"))
        })
        .collect();
    segments.sort();
    for seg in segments {
        let name = seg
            .file_name()
            .and_then(|n| n.to_str())
            .context("segment file name is not valid UTF-8")?;
        members.push((
            format!("audit/{name}"),
            std::fs::read(&seg).with_context(|| format!("reading segment {}", seg.display()))?,
        ));
    }
    Ok(())
}

/// Turn every sealed-transcript chain entry into a citation.
fn collect_transcripts(entries: &[PlanAuditEntry], embed: bool) -> Result<Vec<TranscriptCitation>> {
    let mut out = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.event != TRANSCRIPT_SEALED_EVENT {
            continue;
        }
        let label = |k: &str| -> Result<String> {
            entry
                .labels
                .get(k)
                .cloned()
                .with_context(|| format!("sealed-transcript entry is missing label '{k}'"))
        };
        out.push(TranscriptCitation {
            capture_id: label(LABEL_CAPTURE_ID)?,
            vm_name: label(LABEL_VM_NAME)?,
            root: label(LABEL_TRANSCRIPT_ROOT)?,
            chunk_count: label(LABEL_CHUNK_COUNT)?
                .parse()
                .context("sealed-transcript chunk_count is not a number")?,
            // Embedding the ciphertext is a separate step; until it lands, an
            // archive says plainly that the chunks are not here rather than
            // implying they are.
            embedded: false,
            anchored_at_leaf: index as u64,
        });
    }
    if embed && !out.is_empty() {
        bail!(
            "embedding sealed transcript chunks is not implemented; \
             re-run without --with-transcripts to cite their roots instead"
        );
    }
    Ok(out)
}

fn digest_map(members: &[(String, Vec<u8>)]) -> BTreeMap<String, String> {
    members
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            )
        })
        .collect()
}

/// Write the tar: manifest and signature first, then members in sorted order.
fn emit_tar(
    signed: &SignedEvidenceManifest,
    signing_key: &SigningKey,
    mut members: Vec<(String, Vec<u8>)>,
) -> Result<Vec<u8>> {
    for (name, _) in &members {
        ensure_safe_path(name)
            .map_err(|e| anyhow::anyhow!("archive member path {name:?} rejected: {e}"))?;
    }

    let manifest_bytes =
        serde_json::to_vec_pretty(signed).context("serializing the signed manifest")?;

    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut tar = tar::Builder::new(&mut buf);
        // manifest first so a partial-read consumer finds it without scanning.
        append(&mut tar, MANIFEST_MEMBER, &manifest_bytes)?;
        append(&mut tar, SIGNATURE_MEMBER, signed.signature.as_bytes())?;
        append(
            &mut tar,
            HOST_PUBKEY_MEMBER,
            &signing_key.verifying_key().to_bytes(),
        )?;
        append(&mut tar, HOST_DID_MEMBER, signed.signed_by.as_bytes())?;

        members.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (name, bytes) in &members {
            append(&mut tar, name, bytes)?;
        }
        tar.finish().context("finalising the archive tar")?;
    }
    Ok(buf.into_inner())
}

fn append<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, path, Cursor::new(bytes))
        .with_context(|| format!("writing archive member {path:?}"))
}
