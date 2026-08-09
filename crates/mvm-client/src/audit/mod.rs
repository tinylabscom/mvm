//! Verified, normalized local audit events for UI consumers.
//!
//! [`LocalAuditReader`] is the one seam through which a local consumer
//! (mvm-studio, `mvmctl audit verify`) reads mvm's chain-signed audit
//! sources. It discovers the per-tenant lifecycle chains
//! (`<audit_dir>/<tenant>.jsonl`) and the per-VM workload chains
//! (`<audit_dir>/<tenant>.<vm>.workload.jsonl`), verifies each through the
//! canonical verifiers (`mvm_hostd::supervisor::verify_audit_chain_entries`
//! and `mvm_hostd::audit_signer::verify::verify_workload_chain_entries`),
//! and returns normalized [`VerifiedAuditEvent`]s only from sources whose
//! signatures, chain links, and tenant scope all hold. A source that fails
//! any check contributes an explicit typed [`AuditSourceRefusal`] and
//! **zero** events — never a partial prefix, never an unverified line.
//!
//! Reads are bounded and newest-first with a typed cursor; ordering is a
//! pure function of signed entry content and source identity (timestamp,
//! then source rank, then chain position), so pagination is stable across
//! reads without rewriting any chain. All free text is sanitized and
//! capped at this boundary; secret material, environment values, raw
//! payloads, host paths, and terminal control sequences never leave it.
//!
//! The unsigned operator logs — the legacy `<state_dir>/log/audit.jsonl`
//! and the `<audit_dir>/secrets.jsonl` the secret CLI writes — are
//! deliberately not sources: they carry no authenticity and can never be
//! presented as trusted activity, so they yield neither events nor
//! refusals.

mod event;
mod normalize;
mod sanitize;

pub use event::{
    AuditCursor, AuditEventId, AuditEventKind, AuditReadRequest, AuditReadRequestBuilder,
    AuditReadResponse, AuditRefusalKind, AuditSourceId, AuditSourceKind, AuditSourceRefusal,
    DEFAULT_READ_LIMIT, MAX_READ_LIMIT, VerifiedAuditEvent, VerifiedSourceSummary,
};
pub use sanitize::{MAX_DETAIL_LEN, MAX_FIELD_LEN, REDACTED_PATH, sanitize_free_text};

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use event::{OrderKey, parse_ts_millis};
use normalize::{
    normalize_lifecycle_entry, normalize_workload_entry, refusal_from_lifecycle,
    refusal_from_workload, scope_mismatch_refusal,
};

/// Infrastructure failure of a read. Verification failures are **not**
/// errors — they surface as typed refusals in the response.
#[derive(Debug, Error)]
pub enum AuditReadError {
    /// The audit directory could not be enumerated.
    #[error("reading audit directory {dir}: {reason}")]
    Io {
        /// Directory the reader was pointed at.
        dir: PathBuf,
        /// Underlying I/O failure.
        reason: String,
    },
    /// The trusted host verifying key could not be loaded.
    #[error("loading host signer key: {0}")]
    Signer(String),
}

/// Outcome of verifying every discovered source without reading a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceVerification {
    /// Sources that verified clean, in deterministic order (lifecycle
    /// chains first, then workload chains, each sorted by scope).
    pub sources: Vec<VerifiedSourceSummary>,
    /// Sources withheld because verification failed.
    pub refusals: Vec<AuditSourceRefusal>,
}

/// Verified local audit reader: one audit directory, one trusted key.
pub struct LocalAuditReader {
    audit_dir: PathBuf,
    verifying_key: VerifyingKey,
}

impl LocalAuditReader {
    /// Reader over an explicit audit directory and trusted verifying key.
    pub fn new(audit_dir: impl Into<PathBuf>, verifying_key: VerifyingKey) -> Self {
        Self {
            audit_dir: audit_dir.into(),
            verifying_key,
        }
    }

    /// Reader over the host's default audit directory
    /// (`<mvm_home>/audit/`) and the host signer's verifying key.
    pub fn open_default() -> Result<Self, AuditReadError> {
        let dir = mvm_hostd::audit::emitter::default_audit_dir()
            .map_err(|e| AuditReadError::Signer(e.to_string()))?;
        let signer = mvm_hostd::audit::host_keypair::load_or_init()
            .map_err(|e| AuditReadError::Signer(e.to_string()))?;
        Ok(Self::new(dir, signer.verifying))
    }

    /// Verify every discovered source (optionally scoped to one tenant)
    /// and report per-source outcomes without materializing events.
    pub fn verify_sources(
        &self,
        tenant: Option<&str>,
    ) -> Result<SourceVerification, AuditReadError> {
        let collected = self.collect(tenant)?;
        Ok(SourceVerification {
            sources: collected
                .verified
                .iter()
                .map(|(summary, _)| summary.clone())
                .collect(),
            refusals: collected.refusals,
        })
    }

    /// Bounded newest-first read of verified events. See the module docs
    /// for the ordering, identity, and refusal contract.
    pub fn read(&self, request: &AuditReadRequest) -> Result<AuditReadResponse, AuditReadError> {
        let collected = self.collect(request.tenant.as_deref())?;
        let sources: Vec<VerifiedSourceSummary> = collected
            .verified
            .iter()
            .map(|(summary, _)| summary.clone())
            .collect();

        let mut events: Vec<VerifiedAuditEvent> = collected
            .verified
            .into_iter()
            .flat_map(|(_, events)| events)
            .filter(|e| event_matches(request, e))
            .collect();
        // Newest first: descending by the stable ordering key.
        events.sort_by(|a, b| OrderKey::of_event(b).cmp(&OrderKey::of_event(a)));

        if let Some(cursor) = &request.cursor {
            let cursor_key = OrderKey::of_cursor(cursor);
            events.retain(|e| OrderKey::of_event(e) < cursor_key);
        }

        let limit = request.effective_limit();
        let has_more = events.len() > limit;
        events.truncate(limit);
        let next_cursor = if has_more {
            events.last().map(AuditCursor::after)
        } else {
            None
        };

        Ok(AuditReadResponse {
            events,
            sources,
            refusals: collected.refusals,
            next_cursor,
        })
    }

    /// Verify every discovered source, splitting clean sources (with their
    /// normalized events) from typed refusals. A refused source
    /// contributes no events at all.
    fn collect(&self, tenant: Option<&str>) -> Result<Collected, AuditReadError> {
        let mut verified = Vec::new();
        let mut refusals = Vec::new();
        for source_file in discover_sources(&self.audit_dir, tenant)? {
            match self.verify_one(&source_file) {
                Ok((summary, events)) => verified.push((summary, events)),
                Err(refusal) => refusals.push(*refusal),
            }
        }
        Ok(Collected { verified, refusals })
    }

    /// Verify one source end-to-end: chain verification through the
    /// canonical seam, then tenant-scope check, then normalization.
    fn verify_one(
        &self,
        source_file: &SourceFile,
    ) -> Result<(VerifiedSourceSummary, Vec<VerifiedAuditEvent>), Box<AuditSourceRefusal>> {
        let source = &source_file.id;
        let events = match source.kind {
            AuditSourceKind::Lifecycle => {
                let entries = mvm_hostd::supervisor::verify_audit_chain_entries(
                    &source_file.path,
                    &self.verifying_key,
                )
                .map_err(|e| Box::new(refusal_from_lifecycle(source, &e)))?;
                for (i, entry) in entries.iter().enumerate() {
                    if entry.tenant.0 != source.tenant {
                        return Err(Box::new(scope_mismatch_refusal(
                            source,
                            i as u64,
                            &entry.tenant.0,
                        )));
                    }
                }
                entries
                    .iter()
                    .enumerate()
                    .map(|(i, entry)| normalize_lifecycle_entry(source, i as u64, entry))
                    .collect::<Vec<_>>()
            }
            AuditSourceKind::Workload => {
                let entries = mvm_hostd::audit_signer::verify::verify_workload_chain_entries(
                    &source_file.path,
                    &self.verifying_key,
                )
                .map_err(|e| Box::new(refusal_from_workload(source, &e)))?;
                for (i, entry) in entries.iter().enumerate() {
                    if entry.tenant_id != source.tenant {
                        return Err(Box::new(scope_mismatch_refusal(
                            source,
                            i as u64,
                            &entry.tenant_id,
                        )));
                    }
                }
                entries
                    .iter()
                    .enumerate()
                    .map(|(i, entry)| normalize_workload_entry(source, i as u64, entry))
                    .collect::<Vec<_>>()
            }
        };
        let summary = VerifiedSourceSummary {
            source: source.clone(),
            entries: events.len() as u64,
        };
        Ok((summary, events))
    }
}

struct Collected {
    verified: Vec<(VerifiedSourceSummary, Vec<VerifiedAuditEvent>)>,
    refusals: Vec<AuditSourceRefusal>,
}

/// One discovered chain file.
struct SourceFile {
    id: AuditSourceId,
    path: PathBuf,
}

/// The unsigned plain-JSON operator log `mvmctl secret …` writes into the
/// audit directory. It is not a chain and carries no authenticity, so it
/// is never a source — neither events nor a refusal. Shared with the
/// lifecycle-chain rule in `mvm_core::config`: this exclusion used to live only
/// here, so the sweeps that did not have it verified the operator log as if it
/// were a chain and reported the resulting parse error as a broken chain.
use mvm_core::config::SECRETS_OPERATOR_LOG;

/// Enumerate the source identities under `dir` without verifying anything
/// (and without needing a verifying key). Same discovery rules as a read:
/// lifecycle chains first, then workload chains, sorted by scope; the
/// unsigned operator log and non-chain sidecars are never included. A
/// missing directory is an empty host, not an error.
pub fn discover_source_ids(
    dir: &Path,
    tenant: Option<&str>,
) -> Result<Vec<AuditSourceId>, AuditReadError> {
    Ok(discover_sources(dir, tenant)?
        .into_iter()
        .map(|s| s.id)
        .collect())
}

/// Enumerate the audit sources under `dir`, optionally scoped to one
/// tenant, in deterministic order: lifecycle chains first, then workload
/// chains, each sorted by (tenant, machine).
fn discover_sources(dir: &Path, tenant: Option<&str>) -> Result<Vec<SourceFile>, AuditReadError> {
    let names = list_dir_names(dir)?;
    let mut sources: Vec<SourceFile> = match tenant {
        // Tenant-scoped: anchor parsing on the requested tenant, exactly
        // like the chain writers name their files — a tenant name may
        // itself contain dots.
        Some(tenant) => names
            .iter()
            .filter_map(|(name, path)| {
                classify_for_tenant(name, tenant).map(|id| SourceFile {
                    id,
                    path: path.clone(),
                })
            })
            .collect(),
        // Unscoped: lifecycle stems name the tenants; workload files are
        // matched against those known tenants first so dotted tenant
        // names split correctly, falling back to the first dot.
        None => {
            let known_tenants: Vec<String> = names
                .iter()
                .filter_map(|(name, _)| lifecycle_tenant(name))
                .collect();
            names
                .iter()
                .filter_map(|(name, path)| {
                    classify_unscoped(name, &known_tenants).map(|id| SourceFile {
                        id,
                        path: path.clone(),
                    })
                })
                .collect()
        }
    };
    sources.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(sources)
}

/// File names (with paths) in the audit directory. Missing dir ⇒ empty.
fn list_dir_names(dir: &Path) -> Result<Vec<(String, PathBuf)>, AuditReadError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(AuditReadError::Io {
                dir: dir.to_path_buf(),
                reason: e.to_string(),
            });
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| AuditReadError::Io {
            dir: dir.to_path_buf(),
            reason: e.to_string(),
        })?;
        if let Some(name) = entry.file_name().to_str() {
            names.push((name.to_string(), entry.path()));
        }
    }
    Ok(names)
}

/// Tenant named by a lifecycle chain file (`<tenant>.jsonl`), excluding
/// the unsigned operator log and workload chains.
fn lifecycle_tenant(name: &str) -> Option<String> {
    if name == SECRETS_OPERATOR_LOG || name.ends_with(mvm_core::config::WORKLOAD_AUDIT_SUFFIX) {
        return None;
    }
    let tenant = name.strip_suffix(".jsonl")?;
    if tenant.is_empty() {
        return None;
    }
    Some(tenant.to_string())
}

/// Tenant-anchored classification: is `name` one of `tenant`'s chains?
/// Uses the same naming helper the chain writers use, so a tenant name
/// containing dots parses identically on both sides.
fn classify_for_tenant(name: &str, tenant: &str) -> Option<AuditSourceId> {
    if name == SECRETS_OPERATOR_LOG {
        return None;
    }
    if let Some(vm) = mvm_core::config::workload_audit_vm_name(name, tenant) {
        return Some(AuditSourceId {
            kind: AuditSourceKind::Workload,
            tenant: tenant.to_string(),
            machine: Some(vm.to_string()),
        });
    }
    if lifecycle_tenant(name).is_some_and(|t| t == tenant) {
        return Some(AuditSourceId {
            kind: AuditSourceKind::Lifecycle,
            tenant: tenant.to_string(),
            machine: None,
        });
    }
    None
}

/// Unscoped classification of one file name. Workload stems are matched
/// against the known lifecycle tenants (longest match wins) before the
/// first-dot fallback, so `<a.b>.<vm>.workload.jsonl` splits correctly
/// whenever tenant `a.b` has a lifecycle chain alongside.
fn classify_unscoped(name: &str, known_tenants: &[String]) -> Option<AuditSourceId> {
    if name == SECRETS_OPERATOR_LOG {
        return None;
    }
    if let Some(stem) = name.strip_suffix(mvm_core::config::WORKLOAD_AUDIT_SUFFIX) {
        let (tenant, vm) = split_workload_stem(stem, known_tenants)?;
        return Some(AuditSourceId {
            kind: AuditSourceKind::Workload,
            tenant,
            machine: Some(vm),
        });
    }
    lifecycle_tenant(name).map(|tenant| AuditSourceId {
        kind: AuditSourceKind::Lifecycle,
        tenant,
        machine: None,
    })
}

/// Split a workload-chain stem (`<tenant>.<vm>`) into its parts: longest
/// known-tenant prefix first, then the first-dot fallback.
fn split_workload_stem(stem: &str, known_tenants: &[String]) -> Option<(String, String)> {
    let known = known_tenants
        .iter()
        .filter_map(|t| {
            stem.strip_prefix(t.as_str())
                .and_then(|rest| rest.strip_prefix('.'))
                .filter(|vm| !vm.is_empty())
                .map(|vm| (t.clone(), vm.to_string()))
        })
        .max_by_key(|(t, _)| t.len());
    if known.is_some() {
        return known;
    }
    let (tenant, vm) = stem.split_once('.')?;
    if tenant.is_empty() || vm.is_empty() {
        return None;
    }
    Some((tenant.to_string(), vm.to_string()))
}

/// Apply the request's machine, kind, and time-window filters.
fn event_matches(request: &AuditReadRequest, event: &VerifiedAuditEvent) -> bool {
    if let Some(machine) = &request.machine
        && event.machine.as_deref() != Some(machine.as_str())
    {
        return false;
    }
    if !request.kinds.is_empty() && !request.kinds.contains(&event.kind) {
        return false;
    }
    if request.since.is_some() || request.until.is_some() {
        let ts = parse_ts_millis(&event.timestamp);
        if let Some(since) = request.since
            && ts < instant_millis(since)
        {
            return false;
        }
        if let Some(until) = request.until
            && ts > instant_millis(until)
        {
            return false;
        }
    }
    true
}

fn instant_millis(instant: DateTime<Utc>) -> i64 {
    instant.timestamp_millis()
}

#[cfg(test)]
mod tests;
