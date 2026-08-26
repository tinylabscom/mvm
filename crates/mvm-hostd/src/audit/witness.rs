//! Off-host witnessing for published audit roots.
//!
//! # Why this exists
//!
//! [`crate::audit::merkle::verify_root_history`] proves the log only grew
//! between the roots it can see. Every one of those roots was signed by the
//! host that produced the log and stored beside it, so against that host the
//! proof is worth nothing: a host that rewrites the log reissues the whole
//! history and every local check still passes.
//!
//! A witness is somewhere the host cannot rewrite. Once a root has reached
//! one, a later rewrite is detectable by comparing what the host now claims
//! against what the witness recorded.
//!
//! # What this buys, stated exactly
//!
//! It converts "detects nothing against a malicious host" into "detects a
//! host that rewrites the log **after** a root reached the sink". That is
//! narrower than it sounds and the difference matters:
//!
//! - Everything before the first successful witness is unprotected. A host
//!   compromised from the start witnesses whatever it likes.
//! - The detection window is the publishing interval. Entries appended and
//!   removed between two witnessed roots leave no trace in either.
//! - Detection still needs someone to **compare**. Shipping roots to a sink
//!   nobody reads records evidence; it does not check anything.
//! - Tail truncation past the newest witnessed root stays undetectable.
//!
//! This is a real improvement and not tamper-proofing. Do not describe it as
//! the latter.
//!
//! # Delivery
//!
//! Sending is fail-open: a workload does not die because a witness was
//! unreachable, matching the posture `publish_root` already takes. Fail-open
//! needs a retry path, and the retry queue here is the root history itself
//! plus a per-sink high-water mark. A separate queue file could diverge from
//! the history it mirrors; a mark into the history cannot, and it recovers
//! from an arbitrary outage by replaying whatever sits above it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_contract::merkle::SignedAuditRoot;

/// Somewhere a published root is recorded that the producing host does not
/// control.
///
/// A trait rather than a `match` because the two shapes differ in more than a
/// branch: one appends to a path, the other opens a TLS connection and can
/// fail in ways a file cannot.
pub trait WitnessSink {
    /// How this sink appears in logs. Short and stable — operators grep it.
    fn name(&self) -> String;

    /// Record `roots`, oldest first. Must be all-or-nothing from the caller's
    /// point of view: a partial success that reported `Ok` would advance the
    /// high-water mark past roots that never arrived.
    fn witness(&self, roots: &[SignedAuditRoot]) -> Result<()>;
}

/// Append roots to a path the operator chooses.
///
/// Only a witness if that path is somewhere the host cannot rewrite —
/// separate media, a mount the host has no write access to after the fact, or
/// another machine's filesystem. Pointed at the same disk it is an audit
/// convenience and nothing more, and this type cannot tell the difference.
#[derive(Debug, Clone)]
pub struct FileWitnessSink {
    path: PathBuf,
}

impl FileWitnessSink {
    /// Witness to `path`, creating it on first write.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl WitnessSink for FileWitnessSink {
    fn name(&self) -> String {
        format!("file:{}", self.path.display())
    }

    fn witness(&self, roots: &[SignedAuditRoot]) -> Result<()> {
        use std::io::Write as _;

        if roots.is_empty() {
            return Ok(());
        }
        // One buffer, one write, one sync. A per-root write could leave some
        // roots on disk after an error, and the caller would then be told the
        // batch failed while part of it had landed.
        let mut buf = Vec::new();
        for root in roots {
            serde_json::to_writer(&mut buf, root)?;
            buf.push(b'\n');
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating witness directory {}", parent.display()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening witness file {}", self.path.display()))?;
        file.write_all(&buf)
            .with_context(|| format!("writing to witness file {}", self.path.display()))?;
        file.sync_data()
            .with_context(|| format!("syncing witness file {}", self.path.display()))?;
        Ok(())
    }
}

/// POST roots to a URL.
///
/// The genuinely off-host shape. Uses the workspace's minimal HTTP client
/// rather than adding a second one; it has no redirect following, which is
/// what we want here — a witness that can be redirected is a witness whose
/// location the network decides.
#[derive(Debug, Clone)]
pub struct HttpWitnessSink {
    url: String,
}

impl HttpWitnessSink {
    /// Witness by POSTing newline-delimited JSON to `url`.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

impl WitnessSink for HttpWitnessSink {
    fn name(&self) -> String {
        format!("http:{}", self.url)
    }

    fn witness(&self, roots: &[SignedAuditRoot]) -> Result<()> {
        if roots.is_empty() {
            return Ok(());
        }
        let mut body = Vec::new();
        for root in roots {
            serde_json::to_writer(&mut body, root)?;
            body.push(b'\n');
        }
        let response = mvm_http::blocking::Client::new()
            .post(&self.url)
            .body(body)
            .send()
            .with_context(|| format!("posting audit roots to {}", self.url))?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "witness at {} rejected the roots with status {}",
                self.url,
                status.as_u16()
            );
        }
        Ok(())
    }
}

/// Path of the per-sink high-water mark: the tree size of the newest root
/// this sink has acknowledged for this tenant.
fn mark_path(audit_dir: &Path, tenant: &str, sink: &dyn WitnessSink) -> PathBuf {
    // The sink name can contain a URL or an absolute path, neither of which
    // is a filename. Address the mark by a digest of the name so two sinks
    // never share one and no name can escape the directory.
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(sink.name().as_bytes()));
    audit_dir.join(format!("{tenant}.witness-{}.mark", &digest[..16]))
}

fn read_mark(path: &Path) -> u64 {
    // An unreadable or malformed mark is treated as "nothing witnessed yet".
    // Re-sending a root a sink already has is harmless; skipping one it never
    // got is the failure worth avoiding.
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Send every root this sink has not yet acknowledged, oldest first, and
/// advance its mark only on success.
///
/// Returns how many roots were delivered. Zero is the common case — nothing
/// new since the last flush — and is not an error.
pub fn flush_to_sink(audit_dir: &Path, tenant: &str, sink: &dyn WitnessSink) -> Result<usize> {
    let history = crate::audit::emitter::audit_root_history_path_for_tenant(audit_dir, tenant);
    let Ok(content) = std::fs::read_to_string(&history) else {
        return Ok(0);
    };
    let mark = mark_path(audit_dir, tenant, sink);
    let watermark = read_mark(&mark);

    let mut pending: Vec<SignedAuditRoot> = Vec::new();
    for line in content.lines().filter(|l| !l.is_empty()) {
        let root: SignedAuditRoot = serde_json::from_str(line)
            .with_context(|| format!("decoding a root from {}", history.display()))?;
        if root.tree_size > watermark {
            pending.push(root);
        }
    }
    if pending.is_empty() {
        return Ok(0);
    }

    sink.witness(&pending)
        .with_context(|| format!("witnessing {} root(s) to {}", pending.len(), sink.name()))?;

    // Only after the sink accepted them. A mark advanced first would silently
    // drop the batch on the next flush if the send had actually failed.
    let newest = pending
        .iter()
        .map(|r| r.tree_size)
        .max()
        .unwrap_or(watermark);
    std::fs::write(&mark, newest.to_string())
        .with_context(|| format!("recording the witness mark at {}", mark.display()))?;
    Ok(pending.len())
}

/// Resolve the configured sink, if any.
///
/// `MVM_AUDIT_WITNESS` selects it: a `http://` or `https://` value is an HTTP
/// sink, anything else is a filesystem path. Unset means no witnessing, which
/// is the default: a witness the operator did not choose would be a network
/// call they did not ask for.
pub fn configured_sink() -> Option<Box<dyn WitnessSink>> {
    let raw = std::env::var("MVM_AUDIT_WITNESS").ok()?;
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if value.starts_with("http://") || value.starts_with("https://") {
        Some(Box::new(HttpWitnessSink::new(value)))
    } else {
        Some(Box::new(FileWitnessSink::new(value)))
    }
}

/// Flush to the configured sink, reporting failure as a warning.
///
/// Fail-open: the caller is on a boot or teardown path and a workload must not
/// die because a witness was unreachable. The unsent roots stay above the mark
/// and go out on the next flush, so an outage costs delay rather than
/// evidence.
pub fn flush_configured(audit_dir: &Path, tenant: &str) {
    let Some(sink) = configured_sink() else {
        return;
    };
    match flush_to_sink(audit_dir, tenant, sink.as_ref()) {
        Ok(0) => {}
        Ok(n) => tracing::debug!(tenant, sink = %sink.name(), roots = n, "witnessed audit roots"),
        Err(e) => tracing::warn!(
            error = %format!("{e:#}"),
            tenant,
            sink = %sink.name(),
            "could not witness audit roots off-host; they stay queued and will be retried, but \
             until one lands a log rewrite by this host is undetectable"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A sink that records what it was handed and can be told to fail, so the
    /// retry path is exercised against a real refusal rather than a mock that
    /// always says yes.
    #[derive(Default)]
    struct RecordingSink {
        accepted: Mutex<Vec<u64>>,
        fail: Mutex<bool>,
    }

    impl WitnessSink for RecordingSink {
        fn name(&self) -> String {
            "test:recording".to_string()
        }
        fn witness(&self, roots: &[SignedAuditRoot]) -> Result<()> {
            if *self.fail.lock().unwrap() {
                anyhow::bail!("sink is unreachable");
            }
            self.accepted
                .lock()
                .unwrap()
                .extend(roots.iter().map(|r| r.tree_size));
            Ok(())
        }
    }

    fn root(tree_size: u64) -> SignedAuditRoot {
        SignedAuditRoot {
            tenant: "local".to_string(),
            tree_size,
            root_hash: "ab".repeat(32),
            timestamp: "2026-08-25T00:00:00Z".to_string(),
            signature: "c2ln".to_string(),
            signer_pubkey: "cd".repeat(32),
        }
    }

    fn seed_history(dir: &Path, sizes: &[u64]) {
        let path = crate::audit::emitter::audit_root_history_path_for_tenant(dir, "local");
        let mut out = String::new();
        for size in sizes {
            out.push_str(&serde_json::to_string(&root(*size)).unwrap());
            out.push('\n');
        }
        std::fs::write(path, out).unwrap();
    }

    #[test]
    fn only_roots_above_the_mark_are_sent_and_a_second_flush_sends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        seed_history(dir.path(), &[3, 7, 11]);
        let sink = RecordingSink::default();

        assert_eq!(flush_to_sink(dir.path(), "local", &sink).unwrap(), 3);
        assert_eq!(*sink.accepted.lock().unwrap(), vec![3, 7, 11]);

        // Nothing new: a flush must not re-send what the sink already has.
        assert_eq!(flush_to_sink(dir.path(), "local", &sink).unwrap(), 0);
        assert_eq!(sink.accepted.lock().unwrap().len(), 3);

        // A newly published root goes out alone.
        seed_history(dir.path(), &[3, 7, 11, 15]);
        assert_eq!(flush_to_sink(dir.path(), "local", &sink).unwrap(), 1);
        assert_eq!(*sink.accepted.lock().unwrap(), vec![3, 7, 11, 15]);
    }

    #[test]
    fn a_refused_batch_leaves_the_mark_alone_and_is_retried_whole() {
        // Fail-open is only safe if the unsent roots survive the outage. A
        // mark advanced before the sink accepted would drop them silently.
        let dir = tempfile::tempdir().unwrap();
        seed_history(dir.path(), &[4, 9]);
        let sink = RecordingSink::default();
        *sink.fail.lock().unwrap() = true;

        assert!(flush_to_sink(dir.path(), "local", &sink).is_err());
        assert!(sink.accepted.lock().unwrap().is_empty());

        *sink.fail.lock().unwrap() = false;
        assert_eq!(
            flush_to_sink(dir.path(), "local", &sink).unwrap(),
            2,
            "the whole queued batch is retried, not just the newest"
        );
        assert_eq!(*sink.accepted.lock().unwrap(), vec![4, 9]);
    }

    #[test]
    fn an_outage_spanning_several_publishes_replays_all_of_them() {
        let dir = tempfile::tempdir().unwrap();
        let sink = RecordingSink::default();
        *sink.fail.lock().unwrap() = true;
        for sizes in [&[1u64][..], &[1, 2][..], &[1, 2, 3][..]] {
            seed_history(dir.path(), sizes);
            let _ = flush_to_sink(dir.path(), "local", &sink);
        }
        *sink.fail.lock().unwrap() = false;
        assert_eq!(flush_to_sink(dir.path(), "local", &sink).unwrap(), 3);
        assert_eq!(*sink.accepted.lock().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn no_history_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let sink = RecordingSink::default();
        assert_eq!(flush_to_sink(dir.path(), "local", &sink).unwrap(), 0);
    }

    #[test]
    fn two_sinks_keep_independent_marks() {
        // A shared mark would let one sink's success suppress delivery to the
        // other, which is the failure mode that makes a second witness
        // pointless.
        let dir = tempfile::tempdir().unwrap();
        seed_history(dir.path(), &[5]);
        let a = FileWitnessSink::new(dir.path().join("a.jsonl"));
        let b = FileWitnessSink::new(dir.path().join("b.jsonl"));

        assert_eq!(flush_to_sink(dir.path(), "local", &a).unwrap(), 1);
        assert_eq!(
            flush_to_sink(dir.path(), "local", &b).unwrap(),
            1,
            "the second sink must still receive the root"
        );
        for name in ["a.jsonl", "b.jsonl"] {
            let content = std::fs::read_to_string(dir.path().join(name)).unwrap();
            assert_eq!(content.lines().filter(|l| !l.is_empty()).count(), 1);
        }
    }

    #[test]
    fn the_file_sink_appends_rather_than_replacing() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("witness.jsonl");
        let sink = FileWitnessSink::new(&out);
        sink.witness(&[root(1)]).unwrap();
        sink.witness(&[root(2), root(3)]).unwrap();
        let content = std::fs::read_to_string(&out).unwrap();
        assert_eq!(content.lines().filter(|l| !l.is_empty()).count(), 3);
    }
}
