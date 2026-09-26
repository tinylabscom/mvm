//! Watch one machine's egress refusals while its output is on screen.
//!
//! The source is the tenant's chain-signed audit log — the record the per-VM
//! network endpoint already writes for every refusal, read the way `trust
//! audit tail --chain -f` reads it. Nothing new is added to the egress path:
//! the endpoint decides and records exactly as before, and this only reads
//! what it recorded.
//!
//! The watch starts from the chain's current end before the machine boots, so
//! everything the endpoint records for the machine is seen and nothing from an
//! earlier run with the same name is.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::super::audit_follow::{ChainFollower, ChainLine, parse_chain_line};
use super::super::host_notices::NoticeSink;
use super::denial::EgressDenial;
use super::tally::DenialTally;

/// How often the chain is polled. Short enough that a refusal is on screen
/// before the workload has finished printing its own error about it.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Whether each distinct refusal is printed as it happens, or only counted
/// for the exit summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum Live {
    /// A notice per distinct refusal, as it is recorded.
    Notices,
    /// Count only. For a raw-mode terminal, where a stray line would corrupt
    /// the session, and for machine-readable output.
    Quiet,
}

struct Shared {
    tally: Mutex<DenialTally>,
    stop: AtomicBool,
}

/// A running watch. [`Self::finish`] stops it and hands back what it saw.
pub(in crate::commands) struct DenialWatch {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

/// What a watch reads and where its notices go.
pub(in crate::commands) struct WatchTarget {
    /// The tenant's live chain file.
    pub chain: PathBuf,
    /// The machine whose refusals count.
    pub vm_name: String,
    pub live: Live,
    pub sink: Arc<dyn NoticeSink>,
}

impl DenialWatch {
    /// Start watching from the chain's current end.
    pub(in crate::commands) fn start(target: WatchTarget) -> Self {
        let shared = Arc::new(Shared {
            tally: Mutex::new(DenialTally::default()),
            stop: AtomicBool::new(false),
        });
        // Positioned here, on the caller's thread, so the starting offset is
        // fixed before the caller boots anything that could write.
        let follower = ChainFollower::from_end(target.chain.clone());
        let thread = std::thread::Builder::new()
            .name("egress-denials".into())
            .spawn({
                let shared = Arc::clone(&shared);
                move || run(follower, &target, &shared)
            })
            .ok();
        Self { shared, thread }
    }

    /// Stop, read whatever was recorded up to now, and return the tally.
    pub(in crate::commands) fn finish(mut self) -> DenialTally {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.shared
            .tally
            .lock()
            .map(|tally| tally.clone())
            .unwrap_or_default()
    }
}

impl Drop for DenialWatch {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

fn run(mut follower: ChainFollower, target: &WatchTarget, shared: &Shared) {
    loop {
        // Read the flag before polling, so the poll after a stop request is
        // the last one and still sees everything written before it.
        let stopping = shared.stop.load(Ordering::SeqCst);
        for line in follower.poll() {
            let ChainLine::Entry(entry) = parse_chain_line(&line) else {
                continue;
            };
            let Some(denial) = EgressDenial::from_entry(&entry, &target.vm_name) else {
                continue;
            };
            let notice = denial.notice();
            let first = shared
                .tally
                .lock()
                .map(|mut tally| tally.observe(denial))
                .unwrap_or(false);
            if first && target.live == Live::Notices {
                target.sink.line(&notice);
            }
        }
        if stopping {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Print a finished watch's exit summary as one block, if anything was
/// refused.
pub(in crate::commands) fn print_summary(tally: &DenialTally, sink: &dyn NoticeSink) {
    let lines = tally.summary_lines();
    if !lines.is_empty() {
        sink.block(&lines);
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::host_notices::Captured;
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_hostd::supervisor::audit_recorder::{EventCategory, Recorder};

    /// Write real chain-signed entries through the recorder the endpoint
    /// uses, as the endpoint would for machine `vm`.
    fn endpoint_recorder(dir: &std::path::Path, vm: &str) -> Recorder {
        let signer = mvm_hostd::supervisor::audit_file::FileAuditSigner::open(
            SigningKey::from_bytes(&[9; 32]),
            dir.to_path_buf(),
        )
        .unwrap();
        Recorder::new(Arc::new(signer), mvm_core::plan::TenantId("local".into())).with_vm_name(vm)
    }

    fn deny(recorder: &Recorder, target: &str, reason: &str) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(recorder.record_unbound(
                EventCategory::Host,
                "host.flow.denied",
                [
                    ("class".to_string(), "tcp".to_string()),
                    ("target".to_string(), target.to_string()),
                    ("reason".to_string(), reason.to_string()),
                ],
            ))
            .unwrap();
    }

    fn wait_for(sink: &Captured, n: usize) {
        for _ in 0..100 {
            if sink.lines().len() >= n {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The whole path over a real signed chain: two machines share it, one is
    /// watched, it retries a refused destination, and it reaches metadata —
    /// recorded here under the generic label, which must still never earn an
    /// allow. Its own refusals print once each, live; the other machine's never do;
    /// the tally counts every attempt; and nothing from before the watch
    /// started is counted.
    #[test]
    fn a_watch_prints_each_distinct_refusal_of_its_machine_once_and_counts_all() {
        let dir = tempfile::tempdir().unwrap();
        let watched = endpoint_recorder(dir.path(), "vm-a");
        let other = endpoint_recorder(dir.path(), "vm-b");
        deny(&watched, "stale.example:443", "policy_denied");

        let sink = Arc::new(Captured::default());
        let watch = DenialWatch::start(WatchTarget {
            chain: dir.path().join("local.jsonl"),
            vm_name: "vm-a".into(),
            live: Live::Notices,
            sink: Arc::clone(&sink) as Arc<dyn NoticeSink>,
        });
        deny(&watched, "api.example.com:443", "policy_denied");
        deny(&other, "other.example:443", "policy_denied");
        deny(&watched, "api.example.com:443", "policy_denied");
        deny(&watched, "169.254.169.254:80", "policy_denied");
        wait_for(&sink, 2);
        let tally = watch.finish();

        assert_eq!(
            sink.lines(),
            [
                "egress blocked: api.example.com:443 (not in the allow-list) — allow with \
                 --allow-host api.example.com:443",
                "egress blocked: 169.254.169.254:80 (a cloud instance-metadata endpoint) — never \
                 reachable from a workload; no grant admits it",
            ]
        );
        let rows = tally.destinations();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].count, 2);
        assert!(rows.iter().all(|row| !row.destination.contains("stale")));
        assert!(rows.iter().all(|row| !row.destination.contains("other")));
    }

    #[test]
    fn a_quiet_watch_counts_without_printing() {
        let dir = tempfile::tempdir().unwrap();
        let watched = endpoint_recorder(dir.path(), "vm-a");
        let sink = Arc::new(Captured::default());
        let watch = DenialWatch::start(WatchTarget {
            chain: dir.path().join("local.jsonl"),
            vm_name: "vm-a".into(),
            live: Live::Quiet,
            sink: Arc::clone(&sink) as Arc<dyn NoticeSink>,
        });
        deny(&watched, "api.example.com:443", "policy_denied");
        let tally = watch.finish();
        assert!(sink.lines().is_empty());
        assert_eq!(tally.destinations().len(), 1);
    }

    /// Entries recorded after the machine exits but before the watch is
    /// finished still count: the last poll runs after the stop request.
    #[test]
    fn finishing_reads_what_was_recorded_just_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let watched = endpoint_recorder(dir.path(), "vm-a");
        let watch = DenialWatch::start(WatchTarget {
            chain: dir.path().join("local.jsonl"),
            vm_name: "vm-a".into(),
            live: Live::Quiet,
            sink: Arc::new(Captured::default()),
        });
        deny(&watched, "late.example:443", "policy_denied");
        let tally = watch.finish();
        assert_eq!(tally.destinations()[0].destination, "late.example:443");
    }
}
