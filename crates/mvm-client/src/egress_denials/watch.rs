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

use super::denial::EgressDenial;
use super::tally::DenialTally;
use crate::audit::follow::{ChainFollower, ChainLine, parse_chain_line};
use crate::notices::NoticeSink;
use mvm_hostd::file_wait::{self, FileWait};

/// Whether each distinct refusal is printed as it happens, or only counted
/// for the exit summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Live {
    /// A notice per distinct refusal, as it is recorded.
    Notices,
    /// Count only. For a raw-mode terminal, where a stray line would corrupt
    /// the session, and for machine-readable output.
    Quiet,
}

struct Shared {
    tally: Mutex<DenialTally>,
    stop: AtomicBool,
    /// What the thread blocks on between reads of the chain: a change to the
    /// file where the host can report one, so an idle machine's watch costs
    /// no wakeup, and a stop either way.
    waiter: Box<dyn FileWait>,
}

impl Shared {
    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.waiter.interrupt();
    }
}

/// A running watch. [`Self::finish`] stops it and hands back what it saw.
pub struct DenialWatch {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

/// What a watch reads and where its notices go.
pub struct WatchTarget {
    /// The tenant's live chain file.
    pub chain: PathBuf,
    /// The machine whose refusals count.
    pub vm_name: String,
    pub live: Live,
    pub sink: Arc<dyn NoticeSink>,
}

impl DenialWatch {
    /// Start watching from the chain's current end.
    pub fn start(target: WatchTarget) -> Self {
        let shared = Arc::new(Shared {
            tally: Mutex::new(DenialTally::default()),
            stop: AtomicBool::new(false),
            waiter: file_wait::for_file(),
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
    pub fn finish(mut self) -> DenialTally {
        self.shared.stop();
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
        self.shared.stop();
    }
}

fn run(mut follower: ChainFollower, target: &WatchTarget, shared: &Shared) {
    loop {
        // Armed before the read, so an entry recorded between the read and the
        // wait ends the wait instead of sitting unseen until the next one.
        shared.waiter.arm(&target.chain);
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
        shared.waiter.wait();
    }
}

/// Print a finished watch's exit summary as one block, if anything was
/// refused.
pub fn print_summary(tally: &DenialTally, sink: &dyn NoticeSink) {
    let lines = tally.summary_lines();
    if !lines.is_empty() {
        sink.block(&lines);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A sink that keeps what it was given.
    #[derive(Default)]
    struct Captured(Mutex<Vec<String>>);

    impl NoticeSink for Captured {
        fn block(&self, lines: &[String]) {
            self.0.lock().unwrap().extend_from_slice(lines);
        }
    }

    impl Captured {
        fn lines(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }
    use ed25519_dalek::SigningKey;
    use mvm_hostd::supervisor::audit::audit_recorder::{EventCategory, Recorder};

    struct WatchFixture {
        watch: Option<DenialWatch>,
        dir: tempfile::TempDir,
        // Restore the environment only after the watch has joined and its directory is gone.
        _env: mvm_core::util::test_env::TestEnv,
    }

    impl WatchFixture {
        fn new() -> Self {
            let env = mvm_core::util::test_env::TestEnv::new();
            Self {
                watch: None,
                dir: tempfile::tempdir().unwrap(),
                _env: env,
            }
        }

        /// Callers keep recorders in later locals so they drop before this fixture.
        fn endpoint_recorder(&self, vm: &str) -> Recorder {
            let signer = mvm_hostd::supervisor::audit::audit_file::FileAuditSigner::open(
                SigningKey::from_bytes(&[9; 32]),
                self.dir.path().to_path_buf(),
            )
            .unwrap();
            Recorder::new(Arc::new(signer), mvm_core::plan::TenantId("local".into()))
                .with_vm_name(vm)
        }

        fn finish(&mut self) -> DenialTally {
            self.watch.take().expect("fixture watch started").finish()
        }
    }

    impl Drop for WatchFixture {
        fn drop(&mut self) {
            // DenialWatch::drop only signals stop; join even when a test unwinds.
            if let Some(watch) = self.watch.take() {
                watch.finish();
            }
        }
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
        for _ in 0..500 {
            if sink.lines().len() >= n {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn start_noticing(fixture: &mut WatchFixture, sink: &Arc<Captured>) {
        fixture.watch = Some(DenialWatch::start(WatchTarget {
            chain: fixture.dir.path().join("local.jsonl"),
            vm_name: "vm-a".into(),
            live: Live::Notices,
            sink: Arc::clone(sink) as Arc<dyn NoticeSink>,
        }));
    }

    /// A refusal recorded while the watch is idle is printed without a stop
    /// to flush it, and a stop does not wait for the chain to change — an idle
    /// machine's never will. The bound is loose for a loaded host; a stop that
    /// waited on the file would never return.
    #[test]
    fn an_idle_watch_reports_a_late_refusal_and_stops_at_once() {
        let mut fixture = WatchFixture::new();
        let watched = fixture.endpoint_recorder("vm-a");
        let sink = Arc::new(Captured::default());
        start_noticing(&mut fixture, &sink);
        std::thread::sleep(Duration::from_millis(500));

        deny(&watched, "late.example:443", "policy_denied");
        wait_for(&sink, 1);
        assert_eq!(sink.lines().len(), 1, "reported while still running");

        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        let tally = fixture.finish();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "finish took {:?}",
            started.elapsed()
        );
        assert_eq!(tally.destinations().len(), 1);
    }

    /// The live chain is sealed and renamed away, and a fresh file takes its
    /// place: refusals recorded in the replacement are still reported.
    #[test]
    fn a_watch_follows_the_chain_across_a_rotation() {
        let mut fixture = WatchFixture::new();
        let watched = fixture.endpoint_recorder("vm-a");
        let sink = Arc::new(Captured::default());
        deny(&watched, "stale.example:443", "policy_denied");
        start_noticing(&mut fixture, &sink);
        std::thread::sleep(Duration::from_millis(300));

        let live = fixture.dir.path().join("local.jsonl");
        let entry = std::fs::read_to_string(&live).unwrap();
        std::fs::rename(&live, fixture.dir.path().join("local.seg-000001.jsonl")).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(&live, entry.replace("stale.example", "fresh.example")).unwrap();
        wait_for(&sink, 1);
        fixture.finish();

        assert_eq!(sink.lines().len(), 1);
        assert!(sink.lines()[0].contains("fresh.example:443"));
    }

    /// A sink that also records which thread called it: the watch's own.
    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct OnWatchThread {
        lines: Captured,
        task: Mutex<Option<PathBuf>>,
    }

    #[cfg(target_os = "linux")]
    impl NoticeSink for OnWatchThread {
        fn block(&self, lines: &[String]) {
            *self.task.lock().unwrap() = std::fs::read_link("/proc/thread-self").ok();
            self.lines.block(lines);
        }
    }

    /// The kernel's count of the times a thread gave up the CPU to wait.
    #[cfg(target_os = "linux")]
    fn voluntary_switches(task: &std::path::Path) -> u64 {
        std::fs::read_to_string(std::path::Path::new("/proc").join(task).join("status"))
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    /// What an idle unit's wakeup budget rests on: once caught up, the watch
    /// thread does not wake while nothing is recorded. Counted by the kernel
    /// on the thread itself; a 200 ms re-check would wake ten times here.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_idle_watch_thread_does_not_wake() {
        let mut fixture = WatchFixture::new();
        let watched = fixture.endpoint_recorder("vm-a");
        let sink = Arc::new(OnWatchThread::default());
        fixture.watch = Some(DenialWatch::start(WatchTarget {
            chain: fixture.dir.path().join("local.jsonl"),
            vm_name: "vm-a".into(),
            live: Live::Notices,
            sink: Arc::clone(&sink) as Arc<dyn NoticeSink>,
        }));
        deny(&watched, "first.example:443", "policy_denied");
        wait_for(&sink.lines, 1);
        let task = sink.task.lock().unwrap().clone().expect("watch thread");
        // Let the events of that write finish arriving.
        std::thread::sleep(Duration::from_millis(300));

        let settled = voluntary_switches(&task);
        std::thread::sleep(Duration::from_secs(2));
        let woken = voluntary_switches(&task) - settled;
        eprintln!("idle egress-denials thread: {woken} wakeups in 2 s");
        assert!(woken <= 1, "{woken} wakeups in 2 s with nothing recorded");

        deny(&watched, "second.example:443", "policy_denied");
        wait_for(&sink.lines, 2);
        assert_eq!(sink.lines.lines().len(), 2);
        fixture.finish();
    }

    /// The whole path over a real signed chain: two machines share it, one is
    /// watched, it retries a refused destination, and it reaches metadata —
    /// recorded here under the generic label, which must still never earn an
    /// allow. Its own refusals print once each, live; the other machine's never do;
    /// the tally counts every attempt; and nothing from before the watch
    /// started is counted.
    #[test]
    fn a_watch_prints_each_distinct_refusal_of_its_machine_once_and_counts_all() {
        let mut fixture = WatchFixture::new();
        let watched = fixture.endpoint_recorder("vm-a");
        let other = fixture.endpoint_recorder("vm-b");
        deny(&watched, "stale.example:443", "policy_denied");

        let sink = Arc::new(Captured::default());
        fixture.watch = Some(DenialWatch::start(WatchTarget {
            chain: fixture.dir.path().join("local.jsonl"),
            vm_name: "vm-a".into(),
            live: Live::Notices,
            sink: Arc::clone(&sink) as Arc<dyn NoticeSink>,
        }));
        deny(&watched, "api.example.com:443", "policy_denied");
        deny(&other, "other.example:443", "policy_denied");
        deny(&watched, "api.example.com:443", "policy_denied");
        deny(&watched, "169.254.169.254:80", "policy_denied");
        wait_for(&sink, 2);
        let tally = fixture.finish();

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
        let mut fixture = WatchFixture::new();
        let watched = fixture.endpoint_recorder("vm-a");
        let sink = Arc::new(Captured::default());
        fixture.watch = Some(DenialWatch::start(WatchTarget {
            chain: fixture.dir.path().join("local.jsonl"),
            vm_name: "vm-a".into(),
            live: Live::Quiet,
            sink: Arc::clone(&sink) as Arc<dyn NoticeSink>,
        }));
        deny(&watched, "api.example.com:443", "policy_denied");
        let tally = fixture.finish();
        assert!(sink.lines().is_empty());
        assert_eq!(tally.destinations().len(), 1);
    }

    /// Entries recorded after the machine exits but before the watch is
    /// finished still count: the last poll runs after the stop request.
    #[test]
    fn finishing_reads_what_was_recorded_just_before_it() {
        let mut fixture = WatchFixture::new();
        let watched = fixture.endpoint_recorder("vm-a");
        fixture.watch = Some(DenialWatch::start(WatchTarget {
            chain: fixture.dir.path().join("local.jsonl"),
            vm_name: "vm-a".into(),
            live: Live::Quiet,
            sink: Arc::new(Captured::default()),
        }));
        deny(&watched, "late.example:443", "policy_denied");
        let tally = fixture.finish();
        assert_eq!(tally.destinations()[0].destination, "late.example:443");
    }

    #[test]
    fn dropping_fixture_joins_watch_before_restoring_home() {
        mvm_core::util::test_env::isolated_env_probe(|| {
            let previous_home = std::env::var_os("MVM_HOME");
            let sink = Arc::new(Captured::default());
            let fixture_home;
            {
                let mut fixture = WatchFixture::new();
                fixture_home = std::path::PathBuf::from(mvm_core::config::mvm_home());
                assert_ne!(Some(fixture_home.as_os_str()), previous_home.as_deref());
                assert!(fixture_home.is_dir());
                let watched = fixture.endpoint_recorder("vm-a");
                fixture.watch = Some(DenialWatch::start(WatchTarget {
                    chain: fixture.dir.path().join("local.jsonl"),
                    vm_name: "vm-a".into(),
                    live: Live::Notices,
                    sink: Arc::clone(&sink) as Arc<dyn NoticeSink>,
                }));
                deny(&watched, "late.example:443", "policy_denied");
            }
            assert_eq!(sink.lines().len(), 1);
            assert_eq!(Arc::strong_count(&sink), 1, "watch released its target");
            assert_eq!(std::env::var_os("MVM_HOME"), previous_home);
            assert!(!fixture_home.exists());
        });
    }
}
