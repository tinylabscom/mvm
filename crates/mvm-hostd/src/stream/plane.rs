//! [`StreamPlane`] — the thing that actually stands a broker up for a running
//! VM, and takes it down again when the VM ends.
//!
//! Everything else in this module is a part; this is the assembly. On
//! [`attach`](StreamPlane::attach) one VM gets a [`StreamBroker`] over the
//! curated redaction seam, an encrypted transcript under
//! [`config::vm_stream_transcript_dir`], a follower socket at
//! [`config::vm_stream_socket`], and a [`ConsoleSource`] pointed at the
//! write-only capture the backend is already writing. On
//! [`release`](StreamPlane::release) the follower stops, the socket goes, and
//! the transcript seals to a manifest a reader can verify after the VM is
//! gone.
//!
//! **A map entry, not a process.** The broker's life is bounded by the VM's
//! registration in this plane — one entry per running VM, resident in whatever
//! host process owns that VM's lifecycle, in the same spirit as the per-tenant
//! host-agent daemon holding many VMs as registrations rather than spawning a
//! process each.
//!
//! **But the seal is not.** A map entry dies with its process, and most
//! workloads are not started and stopped by the same one: a detached start
//! exits immediately, an interrupted foreground run exits early, and the
//! `stop` that ends either of them is a fresh invocation with an empty map.
//! If the seal lived only in the map, those runs would leave a directory of
//! ciphertext no reader could open — "capturable when it exits" met by the
//! unchained console file rather than by the chained transcript. So each
//! capture also mirrors its manifest into [`super::journal`] as it is built,
//! and [`release`](StreamPlane::release) falls back to sealing from that
//! mirror for a VM this process never attached. A seal rebuilt that way is
//! marked as one: it cannot account for whatever the departed process
//! dropped between its last durable append and its exit.
//!
//! **The socket bind is the registration token.** Two host processes must
//! never write one VM's transcript at once: the second would interleave
//! segment files under the first's manifest and leave a capture that verifies
//! as tampered. [`serve_stream`] refuses a socket something is already
//! answering on, so a failed bind means someone else owns this VM's stream and
//! the attach gives up rather than racing them for the transcript.
//!
//! **Read-only towards the guest, always.** The plane adds a *reader* of the
//! console capture. Nothing here opens that file for writing, and no path
//! through it reaches the guest — the sealed production console has no host
//! input fd, and that absence is a security property, not an oversight.
//!
//! **A fresh capture per boot, discarded only once this process owns it.** A
//! restarted VM reuses its state dir, and a new writer appending beside a
//! previous run's segments would produce a manifest whose chunks do not match
//! what is on disk — a capture that reads as tampered when nothing tampered
//! with it. So attach clears the directory; it clears it *after* the bind,
//! because a refused bind means someone else's live capture is in there.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use mvm_core::config;
use mvm_core::crypto::aead;
use mvm_core::plan::DEFAULT_TENANT;
use mvm_core::policy::RedactionPolicy;
use mvm_core::transcript::{
    self, CaptureBinding, MANIFEST_FILENAME, TRANSCRIPT_KEK_RECIPIENT, TranscriptManifest,
    TranscriptWriter,
};
use mvm_core::util::atomic_io::atomic_write;
use mvm_runtime::workload_runner::{ConsoleCapture, ConsoleStreamer};

use crate::stream::broker::{StreamBroker, StreamCaptureIdentity, stream_capture_config};
use crate::stream::console_source::{ConsoleSource, ConsoleSourceHandle, SharedBroker};
use crate::stream::entrypoint_source::EntrypointSink;
use crate::stream::journal;
use crate::stream::redact::StreamRedaction;
use crate::stream::serve::{self, StreamServerHandle, serve_stream};

/// One running VM's live capture: the broker, the socket serving it, and the
/// console follower feeding it.
///
/// Field order is drop order, and it is the teardown order
/// [`StreamPlane::release`] performs explicitly — kept the same here so a
/// plane dropped without a release (a host process exiting under a signal)
/// unwinds the same way rather than a different one.
struct VmStream {
    console: Option<ConsoleSourceHandle>,
    server: StreamServerHandle,
    broker: SharedBroker,
    transcript_dir: PathBuf,
}

/// The per-process registry of live per-VM stream captures.
pub struct StreamPlane {
    vms: Mutex<HashMap<String, VmStream>>,
}

impl Default for StreamPlane {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamPlane {
    pub fn new() -> Self {
        Self {
            vms: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this plane currently holds a capture for `vm`.
    pub fn is_attached(&self, vm: &str) -> bool {
        self.registry().contains_key(vm)
    }

    /// VMs this plane is capturing, for a caller reporting host state.
    pub fn attached_vms(&self) -> Vec<String> {
        let mut names: Vec<String> = self.registry().keys().cloned().collect();
        names.sort();
        names
    }

    /// Stand up `vm`'s capture under `redaction` and start following its
    /// console.
    ///
    /// Idempotent: a VM already attached here keeps the capture it has, rather
    /// than getting a second broker that would split its output across two
    /// hash chains.
    pub fn attach(&self, capture: &ConsoleCapture<'_>) -> Result<()> {
        let vm = capture.vm_name;
        let mut registry = self.registry();
        if registry.contains_key(vm) {
            return Ok(());
        }
        let transcript_dir = config::vm_stream_transcript_dir(vm);
        let broker: SharedBroker = Arc::new(Mutex::new(build_broker(
            vm,
            &transcript_dir,
            capture.redaction,
        )?));

        // Bind before anything destructive and before following: the bind is
        // what claims this VM. A follower started ahead of it would have to be
        // unwound on a refusal, and the discard below would have already
        // deleted the capture whoever holds the socket is still writing.
        let server = serve_stream(&config::vm_stream_socket(vm), Arc::clone(&broker))
            .with_context(|| format!("serve the output stream for microVM {vm:?}"))?;

        // Owning the socket is what licenses throwing the previous boot's
        // segments away. Fail the attach if they cannot go: the new writer
        // would otherwise lay chunks over files its manifest does not
        // describe. `server` unbinds on the way out.
        discard_previous_capture(&transcript_dir)?;

        registry.insert(
            vm.to_string(),
            VmStream {
                console: follow_console(vm, capture.console_log, &broker),
                server,
                broker,
                transcript_dir,
            },
        );
        Ok(())
    }

    /// The entrypoint-side ingest for `vm`: a sink over its broker when this
    /// plane holds one, and a record-nothing sink when it does not.
    ///
    /// The sink holds the broker weakly, so a [`release`](Self::release) that
    /// lands while a call is still streaming still takes sole ownership and
    /// seals — the frames after it are unrecorded rather than the transcript
    /// being left without a manifest.
    pub fn entrypoint_sink(&self, vm: &str) -> EntrypointSink {
        self.registry()
            .get(vm)
            .map_or_else(EntrypointSink::unrecorded, |stream| {
                EntrypointSink::recorded(&stream.broker)
            })
    }

    /// Tear `vm`'s capture down and seal its transcript.
    ///
    /// Two shapes, and both have to end in a sealed manifest. When this plane
    /// holds the capture, the seal comes from the writer that produced it and
    /// accounts for the whole of it. When it does not — a workload started
    /// detached and stopped by a later invocation, or a foreground run whose
    /// caller was interrupted — the capture is rebuilt from the journal its
    /// departed writer left beside the segments and sealed from that instead.
    /// Doing nothing in the second case is what left every non-foreground
    /// workload with a directory of ciphertext and no manifest.
    pub fn release(&self, vm: &str) {
        // Bound to a `let` so the registry lock is released before either
        // seal runs: both touch the disk, and neither needs the map.
        let held = self.registry().remove(vm);
        match held {
            Some(stream) => seal_capture(vm, stream),
            None => adopt_capture(vm),
        }
    }

    fn registry(&self) -> MutexGuard<'_, HashMap<String, VmStream>> {
        // A panic under the lock leaves a `HashMap` of handles, not a
        // half-written invariant, and refusing to capture output for the rest
        // of the process would be a far worse outcome than reusing it.
        self.vms.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The console hook the workload runner calls. Best-effort by contract: a
/// capture that cannot be stood up is logged and the workload boots anyway,
/// because refusing to launch over an observability feature trades a missing
/// log for a missing workload.
impl ConsoleStreamer for StreamPlane {
    fn start(&self, capture: &ConsoleCapture<'_>) {
        if let Err(error) = self.attach(capture) {
            tracing::warn!(
                vm = %capture.vm_name,
                error = %format!("{error:#}"),
                "output stream could not be started; this workload's output will not be \
                 captured or followable"
            );
        }
    }

    fn stop(&self, vm_name: &str) {
        self.release(vm_name);
    }
}

/// Build the VM's broker over a fresh encrypted transcript, under the same
/// redaction policy the launch handed the substitution endpoint.
fn build_broker(
    vm: &str,
    transcript_dir: &Path,
    redaction: &RedactionPolicy,
) -> Result<StreamBroker> {
    let writer = build_writer(vm, transcript_dir)?;
    Ok(StreamBroker::new(
        vm,
        writer,
        StreamRedaction::curated(redaction),
    ))
}

/// Provision the durable half: a fresh capture directory, a per-capture data
/// key wrapped under the host KEK, and the ring-retention policy every stream
/// capture runs under.
fn build_writer(vm: &str, transcript_dir: &Path) -> Result<TranscriptWriter> {
    let keys_dir = config::mvm_keys_dir();
    let kek = transcript::load_or_init_kek(&keys_dir)
        .with_context(|| format!("open the transcript key in {}", keys_dir.display()))?;
    let data_key = aead::Key::random();
    let wrapped_data_key_b64 = transcript::wrap_data_key(&kek, &data_key);

    // The writer's directory has to exist before it does. Creating it is not
    // destructive, so unlike the discard it can run before the socket claim.
    std::fs::create_dir_all(transcript_dir)
        .with_context(|| format!("create the capture dir {}", transcript_dir.display()))?;

    // Through `stream_capture_config` and nowhere else: it is the one door
    // that installs ring retention, and a config assembled by hand would
    // silently get the fail-closed default — a workload that stops being
    // observable because it talked too much.
    let config = stream_capture_config(StreamCaptureIdentity {
        capture_id: format!("stream-{vm}"),
        binding: CaptureBinding {
            tenant_id: DEFAULT_TENANT.to_string(),
            vm_name: vm.to_string(),
            session_id: None,
        },
        created_unix_secs: now_unix_secs(),
        recipient: TRANSCRIPT_KEK_RECIPIENT.to_string(),
        wrapped_data_key_b64,
    });
    Ok(TranscriptWriter::new(transcript_dir, data_key, config))
}

/// Throw away whatever a previous boot left in the capture directory, keeping
/// the directory itself so the writer already pointed at it stays valid. See
/// the module docs on why a boot starts from an empty one, and why this runs
/// only after the socket claim.
fn discard_previous_capture(dir: &Path) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("read the capture dir {}", dir.display()))?;
    for entry in entries {
        let path = entry
            .with_context(|| format!("read the capture dir {}", dir.display()))?
            .path();
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.with_context(|| format!("discard the previous capture at {}", path.display()))?;
    }
    Ok(())
}

/// Start the console follower, or report that this VM has no console source.
///
/// A follower that cannot be spawned costs this workload its pre-agent output
/// and nothing else, so the capture stands up without one rather than failing
/// the attach — `ConsoleSource::follow` has already logged the reason.
fn follow_console(
    vm: &str,
    console_log: &Path,
    broker: &SharedBroker,
) -> Option<ConsoleSourceHandle> {
    ConsoleSource::follow(console_log, Arc::clone(broker))
        .inspect_err(|error| {
            tracing::warn!(
                vm = %vm,
                error = %error,
                "console capture will not be streamed for this workload"
            );
        })
        .ok()
}

/// Wind one VM's capture down in the order that neither loses bytes nor
/// wedges.
///
/// The follower goes first, because its stop drains what the console
/// accumulated since the last poll and every byte it takes still has a live
/// broker to land in. The socket goes second: it joins its follower threads,
/// each of which writes under a send timeout, so a consumer that stopped
/// reading without hanging up cannot hold this call open. Sealing is last
/// because it consumes the broker, and it can only do that once both of those
/// threads have dropped their handles on it.
fn seal_capture(vm: &str, stream: VmStream) {
    let VmStream {
        console,
        server,
        broker,
        transcript_dir,
    } = stream;
    if let Some(console) = console {
        console.stop();
    }
    server.stop();

    let Some(broker) = Arc::into_inner(broker) else {
        // Unreachable while the two joins above are the only other holders,
        // and worth saying rather than asserting: the live output was served
        // either way, and the cost is a capture with no manifest.
        tracing::warn!(
            vm = %vm,
            "output stream still had a live producer at teardown; its transcript is unsealed"
        );
        return;
    };
    let manifest = broker
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .seal();
    if let Err(error) = write_manifest(&transcript_dir, &manifest) {
        tracing::warn!(
            vm = %vm,
            error = %format!("{error:#}"),
            "output transcript could not be sealed; recorded output for this run is unreadable"
        );
    }
}

/// Seal a capture whose writer this process never held.
///
/// The whole reason [`release`](StreamPlane::release) used to be a no-op
/// here. A workload started detached, or one whose foreground caller
/// detached, leaves its transcript on disk with no manifest — and a
/// transcript with no manifest is unreadable, so `mvmctl logs` falls back to
/// the unchained console file and the verifiable half of the capture is dead
/// weight. Rebuilding from the journal the departed writer mirrored is what
/// makes "capturable when it exits" true for a workload nobody was watching
/// when it did.
///
/// Three refusals, in order, each protecting something a blind rebuild would
/// break:
///
/// - **A manifest already there** means this capture is sealed. Overwriting
///   it with a reconstruction would replace an exact seal with a floor.
/// - **A socket something answers on** means another host process is still
///   writing this capture. Sealing it from here would publish a manifest that
///   the very next append makes fail verification.
/// - **No journal** means there is nothing to rebuild from — an unrecorded
///   VM, or one whose journal could not be written. Silence is correct.
fn adopt_capture(vm: &str) {
    let dir = config::vm_stream_transcript_dir(vm);
    if dir.join(MANIFEST_FILENAME).exists() {
        return;
    }
    if serve::stream_is_served(&config::vm_stream_socket(vm)) {
        tracing::debug!(
            vm = %vm,
            "another host process is still capturing this workload's output; leaving its \
             transcript to whoever owns it"
        );
        return;
    }
    let Some(replayed) = journal::replay(&dir) else {
        return;
    };
    // An append the departed process died partway through leaves bytes past
    // the last mirrored record. Nothing accounts for them, so the sealed root
    // loses nothing when they go — and left in place they make every intact
    // segment in the same manifest fail verification.
    for (file, declared) in &replayed.declared_lengths {
        drop_unaccounted_tail(&dir.join(file), *declared);
    }
    match write_manifest(&dir, &replayed.manifest) {
        Ok(()) => {
            journal::CaptureJournal::discard(&dir.join(journal::JOURNAL_FILENAME));
            tracing::info!(
                vm = %vm,
                chunks = replayed.manifest.chunks.len(),
                "sealed the transcript of a workload this process did not start; it is marked \
                 as an incomplete record because the capturing process is gone"
            );
        }
        Err(error) => tracing::warn!(
            vm = %vm,
            error = %format!("{error:#}"),
            "output transcript could not be sealed from its journal; recorded output for this \
             run is unreadable"
        ),
    }
}

/// Cut bytes no record accounts for off the end of one segment. Best-effort:
/// a file that will not shrink stays as it is and `verify_chunks` reports it,
/// which is better than refusing to seal the rest of the capture over it.
fn drop_unaccounted_tail(path: &Path, declared: u64) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.len() <= declared {
        return;
    }
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|handle| handle.set_len(declared));
}

/// Publish the manifest, all of it or none of it.
///
/// Atomically, because a reader that finds a half-written manifest cannot
/// tell it from a corrupt one, and the sibling segment store already writes
/// this way. The read side degrades on an unparseable manifest rather than
/// hard-erroring; this is the other half of that pair, and the half that
/// stops the case arising.
fn write_manifest(dir: &Path, manifest: &TranscriptManifest) -> Result<()> {
    let path = dir.join(MANIFEST_FILENAME);
    let body = serde_json::to_vec_pretty(manifest).context("serialize the capture manifest")?;
    atomic_write(&path, &body).with_context(|| format!("write {}", path.display()))
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::stream_client::{
        OutputRecord, OutputRequest, RecordOrigin, StreamAvailability, StreamOpts, open_vm_output,
    };
    use mvm_core::util::test_env::TestEnv;
    use mvm_protocol::stream::StreamKind;
    use std::sync::mpsc::{Receiver, channel};
    use std::time::Duration;

    /// How long a test waits for a record that has to cross the console
    /// follower's poll interval and then the socket server's. Generous: a
    /// missed record fails on the deadline either way, and a tight bound
    /// would only turn scheduler jitter under full-suite parallelism into a
    /// failure.
    const DEADLINE: Duration = Duration::from_secs(10);

    /// Long enough for the accept loop to take a queued connection and
    /// subscribe its reader before the test produces the bytes it expects
    /// that reader to see. `connect` returns as soon as the connection is
    /// queued, not when it is accepted.
    const ACCEPT_SETTLE: Duration = Duration::from_millis(250);

    /// An `MVM_HOME` of its own so the plane writes sockets, transcripts, and
    /// the host KEK under a tempdir rather than the developer's real tree.
    fn isolated_home() -> (TestEnv, tempfile::TempDir) {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(tmp.path());
        (env, tmp)
    }

    /// One workload's capture, the way the runner hands it over.
    fn capture<'a>(vm: &'a str, console_log: &'a Path) -> ConsoleCapture<'a> {
        ConsoleCapture {
            vm_name: vm,
            console_log,
            redaction: &DEFAULT_REDACTION,
        }
    }

    /// The launch policy every test here runs under: the shipped default, so a
    /// test asserting on redaction is asserting on the shipped ruleset.
    static DEFAULT_REDACTION: std::sync::LazyLock<RedactionPolicy> =
        std::sync::LazyLock::new(RedactionPolicy::default);

    /// The console capture path a backend would write, under the VM's own
    /// state dir the way a real one is.
    fn console_log_for(vm: &str) -> PathBuf {
        let state = config::vm_state_dir(vm);
        std::fs::create_dir_all(&state).expect("state dir");
        state.join("console.log")
    }

    /// A follower attached on its own thread.
    ///
    /// `next_output` blocks on the socket while following, so reading it
    /// inline would hang the suite on a wiring regression instead of failing
    /// it. The thread ends when the server does.
    struct Follower {
        availability: StreamAvailability,
        records: Receiver<OutputRecord>,
    }

    impl Follower {
        /// Attach to `vm` through the same resolver `mvmctl logs -f` uses,
        /// and report what that resolution found.
        fn attach(vm: &str) -> Self {
            let (ready_tx, ready_rx) = channel();
            let (record_tx, record_rx) = channel();
            let vm = vm.to_string();
            std::thread::spawn(move || {
                let request = OutputRequest {
                    opts: StreamOpts::builder().follow(true).build(),
                    history_tail: Some(0),
                    console_tail_bytes: None,
                };
                let mut stream = open_vm_output(&vm, request).expect("open the output stream");
                if ready_tx.send(stream.availability()).is_err() {
                    return;
                }
                while let Ok(Some(record)) = stream.next_output() {
                    if record_tx.send(record).is_err() {
                        return;
                    }
                }
            });
            let availability = ready_rx
                .recv_timeout(DEADLINE)
                .expect("the follower must resolve a source");
            std::thread::sleep(ACCEPT_SETTLE);
            Self {
                availability,
                records: record_rx,
            }
        }

        fn next(&self) -> OutputRecord {
            self.records
                .recv_timeout(DEADLINE)
                .expect("a record must reach the follower")
        }
    }

    /// Every record a sealed capture holds, oldest first.
    fn sealed_payloads(vm: &str) -> Vec<Vec<u8>> {
        sealed_records(vm)
            .into_iter()
            .map(|(_, body)| body)
            .collect()
    }

    /// The manifest on disk for `vm`, or `None` when nothing sealed one.
    fn manifest_of(vm: &str) -> Option<TranscriptManifest> {
        let path = config::vm_stream_transcript_dir(vm).join(MANIFEST_FILENAME);
        let bytes = std::fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Every record a sealed capture holds, with the channel it was recorded
    /// on — the half a console-only capture could never supply.
    fn sealed_records(vm: &str) -> Vec<(StreamKind, Vec<u8>)> {
        let mut stream =
            open_vm_output(vm, OutputRequest::default()).expect("the sealed transcript must open");
        assert_eq!(
            stream.availability(),
            StreamAvailability::HistoryOnly,
            "a released VM has no live broker left"
        );
        let mut out = Vec::new();
        while let Some(record) = stream.next_output().expect("read the sealed capture") {
            assert_eq!(record.origin, RecordOrigin::Durable);
            out.push((record.kind, record.payload));
        }
        out
    }

    #[test]
    fn attach_serves_the_console_over_the_broker_socket() {
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-vm");
        let plane = StreamPlane::new();

        plane
            .attach(&capture("plane-vm", &console))
            .expect("attach");
        assert!(plane.is_attached("plane-vm"));
        assert_eq!(plane.attached_vms(), ["plane-vm"]);
        assert!(config::vm_stream_socket("plane-vm").exists());

        let follower = Follower::attach("plane-vm");
        assert_eq!(follower.availability, StreamAvailability::LiveOnly);

        std::fs::write(&console, b"from the console\n").expect("write the console capture");
        let record = follower.next();
        assert!(
            matches!(record.origin, RecordOrigin::Live { .. }),
            "the broker served the read, not the console fallback: {:?}",
            record.origin
        );
        assert_eq!(record.payload, b"from the console\n");

        plane.release("plane-vm");
    }

    #[test]
    fn attach_is_idempotent_and_keeps_the_first_capture() {
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-twice");
        let plane = StreamPlane::new();

        plane
            .attach(&capture("plane-twice", &console))
            .expect("first attach");
        plane
            .attach(&capture("plane-twice", &console))
            .expect("a second attach must not fail");
        assert_eq!(plane.attached_vms(), ["plane-twice"]);

        plane.release("plane-twice");
    }

    #[test]
    fn a_second_plane_will_not_take_a_vm_another_one_is_already_serving() {
        // Two host processes writing one transcript interleave segment files
        // under one manifest, which reads as tampering afterwards.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-contested");
        let first = StreamPlane::new();
        first
            .attach(&capture("plane-contested", &console))
            .expect("attach");

        let follower = Follower::attach("plane-contested");
        std::fs::write(&console, b"the incumbent's output\n").expect("write");
        assert_eq!(follower.next().payload, b"the incumbent's output\n");

        let second = StreamPlane::new();
        let err = second
            .attach(&capture("plane-contested", &console))
            .expect_err("a live socket must not be stolen");
        assert!(format!("{err:#}").contains("already serving"), "{err:#}");
        assert!(!second.is_attached("plane-contested"));

        // And it must not have taken anything on its way out: the refused
        // attach runs before the capture discard, so the incumbent's segments
        // are still there to seal.
        first.release("plane-contested");
        assert_eq!(
            sealed_payloads("plane-contested"),
            [b"the incumbent's output\n"]
        );
    }

    #[test]
    fn release_seals_a_readable_transcript_and_frees_the_socket() {
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-sealed");
        let plane = StreamPlane::new();
        plane
            .attach(&capture("plane-sealed", &console))
            .expect("attach");

        let follower = Follower::attach("plane-sealed");
        std::fs::write(&console, b"before the end\n").expect("write the console capture");
        assert_eq!(follower.next().payload, b"before the end\n");

        plane.release("plane-sealed");
        assert!(!plane.is_attached("plane-sealed"));
        assert!(
            !config::vm_stream_socket("plane-sealed").exists(),
            "release must unlink the socket so a restart can rebind it"
        );

        // The point of sealing: the run stays readable after the VM ends, off
        // the durable half rather than the console fallback.
        assert_eq!(sealed_payloads("plane-sealed"), [b"before the end\n"]);
    }

    #[test]
    fn release_keeps_the_last_bytes_a_dying_workload_wrote() {
        // The final drain is what makes a panic printed a few milliseconds
        // before teardown part of the record instead of a file nobody reads.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-last-words");
        let plane = StreamPlane::new();
        plane
            .attach(&capture("plane-last-words", &console))
            .expect("attach");

        std::fs::write(&console, b"kernel panic\n").expect("write the console capture");
        plane.release("plane-last-words");

        assert_eq!(sealed_payloads("plane-last-words"), [b"kernel panic\n"]);
    }

    #[test]
    fn both_sources_land_in_one_capture_with_the_entrypoint_keeping_its_channels() {
        // The design's premise, end to end: the console covers the windows the
        // agent cannot and is merged into stdout because a console cannot do
        // better; the entrypoint frames carry the channel the guest sent them
        // on. One broker, one chain, two sources.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-two-sources");
        let plane = StreamPlane::new();
        plane
            .attach(&capture("plane-two-sources", &console))
            .expect("attach");

        // Wait for the console record before producing the entrypoint ones:
        // between sources the order is host arrival order and nothing
        // stronger, so a test that raced them would be asserting on the
        // follower's poll interval.
        let follower = Follower::attach("plane-two-sources");
        std::fs::write(&console, b"booting\n").expect("write the console capture");
        assert_eq!(follower.next().payload, b"booting\n");

        let mut sink = plane.entrypoint_sink("plane-two-sources");
        assert!(
            sink.is_recorded(),
            "an attached VM has a broker to record to"
        );
        sink.ingest(StreamKind::Stdout, b"result");
        sink.ingest(StreamKind::Stderr, b"warning");
        drop(sink);

        plane.release("plane-two-sources");
        assert_eq!(
            sealed_records("plane-two-sources"),
            vec![
                (StreamKind::Stdout, b"booting\n".to_vec()),
                (StreamKind::Stdout, b"result".to_vec()),
                (StreamKind::Stderr, b"warning".to_vec()),
            ]
        );
    }

    #[test]
    fn the_capture_is_redacted_under_the_policy_the_launch_threaded() {
        // The launch already resolves a redaction policy and hands it to the
        // substitution endpoint. A capture that picked its own would give one
        // answer on egress and a different one in the transcript.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-policy");
        let narrowed = RedactionPolicy {
            default: mvm_core::policy::RedactionAction {
                pii: mvm_core::policy::PiiPolicy {
                    mode: None,
                    categories: vec!["email".to_string()],
                },
                ..Default::default()
            },
            profiles: Vec::new(),
        };
        let plane = StreamPlane::new();
        plane
            .attach(&ConsoleCapture {
                vm_name: "plane-policy",
                console_log: &console,
                redaction: &narrowed,
            })
            .expect("attach");

        let mut sink = plane.entrypoint_sink("plane-policy");
        sink.ingest(StreamKind::Stdout, b"a@b.com and 4111111111111111");
        drop(sink);
        plane.release("plane-policy");

        let recorded = sealed_payloads("plane-policy").concat();
        assert!(
            !recorded.windows(7).any(|w| w == b"a@b.com"),
            "the category the policy named must be masked in the transcript"
        );
        assert!(
            recorded.windows(16).any(|w| w == b"4111111111111111"),
            "and the categories it left out must not be, or the policy was ignored"
        );
    }

    #[test]
    fn a_vm_this_plane_never_attached_gets_an_unrecorded_sink_rather_than_a_refusal() {
        // The `--attach`-into-someone-else's-machine case. The call still has
        // to run and still has to print; what it loses is the capture.
        let (_env, _tmp) = isolated_home();
        assert!(
            !StreamPlane::new()
                .entrypoint_sink("elsewhere")
                .is_recorded()
        );
    }

    #[test]
    fn releasing_a_vm_that_never_had_a_capture_is_a_no_op() {
        // Nothing on disk to rebuild from, so nothing to seal — and above
        // all, no empty manifest invented for a VM that never ran here.
        let (_env, _tmp) = isolated_home();
        StreamPlane::new().release("never-attached");
        assert_eq!(manifest_of("never-attached"), None);
    }

    /// A host process that started a workload and then exited without ever
    /// stopping it: `machine run -d`, `up`, or a foreground run whose caller
    /// detached. The plane goes with the process; the VM and its capture
    /// directory stay.
    fn detached_start(vm: &str, console: &Path, output: &[u8]) {
        let plane = StreamPlane::new();
        plane.attach(&capture(vm, console)).expect("attach");
        std::fs::write(console, output).expect("write the console capture");
        // Wait for the follower to have taken those bytes before the process
        // "exits": a real detached start runs for as long as it takes to
        // print, and a race here would be the test's, not the plane's.
        let deadline = std::time::Instant::now() + DEADLINE;
        while std::fs::read(console).map(|c| c.is_empty()).unwrap_or(true)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(ACCEPT_SETTLE);
        drop(plane);
    }

    #[test]
    fn a_workload_stopped_by_a_later_process_still_gets_a_sealed_transcript() {
        // The gap this exists to close: the plane that captured the run is
        // gone, and until now the `stop` that ended the VM wrote no manifest
        // at all — so `logs` fell back to the unchained console file and the
        // verifiable half of the capture was dead weight.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-detached");
        detached_start("plane-detached", &console, b"ran while nobody watched\n");
        assert_eq!(
            manifest_of("plane-detached"),
            None,
            "the fixture must really leave the capture unsealed"
        );

        // A fresh process's plane, which never saw this VM start.
        StreamPlane::new().release("plane-detached");

        assert_eq!(
            sealed_payloads("plane-detached"),
            [b"ran while nobody watched\n"]
        );
    }

    #[test]
    fn a_transcript_sealed_by_another_process_says_it_cannot_vouch_for_the_whole_run() {
        // Nothing on disk records what the departed process shed between its
        // last durable append and its exit. A manifest that stayed silent
        // about that would claim a completeness it cannot have.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-adopted");
        detached_start("plane-adopted", &console, b"partial\n");

        StreamPlane::new().release("plane-adopted");

        let manifest = manifest_of("plane-adopted").expect("a manifest was written");
        assert!(manifest.adopted);
        assert!(manifest.is_truncated());
        transcript::verify_sealed_root(&manifest).expect("an adopted manifest still verifies");
        transcript::verify_chunks(
            &manifest,
            &config::vm_stream_transcript_dir("plane-adopted"),
        )
        .expect("its chunks are exactly the bytes on disk");
    }

    #[test]
    fn a_capture_another_process_is_still_serving_is_left_alone() {
        // Sealing behind a live writer's back publishes a manifest the very
        // next append makes fail verification.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-live-elsewhere");
        let owner = StreamPlane::new();
        owner
            .attach(&capture("plane-live-elsewhere", &console))
            .expect("attach");

        StreamPlane::new().release("plane-live-elsewhere");
        assert_eq!(
            manifest_of("plane-live-elsewhere"),
            None,
            "a live capture must not be sealed from under its owner"
        );

        // And the owner's own seal still lands, unchanged.
        std::fs::write(&console, b"still mine\n").expect("write the console capture");
        owner.release("plane-live-elsewhere");
        assert_eq!(sealed_payloads("plane-live-elsewhere"), [b"still mine\n"]);
    }

    #[test]
    fn a_capture_its_own_writer_sealed_is_not_reseated_by_a_later_stop() {
        // A `stop` after a foreground run must not replace an exact seal with
        // a reconstruction that only claims to be a floor.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-double-stop");
        let plane = StreamPlane::new();
        plane
            .attach(&capture("plane-double-stop", &console))
            .expect("attach");
        std::fs::write(&console, b"foreground run\n").expect("write the console capture");
        plane.release("plane-double-stop");

        let sealed = manifest_of("plane-double-stop").expect("the owner sealed it");
        assert!(!sealed.adopted);

        StreamPlane::new().release("plane-double-stop");
        assert_eq!(
            manifest_of("plane-double-stop"),
            Some(sealed),
            "a second stop must leave the owner's seal exactly as it was"
        );
    }

    #[test]
    fn an_owned_seal_leaves_no_journal_for_a_later_stop_to_rebuild_from() {
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-journal-gone");
        let plane = StreamPlane::new();
        plane
            .attach(&capture("plane-journal-gone", &console))
            .expect("attach");
        std::fs::write(&console, b"done\n").expect("write the console capture");
        plane.release("plane-journal-gone");

        assert!(
            !config::vm_stream_transcript_dir("plane-journal-gone")
                .join(journal::JOURNAL_FILENAME)
                .exists(),
            "the mirror is superseded by the manifest and must not outlive it"
        );
    }

    #[test]
    fn a_restart_after_a_detached_run_does_not_inherit_the_previous_journal() {
        // The capture discard clears the whole directory, mirror included; a
        // journal left from the previous boot would rebuild a manifest naming
        // segments this boot already deleted.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-detached-restart");
        detached_start("plane-detached-restart", &console, b"first run\n");

        std::fs::write(&console, b"").expect("truncate the console capture");
        let plane = StreamPlane::new();
        plane
            .attach(&capture("plane-detached-restart", &console))
            .expect("reattach");
        std::fs::write(&console, b"second run\n").expect("write the console capture");
        plane.release("plane-detached-restart");

        assert_eq!(sealed_payloads("plane-detached-restart"), [b"second run\n"]);
    }

    #[test]
    fn a_restart_replaces_the_previous_runs_capture_instead_of_appending_to_it() {
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-restarted");
        let plane = StreamPlane::new();

        plane
            .attach(&capture("plane-restarted", &console))
            .expect("attach");
        std::fs::write(&console, b"first run\n").expect("write the console capture");
        plane.release("plane-restarted");
        assert_eq!(sealed_payloads("plane-restarted"), [b"first run\n"]);

        // Second boot, same name and the same state dir. The backend
        // truncates the console capture on boot, so the follower starts over.
        std::fs::write(&console, b"").expect("truncate the console capture");
        plane
            .attach(&capture("plane-restarted", &console))
            .expect("reattach");
        std::fs::write(&console, b"second run\n").expect("write the console capture");
        plane.release("plane-restarted");

        assert_eq!(
            sealed_payloads("plane-restarted"),
            [b"second run\n"],
            "the second boot's capture must not carry the first boot's chunks"
        );
    }
}
