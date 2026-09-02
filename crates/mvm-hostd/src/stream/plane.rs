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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use mvm_contract::stream::input::InputFrame;

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

use crate::audit::emitter::AuditEmitter;
use crate::audit::host_keypair;
use crate::audit::plan_persist;
use crate::stream::broker::{StreamBroker, StreamCaptureIdentity, stream_capture_config};
use crate::stream::console_source::{ConsoleSource, ConsoleSourceHandle, SharedBroker};
use crate::stream::entrypoint_source::EntrypointSink;
use crate::stream::fanout::ReaderHandle;
use crate::stream::input_gate::InputRefusal;
use crate::stream::input_route::{InputRoute, InputRouteError, InputTransport, WireSequence};
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
    /// Where this capture's manifest goes, or `None` when the plan admitted
    /// the run as ephemeral and there is no transcript to write one for.
    transcript_dir: Option<PathBuf>,
}

/// The per-process registry of live per-VM stream captures, and of the input
/// routes pointing the other way.
///
/// Two maps, one lock each, because they answer to different lifetimes: a
/// capture lives for the whole VM, an input route only for as long as a writer
/// holds the lease. What they share is that both are per-VM registrations in
/// whichever host process owns the VM, and that [`release`](StreamPlane::release)
/// ends both.
///
/// Ordering is arbitrated per route, not per map. Every write holds *that
/// VM's* route lock across accept-drain-deliver, so two concurrent writers
/// cannot interleave the bytes of one stream and the gate's secret scan —
/// defined over the order it accepted bytes in — describes what the guest
/// actually receives. The map's own lock is released before any of that
/// happens: delivering crosses a vsock round trip, and holding one lock across
/// it would make a slow guest on one VM stall writes to every other.
pub struct StreamPlane {
    vms: Mutex<HashMap<String, VmStream>>,
    inputs: Mutex<HashMap<String, VmInput>>,
}

/// One VM's input registration: the route whichever writer holds the lease is
/// using, and the delivery counter that outlives all of them.
///
/// The counter is here rather than inside the route because it answers to the
/// *guest's* stdin, which does not restart when a lease changes hands — see
/// [`input_route`](crate::stream::input_route)'s module docs.
#[derive(Clone)]
struct VmInput {
    route: SharedRoute,
    wire_seq: WireSequence,
}

/// One VM's input route, shared between the map and whoever is mid-write.
///
/// `Option` because ending the stream consumes the route — [`InputRoute::close`]
/// takes `self` — and the taking has to happen under the same lock a concurrent
/// writer would be holding, so a write and a close cannot both think they own
/// the stream.
type SharedRoute = Arc<Mutex<Option<InputRoute>>>;

impl Default for StreamPlane {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamPlane {
    pub fn new() -> Self {
        Self {
            vms: Mutex::new(HashMap::new()),
            inputs: Mutex::new(HashMap::new()),
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

    /// Subscribe to the redacted output of a VM this plane owns.
    ///
    /// Returns `None` for every absent source. Authorization and binding
    /// resolution belong to the fleet caller; this method deliberately does
    /// not expose why a name failed to resolve. A successful subscription is
    /// recorded by the broker in the source workload's chain-signed audit
    /// log.
    pub fn subscribe(&self, vm: &str) -> Option<ReaderHandle> {
        let broker = {
            let registry = self.registry();
            Arc::clone(&registry.get(vm)?.broker)
        };
        let mut broker = broker.lock().unwrap_or_else(PoisonError::into_inner);
        Some(broker.subscribe())
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
        // Where this VM's capture lives, whether or not this run writes one:
        // the discard below has to reach a previous run's transcript even when
        // this run keeps none. An ephemeral run gets a broker and a socket and
        // no disk at all — the directory is never created, so the mode is
        // visible as an absence rather than as an empty artifact somebody has
        // to interpret.
        let capture_dir = config::vm_stream_transcript_dir(vm);
        let transcript_dir = capture.retention.persists().then(|| capture_dir.clone());
        let broker: SharedBroker = Arc::new(Mutex::new(build_broker(
            vm,
            transcript_dir.as_deref(),
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
        //
        // An ephemeral run discards too, and for a sharper reason: a previous
        // recording boot's transcript left in place would be read as this
        // run's, so the one shape worse than no recording — somebody else's,
        // presented as yours — cannot arise.
        discard_previous_capture(&capture_dir)?;

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
    ///
    /// Open the host→guest input route for `vm` under `admitted`.
    ///
    /// Everything that decides whether a writer may do this lives in
    /// [`InputRoute::open`] and, below it, the gate: the signed grant, the
    /// single-writer lease, and the chain-signed record of the decision. The
    /// plane's part is to own the route for as long as the VM does, so a
    /// [`release`](Self::release) ends the input stream along with the
    /// capture.
    ///
    /// A route already open for `vm` whose lease is still live refuses this
    /// caller — the gate does it, below, before anything of the incumbent's is
    /// touched. What can still arrive here is a *successor*: an incumbent that
    /// let its lease lapse does not hold the stream any more, and this call is
    /// the new writer taking it over. That handover is not silent. The
    /// displaced route is wound up explicitly, what it can no longer deliver
    /// is reported, and the VM's delivery counter carries across it so the
    /// successor is not refused by the guest for its predecessor's sequence.
    ///
    /// This is also where the gate learns what to scan for. The substitution
    /// endpoint fingerprinted every secret it resolved for this VM at spawn,
    /// and binding here rather than at boot is what makes the two orders
    /// independent: a session snapshots the fingerprint set when it opens, so
    /// the set has to be installed immediately before, not at some earlier
    /// point a backend might reorder.
    pub fn open_input(
        &self,
        vm: &str,
        admitted: &crate::plan_admission::AdmittedPlan,
        transport: Box<dyn InputTransport>,
    ) -> Result<(), InputRefusal> {
        bind_known_secrets(vm);

        // Cloned out from under the registry lock, which is not held across
        // anything below: winding up an incumbent waits on that VM's route
        // lock, and a wedged guest holding it must not stall every other VM.
        let incumbent = self.inputs().get(vm).cloned();
        let wire_seq = incumbent
            .as_ref()
            .map_or_else(WireSequence::default, |held| held.wire_seq.clone());

        // The gate first: a live incumbent lease refuses here, so the wind-up
        // below can only ever be reached for one that already lapsed.
        let route = InputRoute::open(vm, admitted, transport, wire_seq.clone())?;

        if let Some(held) = incumbent {
            wind_up_displaced(vm, &held.route);
        }
        self.inputs().insert(
            vm.to_string(),
            VmInput {
                route: Arc::new(Mutex::new(Some(route))),
                wire_seq,
            },
        );
        Ok(())
    }

    /// Whether a writer currently holds `vm`'s input route.
    pub fn input_is_open(&self, vm: &str) -> bool {
        self.inputs().contains_key(vm)
    }

    /// Tell `vm`'s gate that its writer is idle but alive.
    ///
    /// Two things ride on the same call. The lease exists to free a stdin
    /// whose writer died, not to punish one that is thinking: without this, an
    /// interactive writer that paused past the TTL would find its next write
    /// refused *and* its close refused, which drops the tail the gate
    /// withheld. And on a secret-bearing VM the gate releases that withheld
    /// tail once the silence is long enough, which is what lets a workload
    /// reading one request line at a time ever receive one. Both are the
    /// holder's job, and this is the only way to do either without sending
    /// bytes.
    pub fn refresh_input(&self, vm: &str) -> Result<(), InputRouteError> {
        let shared = self.route(vm)?;
        let mut held = shared.lock().unwrap_or_else(PoisonError::into_inner);
        held.as_mut().ok_or(InputRouteError::NoSession)?.refresh()
    }

    /// Offer one frame to `vm`'s workload.
    ///
    /// This VM's route lock is held across the whole of accept-drain-deliver
    /// inside [`InputRoute::write`], which is what makes delivery order
    /// acceptance order under concurrent callers. Splitting it into "accept
    /// now, deliver later" would reintroduce exactly the reordering the gate's
    /// scan cannot see through. The registry lock is not held across it: the
    /// delivery is a round trip to a guest, and one shared lock over that would
    /// let a wedged VM stall every other VM's writer.
    pub fn write_input(&self, vm: &str, frame: InputFrame) -> Result<(), InputRouteError> {
        let shared = self.route(vm)?;
        let mut held = shared.lock().unwrap_or_else(PoisonError::into_inner);
        held.as_mut()
            .ok_or(InputRouteError::NoSession)?
            .write(frame)
    }

    /// End `vm`'s input stream: the withheld tail, then EOF.
    pub fn close_input(&self, vm: &str) -> Result<(), InputRouteError> {
        let held = self.inputs().remove(vm).ok_or(InputRouteError::NoSession)?;
        close_shared(&held.route)
    }

    /// This VM's route, or the absence of one. Cloned out from under the
    /// registry lock so the caller can take its time with it.
    fn route(&self, vm: &str) -> Result<SharedRoute, InputRouteError> {
        self.inputs()
            .get(vm)
            .map(|held| Arc::clone(&held.route))
            .ok_or(InputRouteError::NoSession)
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
        // The input stream goes first, and it goes properly: a route dropped
        // rather than closed would leave a workload waiting on a stdin that
        // never EOFs, and would lose the tail the gate withheld.
        let held = self.inputs().remove(vm);
        if let Some(held) = held
            && let Err(error) = close_shared(&held.route)
        {
            // A workload that never saw EOF and a tail that never arrived are
            // both data-loss events, not diagnostic detail.
            tracing::warn!(
                vm = %vm,
                error = %error,
                "the workload's input stream could not be closed cleanly at teardown"
            );
        }
        // Bound to a `let` so the registry lock is released before either
        // seal runs: both touch the disk, and neither needs the map.
        let held = self.registry().remove(vm);
        match held {
            Some(stream) => seal_capture(vm, stream),
            // Nothing held here, so this process cannot know whether the run
            // was ephemeral. The journal answers it: an ephemeral capture
            // wrote none, so the adopt finds nothing to rebuild and correctly
            // does nothing.
            None => adopt_capture(vm),
        }
    }

    /// The input registry, recovered rather than propagated on poison for the
    /// same reason as the capture registry: a panicking writer must not take
    /// every other VM's input path down with it.
    fn inputs(&self) -> MutexGuard<'_, HashMap<String, VmInput>> {
        self.inputs.lock().unwrap_or_else(PoisonError::into_inner)
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

/// Install the fingerprint set the input gate scans `vm`'s stdin against.
///
/// The values behind these fingerprints live in the per-VM substitution
/// endpoint, a separate process, and stay there: what reaches this process is
/// a length, a rolling hash and a category each, computed by the endpoint at
/// spawn. That separation is the reason the gate matches fingerprints instead
/// of bytes — copying credentials in here to populate a scan would create a
/// plaintext location where there is none.
///
/// An empty set is the honest outcome for a VM whose plan carried no secrets,
/// and for one this process did not boot: in the second case no writer can
/// open a session anyway, because it holds no admitted plan to write under.
/// Binding unconditionally rather than skipping the empty case keeps a stale
/// set from a previous VM of the same name out of the gate.
fn bind_known_secrets(vm: &str) {
    let fingerprints = mvm_vmm::host::network_endpoint_spawn::recorded_secret_fingerprints(vm);
    tracing::debug!(
        vm = %vm,
        fingerprints = fingerprints.len(),
        "installing the input gate's known-secret fingerprints"
    );
    crate::stream::input_gate::InputGate::bind_fingerprints(vm, fingerprints);
}

/// End the stream a shared route holds, taking it out under the route's own
/// lock so a concurrent writer cannot be mid-frame while it goes.
fn close_shared(shared: &SharedRoute) -> Result<(), InputRouteError> {
    let taken = shared.lock().unwrap_or_else(PoisonError::into_inner).take();
    taken.map_or(Err(InputRouteError::NoSession), InputRoute::close)
}

/// Wind up the route a successor displaced, and say what it cost.
///
/// The route's own lock is taken and *waited on*, not skipped: a predecessor
/// that is mid-delivery has to finish before the successor's first frame goes
/// out, or two writers interleave in the one stdin the lease exists to
/// arbitrate. Taking the route out under that lock is also what makes a
/// concurrent `write_input` on the stale handle answer `NoSession` rather than
/// deliver.
fn wind_up_displaced(vm: &str, route: &SharedRoute) {
    let taken = route.lock().unwrap_or_else(PoisonError::into_inner).take();
    let Some(route) = taken else {
        // Already closed or released; there is nothing to lose.
        return;
    };
    let displaced = route.displace();
    tracing::warn!(
        vm = %vm,
        holder = %displaced.holder,
        stranded_bytes = displaced.stranded_bytes,
        "a new writer took the workload's stdin from a lease that had lapsed; \
         the previous writer's undelivered bytes are discarded"
    );
}

/// Build the VM's broker over a fresh encrypted transcript, under the same
/// redaction policy the launch handed the substitution endpoint.
fn build_broker(
    vm: &str,
    transcript_dir: Option<&Path>,
    redaction: &RedactionPolicy,
) -> Result<StreamBroker> {
    let redaction = StreamRedaction::curated(redaction);
    // Same seam either way. Retention decides whether the cleared bytes are
    // also written down, never whether they are cleared.
    match transcript_dir {
        Some(dir) => Ok(StreamBroker::new(vm, build_writer(vm, dir)?, redaction)),
        None => Ok(StreamBroker::live_only(vm, redaction)),
    }
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
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // No directory is the same state as an empty one, and it is the
        // ordinary state for a first boot and for every ephemeral run — the
        // recording path creates it later, when it has a writer to put in it.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("read the capture dir {}", dir.display()));
        }
    };
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
    // Teardown reports console cleanup as one number, and it is the largest
    // span of a transient stop. The work behind it is two independent writer
    // joins and a manifest write, so the total is not actionable until split.
    let t_console = std::time::Instant::now();
    if let Some(console) = console {
        console.stop();
    }
    tracing::debug!(
        vm = %vm,
        ms = t_console.elapsed().as_secs_f64() * 1000.0,
        "seal: console writer stop"
    );

    let t_server = std::time::Instant::now();
    server.stop();
    tracing::debug!(
        vm = %vm,
        ms = t_server.elapsed().as_secs_f64() * 1000.0,
        "seal: server writer stop"
    );

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
    let sealed = broker
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .seal();
    let (Some(transcript_dir), Some(manifest)) = (transcript_dir, sealed) else {
        // An ephemeral capture. Both halves are absent together — the broker
        // has no manifest and the plane has no directory to put one in — so
        // there is nothing to write and nothing lost by not writing it.
        return;
    };
    if let Err(error) = write_manifest(&transcript_dir, &manifest) {
        tracing::warn!(
            vm = %vm,
            error = %format!("{error:#}"),
            "output transcript could not be sealed; recorded output for this run is unreadable"
        );
        return;
    }
    anchor_sealed_transcript(vm, &manifest);
}

/// Bind a sealed transcript's ciphertext-manifest root into the host audit
/// chain, so the chain-signed log commits to the recorded output and not only
/// to the control-plane events around it.
///
/// **Only the root crosses.** The chain carries no payload bytes and no
/// plaintext digest by construction; what lands here is the same
/// authenticated root a reader verifies before decrypting anything, which is
/// enough to detect a substituted transcript and nothing more.
///
/// **Best-effort, and loud when it fails.** A workload that ran must not fail
/// its teardown because the chain could not be written, but an unanchored
/// transcript is a real gap in the evidence: it stays verifiable on its own
/// terms and is no longer tied to the run that produced it. So every arm
/// warns rather than returning, and none of them is silent.
///
/// **No signer is minted here.** Teardown loads the host signer that admitted
/// the run; it never creates one. A host with no signer never admitted a plan
/// under it, so there is no chain this transcript belongs in.
fn anchor_sealed_transcript(vm: &str, manifest: &TranscriptManifest) {
    let plan = match plan_persist::read_plan(vm) {
        Ok(plan) => plan,
        Err(error) => {
            tracing::warn!(
                vm = %vm,
                error = %format!("{error:#}"),
                "no admitted plan for this workload; its sealed transcript is not anchored in                  the audit chain"
            );
            return;
        }
    };
    let keys_dir = mvm_core::config::mvm_keys_dir();
    if !keys_dir.join(host_keypair::SECRET_FILENAME).exists() {
        tracing::warn!(
            vm = %vm,
            "no host signer on this host; the sealed transcript is not anchored in the audit chain"
        );
        return;
    }
    let signer = match host_keypair::load_or_init_at(&keys_dir) {
        Ok(signer) => signer,
        Err(error) => {
            tracing::warn!(
                vm = %vm,
                error = %format!("{error:#}"),
                "the host signer could not be loaded; the sealed transcript is not anchored in                  the audit chain"
            );
            return;
        }
    };
    let emitted = AuditEmitter::new(signer.signing).and_then(|emitter| {
        emitter.emit_transcript_sealed(
            &plan,
            &manifest.capture_id,
            &manifest.binding.vm_name,
            &manifest.sealed_root_hex,
            manifest.chunks.len(),
            manifest.adopted,
        )
    });
    if let Err(error) = emitted {
        tracing::warn!(
            vm = %vm,
            error = %format!("{error:#}"),
            "the sealed transcript could not be anchored in the audit chain; its recorded              output is still verifiable on its own but is no longer bound to this run"
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
///
/// The first of those is a check, and a check races: two concurrent stops, or
/// a stop that overlaps the owner's own seal, can both pass it. So the write
/// itself is exclusive ([`link_manifest_exclusively`]) rather than the
/// overwriting [`write_manifest`] the owner uses — an adopted floor can never
/// land on top of anything, whoever wins the race, while the owner's exact
/// seal still overwrites an adopted one as it should.
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
    match link_manifest_exclusively(&dir, &replayed.manifest) {
        Ok(true) => {
            journal::CaptureJournal::discard(&dir.join(journal::JOURNAL_FILENAME));
            tracing::info!(
                vm = %vm,
                chunks = replayed.manifest.chunks.len(),
                "sealed the transcript of a workload this process did not start; it is marked \
                 as an incomplete record because the capturing process is gone"
            );
            anchor_sealed_transcript(vm, &replayed.manifest);
        }
        Ok(false) => tracing::debug!(
            vm = %vm,
            "this capture was sealed by someone else while it was being rebuilt; leaving \
             their manifest in place"
        ),
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

/// Publish the manifest only if nothing has published one yet, and report
/// which happened.
///
/// A whole file written elsewhere and then `link`ed into place: `link(2)`
/// fails with `EEXIST` rather than replacing, and it fails or succeeds as one
/// operation, so this is both atomic and exclusive where
/// [`write_manifest`]'s rename is only atomic. That is what an adopted seal
/// needs — the manifest it would replace is by definition a better one, either
/// another adopter that got there first or the owning process's exact seal.
///
/// `Ok(false)` means someone else's manifest is there.
fn link_manifest_exclusively(dir: &Path, manifest: &TranscriptManifest) -> Result<bool> {
    let path = dir.join(MANIFEST_FILENAME);
    let body = serde_json::to_vec_pretty(manifest).context("serialize the capture manifest")?;
    let staged = dir.join(format!(
        "{MANIFEST_FILENAME}.{}.{}.adopting",
        std::process::id(),
        now_unix_nanos()
    ));
    write_staged(&staged, &body)
        .with_context(|| format!("stage the manifest for {}", path.display()))?;

    let linked = std::fs::hard_link(&staged, &path);
    // Whichever way the link went, the staging name has served its purpose:
    // on success the manifest is a second name for the same inode, on failure
    // it is litter in a capture directory a reader will scan.
    let _ = std::fs::remove_file(&staged);
    match linked {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => {
            Err(anyhow::Error::from(error)).with_context(|| format!("publish {}", path.display()))
        }
    }
}

/// Write the staged copy, refusing to reuse a name that already exists and
/// syncing before it is linked into place.
fn write_staged(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::stream::StreamKind;
    use mvm_core::plan::StreamRetention;
    use mvm_core::stream_client::{
        OutputRecord, OutputRequest, RecordOrigin, StreamAvailability, StreamOpts, open_vm_output,
    };
    use mvm_core::util::test_env::TestEnv;
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

    /// One workload's capture, the way the runner hands it over — recording,
    /// which is what an admitted plan says unless it opts out.
    fn capture<'a>(vm: &'a str, console_log: &'a Path) -> ConsoleCapture<'a> {
        ConsoleCapture {
            vm_name: vm,
            console_log,
            redaction: &DEFAULT_REDACTION,
            retention: StreamRetention::Persist,
        }
    }

    /// The same capture under a plan that opted out of a durable transcript.
    fn ephemeral_capture<'a>(vm: &'a str, console_log: &'a Path) -> ConsoleCapture<'a> {
        ConsoleCapture {
            retention: StreamRetention::Ephemeral,
            ..capture(vm, console_log)
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
                    console_tail_lines: None,
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

    /// The **durable** half of a sealed capture, with the channel each record
    /// was recorded on — the half a console-only capture could never supply.
    ///
    /// Console records are filtered out rather than asserted against: an
    /// adopted capture is deliberately read with the console spliced behind
    /// it, and what these tests are about is what the chain holds.
    fn sealed_records(vm: &str) -> Vec<(StreamKind, Vec<u8>)> {
        let mut stream =
            open_vm_output(vm, OutputRequest::default()).expect("the sealed transcript must open");
        assert!(
            !stream.availability().is_live(),
            "a released VM has no live broker left: {:?}",
            stream.availability()
        );
        let mut out = Vec::new();
        while let Some(record) = stream.next_output().expect("read the sealed capture") {
            if record.origin == RecordOrigin::Durable {
                out.push((record.kind, record.payload));
            }
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
        let mut edge_reader = plane
            .subscribe("plane-vm")
            .expect("an attached VM is subscribable");
        assert_eq!(follower.availability, StreamAvailability::LiveOnly);

        std::fs::write(&console, b"from the console\n").expect("write the console capture");
        let record = follower.next();
        assert!(
            matches!(record.origin, RecordOrigin::Live { .. }),
            "the broker served the read, not the console fallback: {:?}",
            record.origin
        );
        assert_eq!(record.payload, b"from the console\n");
        assert_eq!(
            edge_reader
                .recv()
                .expect("the edge reader saw the frame")
                .payload,
            b"from the console\n"
        );
        assert!(
            plane.subscribe("not-attached").is_none(),
            "all absent sources have the same result"
        );

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

    /// The signed opt-out takes away the recording and nothing else. A run
    /// that cannot be followed while it runs would be a different and much
    /// worse feature than a run that is not kept.
    #[test]
    fn an_ephemeral_capture_still_streams_live() {
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-ephemeral-live");
        let plane = StreamPlane::new();
        plane
            .attach(&ephemeral_capture("plane-ephemeral-live", &console))
            .expect("attach");

        let follower = Follower::attach("plane-ephemeral-live");
        assert_eq!(follower.availability, StreamAvailability::LiveOnly);
        std::fs::write(&console, b"still watchable\n").expect("write the console capture");
        let record = follower.next();
        assert!(
            matches!(record.origin, RecordOrigin::Live { .. }),
            "an ephemeral capture is served by the broker like any other: {:?}",
            record.origin
        );
        assert_eq!(record.payload, b"still watchable\n");

        plane.release("plane-ephemeral-live");
    }

    /// No transcript directory and no manifest — no journal for a later stop
    /// to adopt, either. An empty transcript artifact would be worse than
    /// none, because it asserts the workload printed nothing.
    ///
    /// This plane never touches the backend's own console capture, so that
    /// file is untouched by the retention mode: it is still there, and still
    /// readable by `logs`, after an ephemeral run. That is not a gap in the
    /// plane — it is a fact an operator picking `Ephemeral` to keep output
    /// off disk needs to know, so it is checked here rather than left
    /// implicit.
    #[test]
    fn an_ephemeral_capture_creates_no_transcript_dir_or_manifest() {
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-ephemeral-disk");
        let plane = StreamPlane::new();
        plane
            .attach(&ephemeral_capture("plane-ephemeral-disk", &console))
            .expect("attach");

        std::fs::write(&console, b"unrecorded\n").expect("write the console capture");
        let mut sink = plane.entrypoint_sink("plane-ephemeral-disk");
        sink.ingest(StreamKind::Stdout, b"also unrecorded");
        drop(sink);
        plane.release("plane-ephemeral-disk");

        let dir = config::vm_stream_transcript_dir("plane-ephemeral-disk");
        assert!(
            !dir.exists(),
            "an ephemeral run must not create a capture dir at all: {}",
            dir.display()
        );
        assert!(manifest_of("plane-ephemeral-disk").is_none());
        assert!(
            console.exists(),
            "the backend's console capture is outside this plane and must survive \
             an ephemeral release: {}",
            console.display()
        );
    }

    /// A machine that recorded, then restarted under a plan that opted out,
    /// must not leave the old run's transcript behind to be read as the new
    /// one's. Somebody else's recording presented as yours is the one outcome
    /// worse than no recording.
    #[test]
    fn an_ephemeral_restart_discards_the_previous_runs_recording() {
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-ephemeral-restart");
        let first = StreamPlane::new();
        first
            .attach(&capture("plane-ephemeral-restart", &console))
            .expect("first attach");
        std::fs::write(&console, b"first run\n").expect("write the console capture");
        first.release("plane-ephemeral-restart");
        assert!(manifest_of("plane-ephemeral-restart").is_some());

        let second = StreamPlane::new();
        second
            .attach(&ephemeral_capture("plane-ephemeral-restart", &console))
            .expect("second attach");
        second.release("plane-ephemeral-restart");

        assert!(
            manifest_of("plane-ephemeral-restart").is_none(),
            "the previous run's manifest must not survive an ephemeral restart"
        );
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
                retention: StreamRetention::Persist,
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

    /// Stand up what an anchor needs: a host signer and the admitted plan the
    /// run was launched under, both where the seal path looks for them.
    fn admitted_plan_for(vm: &str) -> mvm_core::plan::ExecutionPlan {
        host_keypair::load_or_init_at(&mvm_core::config::mvm_keys_dir())
            .expect("mint a host signer under the isolated home");
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plane-anchor-plan")
            .build();
        plan_persist::write_plan(vm, &plan).expect("persist the admitted plan");
        plan
    }

    fn chain_entries(tenant: &str) -> Vec<serde_json::Value> {
        let dir = crate::audit::emitter::default_audit_dir().expect("audit dir");
        let path = crate::audit::emitter::audit_path_for_tenant(&dir, tenant);
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        content
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("an audit line is JSON"))
            .collect()
    }

    /// The chain stores each entry inside a `SignedEnvelope`; anchors are
    /// returned unwrapped so a caller reads labels off the entry itself.
    fn transcript_anchors(tenant: &str) -> Vec<serde_json::Value> {
        chain_entries(tenant)
            .into_iter()
            .map(|e| e["entry"].clone())
            .filter(|e| e["event"] == crate::supervisor::audit::TRANSCRIPT_SEALED_EVENT)
            .collect()
    }

    #[test]
    fn sealing_a_transcript_anchors_its_root_in_the_audit_chain() {
        // Without this the chain commits to the control-plane events around a
        // run and to nothing the workload actually produced: the transcript
        // stays verifiable on its own terms and unbound to the run.
        let (_env, _tmp) = isolated_home();
        let vm = "plane-anchored";
        admitted_plan_for(vm);

        let console = console_log_for(vm);
        let plane = StreamPlane::new();
        plane.attach(&capture(vm, &console)).expect("attach");
        std::fs::write(&console, b"work happened\n").expect("write console");
        std::thread::sleep(ACCEPT_SETTLE);
        plane.release(vm);

        let manifest = manifest_of(vm).expect("the capture sealed");
        let anchors = transcript_anchors("local");
        assert_eq!(anchors.len(), 1, "exactly one anchor per sealed capture");

        let labels = &anchors[0]["labels"];
        assert_eq!(
            labels[crate::supervisor::audit::LABEL_TRANSCRIPT_ROOT],
            manifest.sealed_root_hex,
            "the anchored root must be the root a reader verifies"
        );
        assert_eq!(labels[crate::supervisor::audit::LABEL_ADOPTED], "false");

        // The whole point of anchoring a ciphertext root: no payload reaches
        // the chain. A byte the workload printed must not appear in any entry.
        let raw = serde_json::to_string(&chain_entries("local")).expect("serialize");
        assert!(
            !raw.contains("work happened"),
            "captured output must never reach the audit chain"
        );
    }

    #[test]
    fn an_adopted_seal_anchors_itself_as_an_incomplete_record() {
        // A rebuilt seal is a floor, not a full account. Anchoring it as
        // though its writer produced it would write a wrong entry rather than
        // leave a missing one.
        let (_env, _tmp) = isolated_home();
        let vm = "plane-anchored-adopted";
        admitted_plan_for(vm);

        let console = console_log_for(vm);
        detached_start(vm, &console, b"nobody was watching\n");
        assert_eq!(manifest_of(vm), None, "the fixture leaves it unsealed");
        assert!(
            transcript_anchors("local").is_empty(),
            "an unsealed capture has nothing to anchor"
        );

        StreamPlane::new().release(vm);

        let manifest = manifest_of(vm).expect("the adopted seal wrote a manifest");
        assert!(manifest.adopted);
        let anchors = transcript_anchors("local");
        assert_eq!(anchors.len(), 1);
        assert_eq!(
            anchors[0]["labels"][crate::supervisor::audit::LABEL_ADOPTED],
            "true",
            "an adopted seal must be distinguishable in the chain"
        );
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
    fn an_adopted_seal_never_lands_on_top_of_a_manifest_that_appeared_mid_rebuild() {
        // The existence check and the write are two steps, and two concurrent
        // stops — or a stop racing the owner's own seal — can both pass the
        // check. The write itself has to be the exclusive one, or an adopted
        // floor overwrites an exact seal.
        let (_env, _tmp) = isolated_home();
        let dir = config::vm_stream_transcript_dir("plane-link-race");
        std::fs::create_dir_all(&dir).expect("capture dir");

        let incumbent = br#"{"whoever":"got here first"}"#;
        std::fs::write(dir.join(MANIFEST_FILENAME), incumbent).expect("incumbent manifest");

        let mut manifest = TranscriptWriter::new(
            &dir,
            aead::Key::from_bytes([0x44; 32]),
            stream_capture_config(StreamCaptureIdentity {
                capture_id: "race".to_string(),
                binding: CaptureBinding {
                    tenant_id: DEFAULT_TENANT.to_string(),
                    vm_name: "plane-link-race".to_string(),
                    session_id: None,
                },
                created_unix_secs: 0,
                recipient: TRANSCRIPT_KEK_RECIPIENT.to_string(),
                wrapped_data_key_b64: String::new(),
            }),
        )
        .sealed_manifest();
        manifest.adopted = true;

        assert!(
            !link_manifest_exclusively(&dir, &manifest).expect("the publish attempt returns"),
            "an adopted seal must report that it did not publish"
        );
        assert_eq!(
            std::fs::read(dir.join(MANIFEST_FILENAME)).expect("read"),
            incumbent,
            "and must leave the manifest that beat it exactly as it was"
        );
        assert!(
            !std::fs::read_dir(&dir)
                .expect("read the capture dir")
                .filter_map(Result::ok)
                .any(|e| e.file_name().to_string_lossy().ends_with(".adopting")),
            "a refused publish must not leave its staging file behind"
        );
    }

    #[test]
    fn a_journal_naming_a_segment_outside_the_capture_dir_seals_nothing() {
        // `adopt_capture` joins journalled names onto the capture dir and
        // opens them for a truncating `set_len` before anything verifies them.
        let (_env, _tmp) = isolated_home();
        let console = console_log_for("plane-traversal");
        detached_start("plane-traversal", &console, b"legitimate output\n");

        let dir = config::vm_stream_transcript_dir("plane-traversal");
        let victim = config::mvm_keys_dir().join("host-signer.ed25519");
        std::fs::create_dir_all(config::mvm_keys_dir()).expect("keys dir");
        std::fs::write(&victim, b"private key material").expect("victim");

        // Point every journalled record at the key, the way a tampered or
        // corrupted mirror would.
        let journal_path = dir.join(journal::JOURNAL_FILENAME);
        let whole = std::fs::read_to_string(&journal_path).expect("read the journal");
        let escape = "../../keys/host-signer.ed25519";
        let rewritten: Vec<String> = whole
            .lines()
            .map(|line| {
                let mut value: serde_json::Value =
                    serde_json::from_str(line).expect("a journal line parses");
                if let Some(file) = value.pointer_mut("/chunk/chunk/file") {
                    *file = serde_json::Value::String(escape.to_string());
                }
                serde_json::to_string(&value).expect("reserialize")
            })
            .collect();
        std::fs::write(&journal_path, format!("{}\n", rewritten.join("\n")))
            .expect("rewrite the journal");

        StreamPlane::new().release("plane-traversal");

        assert_eq!(
            std::fs::read(&victim).expect("the key is still there"),
            b"private key material",
            "nothing outside the capture dir may be opened, let alone truncated"
        );
        assert_eq!(
            manifest_of("plane-traversal"),
            None,
            "a journal naming a path outside its directory must seal nothing"
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
