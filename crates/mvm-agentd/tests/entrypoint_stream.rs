//! Wire-level tests for the streamed `RunEntrypoint` response.
//!
//! One layer up from the pump's own regression guard: the pump takes care to
//! emit a chunk the moment the kernel has one, and these assert the transport
//! does not put the buffering back by replaying those chunks after the child
//! has exited.
//!
//! The transport is the real one — a `UnixStream` pair carrying the same
//! length-prefixed `GuestResponse` frames the agent's control socket does.
//! Only the authenticated-session envelope is absent, which changes nothing
//! about arrival order or frame count.
//!
//! The workload is `/bin/sh` reading its script from stdin, which is exactly
//! how a wrapper is invoked in production: no argv, `env_clear()`, script
//! bytes piped in. It is an ELF binary, so the `/proc/self/fd/<n>` argv[0]
//! that `spawn_path` synthesizes on Linux loads it directly.

use std::fs::File;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use mvm_agentd::entrypoint::ProcessResourceLimits;
use mvm_agentd::entrypoint::{CallCaps, CancellationToken, EntrypointCall, ValidatedEntrypoint};
use mvm_agentd::entrypoint_stream::stream_call;
use mvm_agentd::vsock::{
    EntrypointEvent, GuestResponse, RunEntrypointError, read_frame, write_frame,
};

/// `env_clear()` leaves the script with no `PATH`, so anything it runs that
/// is not a shell builtin has to be findable through this.
const SCRIPT_PATH: &str = "/usr/bin:/bin:/usr/local/bin";

/// Wall-clock budget for the calls whose subject is *not* the deadline. Long
/// enough that a loaded machine cannot turn a scheduling delay into a
/// timeout, which is the whole reason it exists.
const GENEROUS_TIMEOUT: Duration = Duration::from_secs(60);

/// Backstop so a frame that never arrives fails the test instead of hanging
/// it. Set once, at creation: macOS refuses a `setsockopt` on a socket whose
/// peer has already hung up, which is exactly the state a finished call
/// leaves behind, so re-arming it per read would be a race.
const HOST_READ_TIMEOUT: Duration = Duration::from_secs(30);

fn loopback_pair() -> (UnixStream, UnixStream) {
    let (host, guest) = UnixStream::pair().expect("a socket pair");
    host.set_read_timeout(Some(HOST_READ_TIMEOUT))
        .expect("host read timeout");
    (host, guest)
}

/// `/bin/sh` as a validated wrapper. Production builds one of these from
/// `EntrypointPolicy::validate`; a test names the binary directly, as the
/// other runner-side suites in this crate do.
fn shell_entrypoint() -> ValidatedEntrypoint {
    let resolved = PathBuf::from("/bin/sh");
    let file = File::open(&resolved).expect("/bin/sh");
    ValidatedEntrypoint {
        resolved,
        file,
        use_resolved_path: false,
    }
}

fn caps() -> CallCaps {
    CallCaps {
        kill_grace_period: Duration::from_millis(1500),
        poll_interval: Duration::from_millis(20),
        ..CallCaps::default()
    }
}

/// Serve one `RunEntrypoint` call onto `guest`, framing each event as it
/// arrives and the terminal last — the guest half of the agent's handler.
fn serve_one_run_entrypoint(guest: UnixStream, script: &str, timeout: Duration) {
    serve_with_caps(guest, script, timeout, caps());
}

/// As [`serve_one_run_entrypoint`], with the per-call caps spelled out — for
/// the tests whose subject is a bound rather than the transport.
fn serve_with_caps(mut guest: UnixStream, script: &str, timeout: Duration, caps: CallCaps) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let entrypoint = shell_entrypoint();
    let call = EntrypointCall {
        entrypoint: &entrypoint,
        cwd: tmp.path(),
        stdin: script.as_bytes(),
        timeout,
        caps,
        resource_limits: None,
        cancellation: None,
        env: vec![("PATH".to_string(), SCRIPT_PATH.to_string())],
        stream_input: false,
    };
    let terminal = stream_call(call, &mut |event| {
        write_frame(&mut guest, &GuestResponse::EntrypointEvent(event)).expect("frame an event");
    });
    write_frame(&mut guest, &GuestResponse::EntrypointEvent(terminal)).expect("frame the terminal");
}

/// `None` on end-of-stream or on the read timeout above.
fn next_frame(host: &mut UnixStream) -> Option<GuestResponse> {
    read_frame::<GuestResponse>(host).ok()
}

/// Read frames until the terminal one, returning `(non_terminal, terminal)`.
fn read_to_terminal(host: &mut UnixStream) -> (Vec<EntrypointEvent>, EntrypointEvent) {
    let mut seen = Vec::new();
    loop {
        match next_frame(host) {
            Some(GuestResponse::EntrypointEvent(event)) if event.is_terminal() => {
                return (seen, event);
            }
            Some(GuestResponse::EntrypointEvent(event)) => seen.push(event),
            other => panic!("expected an EntrypointEvent frame, got {other:?}"),
        }
    }
}

fn concat_stdout(events: &[EntrypointEvent]) -> Vec<u8> {
    events
        .iter()
        .filter_map(|e| match e {
            EntrypointEvent::Stdout { chunk } => Some(chunk.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

fn concat_stderr(events: &[EntrypointEvent]) -> Vec<u8> {
    events
        .iter()
        .filter_map(|e| match e {
            EntrypointEvent::Stderr { chunk } => Some(chunk.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

/// Every control record's header, decoded.
fn control_headers(events: &[EntrypointEvent]) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter_map(|event| match event {
            EntrypointEvent::Control { header_json, .. } => Some(
                serde_json::from_str(header_json)
                    .unwrap_or_else(|_| serde_json::Value::String(header_json.clone())),
            ),
            _ => None,
        })
        .collect()
}

/// One fd-3 control frame: `header_len | header | payload_len | payload`.
fn fd3_frame(header_json: &str, payload: &[u8]) -> Vec<u8> {
    let header = header_json.as_bytes();
    let mut frame = Vec::new();
    frame.extend_from_slice(&(header.len() as u32).to_le_bytes());
    frame.extend_from_slice(header);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn entrypoint_rpc_frames_reach_the_host_before_the_child_exits() {
    // The same shape as the pump's regression guard, one layer up: the
    // transport must not re-buffer what the pump took care to stream.
    let (mut host, guest) = loopback_pair();
    let serving = std::thread::spawn(move || {
        serve_one_run_entrypoint(guest, "printf early; sleep 3", GENEROUS_TIMEOUT)
    });

    let started = Instant::now();
    let first = next_frame(&mut host).expect("a frame must arrive, not time out");
    let waited = started.elapsed();
    match first {
        GuestResponse::EntrypointEvent(EntrypointEvent::Stdout { chunk }) => {
            assert_eq!(chunk, b"early")
        }
        other => panic!("expected a stdout frame, got {other:?}"),
    }
    assert!(
        waited < Duration::from_millis(1500),
        "the first frame took {waited:?}; the child holds the process open for 3s after \
         printing, so anything near that is the transport replaying buffers at exit"
    );

    // Everything above is the assertion; the rest only reaps. Returning here
    // would end the test while the serving thread still owns a live child,
    // orphaning `sleep 3` onto init.
    let (_, terminal) = read_to_terminal(&mut host);
    assert_eq!(terminal, EntrypointEvent::Exit { code: 0 });
    serving.join().expect("serving thread");
}

#[test]
fn one_stream_arrives_in_order_and_exactly_one_terminal_ends_the_call() {
    // Interleaving *between* stdout and stderr now reflects arrival order,
    // so it is deliberately not asserted. Order within each stream is, and
    // so is the frame count that ends the response: a second terminal would
    // desync the host, and none would hang it.
    let (mut host, guest) = loopback_pair();
    let serving = std::thread::spawn(move || {
        serve_one_run_entrypoint(
            guest,
            "printf a; printf b; printf c >&2; printf d; exit 5",
            GENEROUS_TIMEOUT,
        )
    });

    let (events, terminal) = read_to_terminal(&mut host);
    assert_eq!(concat_stdout(&events), b"abd");
    assert_eq!(concat_stderr(&events), b"c");
    assert_eq!(terminal, EntrypointEvent::Exit { code: 5 });
    // The guest wrote nothing after the terminal and hung up, so the next
    // read is the end of the stream rather than a second terminal.
    assert!(
        next_frame(&mut host).is_none(),
        "the terminal must be the last frame of the call"
    );
    serving.join().expect("serving thread");
}

#[test]
fn a_control_record_reaches_the_wire_and_a_forged_one_does_not() {
    // fd 3 is the workload's to write, so this is where a forged gap marker
    // would enter the streamed response. A consumer downstream cannot tell a
    // forged agent-authored record from a real one, so the refusal has to
    // survive the rewiring that put these events on the wire live.
    let dir = tempfile::tempdir().expect("tempdir");
    let frames = dir.path().join("fd3-frames");
    let mut wire = fd3_frame(r#"{"kind":"mvm.stream.gap","after_seq":99}"#, b"");
    wire.extend_from_slice(&fd3_frame(r#"{"kind":"app.log"}"#, b"payload-bytes"));
    std::fs::write(&frames, &wire).expect("write fd-3 fixture");

    let script = format!("cat {} >&3; printf done", frames.display());
    let (mut host, guest) = loopback_pair();
    let serving =
        std::thread::spawn(move || serve_one_run_entrypoint(guest, &script, GENEROUS_TIMEOUT));

    let (events, terminal) = read_to_terminal(&mut host);
    assert_eq!(terminal, EntrypointEvent::Exit { code: 0 });
    assert_eq!(concat_stdout(&events), b"done");
    let controls: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, EntrypointEvent::Control { .. }))
        .collect();
    assert_eq!(
        controls.len(),
        1,
        "only the workload's own record may reach the wire, got {controls:?}"
    );
    match controls[0] {
        EntrypointEvent::Control {
            header_json,
            payload,
        } => {
            assert_eq!(header_json, r#"{"kind":"app.log"}"#);
            assert_eq!(payload, b"payload-bytes");
        }
        other => panic!("expected a control event, got {other:?}"),
    }
    serving.join().expect("serving thread");
}

#[test]
fn a_slow_host_does_not_stall_the_child() {
    // The host reads one frame and then stops. 4 MiB of output is far past
    // any socket buffer, so the guest's consumer is parked on a full socket
    // long before the child is done — and the child must still run to its own
    // clean end while it is. Were the wire written from the pump's reader
    // threads, the child's pipe would fill at 64 KiB, the child would block
    // mid-write, and the marker would never appear.
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("child-finished");
    let script = format!(
        "printf early; head -c 4194304 /dev/zero; : > {}",
        marker.display()
    );

    let (mut host, guest) = loopback_pair();
    let serving =
        std::thread::spawn(move || serve_one_run_entrypoint(guest, &script, GENEROUS_TIMEOUT));

    next_frame(&mut host).expect("a first frame");

    let wait_until = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < wait_until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        marker.exists(),
        "the child must finish writing while the host has stopped reading"
    );

    let (_, terminal) = read_to_terminal(&mut host);
    assert_eq!(terminal, EntrypointEvent::Exit { code: 0 });
    serving.join().expect("serving thread");
}

#[test]
fn a_stopped_host_bounds_guest_memory_and_the_call_reports_the_gap() {
    // The bound the streaming rewiring has to carry. Reader threads never stop
    // reading the child's pipe — by design — and the wire is several times the
    // width of that pipe, so a host that stops reading makes the guest's queue
    // grow at the difference for the whole deadline. Here the host reads one
    // frame and then waits for the child to write 8 MiB; what finally arrives
    // must be bounded by the retention caps, not by what the child produced,
    // and the loss must be reported rather than passed off as complete output.
    const WRITTEN: usize = 8 * 1024 * 1024;
    const RETENTION: usize = 128 * 1024;
    // Retention plus the hand-off channel plus whatever the socket itself
    // buffered. Every term is a fixed bound; the point is that none of them
    // scale with `WRITTEN`.
    const DELIVERED_MAX: usize = 2 * 1024 * 1024;

    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("child-finished");
    let script = format!(
        "printf early; head -c {WRITTEN} /dev/zero; : > {}",
        marker.display()
    );
    let bounded_caps = CallCaps {
        stdout_max: RETENTION,
        stderr_max: RETENTION,
        ..caps()
    };

    let (mut host, guest) = loopback_pair();
    let serving =
        std::thread::spawn(move || serve_with_caps(guest, &script, GENEROUS_TIMEOUT, bounded_caps));

    next_frame(&mut host).expect("a first frame");
    let wait_until = Instant::now() + Duration::from_secs(30);
    while !marker.exists() && Instant::now() < wait_until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        marker.exists(),
        "the child must finish writing while the host has stopped reading"
    );

    let (events, terminal) = read_to_terminal(&mut host);
    assert_eq!(terminal, EntrypointEvent::Exit { code: 0 });

    let delivered = concat_stdout(&events).len();
    assert!(
        delivered < DELIVERED_MAX,
        "the guest held {delivered} bytes for a stopped host; an unbounded hand-off would have \
         grown to the {WRITTEN} the child wrote"
    );
    assert!(delivered > 0, "the newest output must still survive");

    let headers = control_headers(&events);
    assert_eq!(
        headers.len(),
        1,
        "expected exactly one gap record, got {headers:?}"
    );
    assert_eq!(headers[0]["kind"], "mvm.stream.gap");
    assert_eq!(headers[0]["stream"], "stdout");
    assert!(
        headers[0]["dropped_bytes"]
            .as_u64()
            .is_some_and(|dropped| dropped > 0),
        "the gap must say what was lost: {}",
        headers[0]
    );
    serving.join().expect("serving thread");
}

#[test]
fn only_the_agents_own_gap_record_reaches_a_host_that_stopped_reading() {
    // The two gap paths in one call. The workload writes a forged
    // `mvm.stream.gap` to fd 3 — the one channel it can write — while
    // producing enough output that the agent has a real gap of its own to
    // report. Only the agent's may arrive: a verifier cannot tell the two
    // apart downstream, and one that trusts a forged marker blesses a chain
    // skipping output it never saw.
    const WRITTEN: usize = 8 * 1024 * 1024;
    const FORGED_AFTER_SEQ: u64 = 99;

    let dir = tempfile::tempdir().expect("tempdir");
    let frames = dir.path().join("fd3-frames");
    let marker = dir.path().join("child-finished");
    std::fs::write(
        &frames,
        fd3_frame(
            &format!(r#"{{"kind":"mvm.stream.gap","after_seq":{FORGED_AFTER_SEQ}}}"#),
            b"",
        ),
    )
    .expect("write fd-3 fixture");
    let script = format!(
        "cat {} >&3; head -c {WRITTEN} /dev/zero; : > {}",
        frames.display(),
        marker.display()
    );
    let bounded_caps = CallCaps {
        stdout_max: 128 * 1024,
        ..caps()
    };

    let (mut host, guest) = loopback_pair();
    let serving =
        std::thread::spawn(move || serve_with_caps(guest, &script, GENEROUS_TIMEOUT, bounded_caps));

    next_frame(&mut host).expect("a first frame");
    let wait_until = Instant::now() + Duration::from_secs(30);
    while !marker.exists() && Instant::now() < wait_until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(marker.exists(), "the child must finish writing");

    let (events, terminal) = read_to_terminal(&mut host);
    assert_eq!(terminal, EntrypointEvent::Exit { code: 0 });
    let gaps: Vec<_> = control_headers(&events)
        .into_iter()
        .filter(|header| header["kind"] == "mvm.stream.gap")
        .collect();
    assert_eq!(
        gaps.len(),
        1,
        "exactly one gap record — the agent's — may reach the host, got {gaps:?}"
    );
    assert_ne!(
        gaps[0]["after_seq"].as_u64(),
        Some(FORGED_AFTER_SEQ),
        "the record that arrived is the workload's forgery"
    );
    assert!(
        gaps[0]["dropped_bytes"]
            .as_u64()
            .is_some_and(|dropped| dropped > 0)
    );
    serving.join().expect("serving thread");
}

#[test]
fn an_unframeable_control_record_does_not_end_the_call_early() {
    // A header only has to be valid UTF-8, and control bytes cost six
    // characters each once escaped — so a record the fd-3 decoder accepts can
    // still encode past the response frame cap. The writer answers an
    // oversized frame with a generic error response, which a host reading
    // until terminal treats as the end of the call: without a bound at
    // emission, one such record discards every event behind it, including the
    // terminal.
    let dir = tempfile::tempdir().expect("tempdir");
    let frames = dir.path().join("fd3-frames");
    std::fs::write(&frames, fd3_frame(&"\u{1}".repeat(64 * 1024), b""))
        .expect("write fd-3 fixture");

    let script = format!("cat {} >&3; printf done", frames.display());
    let (mut host, guest) = loopback_pair();
    let serving =
        std::thread::spawn(move || serve_one_run_entrypoint(guest, &script, GENEROUS_TIMEOUT));

    let (events, terminal) = read_to_terminal(&mut host);
    assert_eq!(terminal, EntrypointEvent::Exit { code: 0 });
    assert_eq!(
        concat_stdout(&events),
        b"done",
        "output behind the unframeable record must still arrive"
    );
    let headers = control_headers(&events);
    assert_eq!(
        headers.len(),
        1,
        "one record in, one record out: {headers:?}"
    );
    assert_eq!(headers[0]["kind"], "mvm.stream.control_dropped");
    assert_eq!(headers[0]["header_bytes"], 64 * 1024);
    serving.join().expect("serving thread");
}

#[test]
fn a_blocked_consumer_does_not_defer_the_child_deadline() {
    // The witness for running the pump and its consumer on separate threads.
    // A consumer invoked from the pump's own loop parks that loop, and the
    // deadline is only checked between drains — so a workload past its
    // timeout would go on running for exactly as long as the consumer blocks.
    // Here the wrapper ignores SIGTERM and never exits, so the call can only
    // end by walking the whole kill ladder, and when that ladder starts is
    // the thing being measured.
    const CONSUMER_BLOCK: Duration = Duration::from_millis(2000);
    let tmp = tempfile::tempdir().expect("tempdir");
    let entrypoint = shell_entrypoint();
    let call = EntrypointCall {
        entrypoint: &entrypoint,
        cwd: tmp.path(),
        stdin: b"trap '' TERM; printf early; while :; do sleep 1; done",
        timeout: Duration::from_millis(300),
        caps: caps(),
        resource_limits: None,
        cancellation: None,
        env: vec![("PATH".to_string(), SCRIPT_PATH.to_string())],
        stream_input: false,
    };

    let started = Instant::now();
    let mut blocked = false;
    let terminal = stream_call(call, &mut |_| {
        if !blocked {
            blocked = true;
            std::thread::sleep(CONSUMER_BLOCK);
        }
    });
    let elapsed = started.elapsed();

    assert!(blocked, "the consumer never saw an event to block on");
    match terminal {
        EntrypointEvent::Error { kind, .. } => assert_eq!(kind, RunEntrypointError::Timeout),
        other => panic!("expected a Timeout terminal, got {other:?}"),
    }
    // SIGTERM at the 300 ms deadline, SIGKILL 1500 ms later: ~1800 ms, and
    // the 2000 ms the consumer spends blocked overlaps all of it. Deferring
    // the ladder until the consumer returns would put the same work at
    // ~3500 ms instead.
    assert!(
        elapsed < Duration::from_millis(2800),
        "the kill ladder waited for the consumer; call took {elapsed:?}"
    );
}

#[test]
fn cancellation_kills_the_active_process_group_and_reports_canceled() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let entrypoint = shell_entrypoint();
    let cancellation = CancellationToken::default();
    let call = EntrypointCall {
        entrypoint: &entrypoint,
        cwd: tmp.path(),
        stdin: b"trap '' TERM; while :; do sleep 1; done",
        timeout: Duration::from_secs(30),
        caps: CallCaps {
            kill_grace_period: Duration::from_millis(100),
            poll_interval: Duration::from_millis(10),
            ..caps()
        },
        resource_limits: None,
        cancellation: Some(cancellation.clone()),
        env: vec![("PATH".to_string(), SCRIPT_PATH.to_string())],
        stream_input: false,
    };

    let started = Instant::now();
    let terminal = std::thread::scope(|scope| {
        let running = scope.spawn(move || stream_call(call, &mut |_| {}));
        std::thread::sleep(Duration::from_millis(100));
        cancellation.request();
        running.join().expect("canceled call")
    });

    assert!(
        started.elapsed() < Duration::from_secs(3),
        "cancellation waited for the wall-clock deadline"
    );
    assert!(matches!(
        terminal,
        EntrypointEvent::Error {
            kind: RunEntrypointError::Canceled,
            ..
        }
    ));
}

#[test]
#[cfg(target_os = "linux")]
fn child_cpu_budget_is_kernel_enforced() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let entrypoint = shell_entrypoint();
    let call = EntrypointCall {
        entrypoint: &entrypoint,
        cwd: tmp.path(),
        stdin: b"while :; do :; done",
        timeout: Duration::from_secs(5),
        caps: caps(),
        resource_limits: Some(ProcessResourceLimits {
            address_space_bytes: 256 * 1024 * 1024,
            cpu_millis: 10,
        }),
        cancellation: None,
        env: vec![("PATH".to_string(), SCRIPT_PATH.to_string())],
        stream_input: false,
    };

    let terminal = stream_call(call, &mut |_| {});
    assert!(
        matches!(
            terminal,
            EntrypointEvent::Error {
                kind: RunEntrypointError::WrapperCrashed,
                ..
            }
        ),
        "CPU exhaustion must terminate the child, got {terminal:?}"
    );
}
