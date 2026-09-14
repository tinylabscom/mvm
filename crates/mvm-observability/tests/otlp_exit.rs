//! A process that ends through `mvm_observability::exit` still delivers its
//! queued spans.
//!
//! `std::process::exit` skips destructors, so the property only exists in a
//! real process that really exits. Each test re-runs this test binary as a
//! child, filtered to itself, and the child does the exiting; the parent plays
//! the collector and checks what arrived.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mvm_observability::LogFormat;

/// Set in the child, to tell it to do the exiting.
const CHILD_ENV: &str = "MVM_OTLP_EXIT_TEST_CHILD";
const CHILD_EXIT_CODE: i32 = 7;
const SPAN_NAME: &str = "span_queued_before_an_early_exit";

/// Variables that would point the child at a collector the test did not open,
/// or filter out the span it emits.
const INHERITED_OTLP_ENV: &[&str] = &[
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TIMEOUT",
    "MVM_OTLP_FILTER",
];

/// In the child, emit one span and exit through the helper; never returns.
/// In the parent, does nothing.
fn run_as_child_if_requested() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let _guard = mvm_observability::init(LogFormat::Json);
    tracing::info_span!(SPAN_NAME).in_scope(|| {});
    mvm_observability::exit(CHILD_EXIT_CODE);
}

/// Re-run this binary, filtered to exactly `test`, as the child, exporting to
/// a collector on `port` if one is given.
fn spawn_child(test: &str, port: Option<u16>) -> Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([test, "--exact", "--nocapture", "--test-threads", "1"])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::null());
    for name in INHERITED_OTLP_ENV {
        command.env_remove(name);
    }
    if let Some(port) = port {
        command.env(
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            format!("http://127.0.0.1:{port}/v1/traces"),
        );
    }
    command.spawn().unwrap()
}

fn wait_with_deadline(child: &mut Child, deadline: Duration) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if started.elapsed() > deadline {
            let _ = child.kill();
            panic!("child did not exit within {deadline:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Accept one request, answer 200, and hand back the body.
fn collect_one_body(listener: TcpListener) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let _ = tx.send(String::from_utf8(body).unwrap());
    });
    rx
}

#[test]
fn exiting_through_the_helper_flushes_spans_the_process_had_queued() {
    run_as_child_if_requested();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies = collect_one_body(listener);

    let mut child = spawn_child(
        "exiting_through_the_helper_flushes_spans_the_process_had_queued",
        Some(port),
    );
    let status = wait_with_deadline(&mut child, Duration::from_secs(60));
    assert_eq!(status.code(), Some(CHILD_EXIT_CODE));

    // The child has exited, so a body that arrives was sent before it did.
    let body = bodies
        .recv_timeout(Duration::from_secs(5))
        .expect("the collector received no export before the child exited");
    assert!(body.contains(SPAN_NAME), "{body}");
}

#[test]
fn exiting_through_the_helper_without_a_collector_exits_promptly_with_the_code() {
    run_as_child_if_requested();

    let started = Instant::now();
    let mut child = spawn_child(
        "exiting_through_the_helper_without_a_collector_exits_promptly_with_the_code",
        None,
    );
    let status = wait_with_deadline(&mut child, Duration::from_secs(60));
    assert_eq!(status.code(), Some(CHILD_EXIT_CODE));
    // Generous for a loaded CI host; far below the ten-second export timeout
    // a pointless wait would cost.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "exit without an exporter waited: {:?}",
        started.elapsed()
    );
}
