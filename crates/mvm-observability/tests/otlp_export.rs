//! End-to-end checks of OTLP export against a local HTTP listener.
//!
//! These use a real socket and the real HTTP client, because the properties
//! that matter — the request a collector sees, and that a collector which never
//! answers cannot stall the instrumented program — live in that seam.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mvm_observability::otlp::{OtlpConfig, spawn_exporter};
use tracing_subscriber::prelude::*;

/// One HTTP request as the collector received it.
struct Received {
    request_line: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Received {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    let length: usize = headers["content-length"].parse().unwrap();
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    Received {
        request_line: request_line.trim_end().to_string(),
        headers,
        body,
    }
}

fn config_for(listener: &TcpListener, extra: &[(&str, &str)]) -> OtlpConfig {
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let mut vars: HashMap<String, String> =
        HashMap::from([("OTEL_EXPORTER_OTLP_ENDPOINT".to_string(), endpoint)]);
    vars.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    OtlpConfig::from_lookup(|name| vars.get(name).cloned(), "otlp-test")
        .unwrap()
        .unwrap()
}

#[test]
fn a_local_collector_receives_a_well_formed_export_with_the_configured_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = config_for(
        &listener,
        &[
            ("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer%20t0ken"),
            ("OTEL_SERVICE_NAME", "export-test"),
        ],
    );
    let (received_tx, received_rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let received = read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            .unwrap();
        received_tx.send(received).unwrap();
    });

    let (layer, guard) = spawn_exporter(&config).unwrap();
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info_span!("export_me", vm = "alpha").in_scope(|| {
            tracing::info!("inside");
        });
    });
    drop(guard);

    let received = received_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(received.request_line, "POST /v1/traces HTTP/1.1");
    assert_eq!(received.headers["content-type"], "application/json");
    assert_eq!(received.headers["authorization"], "Bearer t0ken");

    let body: serde_json::Value = serde_json::from_slice(&received.body).unwrap();
    let resource = &body["resourceSpans"][0]["resource"]["attributes"];
    assert!(
        resource
            .as_array()
            .unwrap()
            .iter()
            .any(|kv| kv["key"] == "service.name" && kv["value"]["stringValue"] == "export-test")
    );
    let span = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
    assert_eq!(span["name"], "export_me");
    assert_eq!(span["traceId"].as_str().unwrap().len(), 32);
    assert_eq!(span["events"][0]["name"], "inside");
}

#[test]
fn a_collector_that_never_answers_neither_blocks_span_close_nor_holds_the_guard_past_its_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let timeout = Duration::from_millis(1500);
    let config = config_for(&listener, &[("OTEL_EXPORTER_OTLP_TIMEOUT", "1500")]);
    let (accepted_tx, accepted_rx) = mpsc::channel();
    thread::spawn(move || {
        // Accept and hold every connection open without ever responding.
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream.unwrap());
            let _ = accepted_tx.send(());
        }
    });

    let (layer, guard) = spawn_exporter(&config).unwrap();
    let subscriber = tracing_subscriber::registry().with(layer);
    let dispatch = tracing::Dispatch::new(subscriber);

    // The first span goes out on the flush interval; once the listener has the
    // connection, the export thread is parked waiting for a response.
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info_span!("first").in_scope(|| {});
    });
    accepted_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    let started = Instant::now();
    tracing::dispatcher::with_default(&dispatch, || {
        for _ in 0..5000 {
            tracing::info_span!("while_stalled").in_scope(|| {});
        }
    });
    let closing = started.elapsed();
    assert!(
        closing < timeout,
        "closing spans waited on the stalled export: {closing:?}"
    );

    let started = Instant::now();
    drop(guard);
    let flushing = started.elapsed();
    assert!(
        flushing < timeout + Duration::from_secs(1),
        "guard drop was not bounded by the export timeout: {flushing:?}"
    );
}
