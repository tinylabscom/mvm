use super::*;
use std::io::{Cursor, Error, ErrorKind, Write};
use std::time::Duration;

/// Wait for producer completion before consuming any queued event. The timeout
/// is a hang guard, not a throughput assertion; disconnect also releases a
/// regressed blocking sender before the test fails.
fn finish_before_consuming(
    task: JoinHandle<VecDeque<EntrypointEvent>>,
    rx: Receiver<EntrypointEvent>,
) -> Vec<EntrypointEvent> {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || done_tx.send(task.join()).unwrap());
    let result = done_rx.recv_timeout(Duration::from_secs(30));
    let tail = match result {
        Ok(result) => result.expect("reader must not panic"),
        Err(error) => {
            drop(rx);
            waiter.join().unwrap();
            panic!("reader waited for the stopped consumer: {error}");
        }
    };
    waiter.join().unwrap();
    rx.into_iter().chain(tail).collect()
}

fn headers(events: &[EntrypointEvent]) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter_map(|event| match event {
            EntrypointEvent::Control { header_json, .. } => {
                Some(serde_json::from_str(header_json).unwrap())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn stopped_reader_consumer_bounds_bytes_and_counts_every_loss() {
    const WRITTEN: u64 = 16 * 1024 * 1024;
    for (stream, cap) in [(CapturedStream::Stdout, 65536), (CapturedStream::Stderr, 0)] {
        let caps = CallCaps {
            stdout_max: cap,
            stderr_max: cap,
            ..CallCaps::default()
        };
        let (tx, rx) = mpsc::sync_channel(HANDOFF_CAPACITY);
        let task = spawn_stream_reader(
            std::io::repeat(7).take(WRITTEN),
            stream,
            Handoff::new(tx, &caps).for_pipe_reader(),
        );
        let events = finish_before_consuming(task, rx);
        let bytes: usize = events
            .iter()
            .map(|event| match event {
                EntrypointEvent::Stdout { chunk } | EntrypointEvent::Stderr { chunk } => {
                    chunk.len()
                }
                _ => 0,
            })
            .sum();
        // The existing ring keeps one newest frame even for a sub-frame cap.
        assert!(bytes <= HANDOFF_CAPACITY * MAX_DATA_CHUNK_SIZE + cap.max(MAX_DATA_CHUNK_SIZE));
        assert!(events.len() <= HANDOFF_CAPACITY + 16 + 1);
        let gaps = headers(&events);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["kind"], GAP_RECORD_KIND);
        assert_eq!(gaps[0]["stage"], "pipe_reader");
        assert_eq!(gaps[0]["stream"], stream.name());
        assert_eq!(
            u64::try_from(bytes).unwrap() + gaps[0]["dropped_bytes"].as_u64().unwrap(),
            WRITTEN
        );
    }
}

#[test]
fn healthy_reader_delivery_is_lossless_and_fifo() {
    let input: Vec<u8> = (0..200_000)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    let (tx, rx) = mpsc::sync_channel(HANDOFF_CAPACITY);
    let task = spawn_stream_reader(
        Cursor::new(input.clone()),
        CapturedStream::Stdout,
        Handoff::new(tx, &CallCaps::default()).for_pipe_reader(),
    );
    let mut events: Vec<_> = rx.into_iter().collect();
    events.extend(task.join().unwrap());
    let actual: Vec<u8> = events
        .iter()
        .flat_map(|event| match event {
            EntrypointEvent::Stdout { chunk } => chunk.as_slice(),
            _ => &[],
        })
        .copied()
        .collect();
    assert_eq!(actual, input);
    assert!(headers(&events).is_empty());
}

struct FailingReader;

struct SingleRead;

impl Read for SingleRead {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        assert_eq!(
            buffer[0], 0,
            "disconnected reader must stop after its offer"
        );
        buffer[0] = 1;
        Ok(1)
    }
}

#[test]
fn disconnected_pump_stops_its_reader() {
    let (tx, rx) = mpsc::sync_channel(1);
    drop(rx);
    let task = spawn_stream_reader(
        SingleRead,
        CapturedStream::Stdout,
        Handoff::new(tx, &CallCaps::default()).for_pipe_reader(),
    );
    assert!(
        task.join()
            .expect("reader stops before reading again")
            .is_empty()
    );
}

impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(Error::other("synthetic-secret-not-for-diagnostics"))
    }
}

#[test]
fn reader_errors_mark_unknown_tail_without_exposing_error_text() {
    let (tx, rx) = mpsc::sync_channel(1);
    let task = spawn_stream_reader(
        FailingReader,
        CapturedStream::Stderr,
        Handoff::new(tx, &CallCaps::default()).for_pipe_reader(),
    );
    let events = finish_before_consuming(task, rx);
    let records = headers(&events);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["kind"], "mvm.stream.capture_incomplete");
    assert_eq!(records[0]["source"], "stderr");
    assert_eq!(records[0]["tail"], "unknown");
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("synthetic-secret")
    );
}

struct InterruptedReader {
    interrupted: bool,
    bytes: Cursor<Vec<u8>>,
}

impl Read for InterruptedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(ErrorKind::Interrupted.into());
        }
        self.bytes.read(buffer)
    }
}

#[test]
fn interrupted_read_retries_without_loss_or_false_gap() {
    let (tx, rx) = mpsc::sync_channel(1);
    let task = spawn_stream_reader(
        InterruptedReader {
            interrupted: false,
            bytes: Cursor::new(b"kept".to_vec()),
        },
        CapturedStream::Stdout,
        Handoff::new(tx, &CallCaps::default()).for_pipe_reader(),
    );
    assert_eq!(
        finish_before_consuming(task, rx),
        vec![EntrypointEvent::Stdout {
            chunk: b"kept".to_vec()
        }]
    );
}

#[test]
fn control_tail_is_preserved_without_waiting_for_queue_space() {
    let (read, mut write) = std::io::pipe().unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    let task = spawn_control_reader(
        OwnedFd::from(read),
        4096,
        Handoff::new(tx, &CallCaps::default()).for_pipe_reader(),
    );
    for n in 0..20 {
        let header = format!("{{\"kind\":\"app.event\",\"seq\":{n}}}");
        write
            .write_all(&u32::try_from(header.len()).unwrap().to_le_bytes())
            .unwrap();
        write.write_all(header.as_bytes()).unwrap();
        write.write_all(&0u32.to_le_bytes()).unwrap();
    }
    drop(write);
    let events = finish_before_consuming(task, rx);
    let records = headers(&events);
    assert_eq!(records.len(), 20);
    for (n, record) in records.iter().enumerate() {
        assert_eq!(record["seq"], n);
    }
}

#[test]
fn disconnected_pump_stops_control_reader_before_eof() {
    let (read, mut write) = std::io::pipe().unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    drop(rx);
    let task = spawn_control_reader(
        OwnedFd::from(read),
        4096,
        Handoff::new(tx, &CallCaps::default()).for_pipe_reader(),
    );
    write.write_all(&0u32.to_le_bytes()).unwrap();
    write.write_all(&0u32.to_le_bytes()).unwrap();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let observer = std::thread::spawn(move || done_tx.send(task.join()).unwrap());
    let result = done_rx.recv_timeout(Duration::from_secs(30));
    // Release a regressed reader before asserting, while still proving it should
    // have finished without waiting for the writer to close.
    drop(write);
    observer.join().unwrap();
    assert!(result.expect("reader waited for EOF").unwrap().is_empty());
}

#[test]
fn reader_panic_reports_incomplete_capture_instead_of_panicking_the_pump() {
    let reader =
        std::thread::spawn(|| -> VecDeque<EntrypointEvent> { panic!("test reader panic") });
    let mut events = Vec::new();
    finish_reader(reader, &mut |event| events.push(event));
    let records = headers(&events);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["kind"], "mvm.stream.capture_incomplete");
    assert_eq!(records[0]["tail"], "unknown");
}

#[test]
fn control_read_error_marks_an_unknown_tail() {
    let dir = tempfile::tempdir().unwrap();
    let directory = std::fs::File::open(dir.path()).unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    let task = spawn_control_reader(
        OwnedFd::from(directory),
        1024,
        Handoff::new(tx, &CallCaps::default()).for_pipe_reader(),
    );
    let events = finish_before_consuming(task, rx);
    let records = headers(&events);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["kind"], "mvm.stream.capture_incomplete");
    assert_eq!(records[0]["source"], "control");
    assert_eq!(records[0]["tail"], "unknown");
}
