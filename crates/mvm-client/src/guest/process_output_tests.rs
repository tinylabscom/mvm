use super::*;
use std::io::Read;
use std::sync::mpsc;
use std::time::Instant;

#[test]
fn channels_and_chunk_bytes_remain_separate() {
    let mut window = Window::default();
    window.event(&ProcWaitEvent::Stdout {
        chunk: b"out\n".to_vec(),
    });
    window.event(&ProcWaitEvent::Stderr {
        chunk: b"err\n".to_vec(),
    });
    window.event(&ProcWaitEvent::Exit { code: 7 });
    let snapshot = window.snapshot("process");
    assert_eq!(snapshot.records[0].stream, ProcessOutputStream::Stdout);
    assert_eq!(snapshot.records[0].data, b"out\n");
    assert_eq!(snapshot.records[1].stream, ProcessOutputStream::Stderr);
    assert_eq!(snapshot.records[1].data, b"err\n");
    assert_eq!(snapshot.end, Some(ProcessOutputEnd::Exited { code: 7 }));
}

#[test]
fn newest_window_reports_record_and_byte_loss() {
    let mut window = Window::default();
    for _ in 0..MAX_RECORDS + 3 {
        window.push(ProcessOutputStream::Stdout, b"x");
    }
    let snapshot = window.snapshot("process");
    assert_eq!(snapshot.records.len(), MAX_RECORDS);
    assert_eq!(snapshot.dropped_records, 3);
    assert_eq!(snapshot.dropped_bytes, 3);
    window.push(ProcessOutputStream::Stderr, &vec![b'z'; MAX_BYTES + 17]);
    let snapshot = window.snapshot("process");
    assert_eq!(snapshot.records.len(), 1);
    assert_eq!(snapshot.records[0].data.len(), MAX_BYTES);
    assert_eq!(snapshot.dropped_bytes, (MAX_RECORDS + 20) as u64);
}

#[test]
fn failures_withhold_payload_and_never_echo_guest_error_text() {
    let mut window = Window::default();
    window.push(ProcessOutputStream::Stdout, b"old output");
    window.event(&ProcWaitEvent::Error {
        kind: mvm_agentd::vsock::ProcErrorKind::UnknownToken,
        message: "guest-controlled-sensitive-message".into(),
    });
    let snapshot = window.snapshot("process");
    assert_eq!(snapshot.end, Some(ProcessOutputEnd::Unavailable));
    assert!(snapshot.records.is_empty());
    assert!(!format!("{snapshot:?}").contains("sensitive"));
}

#[test]
fn every_terminal_is_distinct_and_backpressure_is_not_a_terminal() {
    let mut pressured = Window::default();
    pressured.event(&ProcWaitEvent::Backpressure {
        reason: mvm_core::domain::instance::BackpressureReason::OutputConsumerSlow,
        detail: "not copied into the observation".into(),
    });
    assert!(pressured.snapshot("process").backpressure);
    assert!(pressured.snapshot("process").end.is_none());
    pressured.push(ProcessOutputStream::Stdout, b"resumed");
    assert!(!pressured.snapshot("process").backpressure);
    for (event, expected) in [
        (
            ProcWaitEvent::Exit { code: 0 },
            ProcessOutputEnd::Exited { code: 0 },
        ),
        (
            ProcWaitEvent::Killed { signal: 9 },
            ProcessOutputEnd::Killed { signal: 9 },
        ),
        (ProcWaitEvent::TimedOut, ProcessOutputEnd::TimedOut),
    ] {
        let mut window = Window::default();
        window.event(&event);
        assert_eq!(window.snapshot("process").end, Some(expected));
    }
}

fn fixture(token: &str, data: &[u8]) -> ProcessOutputReader {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let bytes = data.to_vec();
    ProcessOutputReader::spawn(stream, token.to_string(), move |_, window| {
        let mut window = lock(window);
        window.push(ProcessOutputStream::Stdout, &bytes);
        window.end = Some(ProcessOutputEnd::Exited { code: 0 });
        Ok(())
    })
    .unwrap()
}

#[test]
fn closing_interrupts_a_silent_connection_without_sending_a_kill() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let (entered, started) = mpsc::channel();
    let mut reader = ProcessOutputReader::spawn(stream, "quiet".into(), move |stream, _| {
        entered.send(()).unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        Ok(())
    })
    .unwrap();
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    let now = Instant::now();
    assert!(reader.close());
    assert!(now.elapsed() < STOP_GRACE);
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    assert_eq!(reader.snapshot().end, Some(ProcessOutputEnd::Closed));
}

#[test]
fn snapshots_do_not_consume_the_local_window_and_debug_hides_payload() {
    let mut reader = fixture("one", b"private-output");
    let worker = reader.worker.as_ref().unwrap();
    worker.done.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(reader.snapshot(), reader.snapshot());
    assert!(!format!("{:?}", reader.snapshot()).contains("private-output"));
    assert!(reader.close());
}

#[test]
fn replacing_a_process_never_reuses_its_old_window() {
    let outputs = ProcessOutputs::default();
    outputs
        .follow_with("vm", "old", || Ok(fixture("old", b"old")))
        .unwrap();
    outputs
        .follow_with("vm", "new", || Ok(fixture("new", b"new")))
        .unwrap();
    assert_eq!(outputs.snapshot("vm").unwrap().token, "new");
    outputs.forget("vm");
    assert!(outputs.snapshot("vm").is_none());
}

#[test]
fn repeated_follow_of_the_same_token_never_reopens_the_guest_stream() {
    let outputs = ProcessOutputs::default();
    outputs
        .follow_with("vm", "same", || Ok(fixture("same", b"one")))
        .unwrap();
    outputs
        .follow_with("vm", "same", || panic!("must not reopen"))
        .unwrap();
    assert_eq!(outputs.snapshot("vm").unwrap().token, "same");
}

#[test]
fn invalid_names_and_tokens_refuse_before_any_transport() {
    for (name, token) in [("../outside", "p"), ("valid", ""), ("valid", "bad\0token")] {
        assert!(ProcessOutputReader::open(name, token).is_err());
    }
}

#[test]
fn invalid_selection_cannot_retire_a_valid_observation() {
    let outputs = ProcessOutputs::default();
    outputs
        .follow_with("vm", "same", || Ok(fixture("same", b"one")))
        .unwrap();
    assert!(outputs.follow("vm", "").is_err());
    assert_eq!(outputs.snapshot("vm").unwrap().token, "same");
}

#[test]
fn concurrent_replacement_cannot_publish_the_previous_selection() {
    let outputs = Arc::new(ProcessOutputs::default());
    let old = Arc::clone(&outputs);
    let (entered, started) = mpsc::channel();
    let (resume, blocked) = mpsc::channel();
    let opening = std::thread::spawn(move || {
        old.follow_with("vm", "old", || {
            entered.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(fixture("old", b"obsolete"))
        })
    });
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    outputs
        .follow_with("vm", "new", || Ok(fixture("new", b"current")))
        .unwrap();
    resume.send(()).unwrap();
    assert!(opening.join().unwrap().is_err());
    assert_eq!(outputs.snapshot("vm").unwrap().token, "new");
}

#[test]
fn active_reader_capacity_refuses_before_opening_another_connection() {
    let outputs = ProcessOutputs::default();
    let mut peers = Vec::new();
    for i in 0..MAX_MACHINES {
        let (stream, peer) = UnixStream::pair().unwrap();
        peers.push(peer);
        outputs
            .follow_with(&format!("vm-{i}"), "token", || {
                ProcessOutputReader::spawn(stream, "token".into(), |stream, _| {
                    stream.read_exact(&mut [0])?;
                    Ok(())
                })
            })
            .unwrap();
    }
    assert!(
        outputs
            .follow_with("overflow", "token", || panic!("must refuse before open"))
            .is_err()
    );
    assert_eq!(lock(&outputs.machines).len(), MAX_MACHINES);
    drop(outputs);
    drop(peers);
}

#[test]
fn retirement_closes_the_reader_but_keeps_known_bytes_without_claiming_process_exit() {
    let outputs = ProcessOutputs::default();
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let (entered, started) = mpsc::channel();
    outputs
        .follow_with("vm", "quiet", || {
            ProcessOutputReader::spawn(stream, "quiet".into(), move |stream, window| {
                lock(window).push(ProcessOutputStream::Stdout, b"known bytes");
                entered.send(()).unwrap();
                stream.read_exact(&mut [0])?;
                Ok(())
            })
        })
        .unwrap();
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    outputs.retire("vm");
    let output = outputs.snapshot("vm").unwrap();
    assert_eq!(output.end, Some(ProcessOutputEnd::Closed));
    assert_eq!(output.records[0].data, b"known bytes");
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    assert!(
        outputs
            .follow_with("vm", "quiet", || panic!("must not reconnect"))
            .is_err()
    );
}

#[test]
fn retiring_an_opening_observation_closes_its_eventual_reader() {
    let outputs = Arc::new(ProcessOutputs::default());
    let opening = Arc::clone(&outputs);
    let (entered, started) = mpsc::channel();
    let (resume, blocked) = mpsc::channel();
    let task = std::thread::spawn(move || {
        opening.follow_with("vm", "pending", || {
            entered.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(fixture("pending", b"old"))
        })
    });
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    outputs.retire("vm");
    assert_eq!(
        outputs.snapshot("vm").unwrap().end,
        Some(ProcessOutputEnd::Closed)
    );
    resume.send(()).unwrap();
    assert!(task.join().unwrap().is_err());
    let tracked = lock(&outputs.machines).get("vm").cloned().unwrap();
    let reader = lock(tracked.reader.get().unwrap().as_ref().unwrap());
    assert!(reader.worker.is_none());
}
