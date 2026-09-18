//! Hermetic behavior witness for the production pipe pump, without booting a VM.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use cucumber::{then, when};
use mvm_agentd::entrypoint::CallCaps;
use mvm_agentd::stream_pump::{Pump, PumpOutcome};
use mvm_agentd::vsock::EntrypointEvent;

use crate::world::{CaptureReport, CliWorld};

const WRITTEN: u64 = 8 * 1024 * 1024;
const GUARD: Duration = Duration::from_secs(30);

#[when("a workload floods its bounded capture while the consumer is paused")]
async fn flood_capture(world: &mut CliWorld) {
    world.stream_capture = Some(
        tokio::task::spawn_blocking(capture_flood)
            .await
            .expect("capture fixture worker"),
    );
}

fn capture_flood() -> CaptureReport {
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            &format!(
                "read start; printf ready; read flood; head -c {WRITTEN} /dev/zero; printf done >&2"
            ),
        ])
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hermetic workload");
    let mut start = child.stdin.take().expect("start pipe");
    let mut completion = child.stderr.take().expect("completion pipe");
    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let observer = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = completion.read_to_end(&mut bytes).map(|_| bytes);
        let _ = finished_tx.send(result);
    });
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let pump = std::thread::spawn(move || {
        let caps = CallCaps {
            stdout_max: 64 * 1024,
            ..CallCaps::default()
        };
        let mut events = Vec::new();
        let mut paused = false;
        let outcome =
            Pump::new(&caps)
                .deadline(Instant::now() + GUARD)
                .run(&mut child, &mut |event| {
                    if !paused {
                        paused = true;
                        let _ = entered_tx.send(());
                        let _ = release_rx.recv();
                    }
                    events.push(event);
                });
        CaptureReport { outcome, events }
    });
    // Both owned observers are armed before allowing the workload to write.
    start.write_all(b"start\n").expect("release workload");
    let entered = entered_rx.recv_timeout(GUARD);
    // The consumer is paused on the prefix before any flood bytes are written.
    let flood_released = start.write_all(b"flood\n");
    drop(start);
    let finished = finished_rx.recv_timeout(GUARD);
    // Always release and reap before assertions, including on the failure path.
    let _ = release_tx.send(());
    let report = pump.join().expect("pump must not panic");
    observer.join().expect("completion observer");
    assert!(entered.is_ok(), "capture consumer never received output");
    flood_released.expect("release flood after consumer paused");
    assert_eq!(
        finished
            .expect("workload stalled behind capture")
            .expect("completion read"),
        b"done"
    );
    report
}

#[then("the capture is bounded and every output byte is delivered or reported lost")]
fn verify_capture(world: &mut CliWorld) {
    let report = world.stream_capture.as_ref().expect("capture fixture ran");
    assert_eq!(report.outcome, PumpOutcome::Exited(0));
    let mut delivered = 0u64;
    let mut dropped = 0u64;
    let mut gaps = 0;
    for event in &report.events {
        match event {
            EntrypointEvent::Stdout { chunk } => {
                delivered += u64::try_from(chunk.len()).expect("chunk length")
            }
            EntrypointEvent::Control { header_json, .. } => {
                let header: serde_json::Value =
                    serde_json::from_str(header_json).expect("gap JSON");
                assert_eq!(header["kind"], "mvm.stream.gap");
                assert_eq!(header["stage"], "pipe_reader");
                dropped += header["dropped_bytes"].as_u64().expect("loss count");
                gaps += 1;
            }
            other => panic!("unexpected capture event: {other:?}"),
        }
    }
    assert_eq!(gaps, 1);
    assert!(delivered > 0 && delivered < 1024 * 1024);
    assert!(dropped > 0);
    assert_eq!(delivered + dropped, WRITTEN + 5);
}
