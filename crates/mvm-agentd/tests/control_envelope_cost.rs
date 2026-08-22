//! What the control envelope costs per frame, measured rather than argued.
//!
//! `#[ignore]`d: it reports numbers, it does not gate. A wall-clock assertion
//! in CI is the test shape that passes for the wrong reason — it goes red on a
//! loaded runner and green on a fast one, and either way it stops meaning what
//! its name says.
//!
//! Run it when changing how frames reach the wire:
//!
//! ```text
//! cargo test --release -p mvm-agentd --test control_envelope_cost -- --ignored --nocapture
//! ```
//!
//! It exists because the envelope was JSON, and the cost of that was assumed
//! to be bandwidth. It was not — encoding a `Vec<u8>` ciphertext as an array
//! of decimal numbers cost roughly 700us per frame against 3.6x the bytes, so
//! the CPU was two orders of magnitude more of the problem than the wire. The
//! guess that motivated the switch was wrong in the direction that would have
//! made it look not worth doing.

use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use mvm_agentd::vsock::{AuthenticatedSession, ExecEvent, GuestResponse, MAX_DATA_CHUNK_SIZE};
use mvm_core::net::session::{SealedFrame, Session};
use rand::Rng;

fn keypair() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

/// A real handshaked session, so the frames measured are the frames sent.
fn session() -> Session {
    let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
    host_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    guest_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let host_key = keypair();
    let anchor = host_key.verifying_key();
    let guest_key = keypair();

    let guest = std::thread::spawn(move || {
        AuthenticatedSession::guest(&mut guest_stream, guest_key, &anchor).unwrap()
    });
    let host = AuthenticatedSession::host(&mut host_stream, "envelope-cost", host_key).unwrap();
    let _ = guest.join().unwrap();
    host.into()
}

#[test]
#[ignore = "reports measurements; not a gate"]
fn control_envelope_cost_per_frame() {
    const ITERS: u32 = 50;
    let mut session = session();

    println!(
        "\n{:>8}  {:>10}  {:>10}  {:>9}  {:>9}",
        "chunk B", "plaintext", "on wire", "encode", "decode"
    );

    for &n in &[MAX_DATA_CHUNK_SIZE / 4, MAX_DATA_CHUNK_SIZE] {
        // Printable ASCII, the shape real stdout has. 0xFF would be the
        // worst case for the body encoding and is what the cap is derived
        // against; this is what a workload actually pays.
        let chunk: Vec<u8> = (0..n).map(|i| b' ' + (i % 90) as u8).collect();
        let response = GuestResponse::ExecEvent(ExecEvent::Stdout { chunk });
        let plaintext = serde_json::to_vec(&response).unwrap();
        let sealed = session.seal(&plaintext).unwrap();

        let mut wire = Vec::new();
        sealed.encode(&mut wire).unwrap();

        let start = Instant::now();
        for _ in 0..ITERS {
            let mut buf = Vec::new();
            sealed.encode(&mut buf).unwrap();
            std::hint::black_box(&buf);
        }
        let encode = start.elapsed() / ITERS;

        let start = Instant::now();
        for _ in 0..ITERS {
            std::hint::black_box(SealedFrame::decode(&wire).unwrap());
        }
        let decode = start.elapsed() / ITERS;

        println!(
            "{n:>8}  {:>10}  {:>10}  {:>7.1}us  {:>7.1}us",
            plaintext.len(),
            wire.len(),
            encode.as_secs_f64() * 1e6,
            decode.as_secs_f64() * 1e6,
        );
    }
    println!();
}
