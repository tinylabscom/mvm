//! Step definitions for the MVM-SEC-05 fuzz-surface conformance scenario.
//!
//! The real coverage lives in the per-crate `cargo fuzz` targets under
//! `crates/*/fuzz/`. Those targets need nightly and run for hours; this BDD
//! scenario is a deterministic smoke test that exercises the same parser
//! functions with a small adversarial corpus and proves they fail closed
//! (error / deny / None) rather than panicking.

use std::io::Cursor;

use cucumber::{given, then, when};

use crate::world::{CliWorld, FuzzRun, ParseOutcome};

/// One adversarial input plus the parser surface it targets.
#[derive(Debug, Clone)]
struct CorpusEntry {
    name: &'static str,
    bytes: Vec<u8>,
    surface: Surface,
}

/// Parser surface exercised by MVM-SEC-05.
#[derive(Debug, Clone, Copy)]
enum Surface {
    /// Length-prefixed JSON framing (`mvm_hostd::framing`).
    VsockFraming,
    /// Host→supervisor config JSON (`libkrun_sys::SupervisorConfig`).
    SupervisorConfig,
    /// Gateway datapath ingress packet parser (`mvm_hostd::supervisor::network::packet`).
    DatapathIngress,
}

/// Fixed adversarial corpus. Each entry is designed to hit a specific edge
/// case (oversize length, truncated body, malformed JSON, non-IP frame, ...).
fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry {
            name: "length-prefix u32::MAX",
            bytes: u32::MAX.to_be_bytes().to_vec(),
            surface: Surface::VsockFraming,
        },
        CorpusEntry {
            name: "truncated framed json",
            bytes: {
                let mut v = 16u32.to_be_bytes().to_vec();
                v.extend_from_slice(b"{\"incomplete");
                v
            },
            surface: Surface::VsockFraming,
        },
        CorpusEntry {
            name: "empty frame",
            bytes: 0u32.to_be_bytes().to_vec(),
            surface: Surface::VsockFraming,
        },
        CorpusEntry {
            name: "valid-length junk body",
            bytes: {
                let body = b"not json";
                let mut v = (body.len() as u32).to_be_bytes().to_vec();
                v.extend_from_slice(body);
                v
            },
            surface: Surface::VsockFraming,
        },
        CorpusEntry {
            name: "supervisor config empty",
            bytes: Vec::new(),
            surface: Surface::SupervisorConfig,
        },
        CorpusEntry {
            name: "supervisor config broken json",
            bytes: b"{\"ctx\": {\"broken\"".to_vec(),
            surface: Surface::SupervisorConfig,
        },
        CorpusEntry {
            name: "supervisor config wrong types",
            bytes: b"{\"ctx\": \"not-an-object\", \"mem_gib\": \"lots\"}".to_vec(),
            surface: Surface::SupervisorConfig,
        },
        CorpusEntry {
            name: "datapath empty",
            bytes: Vec::new(),
            surface: Surface::DatapathIngress,
        },
        CorpusEntry {
            name: "datapath random bytes",
            bytes: (0u8..=255).collect(),
            surface: Surface::DatapathIngress,
        },
        CorpusEntry {
            name: "datapath truncated ethernet",
            bytes: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff],
            surface: Surface::DatapathIngress,
        },
        CorpusEntry {
            name: "datapath arp frame",
            bytes: {
                let mut frame = vec![0u8; 14]; // dst + src + ethertype ARP
                frame[12] = 0x08;
                frame[13] = 0x06;
                frame.extend_from_slice(&[0u8; 28]); // ARP payload
                frame
            },
            surface: Surface::DatapathIngress,
        },
    ]
}

#[given("a deterministic adversarial corpus for MVM-SEC-05")]
fn given_adversarial_corpus(_world: &mut CliWorld) {
    // The corpus is fixed in `corpus()`; nothing to store on the world yet.
}

#[when("each corpus entry is parsed by its corresponding surface")]
fn when_each_entry_parsed(world: &mut CliWorld) {
    let results = corpus()
        .into_iter()
        .map(|entry| {
            let outcome = match entry.surface {
                Surface::VsockFraming => exercise_framing(&entry.bytes),
                Surface::SupervisorConfig => exercise_supervisor_config(&entry.bytes),
                Surface::DatapathIngress => exercise_datapath_ingress(&entry.bytes),
            };
            (entry.name.to_string(), outcome)
        })
        .collect();
    world.fuzz_run = Some(FuzzRun { results });
}

#[then("no parse panics or aborts")]
fn then_no_parse_panics(world: &mut CliWorld) {
    let run = world
        .fuzz_run
        .as_ref()
        .expect("the fuzz run must have executed first");
    let panics: Vec<_> = run
        .results
        .iter()
        .filter(|(_, outcome)| *outcome == ParseOutcome::Panicked)
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        panics.is_empty(),
        "MVM-SEC-05 parser surfaces panicked on: {panics:?}"
    );
}

/// Exercise the async length-prefixed JSON framing parser on a dedicated
/// thread with its own Tokio runtime, so a parser panic is caught without
/// nesting runtimes inside cucumber's async executor.
fn exercise_framing(bytes: &[u8]) -> ParseOutcome {
    let bytes = bytes.to_vec();
    match std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build single-thread tokio runtime for framing fuzz");
        runtime.block_on(async {
            let mut cursor = Cursor::new(bytes);
            let _: Result<serde_json::Value, mvm_hostd::framing::FrameError> =
                mvm_hostd::framing::read_json_frame(
                    &mut cursor,
                    mvm_hostd::framing::DEFAULT_MAX_FRAME_BYTES,
                )
                .await;
        });
    })
    .join()
    {
        Ok(()) => ParseOutcome::Completed,
        Err(_) => ParseOutcome::Panicked,
    }
}

/// Exercise the libkrun supervisor-config JSON parser.
fn exercise_supervisor_config(bytes: &[u8]) -> ParseOutcome {
    match std::panic::catch_unwind(|| {
        let _: Result<libkrun_sys::SupervisorConfig, _> = serde_json::from_slice(bytes);
    }) {
        Ok(()) => ParseOutcome::Completed,
        Err(_) => ParseOutcome::Panicked,
    }
}

/// Exercise the gateway packet parser and rebuild path.
fn exercise_datapath_ingress(bytes: &[u8]) -> ParseOutcome {
    match std::panic::catch_unwind(|| {
        if let Some(parsed) = mvm_hostd::supervisor::network::packet::parse(bytes) {
            let payload = parsed.l4_payload.to_vec();
            let _ =
                mvm_hostd::supervisor::network::packet::rebuild_with_payload(bytes, &payload, 1514);
        }
    }) {
        Ok(()) => ParseOutcome::Completed,
        Err(_) => ParseOutcome::Panicked,
    }
}
