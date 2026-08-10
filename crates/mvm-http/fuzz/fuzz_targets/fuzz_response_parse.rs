#![no_main]

//! Fuzz the response-head and chunked-body parsers.
//!
//! Both are pure functions over a byte slice, so this harness exercises the
//! exact code a hostile server reaches. The properties asserted are the ones a
//! parse bug would break silently: never panic, never claim to have consumed
//! more input than exists, and never report a chunk whose data lies outside the
//! buffer — an out-of-range span would become an OOB slice in the body reader.

use libfuzzer_sys::fuzz_target;
use mvm_http::parse::{ChunkStep, next_chunk, parse_head};

fuzz_target!(|data: &[u8]| {
    // The HEAD/GET distinction changes the framing decision, so drive both.
    for was_head in [false, true] {
        if let Ok(Some(head)) = parse_head(data, was_head) {
            assert!(
                head.consumed <= data.len(),
                "head consumed {} of {} bytes",
                head.consumed,
                data.len()
            );
        }
    }

    if let Ok(step) = next_chunk(data) {
        match step {
            ChunkStep::Data {
                start,
                len,
                consumed,
            } => {
                assert!(consumed <= data.len(), "chunk consumed past the buffer");
                let end = start
                    .checked_add(len)
                    .expect("chunk span must not overflow");
                assert!(end <= data.len(), "chunk data span lies outside the buffer");
                assert!(end <= consumed, "chunk data must lie within what it consumed");
            }
            ChunkStep::End { consumed } => {
                assert!(consumed <= data.len(), "terminator consumed past the buffer");
            }
            ChunkStep::Incomplete => {}
        }
    }
});
