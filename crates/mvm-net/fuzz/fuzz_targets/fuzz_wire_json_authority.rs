// Fuzz the length-prefixed JSON authority framing.
//
// `LengthPrefixedJsonAuthority` is the first structured host/guest wire parser
// after the raw stream boundary. The harness contract is "never panic on any
// input or I/O cadence". Arbitrary bytes are exposed through partial reads plus
// retry-style `WouldBlock` / `TimedOut` / `Interrupted` behavior, and any
// decoded `NetMessage` is round-tripped back through the encoder/decoder path.

#![no_main]

use std::io::{self, Cursor, Read, Write};

use libfuzzer_sys::fuzz_target;
use mvm_net::proto::NetMessage;
use mvm_net::wire_json::{
    JsonWireConfig, JsonWireRead, LengthPrefixedJsonAuthority,
};

fuzz_target!(|data: &[u8]| {
    let (config_bytes, remainder) = data.split_at(data.len().min(2));
    let max_frame_bytes = match config_bytes {
        [hi, lo] => usize::from(u16::from_be_bytes([*hi, *lo])).max(1),
        [single] => usize::from(*single).max(1),
        _ => 1,
    };
    let Ok(config) = JsonWireConfig::builder()
        .max_frame_bytes(max_frame_bytes)
        .build()
    else {
        return;
    };

    let split = remainder.len().min(32);
    let (script_bytes, payload) = remainder.split_at(split);
    let mut io = ScriptedFuzzIo::new(payload.to_vec(), script_bytes.to_vec());
    let mut authority = LengthPrefixedJsonAuthority::with_config(&mut io, config.clone());

    for _ in 0..64 {
        match authority.read_message() {
            Ok(JsonWireRead::Message(message)) => {
                exercise_message(message, &config);
            }
            Ok(JsonWireRead::WouldBlock | JsonWireRead::Closed) => {}
            Err(_) => {}
        }
    }
});

fn exercise_message(message: NetMessage, config: &JsonWireConfig) {
    match &message {
        NetMessage::Hello(hello) => {
            let _ = hello.validate();
        }
        NetMessage::HelloAck(ack) => {
            let _ = ack.validate();
        }
        _ => {}
    }

    let mut encoded = LengthPrefixedJsonAuthority::with_config(Cursor::new(Vec::new()), config.clone());
    let Ok(()) = encoded.write_message(message.clone()) else {
        return;
    };
    encoded.inner_mut().set_position(0);
    let _ = encoded.read_message();
}

#[derive(Debug)]
struct ScriptedFuzzIo {
    payload: Vec<u8>,
    offset: usize,
    script: Vec<u8>,
    script_offset: usize,
}

impl ScriptedFuzzIo {
    fn new(payload: Vec<u8>, script: Vec<u8>) -> Self {
        Self {
            payload,
            offset: 0,
            script,
            script_offset: 0,
        }
    }

    fn next_action(&mut self) -> u8 {
        if self.script_offset >= self.script.len() {
            return 0;
        }
        let action = self.script[self.script_offset];
        self.script_offset += 1;
        action
    }
}

impl Read for ScriptedFuzzIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.next_action() % 8 {
            1 => return Err(io::Error::new(io::ErrorKind::WouldBlock, "fuzz would block")),
            2 => return Err(io::Error::new(io::ErrorKind::TimedOut, "fuzz timed out")),
            3 => return Err(io::Error::new(io::ErrorKind::Interrupted, "fuzz interrupted")),
            _ => {}
        }
        if self.offset >= self.payload.len() {
            return Ok(0);
        }
        let remaining = self.payload.len() - self.offset;
        let mut limit = buf.len().max(1);
        if let Some(step) = self.script.get(self.script_offset.saturating_sub(1)) {
            limit = usize::from(*step).max(1).min(limit);
        }
        let read_len = remaining.min(limit);
        buf[..read_len].copy_from_slice(&self.payload[self.offset..self.offset + read_len]);
        self.offset += read_len;
        Ok(read_len)
    }
}

impl Write for ScriptedFuzzIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
