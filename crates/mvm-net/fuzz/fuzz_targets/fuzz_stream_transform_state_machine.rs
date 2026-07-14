// Fuzz the built-in decrypted-stream transform state machine.
//
// `StreamTransformChain` is the bounded plaintext plugin pipeline behind the
// terminate/re-originate TLS path. The harness contract is "never panic on any
// valid-or-invalid built-in chain/config plus chunk/finalization cadence".
// Arbitrary bytes become bounded plugin chains, optional secret bindings,
// response-leak secret values, target hosts, and a mixed sequence of
// `process()` / `finish_direction()` / `finish()` / reconstruction steps.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_core::policy::secret_binding::SecretBinding;
use mvm_net::proto::PluginId;
use mvm_net::stream_transform::{
    StreamTransformChain, StreamTransformConfig, StreamTransformDirection,
};

const MAX_STEPS: usize = 64;
const MAX_CHUNK_BYTES: usize = 128;
const KNOWN_PLUGIN_IDS: [&str; 5] = [
    "audit",
    "metadata-endpoint-deny",
    "secret-replacement",
    "response-leak-guard",
    "unknown-plugin",
];
const TARGET_HOSTS: [&str; 4] = [
    "api.openai.com",
    "api.anthropic.com",
    "metadata.google.internal",
    "example.com",
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let split = data.len().min(12);
    let (config_bytes, mut cursor) = data.split_at(split);
    let Ok(config) = build_config(config_bytes) else {
        return;
    };
    let plugin_ids = build_plugin_chain(config_bytes);
    let target_host = target_host_from_byte(config_bytes.first().copied().unwrap_or(0));

    let _ = StreamTransformChain::validate_plugin_ids_with_config(&plugin_ids, &config);

    let mut chain = match StreamTransformChain::from_plugin_ids_with_config_for_target(
        &plugin_ids,
        &config,
        Some(target_host),
    ) {
        Ok(chain) => chain,
        Err(_) => return,
    };

    let _ = chain.manifests();
    let _ = chain.is_empty();

    let mut steps = 0usize;
    while !cursor.is_empty() && steps < MAX_STEPS {
        let opcode = cursor[0];
        cursor = &cursor[1..];
        let take = cursor
            .first()
            .map_or(0usize, |len| usize::from(*len).min(cursor.len().saturating_sub(1)));
        let payload = if cursor.is_empty() {
            &[][..]
        } else {
            let payload = &cursor[1..1 + take];
            cursor = &cursor[1 + take..];
            payload
        };
        steps += 1;

        match opcode % 4 {
            0 => {
                let _ = chain.process(direction_from_byte(opcode), bounded_bytes(payload).as_slice());
            }
            1 => {
                let _ = chain.finish_direction(direction_from_byte(opcode));
            }
            2 => {
                let _ = chain.finish();
            }
            3 => {
                let rebuilt = StreamTransformChain::from_plugin_ids_with_config_for_target(
                    &plugin_ids,
                    &config,
                    Some(target_host_from_byte(payload.first().copied().unwrap_or(opcode))),
                );
                if let Ok(next) = rebuilt {
                    chain = next;
                }
            }
            _ => unreachable!(),
        }
    }

    let _ = chain.finish_direction(StreamTransformDirection::GuestToUpstream);
    let _ = chain.finish_direction(StreamTransformDirection::UpstreamToGuest);
    let _ = chain.finish();
});

fn build_config(
    bytes: &[u8],
) -> Result<StreamTransformConfig, mvm_net::stream_transform::StreamTransformError> {
    let mut config = StreamTransformConfig::default();
    let mut bindings = Vec::new();
    if bytes.first().copied().unwrap_or(0) & 0x01 != 0 {
        bindings.push(
            SecretBinding::new("OPENAI_API_KEY", "api.openai.com").with_value("sk-test-openai"),
        );
    }
    if bytes.get(1).copied().unwrap_or(0) & 0x01 != 0 {
        bindings.push(
            SecretBinding::new("ANTHROPIC_API_KEY", "api.anthropic.com")
                .with_header("x-api-key")
                .with_value("sk-test-anthropic"),
        );
    }
    if !bindings.is_empty() {
        config = config.with_secret_replacement_bindings(bindings)?;
    }

    let mut secret_values = Vec::new();
    if bytes.get(2).copied().unwrap_or(0) & 0x01 != 0 {
        secret_values.push("sk-test-openai".to_string());
    }
    if bytes.get(3).copied().unwrap_or(0) & 0x01 != 0 {
        secret_values.push("sk-test-anthropic".to_string());
    }
    if bytes.get(4).copied().unwrap_or(0) & 0x01 != 0 {
        secret_values.push("Authorization: Bearer secret-token".to_string());
    }
    config.with_response_leak_guard_secret_values(secret_values)
}

fn build_plugin_chain(bytes: &[u8]) -> Vec<PluginId> {
    let mut out = Vec::new();
    for byte in bytes.iter().copied().take(8) {
        let plugin = KNOWN_PLUGIN_IDS[usize::from(byte) % KNOWN_PLUGIN_IDS.len()];
        out.push(PluginId::new(plugin).expect("fixed fuzz plugin id must be valid"));
    }
    out
}

fn target_host_from_byte(byte: u8) -> &'static str {
    TARGET_HOSTS[usize::from(byte) % TARGET_HOSTS.len()]
}

fn direction_from_byte(byte: u8) -> StreamTransformDirection {
    if byte & 1 == 0 {
        StreamTransformDirection::GuestToUpstream
    } else {
        StreamTransformDirection::UpstreamToGuest
    }
}

fn bounded_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().take(MAX_CHUNK_BYTES).collect()
}
