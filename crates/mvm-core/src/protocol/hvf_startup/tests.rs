use super::*;
use serde::ser::SerializeMap;
use std::cell::Cell;

struct ChangingConfig(Cell<u32>);

impl serde::Serialize for ChangingConfig {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let count = self.0.get() + 1;
        self.0.set(count);
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("serialization", &count)?;
        map.end()
    }
}

#[test]
fn frozen_configuration_is_serialized_once_and_shared_without_reserialization() {
    let source = ChangingConfig(Cell::new(0));
    let frozen = FrozenConfig::serialize(&source).unwrap();
    let retained = frozen.clone();
    let startup = frozen.clone();
    assert_eq!(source.0.get(), 1);
    assert_eq!(startup.as_bytes(), br#"{"serialization":1}"#);
    assert!(std::ptr::eq(startup.as_bytes(), retained.as_bytes()));
    assert_eq!(startup.digest(), retained.digest());
    assert_eq!(
        frozen.digest(),
        <[u8; 32]>::from(Sha256::digest(frozen.as_bytes()))
    );
    let debug = format!("{frozen:?}");
    assert!(!debug.contains("serialization"));
}

#[test]
fn raw_json_keeps_original_whitespace_and_utf8_and_hashes_original_bytes() {
    let raw = " { \"tenant\": \"é\" }\n".as_bytes().to_vec();
    let frozen = FrozenConfig::from_json(raw.clone()).unwrap();
    assert_eq!(frozen.as_bytes(), raw);
    let other = FrozenConfig::serialize(&serde_json::json!({"tenant": "é"})).unwrap();
    assert_ne!(frozen.digest(), other.digest());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(frozen.as_bytes()).unwrap(),
        serde_json::from_slice::<serde_json::Value>(other.as_bytes()).unwrap()
    );
}

#[test]
fn invalid_or_oversized_config_refuses_without_returning_payloads_in_errors() {
    for raw in [
        Vec::new(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"{".to_vec(),
        b"{\"secret\":\"not-for-errors\"} trailing".to_vec(),
        vec![0xff],
        vec![b' '; CONFIG_LIMIT + 1],
    ] {
        let error = FrozenConfig::from_json(raw).unwrap_err();
        assert!(!error.to_string().contains("not-for-errors"));
    }
    let large = serde_json::json!({"payload": "x".repeat(CONFIG_LIMIT)});
    assert_eq!(
        FrozenConfig::serialize(&large).unwrap_err(),
        StartupInputError::Bounds
    );
    let boundary = format!("{{\"p\":\"{}\"}}", "x".repeat(CONFIG_LIMIT - 8));
    assert_eq!(boundary.len(), CONFIG_LIMIT);
    assert_eq!(
        FrozenConfig::from_json(boundary.into_bytes())
            .unwrap()
            .as_bytes()
            .len(),
        CONFIG_LIMIT
    );
}

#[cfg(feature = "experimental-owned-capture")]
mod envelope {
    use super::*;
    use uuid::Uuid;

    fn fixture() -> StartupEnvelope {
        FrozenConfig::from_json(b" { \"vm_name\": \"vm-a\", \"tenant\": \"\xc3\xa9\" }\n".to_vec())
            .unwrap()
            .for_call(Uuid::from_u128(5))
            .unwrap()
    }

    #[test]
    fn envelope_layout_roundtrips_without_serializing_its_config_again() {
        let source = ChangingConfig(Cell::new(0));
        let frozen = FrozenConfig::serialize(&source).unwrap();
        let retained = frozen.clone();
        let envelope = frozen.for_call(Uuid::from_u128(5)).unwrap();
        let bytes = envelope.encode().unwrap();
        assert_eq!(source.0.get(), 1);
        assert!(std::ptr::eq(
            envelope.config().as_bytes(),
            retained.as_bytes()
        ));
        assert_eq!(&bytes[..8], b"MVMOCAP\0");
        assert_eq!(bytes[8], 1);
        assert_eq!(
            usize::try_from(u32::from_be_bytes(bytes[9..13].try_into().unwrap())).unwrap(),
            retained.as_bytes().len()
        );
        assert_eq!(
            &bytes[13..13 + retained.as_bytes().len()],
            retained.as_bytes()
        );
        let permit = 13 + retained.as_bytes().len();
        assert_eq!(&bytes[permit..permit + 3], &[0, 53, 1]);
        assert_eq!(
            &bytes[permit + 3..permit + 19],
            Uuid::from_u128(5).as_bytes()
        );
        assert_eq!(&bytes[permit + 19..permit + 51], &retained.digest());
        assert_eq!(bytes.len(), retained.as_bytes().len() + 68);
        let decoded = StartupEnvelope::decode(&bytes).unwrap();
        assert_eq!(decoded.config().as_bytes(), retained.as_bytes());
        assert_eq!(decoded.config().digest(), retained.digest());
        assert_eq!(decoded.call(), envelope.call());
        assert_eq!(decoded.launcher_pid(), std::process::id());
    }

    #[test]
    fn every_truncation_and_forged_length_or_version_refuses() {
        let envelope = fixture();
        let wire = envelope.encode().unwrap();
        for length in 0..wire.len() {
            assert!(
                StartupEnvelope::decode(&wire[..length]).is_err(),
                "prefix {length}"
            );
        }
        for length in [0, u32::try_from(CONFIG_LIMIT + 1).unwrap(), u32::MAX] {
            let mut invalid = wire.clone();
            invalid[9..13].copy_from_slice(&length.to_be_bytes());
            assert!(StartupEnvelope::decode(&invalid).is_err());
        }
        let permit = 13 + envelope.config().as_bytes().len();
        for offset in [0, 8, permit + 2] {
            let mut invalid = wire.clone();
            invalid[offset] = 255;
            assert!(StartupEnvelope::decode(&invalid).is_err());
        }
        for length in [0_u16, 52, 54, u16::MAX] {
            let mut invalid = wire.clone();
            invalid[permit..permit + 2].copy_from_slice(&length.to_be_bytes());
            assert!(StartupEnvelope::decode(&invalid).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(StartupEnvelope::decode(&trailing).is_err());
        assert!(StartupEnvelope::decode(&vec![0; MAX_ENVELOPE_BYTES + 1]).is_err());
    }

    #[test]
    fn changed_config_digest_nil_call_and_invalid_launcher_refuse() {
        let envelope = fixture();
        let wire = envelope.encode().unwrap();
        let permit = 13 + envelope.config().as_bytes().len();
        let mut invalid = wire.clone();
        invalid[13] = b'\n';
        assert_eq!(
            StartupEnvelope::decode(&invalid).unwrap_err(),
            StartupInputError::Binding
        );
        let mut invalid = wire.clone();
        invalid[permit + 19] ^= 1;
        assert_eq!(
            StartupEnvelope::decode(&invalid).unwrap_err(),
            StartupInputError::Binding
        );
        let mut invalid = wire.clone();
        invalid[permit + 3..permit + 19].fill(0);
        assert!(StartupEnvelope::decode(&invalid).is_err());
        for pid in [0_u32, 1] {
            let mut invalid = wire.clone();
            invalid[permit + 51..permit + 55].copy_from_slice(&pid.to_be_bytes());
            assert!(StartupEnvelope::decode(&invalid).is_err());
        }
        assert!(envelope.config().clone().for_call(Uuid::nil()).is_err());
    }

    #[test]
    fn invalid_inner_encoding_refuses_even_with_a_matching_digest() {
        let envelope = fixture();
        let wire = envelope.encode().unwrap();
        let end = 13 + envelope.config().as_bytes().len();
        for byte in [0xff, b'['] {
            let mut invalid = wire.clone();
            invalid[14] = byte;
            let digest = Sha256::digest(&invalid[13..end]);
            invalid[end + 19..end + 51].copy_from_slice(&digest);
            assert_eq!(
                StartupEnvelope::decode(&invalid).unwrap_err(),
                StartupInputError::Invalid
            );
        }
    }

    #[test]
    fn maximum_inner_configuration_stays_within_the_exact_envelope_bound() {
        let raw = format!("{{\"p\":\"{}\"}}", "x".repeat(CONFIG_LIMIT - 8));
        let envelope = FrozenConfig::from_json(raw.into_bytes())
            .unwrap()
            .for_call(Uuid::from_u128(5))
            .unwrap();
        let wire = envelope.encode().unwrap();
        assert_eq!(wire.len(), MAX_ENVELOPE_BYTES);
        assert_eq!(MAX_ENVELOPE_BYTES, 8_388_676);
        assert_eq!(
            StartupEnvelope::decode(&wire).unwrap().config().digest(),
            envelope.config().digest()
        );
    }

    #[cfg(unix)]
    #[test]
    fn mock_io_preserves_bytes_without_establishing_peer_or_launch_authority() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::Duration;
        let envelope = fixture();
        let wire = envelope.encode().unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        for stream in [&sender, &receiver] {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        sender.write_all(&wire).unwrap();
        let mut read = vec![0; wire.len()];
        receiver.read_exact(&mut read).unwrap();
        let decoded = StartupEnvelope::decode(&read).unwrap();
        assert_eq!(decoded.config().as_bytes(), envelope.config().as_bytes());
        assert_eq!(decoded.call(), envelope.call());
    }
}
