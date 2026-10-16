//! Whether a boot is provisioned for host-side telemetry collection, and the
//! on-disk names the embedded collector shares with its readers.
//!
//! There is no collector process: the collector runs as a thread inside the
//! per-VM network endpoint, so it lives and dies with the one host process
//! every workload boot already has. Provisioning is a single decision made
//! by the spawner and consumed twice — the endpoint config grows a telemetry
//! section, and the guest cmdline grows the `mvm.telemetry=1` assertion that
//! tells the agent to serve its listener. One decision, so the guest can
//! never assert a listener the host did not provision for.

use std::path::Path;

/// Where the embedded collector keeps its coverage-status snapshot, in the
/// VM state dir.
pub const TELEMETRY_COLLECTOR_STATUS_FILE: &str = "telemetry-collector-status.json";
/// Where the embedded collector appends received records, size-capped.
pub const TELEMETRY_RECORDS_FILE: &str = "telemetry-records.jsonl";
/// Default byte cap for the records file. Deliberately modest: retention is
/// its own workstream, and this file exists so collection is observable, not
/// as a durable store.
pub const DEFAULT_RECORDS_BYTE_CAP: u64 = 8 * 1024 * 1024;
/// The records file's data key, wrapped under the host transcript
/// key-encryption key. Every line of [`TELEMETRY_RECORDS_FILE`] is sealed
/// under the key this file wraps.
pub const TELEMETRY_RECORDS_KEY_FILE: &str = "telemetry-records.key";
/// Marker written only after this boot's telemetry-capable endpoint spawned.
const TELEMETRY_PROVISIONED_FILE: &str = "telemetry-provisioned";

/// The variable that turns collection off for every boot this host starts.
pub const ENV_TELEMETRY_COLLECT: &str = "MVM_TELEMETRY_COLLECT";

/// Whether this host collects guest telemetry for the boots it starts.
///
/// On by default: collection is a product feature, not a side effect of
/// configuring an exporter, and it costs a launch nothing measurable (the
/// collector starts inside the endpoint process every boot already has, and
/// the guest's listener is a thread). `MVM_TELEMETRY_COLLECT=0` turns it off;
/// an OTLP exporter remains optional either way.
pub fn telemetry_collection_enabled() -> bool {
    collection_enabled_from(std::env::var(ENV_TELEMETRY_COLLECT).ok().as_deref())
}

/// Record whether the endpoint spawned for this boot actually carries a
/// telemetry collector. Absence is fail-closed: the guest asserts no listener.
pub fn record_boot_provisioning(state_dir: &Path, provisioned: bool) -> std::io::Result<()> {
    let marker = state_dir.join(TELEMETRY_PROVISIONED_FILE);
    if provisioned {
        std::fs::write(marker, b"1")
    } else {
        match std::fs::remove_file(marker) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Whether this specific boot has a successfully spawned telemetry endpoint.
pub fn boot_is_provisioned(state_dir: &Path) -> bool {
    state_dir.join(TELEMETRY_PROVISIONED_FILE).is_file()
}

/// The data key this VM's records file is sealed under, minted (and stored
/// wrapped under the host KEK in `keys_dir`, created if absent) on the VM's
/// first provisioned boot and reused after, so a restart keeps the records
/// already written readable. A wrapped key that will not unwrap is replaced
/// along with the records it sealed, which nothing could read any more.
pub fn provision_records_key(
    state_dir: &Path,
    keys_dir: &Path,
) -> std::io::Result<mvm_core::crypto::aead::Key> {
    let kek = mvm_core::transcript::load_or_init_kek(keys_dir)?;
    let key_file = state_dir.join(TELEMETRY_RECORDS_KEY_FILE);
    match std::fs::read_to_string(&key_file) {
        Ok(wrapped) => {
            if let Ok(key) = mvm_core::transcript::unwrap_data_key(&kek, wrapped.trim()) {
                return Ok(key);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match std::fs::remove_file(state_dir.join(TELEMETRY_RECORDS_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let key = mvm_core::crypto::aead::Key::random();
    // Not synced: this runs on every new VM's launch path, where two fsyncs
    // cost tens of milliseconds on rotational storage. A crash that loses the
    // wrapped key loses only records nothing could read without it, and the
    // next provisioning replaces both.
    mvm_core::atomic_io::write_private_ephemeral(
        &key_file,
        mvm_core::transcript::wrap_data_key(&kek, &key).as_bytes(),
    )?;
    Ok(key)
}

/// The data key a reader opens this VM's records with, or `None` when the VM
/// has none or the host has no KEK. Never mints either: a read path that
/// created keys would make every record already written unreadable.
pub fn load_records_key(
    state_dir: &Path,
    keys_dir: &Path,
) -> std::io::Result<Option<mvm_core::crypto::aead::Key>> {
    let wrapped = match std::fs::read_to_string(state_dir.join(TELEMETRY_RECORDS_KEY_FILE)) {
        Ok(wrapped) => wrapped,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(kek) = mvm_core::transcript::load_kek(keys_dir)? else {
        return Ok(None);
    };
    mvm_core::transcript::unwrap_data_key(&kek, wrapped.trim())
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// The pure decision, split from the environment so it is testable without
/// process-global state: only an explicit off value disables collection.
pub fn collection_enabled_from(explicit_collect: Option<&str>) -> bool {
    !matches!(
        explicit_collect
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0" | "false" | "off" | "no")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_is_on_unless_explicitly_turned_off() {
        assert!(collection_enabled_from(None));
        assert!(collection_enabled_from(Some("1")));
        assert!(collection_enabled_from(Some("")));
        for off in ["0", "false", "OFF", " no "] {
            assert!(!collection_enabled_from(Some(off)), "{off:?}");
        }
    }

    #[test]
    fn the_records_key_is_minted_once_wrapped_and_reused() {
        let state = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        assert!(
            load_records_key(state.path(), keys.path())
                .unwrap()
                .is_none()
        );

        let minted = provision_records_key(state.path(), keys.path()).unwrap();
        let wrapped = std::fs::read(state.path().join(TELEMETRY_RECORDS_KEY_FILE)).unwrap();
        assert!(
            !wrapped
                .windows(32)
                .any(|w| w == minted.expose_bytes().as_slice()),
            "the key is stored wrapped, never raw"
        );
        let again = provision_records_key(state.path(), keys.path()).unwrap();
        assert_eq!(again.expose_bytes(), minted.expose_bytes());
        let read = load_records_key(state.path(), keys.path())
            .unwrap()
            .unwrap();
        assert_eq!(read.expose_bytes(), minted.expose_bytes());
    }

    #[test]
    fn a_key_wrapped_under_another_kek_is_replaced_with_its_records() {
        let state = tempfile::tempdir().unwrap();
        let first_keys = tempfile::tempdir().unwrap();
        let other_keys = tempfile::tempdir().unwrap();
        provision_records_key(state.path(), first_keys.path()).unwrap();
        std::fs::write(state.path().join(TELEMETRY_RECORDS_FILE), b"sealed\n").unwrap();

        // A host with no KEK reads no key, and mints none.
        assert!(
            load_records_key(state.path(), other_keys.path())
                .unwrap()
                .is_none()
        );
        provision_records_key(state.path(), other_keys.path()).unwrap();
        assert!(!state.path().join(TELEMETRY_RECORDS_FILE).exists());
        assert!(
            load_records_key(state.path(), other_keys.path())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn boot_provisioning_is_absent_until_recorded_and_can_be_cleared() {
        let state = tempfile::tempdir().unwrap();
        assert!(!boot_is_provisioned(state.path()));

        record_boot_provisioning(state.path(), true).unwrap();
        assert!(boot_is_provisioned(state.path()));

        record_boot_provisioning(state.path(), false).unwrap();
        assert!(!boot_is_provisioned(state.path()));
    }
}
