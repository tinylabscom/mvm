//! Live transcript capture sink — fills an armed capture's manifest with the
//! guest's byte chunks as they cross the host bridge.
//!
//! The operator arms a capture out of band (`mvmctl audit transcript arm`),
//! which writes an empty-chunk manifest under
//! `<transcripts>/<tenant>/<capture-id>/` with the per-capture data key wrapped
//! under the host KEK. When a VM whose binding matches boots, the bridge opens
//! a sink here: it unwraps the data key under the KEK, encrypts each byte buffer
//! into a chunk, and re-seals the manifest on stop so the operator CLI can list
//! and export it. Raw payload bytes never touch the chain-signed audit log; the
//! bridge pays nothing when no capture is armed (the common case).

use std::path::{Path, PathBuf};

use mvm_core::transcript::{
    self, Direction, TranscriptError, TranscriptManifest, TranscriptWriter, TranscriptWriterConfig,
};

/// Manifest filename inside a capture dir — matches the operator CLI.
const MANIFEST_FILE: &str = "manifest.json";

/// An open capture for one VM. Holds the encrypting writer over the capture dir
/// and re-seals the manifest on [`seal`](Self::seal).
pub struct TranscriptCaptureSink {
    dir: PathBuf,
    writer: TranscriptWriter,
    capture_id: String,
}

impl TranscriptCaptureSink {
    /// Open a sink for the armed capture bound to `(tenant, vm)`, if one exists.
    ///
    /// Scans `<transcripts_dir>/<tenant>/*/manifest.json` for an **armed**
    /// manifest — no chunks yet — whose `binding.vm_name == vm`, unwraps its
    /// data key under the host KEK, and opens a writer over the same dir.
    /// `Ok(None)` when nothing is armed for this VM, so the bridge does no work
    /// in the common (capture-off) case. A capture that already has chunks is
    /// not re-opened (it has been captured once already).
    pub fn open_for_vm(
        transcripts_dir: &Path,
        keys_dir: &Path,
        tenant: &str,
        vm: &str,
    ) -> Result<Option<Self>, TranscriptError> {
        let Ok(entries) = std::fs::read_dir(transcripts_dir.join(tenant)) else {
            return Ok(None);
        };
        let mut dirs: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs {
            let Some(manifest) = read_manifest(&dir) else {
                continue;
            };
            if manifest.binding.vm_name != vm || !manifest.chunks.is_empty() {
                continue; // wrong VM, or already captured (not armed)
            }
            // Armed match — unwrap the per-capture data key under the host KEK.
            let kek = transcript::load_or_init_kek(keys_dir).map_err(|e| io_err("kek", &e))?;
            let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64)?;
            let cfg = TranscriptWriterConfig {
                capture_id: manifest.capture_id.clone(),
                binding: manifest.binding.clone(),
                bounds: manifest.bounds,
                created_unix_secs: manifest.created_unix_secs,
                recipient: manifest.recipient.clone(),
                wrapped_data_key_b64: manifest.wrapped_data_key_b64.clone(),
            };
            return Ok(Some(Self {
                writer: TranscriptWriter::new(&dir, data_key, cfg),
                capture_id: manifest.capture_id,
                dir,
            }));
        }
        Ok(None)
    }

    /// The capture id this sink is filling (for the lifecycle audit emit).
    pub fn capture_id(&self) -> &str {
        &self.capture_id
    }

    /// Capture one buffer in `direction`. Budget-checked + encrypted before any
    /// byte lands on disk. A [`TranscriptError::BoundExceeded`] means the caller
    /// should [`seal`](Self::seal) and stop capturing this flow.
    pub fn push(&mut self, direction: Direction, bytes: &[u8]) -> Result<(), TranscriptError> {
        self.writer.push(direction, bytes)
    }

    /// Finalize: re-seal `manifest.json` with the captured chunks so the
    /// operator CLI lists/exports them. Returns the sealed manifest so the
    /// caller can emit the `TranscriptSealed` audit entry with the counts.
    pub fn seal(self) -> Result<TranscriptManifest, TranscriptError> {
        let manifest = self.writer.seal();
        let json =
            serde_json::to_vec_pretty(&manifest).map_err(|e| io_err("serialize manifest", &e))?;
        std::fs::write(self.dir.join(MANIFEST_FILE), &json)
            .map_err(|e| io_err(MANIFEST_FILE, &e))?;
        Ok(manifest)
    }
}

fn read_manifest(dir: &Path) -> Option<TranscriptManifest> {
    let bytes = std::fs::read(dir.join(MANIFEST_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn io_err(file: &str, e: &impl std::fmt::Display) -> TranscriptError {
    TranscriptError::Io {
        file: file.to_string(),
        msg: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::aead;
    use mvm_core::transcript::{CaptureBinding, CaptureBounds};
    use std::path::Path;

    /// Arrange an armed capture exactly the way `mvmctl audit transcript arm`
    /// does: a sealed-but-empty manifest with the data key wrapped under the KEK.
    fn arm(transcripts: &Path, keys: &Path, tenant: &str, vm: &str, id: &str) {
        let dir = transcripts.join(tenant).join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let kek = transcript::load_or_init_kek(keys).unwrap();
        let data_key = aead::Key::random();
        let cfg = TranscriptWriterConfig {
            capture_id: id.into(),
            binding: CaptureBinding {
                tenant_id: tenant.into(),
                vm_name: vm.into(),
                session_id: None,
            },
            bounds: CaptureBounds {
                max_duration_secs: 60,
                max_bytes: 1 << 20,
                max_chunks: 64,
            },
            created_unix_secs: 1_700_000_000,
            recipient: "transcript-kek".into(),
            wrapped_data_key_b64: transcript::wrap_data_key(&kek, &data_key),
        };
        let manifest = TranscriptWriter::new(&dir, data_key, cfg).seal();
        std::fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn sink_captures_into_an_armed_manifest_and_export_round_trips() {
        let t = tempfile::tempdir().unwrap();
        let transcripts = t.path().join("transcripts");
        let keys = t.path().join("keys");
        arm(&transcripts, &keys, "t1", "vm1", "cap-1");

        let mut sink = TranscriptCaptureSink::open_for_vm(&transcripts, &keys, "t1", "vm1")
            .unwrap()
            .expect("an armed capture is open for vm1");
        assert_eq!(sink.capture_id(), "cap-1");
        sink.push(Direction::Egress, b"GET / HTTP/1.1\r\n").unwrap();
        sink.push(Direction::Ingress, b"HTTP/1.1 200 OK\r\n")
            .unwrap();
        let manifest = sink.seal().unwrap();
        assert_eq!(manifest.chunks.len(), 2);

        // The operator export path verifies + decrypts the captured bytes back.
        let dir = transcripts.join("t1").join("cap-1");
        let kek = transcript::load_or_init_kek(&keys).unwrap();
        let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        let out = transcript::export(&manifest, &dir, &data_key).unwrap();
        assert_eq!(out, b"GET / HTTP/1.1\r\nHTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn open_for_vm_is_none_when_nothing_is_armed() {
        let t = tempfile::tempdir().unwrap();
        let none = TranscriptCaptureSink::open_for_vm(
            &t.path().join("transcripts"),
            &t.path().join("keys"),
            "t1",
            "vm1",
        )
        .unwrap();
        assert!(none.is_none(), "no transcripts dir → no capture, no work");
    }

    #[test]
    fn open_for_vm_ignores_already_captured_and_other_vms() {
        let t = tempfile::tempdir().unwrap();
        let transcripts = t.path().join("transcripts");
        let keys = t.path().join("keys");
        arm(&transcripts, &keys, "t1", "vm1", "cap-1");

        // Capture + seal once → the manifest now has chunks, so it is no longer
        // armed and must not be re-opened.
        let mut s = TranscriptCaptureSink::open_for_vm(&transcripts, &keys, "t1", "vm1")
            .unwrap()
            .unwrap();
        s.push(Direction::Egress, b"x").unwrap();
        s.seal().unwrap();
        assert!(
            TranscriptCaptureSink::open_for_vm(&transcripts, &keys, "t1", "vm1")
                .unwrap()
                .is_none(),
            "a captured manifest is not re-opened"
        );

        // A capture armed for vm2 is invisible to vm1 and vice versa.
        arm(&transcripts, &keys, "t1", "vm2", "cap-2");
        assert!(
            TranscriptCaptureSink::open_for_vm(&transcripts, &keys, "t1", "vm1")
                .unwrap()
                .is_none()
        );
        assert!(
            TranscriptCaptureSink::open_for_vm(&transcripts, &keys, "t1", "vm2")
                .unwrap()
                .is_some()
        );
    }
}
