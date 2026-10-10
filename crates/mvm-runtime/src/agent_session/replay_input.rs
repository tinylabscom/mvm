//! Encrypted, content-addressed input artifacts for session replay.
//!
//! Durable agent-session events keep prompt bytes out of ordinary history.
//! This store is the separate, private artifact that makes an explicitly
//! recorded step replayable while history continues to carry only digests.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::crypto::aead;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const FORMAT_VERSION: u32 = 1;
const DIGEST_PREFIX: &str = "sha256:";
pub const MAX_REPLAY_INPUT_BYTES: usize = 1024 * 1024;
const MAX_REPLAY_ARTIFACT_BYTES: u64 = (MAX_REPLAY_INPUT_BYTES as u64 * 2) + 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayInputBinding {
    pub session_id: AgentSessionId,
    pub generation: u64,
    pub journal_cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayInputRef {
    pub binding: ReplayInputBinding,
    pub artifact_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReplayInput {
    format_version: u32,
    binding: ReplayInputBinding,
    prompt_sha256: String,
    ciphertext_sha256: String,
    wrapped_data_key_b64: String,
    ciphertext_b64: String,
}

pub struct ReplayInputStore {
    root: PathBuf,
    keys_dir: PathBuf,
}

impl ReplayInputStore {
    pub fn open() -> Self {
        Self::at(
            mvm_core::config::agent_sessions_dir(),
            mvm_core::config::mvm_keys_dir(),
        )
    }

    pub fn at(root: impl Into<PathBuf>, keys_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            keys_dir: keys_dir.into(),
        }
    }

    pub fn record(&self, binding: ReplayInputBinding, prompt: &[u8]) -> Result<ReplayInputRef> {
        if prompt.len() > MAX_REPLAY_INPUT_BYTES {
            bail!(
                "replay input is {} bytes; the limit is {MAX_REPLAY_INPUT_BYTES}",
                prompt.len()
            );
        }
        let directory = self.directory(&binding);
        mvm_core::config::create_private_dir(&directory)
            .with_context(|| format!("creating replay input store {}", directory.display()))?;
        let path = artifact_path(&directory, binding.journal_cursor);
        if path.exists() {
            return self.existing(&path, &binding, prompt);
        }

        let kek = mvm_core::transcript::load_or_init_kek(&self.keys_dir)
            .context("loading replay input key-encryption key")?;
        let data_key = aead::Key::random();
        let ciphertext = aead::seal(&data_key, prompt, &[]);
        let stored = StoredReplayInput {
            format_version: FORMAT_VERSION,
            binding: binding.clone(),
            prompt_sha256: digest(prompt),
            ciphertext_sha256: digest(&ciphertext),
            wrapped_data_key_b64: mvm_core::transcript::wrap_data_key(&kek, &data_key),
            ciphertext_b64: B64.encode(ciphertext),
        };
        let reference = reference_for(&stored);
        let bytes = serde_json::to_vec_pretty(&stored).context("encoding replay input artifact")?;
        match mvm_core::atomic_io::atomic_write_new(&path, &bytes) {
            Ok(()) => mvm_core::atomic_io::sync_dir(&directory).with_context(|| {
                format!("committing replay input directory {}", directory.display())
            })?,
            Err(error) if mvm_core::atomic_io::is_already_exists(&error) => {
                return self.existing(&path, &binding, prompt);
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("committing replay input artifact {}", path.display())
                });
            }
        }
        Ok(reference)
    }

    pub fn load(&self, reference: &ReplayInputRef) -> Result<Zeroizing<Vec<u8>>> {
        let path = artifact_path(
            &self.directory(&reference.binding),
            reference.binding.journal_cursor,
        );
        let stored = read_stored(&path)?;
        if stored.format_version != FORMAT_VERSION {
            bail!("unsupported replay input format {}", stored.format_version);
        }
        if stored.binding != reference.binding || reference_for(&stored) != *reference {
            bail!("replay input artifact binding or content address does not match");
        }
        let ciphertext = B64
            .decode(&stored.ciphertext_b64)
            .context("decoding replay input ciphertext")?;
        if digest(&ciphertext) != stored.ciphertext_sha256 {
            bail!("replay input ciphertext digest does not match");
        }
        let kek = mvm_core::transcript::load_kek(&self.keys_dir)
            .context("loading replay input key-encryption key")?
            .context("replay input key-encryption key is missing")?;
        let data_key = mvm_core::transcript::unwrap_data_key(&kek, &stored.wrapped_data_key_b64)
            .context("unwrapping replay input data key")?;
        let prompt = aead::open(&data_key, &ciphertext, &[]).context("decrypting replay input")?;
        if digest(&prompt) != stored.prompt_sha256 {
            bail!("replay input plaintext digest does not match");
        }
        Ok(Zeroizing::new(prompt))
    }

    /// Return the recorded inputs after `journal_cursor`, in execution order.
    /// Every artifact is binding-checked while enumerating; a stray or renamed
    /// file fails closed instead of being skipped and silently shortening a
    /// replay.
    pub fn after(
        &self,
        session_id: &AgentSessionId,
        generation: u64,
        journal_cursor: u64,
    ) -> Result<Vec<ReplayInputRef>> {
        let binding = ReplayInputBinding {
            session_id: session_id.clone(),
            generation,
            journal_cursor: 0,
        };
        let directory = self.directory(&binding);
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let metadata = std::fs::symlink_metadata(&directory)
            .with_context(|| format!("reading replay input directory {}", directory.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("replay input directory must be a non-symlink directory");
        }

        let mut references = Vec::new();
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("listing replay input directory {}", directory.display()))?
        {
            let entry = entry.context("reading replay input directory entry")?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("replay input artifact name is not UTF-8"))?;
            let cursor = name
                .strip_prefix("cursor-")
                .and_then(|value| value.strip_suffix(".json"))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| anyhow::anyhow!("unexpected replay input artifact {name:?}"))?;
            let stored = read_stored(&path)?;
            if stored.binding.session_id != *session_id
                || stored.binding.generation != generation
                || stored.binding.journal_cursor != cursor
            {
                bail!("replay input artifact binding does not match its path");
            }
            if cursor > journal_cursor {
                references.push(reference_for(&stored));
            }
        }
        references.sort_by_key(|reference| reference.binding.journal_cursor);
        Ok(references)
    }

    fn directory(&self, binding: &ReplayInputBinding) -> PathBuf {
        self.root
            .join(binding.session_id.as_str())
            .join("replay-inputs")
            .join(format!("generation-{}", binding.generation))
    }

    fn existing(
        &self,
        path: &Path,
        expected_binding: &ReplayInputBinding,
        prompt: &[u8],
    ) -> Result<ReplayInputRef> {
        let stored = read_stored(path)?;
        if stored.binding != *expected_binding {
            bail!("replay input artifact binding does not match its path");
        }
        let reference = reference_for(&stored);
        let existing = self.load(&reference)?;
        if existing.as_slice() != prompt {
            bail!("replay input cursor already records different bytes");
        }
        Ok(reference)
    }
}

fn artifact_path(directory: &Path, cursor: u64) -> PathBuf {
    directory.join(format!("cursor-{cursor}.json"))
}

fn read_stored(path: &Path) -> Result<StoredReplayInput> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading replay input metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("replay input artifact must be a non-symlink file");
    }
    if metadata.len() > MAX_REPLAY_ARTIFACT_BYTES {
        bail!(
            "replay input artifact is {} bytes; the limit is {MAX_REPLAY_ARTIFACT_BYTES}",
            metadata.len()
        );
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading replay input artifact {}", path.display()))?;
    serde_json::from_slice(&bytes).context("parsing replay input artifact")
}

fn reference_for(stored: &StoredReplayInput) -> ReplayInputRef {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm.replay-input.v1\0");
    hasher.update(stored.binding.session_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(stored.binding.generation.to_be_bytes());
    hasher.update(stored.binding.journal_cursor.to_be_bytes());
    hasher.update(stored.prompt_sha256.as_bytes());
    hasher.update(stored.ciphertext_sha256.as_bytes());
    hasher.update(stored.wrapped_data_key_b64.as_bytes());
    ReplayInputRef {
        binding: stored.binding.clone(),
        artifact_digest: format!("{DIGEST_PREFIX}{}", hex::encode(hasher.finalize())),
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{DIGEST_PREFIX}{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(cursor: u64) -> ReplayInputBinding {
        ReplayInputBinding {
            session_id: AgentSessionId::parse("replay-session").unwrap(),
            generation: 3,
            journal_cursor: cursor,
        }
    }

    #[test]
    fn replay_input_is_encrypted_idempotent_and_tamper_evident() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("sessions");
        let keys = temp.path().join("keys");
        let store = ReplayInputStore::at(&root, &keys);
        let private = b"private prompt bytes";
        let reference = store.record(binding(7), private).unwrap();
        assert_eq!(store.load(&reference).unwrap().as_slice(), private);
        assert_eq!(store.record(binding(7), private).unwrap(), reference);

        let path = artifact_path(&store.directory(&binding(7)), 7);
        let on_disk = std::fs::read(&path).unwrap();
        assert!(
            !on_disk
                .windows(private.len())
                .any(|window| window == private)
        );

        let mut stored: StoredReplayInput = serde_json::from_slice(&on_disk).unwrap();
        stored.ciphertext_b64.push('A');
        mvm_core::atomic_io::atomic_write_durable(
            &path,
            &serde_json::to_vec_pretty(&stored).unwrap(),
        )
        .unwrap();
        assert!(store.load(&reference).is_err());
    }

    #[test]
    fn replay_input_refuses_bounds_cursor_reuse_and_wrong_key() {
        let temp = tempfile::tempdir().unwrap();
        let store = ReplayInputStore::at(temp.path().join("sessions"), temp.path().join("keys"));
        assert!(
            store
                .record(binding(1), &vec![0; MAX_REPLAY_INPUT_BYTES + 1])
                .is_err()
        );
        let reference = store.record(binding(2), b"first").unwrap();
        assert!(store.record(binding(2), b"second").is_err());

        let wrong =
            ReplayInputStore::at(temp.path().join("sessions"), temp.path().join("other-keys"));
        mvm_core::transcript::load_or_init_kek(&temp.path().join("other-keys")).unwrap();
        assert!(wrong.load(&reference).is_err());
    }

    #[test]
    fn replay_inputs_after_a_cursor_are_ordered_and_path_bound() {
        let temp = tempfile::tempdir().unwrap();
        let store = ReplayInputStore::at(temp.path().join("sessions"), temp.path().join("keys"));
        store.record(binding(9), b"third").unwrap();
        store.record(binding(3), b"first").unwrap();
        store.record(binding(6), b"second").unwrap();

        let session = binding(0).session_id;
        let references = store.after(&session, 3, 3).unwrap();
        assert_eq!(
            references
                .iter()
                .map(|reference| reference.binding.journal_cursor)
                .collect::<Vec<_>>(),
            vec![6, 9]
        );
        assert_eq!(store.load(&references[0]).unwrap().as_slice(), b"second");

        let original = artifact_path(&store.directory(&binding(9)), 9);
        let renamed = artifact_path(&store.directory(&binding(9)), 10);
        std::fs::rename(original, renamed).unwrap();
        assert!(store.after(&session, 3, 3).is_err());
    }

    #[test]
    fn racing_writers_cannot_clobber_one_cursor() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("sessions");
        let keys = temp.path().join("keys");
        mvm_core::transcript::load_or_init_kek(&keys).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|prompt| {
                let root = root.clone();
                let keys = keys.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let store = ReplayInputStore::at(root, keys);
                    barrier.wait();
                    store.record(binding(11), prompt)
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    }
}
