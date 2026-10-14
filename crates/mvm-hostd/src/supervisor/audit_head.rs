//! A host-signed record of how far a lifecycle chain has been verified, and
//! what a consumer folded out of the verified prefix.
//!
//! [`ChainCheckpoint`] resumes a walk from a stored, unsigned line count, and
//! that is why it is confined to `doctor`: whoever can write the file can have
//! a prefix-truncated chain accepted. A signed head is a different bargain. The
//! position *and* the state folded from the prefix are signed under the host
//! key — the same key that signs the chain — so forging a head costs exactly
//! what forging a chain line costs, and a head whose signature does not verify
//! is discarded before any of it is believed.
//!
//! # What resuming establishes
//!
//! A resumed load reads three things: the head file, the last verified line,
//! and whatever was appended after it. The last verified line must still hash
//! to the head's chain hash, and every appended line must link to that hash
//! and carry a valid signature. The verified prefix *behind* the boundary is
//! not re-read: the host verified it from genesis — or from an earlier head
//! that itself verified — when it signed the head, and re-verifying it on every
//! launch is the cost this module exists to remove. The work a resumed load
//! does is therefore proportional to what was appended since the head was
//! signed, not to the chain's history.
//!
//! An in-place edit behind the boundary is not caught here. It is caught by
//! `mvmctl trust audit verify`, which always walks every chain from genesis,
//! and the head never signs a statement about bytes it did not verify.
//!
//! # Fail closed, never trust the head over the chain
//!
//! Any head that does not fit — a shorter file, a boundary line that no longer
//! hashes to the recorded chain hash, a tail that does not link or does not
//! verify — is dropped and the chain is walked from genesis. Falling back never
//! manufactures a refusal (a stale head after rotation is routine) and never
//! serves the head's state in place of what the chain actually says.
//!
//! [`ChainCheckpoint`]: super::audit_file::ChainCheckpoint

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_contract::verify::hash_line;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::audit_checkpoint;
use super::audit_file::{VerifyError, verify_chain_bytes, verify_chain_bytes_resuming};
use crate::supervisor::audit::PlanAuditEntry;

/// Domain separator prefixed to the signed body, so a head signature can never
/// be mistaken for — or replayed as — a signature over any other bytes the host
/// key signs.
const SIGNING_DOMAIN: &[u8] = b"mvm-audit-head/1\n";

/// Bump when the body layout changes. An older head fails to parse and the
/// caller walks from genesis, so this needs no migration path.
const SCHEMA: u32 = 1;

/// Suffix distinguishing a signed head from the unsigned [`ChainCheckpoint`]
/// cache that shares its directory.
///
/// [`ChainCheckpoint`]: super::audit_file::ChainCheckpoint
const FILE_SUFFIX: &str = ".head.json";

/// Where a verified prefix ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainPosition {
    /// Lines verified, blank lines included.
    pub verified_lines: usize,
    /// The verified prefix is `[0, verified_bytes)`; a resumed walk reads from
    /// here.
    pub verified_bytes: u64,
    /// Byte offset where the last verified non-empty line begins. A resumed
    /// load re-hashes that one line to check the boundary still stands.
    pub last_line_offset: u64,
    /// Running chain hash after the prefix — SHA-256 of the last verified
    /// line, base64url unpadded.
    pub chain_hash: String,
}

impl ChainPosition {
    fn new(
        verified_lines: usize,
        verified_bytes: u64,
        last_line_offset: u64,
        tip: [u8; 32],
    ) -> Self {
        Self {
            verified_lines,
            verified_bytes,
            last_line_offset,
            chain_hash: URL_SAFE_NO_PAD.encode(tip),
        }
    }

    /// The position a genesis walk over `content` ended at, or `None` for a
    /// chain with no entries to stand behind.
    fn after_genesis_walk(content: &str, tip: [u8; 32]) -> Option<Self> {
        let (start, _) = last_nonempty_line_span(content.as_bytes())?;
        Some(Self::new(
            content.lines().count(),
            content.len() as u64,
            start as u64,
            tip,
        ))
    }

    /// The position after verifying `tail`, appended right after `self`.
    fn extended_by(&self, tail: &str, tip: [u8; 32]) -> Self {
        let last_line_offset = last_nonempty_line_span(tail.as_bytes())
            .map_or(self.last_line_offset, |(start, _)| {
                self.verified_bytes + start as u64
            });
        Self::new(
            self.verified_lines + tail.lines().count(),
            self.verified_bytes + tail.len() as u64,
            last_line_offset,
            tip,
        )
    }

    /// Decode the stored hash, or `None` when it is not 32 base64url bytes.
    fn hash_bytes(&self) -> Option<[u8; 32]> {
        let raw = URL_SAFE_NO_PAD.decode(&self.chain_hash).ok()?;
        raw.as_slice().try_into().ok()
    }
}

/// A head whose signature verified under the host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHead<S> {
    pub position: ChainPosition,
    /// Whatever the consumer folded out of the verified prefix.
    pub state: S,
}

/// The bytes the signature covers.
///
/// Generic over how the position and state are held, so `store` serializes
/// borrowed values and `load` deserializes owned ones through the one layout.
#[derive(Serialize, Deserialize)]
struct HeadBody<P, S> {
    schema: u32,
    /// The chain this head describes. Checked on load so a head copied between
    /// cache slots describes nothing.
    chain_path: String,
    position: P,
    state: S,
}

/// On-disk shape: the exact body bytes that were signed, kept as text so
/// verification never depends on re-serializing to the same bytes.
#[derive(Serialize, Deserialize)]
struct HeadFile {
    body: String,
    /// base64url unpadded Ed25519 signature over `SIGNING_DOMAIN || body`.
    signature: String,
}

/// Path of the signed head for `chain_path`.
pub fn head_path(chain_path: &Path) -> PathBuf {
    let name = audit_checkpoint::cache_file_stem(chain_path);
    audit_checkpoint::cache_dir().join(format!("{name}{FILE_SUFFIX}"))
}

fn chain_identity(chain_path: &Path) -> String {
    chain_path.display().to_string()
}

fn signed_bytes(body: &str) -> Vec<u8> {
    let mut bytes = SIGNING_DOMAIN.to_vec();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

/// Load the signed head for `chain_path`, if one exists and verifies under
/// `verifying`.
///
/// A missing or unparseable head is `None` — the caller walks from genesis,
/// which is always correct. A head whose signature does not verify is also
/// `None`, and is logged: it is either another host key's work or a forgery,
/// and in neither case is any of it believed.
pub fn load<S: DeserializeOwned>(
    chain_path: &Path,
    verifying: &VerifyingKey,
) -> Option<VerifiedHead<S>> {
    let path = head_path(chain_path);
    let raw = std::fs::read_to_string(&path).ok()?;
    let file: HeadFile = serde_json::from_str(&raw).ok()?;
    if !signature_verifies(&file, verifying) {
        tracing::warn!(
            head = %path.display(),
            chain = %chain_path.display(),
            "signed audit head does not verify under the host key; walking the chain from genesis"
        );
        return None;
    }
    let body: HeadBody<ChainPosition, S> = serde_json::from_str(&file.body).ok()?;
    if body.schema != SCHEMA || body.chain_path != chain_identity(chain_path) {
        return None;
    }
    Some(VerifiedHead {
        position: body.position,
        state: body.state,
    })
}

fn signature_verifies(file: &HeadFile, verifying: &VerifyingKey) -> bool {
    let Ok(raw) = URL_SAFE_NO_PAD.decode(&file.signature) else {
        return false;
    };
    let Ok(bytes): Result<[u8; 64], _> = raw.as_slice().try_into() else {
        return false;
    };
    verifying
        .verify(&signed_bytes(&file.body), &Signature::from_bytes(&bytes))
        .is_ok()
}

/// Sign and store a head for `chain_path`. Best-effort: a head that cannot be
/// written only costs the next load a genesis walk.
pub fn store<S: Serialize>(
    chain_path: &Path,
    position: &ChainPosition,
    state: &S,
    signing: &SigningKey,
) {
    let body = HeadBody {
        schema: SCHEMA,
        chain_path: chain_identity(chain_path),
        position,
        state,
    };
    let Ok(body) = serde_json::to_string(&body) else {
        return;
    };
    let signature = URL_SAFE_NO_PAD.encode(signing.sign(&signed_bytes(&body)).to_bytes());
    let Ok(encoded) = serde_json::to_vec(&HeadFile { body, signature }) else {
        return;
    };
    let path = head_path(chain_path);
    if let Err(error) = audit_checkpoint::write_cache_file(&path, &encoded) {
        tracing::debug!(head = %path.display(), %error, "could not persist signed audit head");
    }
}

/// What one verification pass established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resumed<S> {
    /// The consumer state after folding every verified entry.
    pub state: S,
    /// Where verification ended, or `None` for a chain with no entries.
    pub position: Option<ChainPosition>,
    /// Entries whose signatures were verified on this pass. A resumed pass
    /// over an unchanged chain verifies none.
    pub verified_now: usize,
    /// Whether the stored head was used. `false` means the chain was walked
    /// from genesis — because no head fit, or because none was supplied.
    pub resumed: bool,
}

impl<S> Resumed<S> {
    /// Whether this pass learned something a stored head does not yet say.
    pub fn advanced(&self) -> bool {
        !self.resumed || self.verified_now > 0
    }
}

/// Verify the chain at `path`, resuming from `head` when it fits and walking
/// from genesis otherwise, folding each newly verified entry into the state.
///
/// `fresh` builds the state a genesis walk starts from; `head.state` is what a
/// resumed walk starts from. The fold sees every entry exactly once across the
/// loads that built the state, in chain order.
pub fn verify_resuming<S, F>(
    path: &Path,
    verifying: &VerifyingKey,
    head: Option<VerifiedHead<S>>,
    fresh: impl FnOnce() -> S,
    mut fold: F,
) -> Result<Resumed<S>, VerifyError>
where
    F: FnMut(&mut S, &PlanAuditEntry),
{
    if let Some(head) = head
        && let Some(resumed) = try_resume(path, verifying, head, &mut fold)?
    {
        return Ok(resumed);
    }
    walk_from_genesis(path, verifying, fresh(), &mut fold)
}

fn io_error(error: std::io::Error) -> VerifyError {
    VerifyError::Io(error.to_string())
}

/// Resume from `head`, or `None` when the head does not fit the file.
///
/// Only an I/O failure is an error here: everything else that can go wrong is
/// "the head is stale", and the genesis walk that follows is what decides
/// whether the chain itself is sound.
fn try_resume<S, F>(
    path: &Path,
    verifying: &VerifyingKey,
    head: VerifiedHead<S>,
    fold: &mut F,
) -> Result<Option<Resumed<S>>, VerifyError>
where
    F: FnMut(&mut S, &PlanAuditEntry),
{
    let Some(seed) = head.position.hash_bytes() else {
        return Ok(None);
    };
    let mut file = File::open(path).map_err(io_error)?;
    let len = file.metadata().map_err(io_error)?.len();
    let position = &head.position;
    if position.last_line_offset >= position.verified_bytes || len < position.verified_bytes {
        return Ok(None);
    }
    if !boundary_stands(&mut file, position, &seed)? {
        return Ok(None);
    }
    let mut tail = String::new();
    if file.read_to_string(&mut tail).is_err() {
        return Ok(None);
    }
    if tail.is_empty() {
        return Ok(Some(Resumed {
            state: head.state,
            position: Some(head.position),
            verified_now: 0,
            resumed: true,
        }));
    }
    let Ok(walk) = verify_chain_bytes_resuming(&tail, verifying, 0, seed) else {
        return Ok(None);
    };
    let mut state = head.state;
    for entry in &walk.entries {
        fold(&mut state, entry);
    }
    Ok(Some(Resumed {
        state,
        position: Some(head.position.extended_by(&tail, walk.tip)),
        verified_now: walk.entries.len(),
        resumed: true,
    }))
}

/// Whether the last verified line still hashes to the head's chain hash.
///
/// Leaves `file` positioned at `verified_bytes`, where the tail begins.
fn boundary_stands(
    file: &mut File,
    position: &ChainPosition,
    seed: &[u8; 32],
) -> Result<bool, VerifyError> {
    file.seek(SeekFrom::Start(position.last_line_offset))
        .map_err(io_error)?;
    let span = position.verified_bytes - position.last_line_offset;
    let Ok(span) = usize::try_from(span) else {
        return Ok(false);
    };
    let mut boundary = vec![0u8; span];
    file.read_exact(&mut boundary).map_err(io_error)?;
    Ok(boundary_line_hash(&boundary) == Some(*seed))
}

/// Hash of the boundary slice as the walk hashed it: without its terminator.
/// `None` when the slice is not a terminated line.
fn boundary_line_hash(boundary: &[u8]) -> Option<[u8; 32]> {
    let (_, end) = last_nonempty_line_span(boundary)?;
    if end == boundary.len() {
        return None;
    }
    Some(hash_line(&boundary[..end]))
}

fn walk_from_genesis<S, F>(
    path: &Path,
    verifying: &VerifyingKey,
    mut state: S,
    fold: &mut F,
) -> Result<Resumed<S>, VerifyError>
where
    F: FnMut(&mut S, &PlanAuditEntry),
{
    let content = std::fs::read_to_string(path).map_err(io_error)?;
    let walk = verify_chain_bytes(&content, verifying)?;
    for entry in &walk.entries {
        fold(&mut state, entry);
    }
    Ok(Resumed {
        state,
        position: ChainPosition::after_genesis_walk(&content, walk.tip),
        verified_now: walk.entries.len(),
        resumed: false,
    })
}

/// Byte span `[start, end)` of the last non-empty line in `bytes`, excluding
/// its terminator. `None` when there is no non-empty line.
fn last_nonempty_line_span(bytes: &[u8]) -> Option<(usize, usize)> {
    let end = bytes.iter().rposition(|b| *b != b'\n')? + 1;
    let start = bytes[..end]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_nonempty_line_is_found_behind_trailing_blank_lines() {
        assert_eq!(last_nonempty_line_span(b"a\nbb\n\n\n"), Some((2, 4)));
        assert_eq!(last_nonempty_line_span(b"a\nbb\n"), Some((2, 4)));
        assert_eq!(last_nonempty_line_span(b"only"), Some((0, 4)));
        assert_eq!(last_nonempty_line_span(b"\n\n"), None);
        assert_eq!(last_nonempty_line_span(b""), None);
    }

    #[test]
    fn a_boundary_must_be_a_terminated_line() {
        assert_eq!(boundary_line_hash(b"line"), None, "no terminator");
        assert_eq!(boundary_line_hash(b"line\n"), Some(hash_line(b"line")));
        assert_eq!(
            boundary_line_hash(b"line\n\n"),
            Some(hash_line(b"line")),
            "blank lines after the boundary do not change what was hashed"
        );
    }

    #[test]
    fn extending_a_position_moves_the_boundary_to_the_tail_s_last_line() {
        let base = ChainPosition::new(2, 20, 10, [1u8; 32]);
        let extended = base.extended_by("xx\nyyy\n", [2u8; 32]);
        assert_eq!(extended.verified_lines, 4);
        assert_eq!(extended.verified_bytes, 27);
        assert_eq!(extended.last_line_offset, 23);
        assert_eq!(extended.hash_bytes(), Some([2u8; 32]));
    }

    #[test]
    fn a_blank_only_tail_keeps_the_old_boundary() {
        let base = ChainPosition::new(2, 20, 10, [1u8; 32]);
        let extended = base.extended_by("\n\n", [1u8; 32]);
        assert_eq!(extended.last_line_offset, 10);
        assert_eq!(extended.verified_bytes, 22);
    }
}
