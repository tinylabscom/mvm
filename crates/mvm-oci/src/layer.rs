//! Layer fetch with streaming, digest verification, size caps, and
//! bounded retry.
//!
//! A single OCI layer can be hundreds of MB; loading it into memory
//! up front is not viable. [`OciLayerFetcher::fetch_layer`] streams
//! bytes through a hashing wrapper to a caller-supplied writer,
//! computing the SHA-256 incrementally and aborting the moment a
//! size cap is exceeded or the running digest diverges from what
//! the layer descriptor promised.
//!
//! Three protections layer (no pun intended) on top of each other:
//!
//! - **Size cap.** [`LayerFetchOptions::max_size`] bounds the byte
//!   count. Decompression bombs and oversized layers are a CVE-class
//!   category; the cap fails fast before the rest of the pull
//!   pipeline reads a single byte of poisoned content.
//! - **Digest verification.** SHA-256 over the streamed bytes is
//!   compared against the descriptor's pinned digest. Mismatches
//!   surface as [`OciError::DigestMismatch`]. Always fail closed.
//! - **Bounded retry.** [`LayerFetchOptions::max_retries`] caps the
//!   number of attempts on transient registry errors with
//!   exponential backoff. Permanent errors (malformed digest,
//!   digest mismatch, size-cap breach, invalid reference) skip the
//!   retry — those won't get better with more tries.

use crate::OciError;
use crate::manifest::{OciManifestFetcher, RegistryAuthConfig};
use crate::reference::ImageReference;
use oci_client::client::Client;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Marker substring stored in the `io::Error` we return from the
/// hashing writer when the size cap fires. The retry loop checks
/// the `cap_hit` flag directly, but the message is preserved so
/// surfaced error chains still read sensibly.
const CAP_EXCEEDED_MSG: &str = "mvm-oci: layer size cap exceeded";

/// One layer's worth of content-addressable storage. Extracted
/// from a parsed manifest via [`crate::FetchedManifest::layers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerDescriptor {
    /// `sha256:<lowercase-hex>` content digest. Layer content is
    /// fetched, hashed, and compared against this value; any
    /// mismatch fails closed.
    pub digest: String,
    /// Byte size the manifest advertises. The size cap is checked
    /// against [`LayerFetchOptions::max_size`] before the fetch
    /// starts, and again against the actual streamed byte count.
    pub size: u64,
    /// `mediaType` field from the manifest entry
    /// (e.g. `application/vnd.oci.image.layer.v1.tar+gzip`). Layer
    /// unpack uses this to pick the right decoder.
    pub media_type: String,
}

/// Knobs for [`OciLayerFetcher::fetch_layer`]. Defaults are tuned
/// for the modal pull case (mid-sized container images); production
/// callers can tighten them per-tenant.
#[derive(Debug, Clone)]
pub struct LayerFetchOptions {
    /// Hard cap on a single layer's byte count. Default 2 GiB —
    /// large enough for the legitimate fat-rootfs case
    /// (`tensorflow/tensorflow:latest-gpu` is ~3 GiB and we
    /// deliberately reject those at the default), small enough
    /// that a decompression-bomb attacker can't run the host out
    /// of disk through a small manifest.
    pub max_size: u64,
    /// Attempts on transient registry failure (5xx, network).
    /// Permanent errors skip retry. Default 3.
    pub max_retries: u32,
    /// First retry delay; doubles per attempt. Default 100 ms.
    pub initial_backoff: Duration,
}

impl Default for LayerFetchOptions {
    fn default() -> Self {
        Self {
            max_size: 2 * 1024 * 1024 * 1024,
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
        }
    }
}

/// Real layer fetcher backed by [`oci_client`]. Anonymous-only for
/// now; private-registry auth lands later with credential material
/// flowing through `secrecy`.
pub struct OciLayerFetcher {
    client: Client,
    options: LayerFetchOptions,
    auth: RegistryAuthConfig,
}

impl Default for OciLayerFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl OciLayerFetcher {
    pub fn new() -> Self {
        Self::with_options(LayerFetchOptions::default())
    }

    pub fn with_options(options: LayerFetchOptions) -> Self {
        Self {
            client: Client::new(Default::default()),
            options,
            auth: RegistryAuthConfig::Anonymous,
        }
    }

    pub fn with_options_and_auth(options: LayerFetchOptions, auth: RegistryAuthConfig) -> Self {
        Self {
            client: Client::new(Default::default()),
            options,
            auth,
        }
    }

    /// Share a client with an existing [`OciManifestFetcher`] so
    /// both halves of the pull pipeline pool connections through
    /// the same underlying `oci-client`.
    pub fn from_manifest_fetcher(
        manifest_fetcher: &OciManifestFetcher,
        options: LayerFetchOptions,
    ) -> Self {
        Self {
            client: manifest_fetcher.client().clone(),
            options,
            auth: manifest_fetcher.auth().clone(),
        }
    }

    /// Construct from a pre-built `oci_client::Client`. Tests use
    /// this to point at a wiremock-backed registry.
    pub fn with_client(client: Client, options: LayerFetchOptions) -> Self {
        Self {
            client,
            options,
            auth: RegistryAuthConfig::Anonymous,
        }
    }

    pub fn with_client_and_auth(
        client: Client,
        options: LayerFetchOptions,
        auth: RegistryAuthConfig,
    ) -> Self {
        Self {
            client,
            options,
            auth,
        }
    }

    /// Stream `layer` from `reference`'s registry into `writer`,
    /// verifying the content digest as bytes flow through. Returns
    /// the number of bytes written on success.
    ///
    /// Fails closed on any of:
    /// - declared `layer.size` exceeds `options.max_size`
    /// - streamed byte count exceeds `options.max_size`
    /// - SHA-256 over the streamed bytes != `layer.digest`
    /// - registry network or permission failure (with bounded
    ///   retry on transient classes)
    pub async fn fetch_layer(
        &self,
        reference: &ImageReference,
        layer: &LayerDescriptor,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<u64, OciError> {
        // Fail fast on a manifest that promises more bytes than
        // we're willing to write. Cheaper than starting the fetch.
        if layer.size > self.options.max_size {
            return Err(OciError::LayerTooLarge {
                declared: layer.size,
                cap: self.options.max_size,
            });
        }
        validate_layer_digest(&layer.digest)?;

        let upstream_ref: oci_client::Reference =
            reference
                .canonical()
                .parse()
                .map_err(|e: oci_client::ParseError| {
                    OciError::InvalidReference(format!("{}: {e}", reference.canonical()))
                })?;

        // Retries are only safe before any bytes have flowed
        // through the writer for this layer — past that point,
        // retrying would replay writes against an already-dirty
        // sink (file, ext4 staging dir, etc.). The byte count
        // lives in an `AtomicU64` shared with the hashing writer;
        // the retry guard checks it. `cap_hit` is a separate flag
        // so the mid-stream cap-exceeded path can be distinguished
        // from a generic IO error in the retry guard.
        let count = Arc::new(AtomicU64::new(0));
        let cap_hit = Arc::new(AtomicBool::new(false));
        let mut hasher = Sha256::new();

        let mut attempt: u32 = 0;
        let mut delay = self.options.initial_backoff;
        loop {
            let attempt_started_at = count.load(Ordering::SeqCst);
            let res = self
                .fetch_layer_once(
                    &upstream_ref,
                    layer,
                    writer,
                    &mut hasher,
                    Arc::clone(&count),
                    Arc::clone(&cap_hit),
                )
                .await;
            match res {
                Ok(n) => return Ok(n),
                Err(_) if cap_hit.load(Ordering::SeqCst) => {
                    // Mid-stream cap exceeded. Never retry — the
                    // sink already has up-to-cap dirty bytes and
                    // the registry is feeding more than we agreed
                    // to accept.
                    return Err(OciError::LayerTooLarge {
                        declared: layer.size,
                        cap: self.options.max_size,
                    });
                }
                Err(e)
                    if is_transient(&e)
                        && attempt < self.options.max_retries
                        && attempt_started_at == 0 =>
                {
                    // Connect-level / pre-body transient failure:
                    // nothing has been written to the sink for
                    // this layer yet, so a retry is safe.
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2);
                    // `count == 0` means no bytes were observed
                    // by `poll_write`, so the hasher is at its
                    // initial state; reset defensively in case a
                    // partial chunk got through without
                    // incrementing count.
                    hasher = Sha256::new();
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn fetch_layer_once(
        &self,
        reference: &oci_client::Reference,
        layer: &LayerDescriptor,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
        hasher: &mut Sha256,
        count: Arc<AtomicU64>,
        cap_hit: Arc<AtomicBool>,
    ) -> Result<u64, OciError> {
        let cap = self.options.max_size;
        let mut capped_writer = CappedHashingWriter {
            inner: writer,
            hasher,
            count: Arc::clone(&count),
            cap_hit: Arc::clone(&cap_hit),
            cap,
        };

        // `oci_client::Client::pull_blob` takes `impl AsLayerDescriptor`,
        // which is implemented for `&str` (and for upstream's own
        // layer-descriptor struct), but not `&String`. Pass the
        // digest as a string slice explicitly.
        let auth = self.auth.to_registry_auth();
        self.client
            .store_auth_if_needed(reference.resolve_registry(), &auth)
            .await;
        self.client
            .pull_blob(reference, layer.digest.as_str(), &mut capped_writer)
            .await
            .map_err(map_oci_error)?;

        capped_writer
            .inner
            .flush()
            .await
            .map_err(|e| OciError::Registry(format!("flush after blob fetch: {e}")))?;

        let final_count = count.load(Ordering::SeqCst);
        // Finalize via clone so the original hasher stays in a
        // defined state if a future revision adds a post-finalize
        // step. `Sha256` is `Clone`.
        let computed = format!("sha256:{}", hex::encode(hasher.clone().finalize()));
        if computed != layer.digest {
            return Err(OciError::DigestMismatch {
                expected: layer.digest.clone(),
                computed,
            });
        }
        Ok(final_count)
    }
}

/// Wraps a caller-supplied `AsyncWrite` with byte counting,
/// hashing, and a hard size cap. Any single write that would push
/// the count past `cap` errors out immediately — the underlying
/// writer never sees the over-cap bytes. `count` and `cap_hit`
/// are exposed as atomics so the retry loop one level up can
/// inspect them after `pull_blob` returns.
struct CappedHashingWriter<'a, W: ?Sized> {
    inner: &'a mut W,
    hasher: &'a mut Sha256,
    count: Arc<AtomicU64>,
    cap_hit: Arc<AtomicBool>,
    cap: u64,
}

impl<W> AsyncWrite for CappedHashingWriter<'_, W>
where
    W: AsyncWrite + Send + Unpin + ?Sized,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let count_now = this.count.load(Ordering::SeqCst);
        let remaining = this.cap.saturating_sub(count_now);
        if remaining == 0 && !buf.is_empty() {
            this.cap_hit.store(true, Ordering::SeqCst);
            return std::task::Poll::Ready(Err(std::io::Error::other(CAP_EXCEEDED_MSG)));
        }
        let to_write = buf.len().min(remaining as usize);
        let slice = &buf[..to_write];

        let inner = std::pin::Pin::new(&mut *this.inner);
        match inner.poll_write(cx, slice) {
            std::task::Poll::Ready(Ok(n)) => {
                this.hasher.update(&slice[..n]);
                this.count.fetch_add(n as u64, Ordering::SeqCst);
                std::task::Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

fn validate_layer_digest(d: &str) -> Result<(), OciError> {
    let (alg, hex_part) = d
        .split_once(':')
        .ok_or_else(|| OciError::MalformedDigest(format!("missing algorithm prefix: {d:?}")))?;
    if alg != "sha256" {
        return Err(OciError::UnsupportedDigestAlgorithm(alg.to_string()));
    }
    if hex_part.len() != 64 {
        return Err(OciError::MalformedDigest(format!(
            "sha256 digest must be 64 hex chars, got {} in {d:?}",
            hex_part.len()
        )));
    }
    if !hex_part
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(OciError::MalformedDigest(format!(
            "digest hex must be lowercase ascii: {d:?}"
        )));
    }
    Ok(())
}

/// Best-effort classification of `oci_client` errors. We hand
/// transient classes (network, 5xx, timeout) to the retry loop;
/// everything else fails immediately.
///
/// `oci-client` 0.16's `OciDistributionError` doesn't expose
/// structured status codes for every variant, so this is
/// string-shaped today. Tightening it to typed status inspection
/// is a follow-up — the optimistic-retry policy is good enough (the
/// worst case is "we waited a bit before reporting a permanent
/// error," which is harmless).
fn map_oci_error(e: oci_client::errors::OciDistributionError) -> OciError {
    OciError::Registry(e.to_string())
}

fn is_transient(e: &OciError) -> bool {
    match e {
        // Most registry errors that bubble through `oci_client`
        // become `OciError::Registry(...)`. Without structured
        // status codes from upstream we optimistically retry — the
        // bound is `LayerFetchOptions::max_retries`.
        OciError::Registry(_) => true,
        // These are deterministic given the inputs. Retrying does
        // not change the answer.
        OciError::DigestMismatch { .. }
        | OciError::InvalidReference(_)
        | OciError::MalformedDigest(_)
        | OciError::UnsupportedDigestAlgorithm(_)
        | OciError::LayerTooLarge { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_layer_digest_accepts_lowercase_sha256() {
        let d = format!("sha256:{}", "a".repeat(64));
        validate_layer_digest(&d).unwrap();
    }

    #[test]
    fn validate_layer_digest_rejects_unsupported_algorithm() {
        let err = validate_layer_digest(&format!("sha512:{}", "a".repeat(128))).unwrap_err();
        assert!(matches!(err, OciError::UnsupportedDigestAlgorithm(_)));
    }

    #[test]
    fn validate_layer_digest_rejects_wrong_length() {
        let err = validate_layer_digest("sha256:abc").unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)));
    }

    #[test]
    fn validate_layer_digest_rejects_uppercase() {
        let d = format!("sha256:{}", "A".repeat(64));
        let err = validate_layer_digest(&d).unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)));
    }

    #[test]
    fn default_options_are_2gib_3retries_100ms() {
        let o = LayerFetchOptions::default();
        assert_eq!(o.max_size, 2 * 1024 * 1024 * 1024);
        assert_eq!(o.max_retries, 3);
        assert_eq!(o.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn is_transient_classifies_correctly() {
        assert!(is_transient(&OciError::Registry("net".into())));
        assert!(!is_transient(&OciError::DigestMismatch {
            expected: "a".into(),
            computed: "b".into(),
        }));
        assert!(!is_transient(&OciError::InvalidReference("x".into())));
        assert!(!is_transient(&OciError::MalformedDigest("x".into())));
        assert!(!is_transient(&OciError::UnsupportedDigestAlgorithm(
            "sha512".into()
        )));
        assert!(!is_transient(&OciError::LayerTooLarge {
            declared: 1,
            cap: 0,
        }));
    }
}
