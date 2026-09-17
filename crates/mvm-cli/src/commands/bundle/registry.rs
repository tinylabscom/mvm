//! Image registries as a transport for signed bundles.
//!
//! A bundle is stored as one artifact manifest whose single layer is the
//! `.mvmpkg` archive. The archive already carries its manifest and detached
//! signature, so the registry needs nothing else and is trusted with nothing:
//! it only moves bytes. The transport proves those bytes are the ones the
//! manifest names; whether the bundle is acceptable is decided afterwards by
//! the same signature check a local file gets.

use anyhow::{Context, Result, bail};

use mvm_contract::plan::bundle::{BUNDLE_ARTIFACT_TYPE, BUNDLE_LAYER_MEDIA_TYPE};
use mvm_core::plan::bundle::{TrustStore, VerifiedBundle, read_and_verify_bundle};
use mvm_fs::oci::{
    ArtifactKind, ArtifactLimits, ClientConfig, ClientProtocol, ImageReference, OciArtifactClient,
    PushedArtifact, RegistryAuthConfig,
};

/// Prefix that marks a bundle source as a registry reference. Required on
/// `fetch` and `install`, where a bare `host/name:tag` is a local path.
pub(super) const REGISTRY_SCHEME: &str = "oci://";

/// Largest bundle layer a pull buffers. Bundles are verified in memory, so
/// this bounds what a registry can make the host allocate.
pub(super) const MAX_BUNDLE_LAYER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

const BUNDLE_KIND: ArtifactKind<'static> = ArtifactKind {
    artifact_type: BUNDLE_ARTIFACT_TYPE,
    layer_media_type: BUNDLE_LAYER_MEDIA_TYPE,
};

/// How to reach a registry: the protocol and the credentials.
pub(super) struct RegistryTransport {
    config: ClientConfig,
    auth: RegistryAuthConfig,
}

impl RegistryTransport {
    /// Credentials come from the same environment variables `image pull`
    /// reads. Plain HTTP is used only when the caller opted in.
    pub(super) fn for_reference(reference: &ImageReference, allow_http: bool) -> Result<Self> {
        let auth = crate::commands::image::registry_auth_for(reference)?.auth;
        if allow_http {
            crate::ui::warn(&format!(
                "Talking to registry {} over plain HTTP. The bundle signature still applies; \
                 credentials and traffic are visible to anyone on the wire.",
                reference.registry
            ));
        }
        Ok(Self::new(protocol_for(allow_http), auth))
    }

    pub(super) fn new(protocol: ClientProtocol, auth: RegistryAuthConfig) -> Self {
        Self {
            config: ClientConfig { protocol },
            auth,
        }
    }

    fn client(&self) -> OciArtifactClient {
        OciArtifactClient::new(self.config.clone(), self.auth.clone()).with_limits(ArtifactLimits {
            max_layer_bytes: MAX_BUNDLE_LAYER_BYTES,
            ..ArtifactLimits::default()
        })
    }
}

fn protocol_for(allow_http: bool) -> ClientProtocol {
    if allow_http {
        ClientProtocol::Http
    } else {
        ClientProtocol::Https
    }
}

/// Parse a registry reference, with or without the `oci://` prefix.
pub(super) fn parse_registry_reference(input: &str) -> Result<ImageReference> {
    let bare = input.strip_prefix(REGISTRY_SCHEME).unwrap_or(input);
    if bare.contains("://") {
        bail!("{input:?} is not a registry reference");
    }
    bare.parse::<ImageReference>()
        .with_context(|| format!("parsing registry reference {input:?}"))
}

/// The form printed back to the user, which `fetch` and `install` accept.
pub(super) fn display_reference(reference: &ImageReference) -> String {
    format!("{REGISTRY_SCHEME}{}", reference.canonical())
}

/// Refuse a tag under `--prod`. A tag can be moved to other bytes after the
/// fact; a digest cannot. Checked from the reference alone, before any
/// network access.
pub(super) fn ensure_prod_digest_pin(reference: &ImageReference, prod: bool) -> Result<()> {
    if prod && !reference.is_digest_pinned() {
        bail!(
            "--prod requires a digest-pinned bundle reference; {} names a tag. \
             Use {REGISTRY_SCHEME}{}/{}@sha256:<digest>",
            display_reference(reference),
            reference.registry,
            reference.repository
        );
    }
    Ok(())
}

/// Archive bytes pulled from a registry, with the digest they were pulled at.
pub(super) struct PulledBundle {
    pub bytes: Vec<u8>,
    /// Digest-pinned: for a pull by tag, the manifest the tag named then.
    pub resolved: ImageReference,
}

pub(super) fn pull_bundle(
    reference: &ImageReference,
    transport: &RegistryTransport,
) -> Result<PulledBundle> {
    let pulled = runtime()?
        .block_on(transport.client().pull(reference, BUNDLE_KIND))
        .with_context(|| format!("pulling bundle from {}", display_reference(reference)))?;
    Ok(PulledBundle {
        bytes: pulled.layer,
        resolved: pulled.reference,
    })
}

/// Verify a bundle against the local trust store, then push it. A bundle
/// this host cannot verify is not published: whoever pulls it would refuse
/// it too, and a registry is a poor place to discover that.
pub(super) fn publish_bundle(
    archive: &[u8],
    reference: &ImageReference,
    transport: &RegistryTransport,
    trust: &dyn TrustStore,
) -> Result<(VerifiedBundle, PushedArtifact)> {
    let verified = read_and_verify_bundle(archive, trust)
        .context("refusing to push a bundle that does not verify against the local trust store")?;
    let pushed = runtime()?
        .block_on(transport.client().push(reference, BUNDLE_KIND, archive))
        .with_context(|| format!("pushing bundle to {}", display_reference(reference)))?;
    Ok((verified, pushed))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the async runtime for registry access")
}
