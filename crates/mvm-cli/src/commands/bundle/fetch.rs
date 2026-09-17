//! `mvmctl bundle fetch <SOURCE>` — verify a `.mvmpkg` archive
//! against the local trust store.
//!
//! `SOURCE` is a path on disk, an `https://` URL, or an `oci://`
//! image-registry reference by tag or digest. HTTPS downloads use the
//! workspace's existing blocking HTTP helper
//! ([`crate::http::download_file`]). Plain `http://` URLs, and registries
//! reached over plain HTTP, are refused unless `--allow-http` opts in — the
//! trust model (Ed25519 signature) catches a tampered bundle, but plain HTTP
//! makes traffic observable, and consumers often have no idea they typed the
//! wrong scheme.
//!
//! Every source ends in the same place: the bytes go to
//! `read_and_verify_bundle` and the local trust store decides. A registry
//! only moves bytes; the digests it is held to prove it moved the right
//! ones, not that they are trustworthy.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::plan::bundle::{FsTrustStore, bundle_sha256, read_and_verify_bundle};
use mvm_core::user_config::MvmConfig;
use mvm_fs::oci::ImageReference;

use super::super::Cli;
use super::registry::{
    REGISTRY_SCHEME, RegistryTransport, admit_registry_source, display_reference,
    parse_registry_reference, pull_bundle,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Local path to a `.mvmpkg` archive, an `https://` URL, or an
    /// `oci://<registry>/<repository>:<tag>` or `@sha256:<digest>`
    /// registry reference (HTTP is opt-in via `--allow-http`).
    #[arg(value_name = "SOURCE")]
    pub source: String,
    /// Override the trust store directory. Defaults to
    /// `~/.mvm/trusted-publishers/`.
    #[arg(long, value_name = "DIR")]
    pub trust_store: Option<PathBuf>,
    /// Output the verified manifest as JSON instead of a
    /// human-readable summary.
    #[arg(long)]
    pub json: bool,
    /// Allow plain-HTTP downloads and registries. The Ed25519 signature
    /// still catches tampering, but HTTP exposes traffic metadata
    /// (e.g. which bundle a host is pulling). Off by default.
    #[arg(long)]
    pub allow_http: bool,
    /// Production mode. Refuses `--allow-http` for every source. For an
    /// `oci://` source, also refuses a tag instead of a digest and a registry
    /// the OCI registry policy does not allow, before contacting it. Paths
    /// and `https://` URLs are not restricted further; every source must
    /// still pass the signature check.
    #[arg(long)]
    pub prod: bool,
}

/// Parsed source. Kept narrow so the dispatch fn below stays a small
/// `match`.
#[derive(Debug, PartialEq, Eq)]
enum BundleSource {
    /// Path on the local filesystem.
    File(PathBuf),
    /// `https://…` URL — verified TLS at the wire layer.
    HttpsUrl(String),
    /// `http://…` URL — refused unless `--allow-http` is set.
    HttpUrl(String),
    /// `oci://…` image-registry reference, by tag or by digest.
    Registry(ImageReference),
}

impl BundleSource {
    /// Parse a user-supplied string into the right variant.
    ///
    /// The rule is prefix-only and never looks at the filesystem, so the
    /// answer does not depend on what happens to exist in the working
    /// directory: `oci://` is a registry reference, `https://` and
    /// `http://` are URLs, and anything else is a local path. A path shaped
    /// like a reference — `registry.local:5000/app:v1` — stays a path, so a
    /// local file is never sent to the network by accident. Prefixes are
    /// case-sensitive, like the URL grammar.
    fn parse(s: &str) -> Result<Self> {
        if s.starts_with(REGISTRY_SCHEME) {
            Ok(Self::Registry(parse_registry_reference(s)?))
        } else if s.starts_with("https://") {
            Ok(Self::HttpsUrl(s.to_string()))
        } else if s.starts_with("http://") {
            Ok(Self::HttpUrl(s.to_string()))
        } else {
            Ok(Self::File(PathBuf::from(s)))
        }
    }
}

/// Transport switches shared by every verb that loads a bundle.
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::commands) struct LoadOptions {
    pub allow_http: bool,
    pub prod: bool,
}

/// Archive bytes plus, for a registry source, the digest they came from.
pub(in crate::commands) struct LoadedBundle {
    pub bytes: Vec<u8>,
    /// Digest-pinned reference the bytes were pulled at. A pull by tag
    /// records here which manifest the tag named at the time.
    pub resolved: Option<ImageReference>,
}

/// Load a bundle from any source, honouring its transport rules. Shared by
/// `fetch` and `install`.
pub(in crate::commands) fn load_bundle(source: &str, options: LoadOptions) -> Result<LoadedBundle> {
    let parsed = BundleSource::parse(source)?;
    load_archive(&parsed, options, |reference| {
        RegistryTransport::for_reference(reference, options.allow_http)
    })
}

/// Load the archive bytes. `transport_for` is only called for a registry
/// source, and only after the `--prod` check has passed.
fn load_archive(
    src: &BundleSource,
    options: LoadOptions,
    transport_for: impl FnOnce(&ImageReference) -> Result<RegistryTransport>,
) -> Result<LoadedBundle> {
    if options.prod && options.allow_http {
        anyhow::bail!(
            "--prod refuses --allow-http: a production bundle is never fetched over plain HTTP"
        );
    }
    let bytes = match src {
        BundleSource::File(path) => std::fs::read(path)
            .with_context(|| format!("reading bundle archive at {}", path.display()))?,
        BundleSource::HttpsUrl(url) => download_to_bytes(url)?,
        BundleSource::HttpUrl(url) => {
            if !options.allow_http {
                anyhow::bail!(
                    "refusing to fetch over plain HTTP: {url}\n   \
                     The Ed25519 signature still catches tampering, but HTTP exposes traffic \
                     metadata. Pass --allow-http to override (with a launch-time warning), or \
                     use the https:// URL if the publisher offers one."
                );
            }
            crate::ui::warn(&format!(
                "⚠ Downloading bundle over plain HTTP from {url}\n   \
                 Signature verification still applies; traffic metadata is visible to anyone \
                 on the wire."
            ));
            download_to_bytes(url)?
        }
        BundleSource::Registry(reference) => {
            admit_registry_source(reference, options.prod, options.allow_http)?;
            let pulled = pull_bundle(reference, &transport_for(reference)?)?;
            return Ok(LoadedBundle {
                bytes: pulled.bytes,
                resolved: Some(pulled.resolved),
            });
        }
    };
    Ok(LoadedBundle {
        bytes,
        resolved: None,
    })
}

fn download_to_bytes(url: &str) -> Result<Vec<u8>> {
    // Write to a temp file then read back. Two passes is fine for
    // v1 — bundles are modest in size, and the second read covers
    // the disk-cache-warm path the verifier would walk anyway.
    let tmp = tempfile::NamedTempFile::new().context("creating temp file for bundle download")?;
    crate::http::download_file(url, tmp.path())
        .with_context(|| format!("downloading bundle from {url}"))?;
    std::fs::read(tmp.path())
        .with_context(|| format!("reading downloaded bundle from {}", tmp.path().display()))
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let loaded = load_bundle(
        &args.source,
        LoadOptions {
            allow_http: args.allow_http,
            prod: args.prod,
        },
    )?;
    let bytes = loaded.bytes;

    let trust = match args.trust_store {
        Some(p) => FsTrustStore::new(p),
        None => FsTrustStore::default_path()
            .context("resolving default trust-store path (~/.mvm/trusted-publishers/)")?,
    };

    let verified = read_and_verify_bundle(&bytes, &trust)
        .with_context(|| format!("verifying bundle from {}", args.source))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&verified.manifest)?);
    } else {
        let summary = BundleSummary {
            bundle_sha256: bundle_sha256(&bytes),
            resolved: loaded.resolved.as_ref().map(display_reference),
            key_id: verified.key_id.0.clone(),
            publisher: verified.manifest.publisher.clone(),
            arch: verified.manifest.arch.clone(),
            profile: verified.manifest.profile.clone(),
            workload_label: verified.manifest.workload_label.clone(),
            artifact_count: verified.manifest.artifacts.len(),
            has_verity: verified.manifest.verity.is_some(),
        };
        summary.render();
    }
    Ok(())
}

struct BundleSummary {
    bundle_sha256: String,
    resolved: Option<String>,
    key_id: String,
    publisher: String,
    arch: String,
    profile: Option<String>,
    workload_label: Option<String>,
    artifact_count: usize,
    has_verity: bool,
}

impl BundleSummary {
    fn render(&self) {
        println!("Bundle verified");
        println!("  sha256:    {}", self.bundle_sha256);
        if let Some(resolved) = &self.resolved {
            println!("  source:    {resolved}");
        }
        println!("  key_id:    {}", self.key_id);
        println!("  publisher: {}", self.publisher);
        println!("  arch:      {}", self.arch);
        if let Some(p) = &self.profile {
            println!("  profile:   {p}");
        }
        if let Some(l) = &self.workload_label {
            println!("  label:     {l}");
        }
        println!("  artifacts: {}", self.artifact_count);
        println!(
            "  verity:    {}",
            if self.has_verity { "yes" } else { "no" }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::bundle::registry::publish_bundle;
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::bundle::{
        ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, key_id_from_pubkey,
        sha256_hex, write_bundle,
    };
    use mvm_fs::oci::test_registry::MemoryRegistry;
    use mvm_fs::oci::{
        ArtifactKind, ClientConfig, ClientProtocol, OciArtifactClient, RegistryAuthConfig,
    };

    #[test]
    fn parse_https_url() {
        let s = BundleSource::parse("https://registry.example.com/foo.mvmpkg").unwrap();
        assert_eq!(
            s,
            BundleSource::HttpsUrl("https://registry.example.com/foo.mvmpkg".to_string())
        );
    }

    #[test]
    fn parse_http_url() {
        let s = BundleSource::parse("http://registry.example.com/foo.mvmpkg").unwrap();
        assert_eq!(
            s,
            BundleSource::HttpUrl("http://registry.example.com/foo.mvmpkg".to_string())
        );
    }

    #[test]
    fn parse_relative_file_path() {
        let s = BundleSource::parse("./bundles/foo.mvmpkg").unwrap();
        assert_eq!(s, BundleSource::File(PathBuf::from("./bundles/foo.mvmpkg")));
    }

    #[test]
    fn parse_absolute_file_path() {
        let s = BundleSource::parse("/tmp/foo.mvmpkg").unwrap();
        assert_eq!(s, BundleSource::File(PathBuf::from("/tmp/foo.mvmpkg")));
    }

    #[test]
    fn parse_scheme_lookalike_is_still_a_path() {
        // A path that happens to begin with "https" but no "://"
        // separator is a file path, not a URL. This protects against
        // accidental misinterpretation of cwd-relative names.
        let s = BundleSource::parse("https-mirror/foo.mvmpkg").unwrap();
        assert_eq!(
            s,
            BundleSource::File(PathBuf::from("https-mirror/foo.mvmpkg"))
        );
    }

    #[test]
    fn parse_scheme_is_case_sensitive() {
        // Match the conventional URL grammar — lowercase only. An
        // uppercase prefix is more likely a filename than a real
        // URL on a filesystem.
        for input in [
            "HTTPS://registry.example.com/foo",
            "OCI://registry.example.com/foo:v1",
        ] {
            assert_eq!(
                BundleSource::parse(input).unwrap(),
                BundleSource::File(PathBuf::from(input))
            );
        }
    }

    #[test]
    fn parse_registry_tag_and_digest_references() {
        let tagged = BundleSource::parse("oci://registry.example:5000/team/app:v1").unwrap();
        let BundleSource::Registry(tagged) = tagged else {
            panic!("oci:// must parse as a registry reference");
        };
        assert_eq!(tagged.registry, "registry.example:5000");
        assert_eq!(tagged.repository, "team/app");
        assert_eq!(tagged.tag.as_deref(), Some("v1"));
        assert!(!tagged.is_digest_pinned());

        let digest = format!("sha256:{}", "a".repeat(64));
        let pinned =
            BundleSource::parse(&format!("oci://registry.example/team/app@{digest}")).unwrap();
        let BundleSource::Registry(pinned) = pinned else {
            panic!("oci:// must parse as a registry reference");
        };
        assert_eq!(pinned.digest.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn a_reference_shaped_path_without_the_prefix_is_a_local_path() {
        // The precedence rule: only `oci://` reaches a registry. A path that
        // happens to read as `host/name:tag` must never be sent to the
        // network, whether or not a file by that name exists.
        for input in [
            "registry.local:5000/app:v1",
            "localhost/app:v1",
            "bundles.d/app@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(
                BundleSource::parse(input).unwrap(),
                BundleSource::File(PathBuf::from(input)),
                "{input}"
            );
        }
    }

    #[test]
    fn a_malformed_registry_reference_is_refused() {
        for input in [
            "oci://",
            "oci://registry.example/app@sha256:short",
            "oci://https://x/y:v1",
        ] {
            assert!(
                BundleSource::parse(input).is_err(),
                "{input} must be refused"
            );
        }
    }

    #[test]
    fn load_archive_refuses_http_without_allow_http() {
        let src = BundleSource::HttpUrl("http://example.com/foo.mvmpkg".to_string());
        let err = load_archive(&src, LoadOptions::default(), no_transport)
            .err()
            .expect("must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refusing to fetch over plain HTTP"),
            "got: {msg}"
        );
        // The escape hatch hint should appear in the same message so
        // users know exactly how to recover.
        assert!(msg.contains("--allow-http"), "got: {msg}");
    }

    #[test]
    fn load_archive_reads_a_local_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello-bundle").unwrap();
        let src = BundleSource::File(tmp.path().to_path_buf());
        let loaded = load_archive(&src, LoadOptions::default(), no_transport).expect("reads");
        assert_eq!(loaded.bytes, b"hello-bundle");
        assert!(loaded.resolved.is_none());
    }

    // ── Registry transport ────────────────────────────────────────────

    struct Publisher {
        key: SigningKey,
        trust_dir: tempfile::TempDir,
    }

    impl Publisher {
        fn new(seed: u8) -> Self {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let trust_dir = tempfile::tempdir().expect("trust dir");
            Self { key, trust_dir }
        }

        fn trusted(seed: u8) -> Self {
            let publisher = Self::new(seed);
            let key_id = key_id_from_pubkey(&publisher.key.verifying_key());
            std::fs::write(
                publisher.trust_dir.path().join(format!("{}.pub", key_id.0)),
                publisher.key.verifying_key().to_bytes(),
            )
            .expect("enrol publisher");
            publisher
        }

        fn trust(&self) -> FsTrustStore {
            FsTrustStore::new(self.trust_dir.path())
        }

        fn bundle(&self, kernel: &[u8]) -> Vec<u8> {
            let artifact = BundleArtifact {
                name: "vmlinux".to_string(),
                role: ArtifactRole::Kernel,
                path: "artifacts/vmlinux".to_string(),
                sha256: sha256_hex(kernel),
                size_bytes: kernel.len() as u64,
            };
            let manifest = BundleManifest {
                schema_version: BUNDLE_SCHEMA_VERSION,
                publisher: "registry-test".to_string(),
                key_id: key_id_from_pubkey(&self.key.verifying_key()),
                arch: "aarch64".to_string(),
                kernel_version: None,
                profile: None,
                workload_label: Some("registry-round-trip".to_string()),
                created_at: "2026-09-16T00:00:00Z".to_string(),
                labels: Default::default(),
                artifacts: vec![artifact],
                verity: None,
                resources: None,
            };
            write_bundle(
                &manifest,
                &self.key,
                vec![("artifacts/vmlinux".to_string(), kernel.to_vec())],
            )
            .expect("write bundle")
        }
    }

    fn http_transport() -> RegistryTransport {
        RegistryTransport::new(ClientProtocol::Http, RegistryAuthConfig::Anonymous)
    }

    fn with_http(_: &ImageReference) -> Result<RegistryTransport> {
        Ok(http_transport())
    }

    fn no_transport(_: &ImageReference) -> Result<RegistryTransport> {
        anyhow::bail!("this source must not reach a registry")
    }

    fn source(registry: &MemoryRegistry, selector: &str) -> BundleSource {
        BundleSource::parse(&format!("oci://{}/team/app{selector}", registry.host()))
            .expect("fixture reference parses")
    }

    fn reference(registry: &MemoryRegistry, selector: &str) -> ImageReference {
        match source(registry, selector) {
            BundleSource::Registry(reference) => reference,
            other => panic!("expected a registry source, got {other:?}"),
        }
    }

    /// Push bytes as a bundle artifact without verifying them first, the
    /// way a hostile or careless publisher could.
    fn push_unverified(registry: &MemoryRegistry, selector: &str, bytes: &[u8]) {
        let client = OciArtifactClient::new(
            ClientConfig {
                protocol: ClientProtocol::Http,
            },
            RegistryAuthConfig::Anonymous,
        );
        let kind = ArtifactKind {
            artifact_type: mvm_contract::plan::bundle::BUNDLE_ARTIFACT_TYPE,
            layer_media_type: mvm_contract::plan::bundle::BUNDLE_LAYER_MEDIA_TYPE,
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(client.push(&reference(registry, selector), kind, bytes))
            .expect("unverified push");
    }

    #[test]
    fn push_then_fetch_by_tag_and_digest_verifies_against_the_trust_store() {
        let registry = MemoryRegistry::start();
        let publisher = Publisher::trusted(7);
        let archive = publisher.bundle(b"kernel bytes");

        let (verified, pushed) = publish_bundle(
            &archive,
            &reference(&registry, ":v1"),
            &http_transport(),
            &publisher.trust(),
        )
        .expect("publish");
        assert_eq!(
            verified.manifest.workload_label.as_deref(),
            Some("registry-round-trip")
        );
        assert_eq!(registry.blob(&pushed.layer_digest), Some(archive.clone()));

        let by_tag = load_archive(&source(&registry, ":v1"), LoadOptions::default(), with_http)
            .expect("fetch by tag");
        assert_eq!(by_tag.bytes, archive);
        assert_eq!(by_tag.resolved.as_ref(), Some(&pushed.reference));
        read_and_verify_bundle(&by_tag.bytes, &publisher.trust()).expect("verifies");

        let pinned = format!("@{}", pushed.manifest_digest);
        let by_digest = load_archive(
            &source(&registry, &pinned),
            LoadOptions::default(),
            with_http,
        )
        .expect("fetch by digest");
        read_and_verify_bundle(&by_digest.bytes, &publisher.trust()).expect("verifies");
    }

    #[test]
    fn push_refuses_a_bundle_the_local_trust_store_cannot_verify() {
        let registry = MemoryRegistry::start();
        let stranger = Publisher::new(9);
        let archive = stranger.bundle(b"kernel bytes");

        let err = publish_bundle(
            &archive,
            &reference(&registry, ":v1"),
            &http_transport(),
            &stranger.trust(),
        )
        .expect_err("an unverifiable bundle must not be published");

        assert!(format!("{err:#}").contains("refusing to push"), "{err:#}");
        assert!(registry.requests().is_empty(), "nothing was sent");
    }

    #[test]
    fn a_tag_reference_under_prod_is_refused_before_any_network_access() {
        let registry = MemoryRegistry::start();

        let err = load_archive(
            &source(&registry, ":v1"),
            LoadOptions {
                prod: true,
                ..LoadOptions::default()
            },
            no_transport,
        )
        .err()
        .expect("a tag under --prod must be refused");

        assert!(format!("{err:#}").contains("digest-pinned"), "{err:#}");
        assert!(
            registry.requests().is_empty(),
            "no request reached the registry"
        );
    }

    /// Point `MVM_OCI_POLICY` at a production policy that allows exactly
    /// `allowed`.
    fn prod_policy(
        env: &mut mvm_core::util::test_env::TestEnv,
        dir: &std::path::Path,
        allowed: &str,
    ) {
        let path = dir.join("oci-policy.toml");
        std::fs::write(
            &path,
            format!(
                "allowed_registries = [\"{allowed}\"]\n\n[[cosign]]\n\
                 certificate_identity = \"release@example.test\"\n\
                 certificate_oidc_issuer = \"https://issuer.example.test\"\n"
            ),
        )
        .expect("write policy");
        env.set("MVM_OCI_POLICY", &path);
    }

    #[test]
    fn prod_refuses_allow_http_before_any_network_access() {
        let registry = MemoryRegistry::start();
        let pinned = format!("@sha256:{}", "a".repeat(64));

        for src in [
            source(&registry, &pinned),
            BundleSource::File(PathBuf::from("./local.mvmpkg")),
        ] {
            let err = load_archive(
                &src,
                LoadOptions {
                    prod: true,
                    allow_http: true,
                },
                no_transport,
            )
            .err()
            .expect("--prod with --allow-http must be refused");
            assert!(
                format!("{err:#}").contains("--prod refuses --allow-http"),
                "{err:#}"
            );
        }
        assert!(registry.requests().is_empty());
    }

    #[test]
    fn prod_refuses_a_registry_the_oci_policy_does_not_allow_before_network() {
        let registry = MemoryRegistry::start();
        let dir = tempfile::tempdir().expect("policy dir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        prod_policy(&mut env, dir.path(), "registry.allowed.example");
        let pinned = format!("@sha256:{}", "a".repeat(64));

        let err = load_archive(
            &source(&registry, &pinned),
            LoadOptions {
                prod: true,
                ..LoadOptions::default()
            },
            no_transport,
        )
        .err()
        .expect("a registry outside the policy must be refused");

        assert!(
            format!("{err:#}").contains("denied by production policy"),
            "{err:#}"
        );
        assert!(registry.requests().is_empty());
    }

    #[test]
    fn prod_refuses_a_registry_source_without_an_oci_policy() {
        let dir = tempfile::tempdir().expect("dir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_OCI_POLICY", dir.path().join("absent.toml"));
        let reference: ImageReference =
            format!("registry.example/team/app@sha256:{}", "a".repeat(64))
                .parse()
                .expect("reference");

        let err = admit_registry_source(&reference, true, false).expect_err("no policy, no prod");

        assert!(
            format!("{err:#}").contains("requires an OCI registry policy"),
            "{err:#}"
        );
    }

    #[test]
    fn prod_admits_a_digest_pinned_reference_on_an_allowed_registry() {
        let dir = tempfile::tempdir().expect("dir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        prod_policy(&mut env, dir.path(), "registry.example");
        let reference: ImageReference =
            format!("registry.example/team/app@sha256:{}", "a".repeat(64))
                .parse()
                .expect("reference");

        admit_registry_source(&reference, true, false).expect("admitted");
    }

    #[test]
    fn a_tampered_bundle_blob_is_refused_before_verification() {
        let registry = MemoryRegistry::start();
        let publisher = Publisher::trusted(7);
        let archive = publisher.bundle(b"kernel bytes");
        let (_, pushed) = publish_bundle(
            &archive,
            &reference(&registry, ":v1"),
            &http_transport(),
            &publisher.trust(),
        )
        .expect("publish");
        registry.serve_blob_as(&pushed.layer_digest, &publisher.bundle(b"other kernel"));

        let err = load_archive(&source(&registry, ":v1"), LoadOptions::default(), with_http)
            .err()
            .expect("a swapped layer must be refused");

        assert!(format!("{err:#}").contains("digest mismatch"), "{err:#}");
    }

    #[test]
    fn a_manifest_not_matching_the_pinned_digest_is_refused() {
        let registry = MemoryRegistry::start();
        let publisher = Publisher::trusted(7);
        let (_, first) = publish_bundle(
            &publisher.bundle(b"first"),
            &reference(&registry, ":v1"),
            &http_transport(),
            &publisher.trust(),
        )
        .expect("publish first");
        publish_bundle(
            &publisher.bundle(b"second"),
            &reference(&registry, ":v2"),
            &http_transport(),
            &publisher.trust(),
        )
        .expect("publish second");
        let second = registry
            .manifest("team/app", "v2")
            .expect("second manifest");
        registry.serve_manifest_as("team/app", &first.manifest_digest, &second);

        let err = load_archive(
            &source(&registry, &format!("@{}", first.manifest_digest)),
            LoadOptions::default(),
            with_http,
        )
        .err()
        .expect("a manifest that is not the pinned one must be refused");

        assert!(format!("{err:#}").contains("digest mismatch"), "{err:#}");
    }

    #[test]
    fn a_bundle_signed_by_an_untrusted_key_is_refused_after_a_clean_pull() {
        let registry = MemoryRegistry::start();
        let consumer = Publisher::trusted(7);
        let stranger = Publisher::new(9);
        push_unverified(&registry, ":v1", &stranger.bundle(b"kernel bytes"));

        let loaded = load_archive(&source(&registry, ":v1"), LoadOptions::default(), with_http)
            .expect("the transport itself succeeds");
        let err = read_and_verify_bundle(&loaded.bytes, &consumer.trust())
            .expect_err("an untrusted publisher must be refused");

        assert!(err.to_string().to_lowercase().contains("key"), "{err}");
    }

    #[test]
    fn an_unsigned_bundle_is_refused_after_a_clean_pull() {
        let registry = MemoryRegistry::start();
        let consumer = Publisher::trusted(7);
        let signed = consumer.bundle(b"kernel bytes");
        let unsigned = strip_signature(&signed);
        push_unverified(&registry, ":v1", &unsigned);

        let loaded = load_archive(&source(&registry, ":v1"), LoadOptions::default(), with_http)
            .expect("the transport itself succeeds");
        assert!(
            read_and_verify_bundle(&loaded.bytes, &consumer.trust()).is_err(),
            "a bundle without a signature must be refused"
        );
    }

    fn strip_signature(archive: &[u8]) -> Vec<u8> {
        let mut out = tar::Builder::new(Vec::new());
        let mut input = tar::Archive::new(archive);
        for entry in input.entries().expect("entries") {
            let mut entry = entry.expect("entry");
            let path = entry.path().expect("path").to_string_lossy().to_string();
            if path == mvm_core::plan::bundle::SIGNATURE_FILENAME {
                continue;
            }
            let mut header = entry.header().clone();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).expect("read entry");
            out.append_data(&mut header, &path, bytes.as_slice())
                .expect("append entry");
        }
        out.into_inner().expect("finish archive")
    }
}
