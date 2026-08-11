//! End-to-end tests for `mvm_fs::oci` against a hermetic in-process
//! OCI registry. Spec for the fixture lives in `tests/common/mod.rs`.
//!
//! These tests deliberately do NOT hit any real network — every
//! registry-client call goes to a hermetic localhost fixture. They
//! run in CI in seconds.

mod common;

use common::{HermeticRegistry, client_config_for, minimal_image_manifest};
use mvm_fs::oci::layer::verify_and_unpack_layer_file;
use mvm_fs::oci::{
    LayerDescriptor, LayerFetchOptions, LinuxPlatform, ManifestFetcher, OciError, OciLayerFetcher,
    OciManifestFetcher, RegistryAuthConfig, UnpackOptions, verify_sha256_digest,
};
use sha2::Digest;
use std::io::Write;
use std::time::Duration;

const LAYER_MEDIA: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const MANIFEST_MEDIA: &str = "application/vnd.oci.image.manifest.v1+json";

#[tokio::test]
async fn manifest_fetch_round_trip_against_hermetic_registry() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"layer-payload-1";
    let (manifest_bytes, _layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);

    let manifest_digest = reg
        .register_manifest_with_digest_path("library/test", "v1", MANIFEST_MEDIA, &manifest_bytes)
        .await;

    let fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let image = reg.image_ref("library/test", "v1");
    let fetched = fetcher.fetch(&image).await.expect("manifest fetch");

    assert_eq!(fetched.digest, manifest_digest);
    assert!(!fetched.bytes.is_empty(), "fetched bytes must not be empty");
    assert!(
        fetched.media_type.contains("vnd.oci.image.manifest")
            || fetched.media_type.contains("vnd.docker.distribution"),
        "got media_type {:?}",
        fetched.media_type
    );
}

#[tokio::test]
async fn manifest_fetch_accepts_missing_docker_content_digest_header() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"layer-payload-no-header";
    let (manifest_bytes, _layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);

    let manifest_digest = reg
        .register_manifest_without_digest_header_with_digest_path(
            "library/test",
            "v1",
            MANIFEST_MEDIA,
            &manifest_bytes,
        )
        .await;

    let fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let image = reg.image_ref("library/test", "v1");
    let fetched = fetcher.fetch(&image).await.expect("manifest fetch");

    assert_eq!(fetched.digest, manifest_digest);
    assert_eq!(fetched.bytes, manifest_bytes);
}

#[tokio::test]
async fn manifest_fetch_pinned_digest_still_verifies_without_digest_header() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"layer-payload-pinned-no-header";
    let (manifest_bytes, _layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);

    let manifest_digest = reg
        .register_manifest_without_digest_header_with_digest_path(
            "library/test",
            "v1",
            MANIFEST_MEDIA,
            &manifest_bytes,
        )
        .await;

    let fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let image = format!("{}/library/test@{manifest_digest}", reg.host())
        .parse()
        .expect("digest-pinned reference parses");
    let fetched = fetcher.fetch(&image).await.expect("manifest fetch");

    assert_eq!(fetched.digest, manifest_digest);
    assert_eq!(
        fetched.reference.digest.as_deref(),
        Some(manifest_digest.as_str())
    );
}

#[tokio::test]
async fn manifest_fetch_uses_explicit_bearer_auth() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"private-layer";
    let (manifest_bytes, _layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);
    let token = "fixture-token";

    let manifest_digest = reg
        .register_bearer_manifest_with_digest_path(
            "private/app",
            "v1",
            MANIFEST_MEDIA,
            &manifest_bytes,
            token,
        )
        .await;

    let fetcher = OciManifestFetcher::with_config_and_auth(
        client_config_for(&reg),
        RegistryAuthConfig::bearer(token),
    );
    let image = reg.image_ref("private/app", "v1");
    let fetched = fetcher.fetch(&image).await.expect("manifest fetch");

    assert_eq!(fetched.digest, manifest_digest);
}

#[tokio::test]
async fn manifest_fetch_rejects_missing_bearer_auth() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"private-layer";
    let (manifest_bytes, _layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);

    reg.register_bearer_manifest_with_digest_path(
        "private/app",
        "v1",
        MANIFEST_MEDIA,
        &manifest_bytes,
        "fixture-token",
    )
    .await;

    let fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let image = reg.image_ref("private/app", "v1");
    let err = fetcher.fetch(&image).await.unwrap_err();

    assert!(matches!(err, OciError::Registry(_)));
}

#[tokio::test]
async fn manifest_fetch_rejects_wrong_bearer_auth() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"private-layer";
    let (manifest_bytes, _layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);

    reg.register_bearer_manifest_with_digest_path(
        "private/app",
        "v1",
        MANIFEST_MEDIA,
        &manifest_bytes,
        "fixture-token",
    )
    .await;

    let fetcher = OciManifestFetcher::with_config_and_auth(
        client_config_for(&reg),
        RegistryAuthConfig::bearer("wrong-token"),
    );
    let image = reg.image_ref("private/app", "v1");
    let err = fetcher.fetch(&image).await.unwrap_err();

    assert!(matches!(err, OciError::Registry(_)));
}

#[tokio::test]
async fn manifest_fetch_follows_bearer_challenge_token_flow() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"challenge-layer";
    let (manifest_bytes, _layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);

    let manifest_digest = reg
        .register_challenged_manifest_with_digest_path(
            "private/challenge",
            "v1",
            MANIFEST_MEDIA,
            &manifest_bytes,
            common::BearerChallengeFixture::builder("private/challenge")
                .issued_token("challenge-token")
                .build(),
        )
        .await;

    let fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let image = reg.image_ref("private/challenge", "v1");
    let fetched = fetcher.fetch(&image).await.expect("manifest fetch");

    assert_eq!(fetched.digest, manifest_digest);
}

#[tokio::test]
async fn manifest_fetch_uses_basic_auth_when_redeeming_bearer_challenge() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"basic-challenge-layer";
    let (manifest_bytes, _layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);

    let manifest_digest = reg
        .register_challenged_manifest_with_digest_path(
            "private/basic-challenge",
            "v1",
            MANIFEST_MEDIA,
            &manifest_bytes,
            common::BearerChallengeFixture::builder("private/basic-challenge")
                .issued_token("basic-challenge-token")
                .basic_auth("fixture-user", "fixture-pass")
                .build(),
        )
        .await;

    let fetcher = OciManifestFetcher::with_config_and_auth(
        client_config_for(&reg),
        RegistryAuthConfig::basic("fixture-user", "fixture-pass"),
    );
    let image = reg.image_ref("private/basic-challenge", "v1");
    let fetched = fetcher.fetch(&image).await.expect("manifest fetch");

    assert_eq!(fetched.digest, manifest_digest);
}

#[tokio::test]
async fn manifest_layers_extracts_single_layer() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"hello-mvm-layer-bytes";
    let (manifest_bytes, expected_layer_digest) = minimal_image_manifest(layer_bytes, LAYER_MEDIA);

    reg.register_manifest_with_digest_path("library/test", "v1", MANIFEST_MEDIA, &manifest_bytes)
        .await;

    let fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let image = reg.image_ref("library/test", "v1");
    let fetched = fetcher.fetch(&image).await.expect("manifest fetch");

    let layers = fetched.layers().expect("parse layers");
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].digest, expected_layer_digest);
    assert_eq!(layers[0].size, layer_bytes.len() as u64);
    assert_eq!(layers[0].media_type, LAYER_MEDIA);
}

#[tokio::test]
async fn platform_manifest_fetch_follows_matching_linux_index_entry() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"linux-arm64-v8-layer";
    let (child_manifest_bytes, expected_layer_digest) =
        minimal_image_manifest(layer_bytes, LAYER_MEDIA);
    let child_digest = reg
        .register_manifest_with_digest_path(
            "library/alpine",
            "child",
            MANIFEST_MEDIA,
            &child_manifest_bytes,
        )
        .await;
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": MANIFEST_MEDIA,
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 1,
                "platform": { "os": "linux", "architecture": "amd64" }
            },
            {
                "mediaType": MANIFEST_MEDIA,
                "digest": child_digest,
                "size": child_manifest_bytes.len(),
                "platform": { "os": "linux", "architecture": "arm64", "variant": "v8" }
            }
        ]
    });
    let index_bytes = serde_json::to_vec(&index).expect("index serializes");
    reg.register_manifest_with_digest_path(
        "library/alpine",
        "3.20",
        "application/vnd.oci.image.index.v1+json",
        &index_bytes,
    )
    .await;

    let fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let image = reg.image_ref("library/alpine", "3.20");
    let fetched = fetcher
        .fetch_linux_platform_manifest(
            &image,
            &LinuxPlatform {
                architecture: "arm64".to_string(),
                variant: Some("v8".to_string()),
            },
        )
        .await
        .expect("fetch platform manifest");
    let layers = fetched.layers().expect("platform manifest layers");

    assert_eq!(fetched.digest, child_digest);
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].digest, expected_layer_digest);
}

#[tokio::test]
async fn platform_manifest_fetch_accepts_arm64_without_variant_for_v8_request() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"linux-arm64-layer-without-variant";
    let (child_manifest_bytes, expected_layer_digest) =
        minimal_image_manifest(layer_bytes, LAYER_MEDIA);
    let child_digest = reg
        .register_manifest_with_digest_path(
            "library/alpine",
            "child-no-variant",
            MANIFEST_MEDIA,
            &child_manifest_bytes,
        )
        .await;
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": MANIFEST_MEDIA,
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 1,
                "platform": { "os": "linux", "architecture": "amd64" }
            },
            {
                "mediaType": MANIFEST_MEDIA,
                "digest": child_digest,
                "size": child_manifest_bytes.len(),
                "platform": { "os": "linux", "architecture": "arm64" }
            }
        ]
    });
    let index_bytes = serde_json::to_vec(&index).expect("index serializes");
    reg.register_manifest_with_digest_path(
        "library/alpine",
        "3.21",
        "application/vnd.oci.image.index.v1+json",
        &index_bytes,
    )
    .await;

    let fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let image = reg.image_ref("library/alpine", "3.21");
    let fetched = fetcher
        .fetch_linux_platform_manifest(
            &image,
            &LinuxPlatform {
                architecture: "arm64".to_string(),
                variant: Some("v8".to_string()),
            },
        )
        .await
        .expect("fetch platform manifest");
    let layers = fetched.layers().expect("platform manifest layers");

    assert_eq!(fetched.digest, child_digest);
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].digest, expected_layer_digest);
}

#[tokio::test]
async fn layer_fetch_happy_path_verifies_digest_and_byte_count() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes: Vec<u8> = (0..4096u32).map(|i| (i & 0xff) as u8).collect();
    let layer_digest = reg
        .register_blob("library/test", LAYER_MEDIA, &layer_bytes)
        .await;

    let layer = LayerDescriptor {
        digest: layer_digest.clone(),
        size: layer_bytes.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };
    let fetcher =
        OciLayerFetcher::with_config(client_config_for(&reg), LayerFetchOptions::default());

    let image = reg.image_ref("library/test", "v1");
    let mut sink: Vec<u8> = Vec::new();
    let n = fetcher
        .fetch_layer(&image, &layer, &mut sink)
        .await
        .expect("layer fetch");

    assert_eq!(n, layer_bytes.len() as u64);
    assert_eq!(sink, layer_bytes);
}

#[tokio::test]
async fn layer_fetch_follows_same_origin_redirect_without_forwarding_auth() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"redirected-layer";
    let token = "registry-only-token";
    let layer_digest = reg
        .register_redirected_bearer_blob("library/test", LAYER_MEDIA, layer_bytes, token)
        .await;
    let layer = LayerDescriptor {
        digest: layer_digest,
        size: layer_bytes.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };
    let fetcher = OciLayerFetcher::with_config_and_auth(
        client_config_for(&reg),
        LayerFetchOptions::default(),
        RegistryAuthConfig::bearer(token),
    );
    let image = reg.image_ref("library/test", "v1");
    let mut sink = Vec::new();

    let count = fetcher
        .fetch_layer(&image, &layer, &mut sink)
        .await
        .expect("redirected blob fetch succeeds");

    assert_eq!(count, layer_bytes.len() as u64);
    assert_eq!(sink, layer_bytes);
}

#[tokio::test]
async fn layer_fetch_stops_at_bounded_blob_redirect_limit() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"redirect-loop";
    let layer_digest = reg
        .register_blob_redirect_loop("library/test", layer_bytes)
        .await;
    let layer = LayerDescriptor {
        digest: layer_digest,
        size: layer_bytes.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };
    let fetcher = OciLayerFetcher::with_config(
        client_config_for(&reg),
        LayerFetchOptions {
            max_retries: 1,
            ..LayerFetchOptions::default()
        },
    );
    let image = reg.image_ref("library/test", "v1");
    let mut sink = Vec::new();

    let error = fetcher
        .fetch_layer(&image, &layer, &mut sink)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("5-redirect OCI blob limit"));
    assert!(sink.is_empty());
}

#[tokio::test]
async fn layer_fetch_rejects_tampered_blob_with_digest_mismatch() {
    let reg = HermeticRegistry::start().await;

    let intended_bytes = b"original-content";
    let tampered_bytes = b"NOT-the-original-content";
    let claimed_digest = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(intended_bytes))
    );
    reg.register_tampered_blob("library/test", &claimed_digest, tampered_bytes)
        .await;

    let layer = LayerDescriptor {
        digest: claimed_digest.clone(),
        size: intended_bytes.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };
    let fetcher =
        OciLayerFetcher::with_config(client_config_for(&reg), LayerFetchOptions::default());

    let image = reg.image_ref("library/test", "v1");
    let mut sink: Vec<u8> = Vec::new();
    let err = fetcher
        .fetch_layer(&image, &layer, &mut sink)
        .await
        .unwrap_err();

    // The registry client may surface tamper as its own digest
    // check or bubble through to ours. Either error class is
    // acceptable as long as we fail closed and the bytes never
    // escape as "OK".
    match err {
        OciError::DigestMismatch { .. } | OciError::Registry(_) => {}
        other => panic!("expected DigestMismatch or Registry (tamper), got {other:?}"),
    }
}

#[tokio::test]
async fn layer_fetch_rejects_declared_size_exceeding_cap() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"tiny-layer";
    let layer_digest = reg
        .register_blob("library/test", LAYER_MEDIA, layer_bytes)
        .await;

    // Manifest claims a huge size; cap is 1 KiB. The fetcher must
    // reject before issuing the pull.
    let layer = LayerDescriptor {
        digest: layer_digest,
        size: 100 * 1024 * 1024, // 100 MiB declared
        media_type: LAYER_MEDIA.to_string(),
    };
    let options = LayerFetchOptions {
        max_size: 1024, // 1 KiB cap
        ..LayerFetchOptions::default()
    };
    let fetcher = OciLayerFetcher::with_config(client_config_for(&reg), options);

    let image = reg.image_ref("library/test", "v1");
    let mut sink: Vec<u8> = Vec::new();
    let err = fetcher
        .fetch_layer(&image, &layer, &mut sink)
        .await
        .unwrap_err();

    match err {
        OciError::LayerTooLarge { declared, cap } => {
            assert_eq!(declared, 100 * 1024 * 1024);
            assert_eq!(cap, 1024);
        }
        other => panic!("expected LayerTooLarge, got {other:?}"),
    }
    assert!(
        sink.is_empty(),
        "fetcher must not write a single byte when failing on declared size"
    );
}

#[tokio::test]
async fn layer_fetch_streamed_byte_count_cap_aborts_mid_stream() {
    // The declared size in the descriptor is within the cap, but
    // the actual streamed bytes exceed it (registry lies about
    // size). The mid-stream cap inside `CappedHashingWriter` must
    // catch this.
    let reg = HermeticRegistry::start().await;
    let layer_bytes: Vec<u8> = vec![0xaa; 4096];
    let layer_digest = reg
        .register_blob("library/test", LAYER_MEDIA, &layer_bytes)
        .await;

    let layer = LayerDescriptor {
        digest: layer_digest,
        size: 100, // lies — cap is 100 but body is 4096
        media_type: LAYER_MEDIA.to_string(),
    };
    let options = LayerFetchOptions {
        max_size: 100,
        ..LayerFetchOptions::default()
    };
    let fetcher = OciLayerFetcher::with_config(client_config_for(&reg), options);

    let image = reg.image_ref("library/test", "v1");
    let mut sink: Vec<u8> = Vec::new();
    let err = fetcher
        .fetch_layer(&image, &layer, &mut sink)
        .await
        .unwrap_err();

    // The cap fires *before* the fetch, because declared=100 is
    // not > cap=100. So we should land in the mid-stream path
    // when the layer body exceeds 100 bytes. The error class is
    // Registry (the wrapped IO error from the writer's
    // `mvm-oci: layer size cap exceeded`).
    assert!(
        matches!(err, OciError::Registry(_) | OciError::LayerTooLarge { .. }),
        "got {err:?}"
    );
    assert!(
        sink.len() <= 100,
        "writer must not exceed cap, got {} bytes",
        sink.len()
    );
}

#[tokio::test]
async fn layer_fetch_retries_transient_5xx_and_eventually_succeeds() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"the-real-bytes";
    // Fail twice with 503, then serve the bytes on attempt 3.
    let layer_digest = reg
        .register_flaky_blob("library/test", layer_bytes, 2)
        .await;

    let layer = LayerDescriptor {
        digest: layer_digest,
        size: layer_bytes.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };
    let options = LayerFetchOptions {
        max_retries: 5,
        initial_backoff: Duration::from_millis(10),
        ..LayerFetchOptions::default()
    };
    let fetcher = OciLayerFetcher::with_config(client_config_for(&reg), options);

    let image = reg.image_ref("library/test", "v1");
    let mut sink: Vec<u8> = Vec::new();
    let n = fetcher
        .fetch_layer(&image, &layer, &mut sink)
        .await
        .expect("retry should recover the layer");

    assert_eq!(n, layer_bytes.len() as u64);
    assert_eq!(sink, layer_bytes);
}

#[tokio::test]
async fn layer_fetch_exhausts_retries_on_persistent_5xx() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = b"unreachable-bytes";
    // Fail 99 times — more than the retry budget allows.
    let layer_digest = reg
        .register_flaky_blob("library/test", layer_bytes, 99)
        .await;

    let layer = LayerDescriptor {
        digest: layer_digest,
        size: layer_bytes.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };
    let options = LayerFetchOptions {
        max_retries: 2,
        initial_backoff: Duration::from_millis(1),
        ..LayerFetchOptions::default()
    };
    let fetcher = OciLayerFetcher::with_config(client_config_for(&reg), options);

    let image = reg.image_ref("library/test", "v1");
    let mut sink: Vec<u8> = Vec::new();
    let err = fetcher
        .fetch_layer(&image, &layer, &mut sink)
        .await
        .unwrap_err();

    match err {
        OciError::Registry(_) => {}
        other => panic!("expected Registry exhaustion, got {other:?}"),
    }
}

#[tokio::test]
async fn layer_fetch_round_trip_manifest_to_layers_to_blob() {
    // The full slice: pull a manifest, parse its layer list,
    // fetch each layer through the layer fetcher, verify each
    // returned the bytes that built the manifest.
    let reg = HermeticRegistry::start().await;
    let layer_bytes_a = b"layer-A".to_vec();
    let _layer_digest_a = reg
        .register_blob("library/multi", LAYER_MEDIA, &layer_bytes_a)
        .await;

    // Construct a manifest pointing at layer A only; multi-layer
    // fan-out is exercised separately with the unpack orchestrator.
    let (manifest_bytes, expected_digest_a) = minimal_image_manifest(&layer_bytes_a, LAYER_MEDIA);
    reg.register_manifest_with_digest_path("library/multi", "v1", MANIFEST_MEDIA, &manifest_bytes)
        .await;

    let manifest_fetcher = OciManifestFetcher::with_config(client_config_for(&reg));
    let layer_fetcher =
        OciLayerFetcher::from_manifest_fetcher(&manifest_fetcher, LayerFetchOptions::default());
    let image = reg.image_ref("library/multi", "v1");

    let fetched_manifest = manifest_fetcher.fetch(&image).await.expect("manifest");
    let layers = fetched_manifest.layers().expect("parse layers");
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].digest, expected_digest_a);

    let mut sink: Vec<u8> = Vec::new();
    let n = layer_fetcher
        .fetch_layer(&image, &layers[0], &mut sink)
        .await
        .expect("layer fetch");
    assert_eq!(n, layer_bytes_a.len() as u64);
    assert_eq!(sink, layer_bytes_a);
}

#[tokio::test]
async fn layer_fetch_reuses_manifest_fetcher_bearer_auth() {
    let reg = HermeticRegistry::start().await;
    let token = "layer-token";
    let layer_bytes = b"private-layer-bytes".to_vec();
    let _layer_digest = reg
        .register_bearer_blob("private/multi", LAYER_MEDIA, &layer_bytes, token)
        .await;
    let (manifest_bytes, expected_digest) = minimal_image_manifest(&layer_bytes, LAYER_MEDIA);
    reg.register_bearer_manifest_with_digest_path(
        "private/multi",
        "v1",
        MANIFEST_MEDIA,
        &manifest_bytes,
        token,
    )
    .await;

    let manifest_fetcher = OciManifestFetcher::with_config_and_auth(
        client_config_for(&reg),
        RegistryAuthConfig::bearer(token),
    );
    let layer_fetcher =
        OciLayerFetcher::from_manifest_fetcher(&manifest_fetcher, LayerFetchOptions::default());
    let image = reg.image_ref("private/multi", "v1");

    let fetched_manifest = manifest_fetcher.fetch(&image).await.expect("manifest");
    let layers = fetched_manifest.layers().expect("parse layers");
    assert_eq!(layers[0].digest, expected_digest);

    let mut sink: Vec<u8> = Vec::new();
    let n = layer_fetcher
        .fetch_layer(&image, &layers[0], &mut sink)
        .await
        .expect("authenticated layer fetch");
    assert_eq!(n, layer_bytes.len() as u64);
    assert_eq!(sink, layer_bytes);
}

fn gzip_tar_layer(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_path(*name).expect("valid tar path");
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, *bytes).expect("append tar entry");
    }
    let raw = builder.into_inner().expect("finish tar");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&raw).expect("gzip input");
    encoder.finish().expect("finish gzip")
}

#[tokio::test]
async fn fetch_and_unpack_layer_streams_and_caches_blob() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = gzip_tar_layer(&[("hello.txt", b"world")]);
    let layer_digest = reg
        .register_blob("library/test", LAYER_MEDIA, &layer_bytes)
        .await;

    let layer = LayerDescriptor {
        digest: layer_digest.clone(),
        size: layer_bytes.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };
    let fetcher =
        OciLayerFetcher::with_config(client_config_for(&reg), LayerFetchOptions::default());
    let image = reg.image_ref("library/test", "v1");

    let tmp = tempfile::tempdir().expect("tempdir");
    let unpacked = tmp.path().join("unpacked");
    std::fs::create_dir_all(&unpacked).expect("create unpacked root");
    let cache = tmp.path().join("layer.tar.gz");

    let report = fetcher
        .fetch_and_unpack_layer(
            &image,
            &layer,
            &cache,
            &unpacked,
            &UnpackOptions::default(),
            &std::collections::HashSet::new(),
        )
        .await
        .expect("fetch and unpack");

    assert_eq!(report.files_written, 1);
    assert!(report.refused.is_empty());
    let out = unpacked.join("hello.txt");
    assert_eq!(std::fs::read(&out).expect("read unpacked file"), b"world");

    // The raw compressed blob was persisted concurrently.
    assert_eq!(std::fs::read(&cache).expect("read cache"), layer_bytes);
}

#[tokio::test]
async fn verify_and_unpack_layer_file_streams_cache_hit() {
    let reg = HermeticRegistry::start().await;
    let layer_bytes = gzip_tar_layer(&[("cached.txt", b"from-cache")]);
    let layer_digest = reg
        .register_blob("library/test", LAYER_MEDIA, &layer_bytes)
        .await;

    let layer = LayerDescriptor {
        digest: layer_digest,
        size: layer_bytes.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let unpacked = tmp.path().join("unpacked");
    std::fs::create_dir_all(&unpacked).expect("create unpacked root");
    let cache = tmp.path().join("layer.tar.gz");
    std::fs::write(&cache, &layer_bytes).expect("write cached blob");

    let report = verify_and_unpack_layer_file(
        &layer,
        &cache,
        &unpacked,
        &UnpackOptions::default(),
        &std::collections::HashSet::new(),
    )
    .await
    .expect("verify and unpack cached layer");

    assert_eq!(report.files_written, 1);
    assert!(report.refused.is_empty());
    assert_eq!(
        std::fs::read(unpacked.join("cached.txt")).expect("read"),
        b"from-cache"
    );
}

#[tokio::test]
async fn verify_and_unpack_layer_file_rejects_corrupt_cache() {
    let intended = gzip_tar_layer(&[("x.txt", b"x")]);
    let tampered = gzip_tar_layer(&[("x.txt", b"y")]);
    let claimed_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&intended)));

    let layer = LayerDescriptor {
        digest: claimed_digest,
        size: intended.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let unpacked = tmp.path().join("unpacked");
    std::fs::create_dir_all(&unpacked).expect("create unpacked root");
    let cache = tmp.path().join("layer.tar.gz");
    std::fs::write(&cache, &tampered).expect("write tampered cached blob");

    let err = verify_and_unpack_layer_file(
        &layer,
        &cache,
        &unpacked,
        &UnpackOptions::default(),
        &std::collections::HashSet::new(),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, OciError::DigestMismatch { .. }),
        "expected DigestMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn fetch_and_unpack_layer_rejects_tampered_blob_and_drops_cache() {
    let reg = HermeticRegistry::start().await;
    let intended = gzip_tar_layer(&[("hello.txt", b"world")]);
    let tampered = gzip_tar_layer(&[("hello.txt", b"evil")]);
    let claimed_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&intended)));
    reg.register_tampered_blob("library/test", &claimed_digest, &tampered)
        .await;

    let layer = LayerDescriptor {
        digest: claimed_digest.clone(),
        size: intended.len() as u64,
        media_type: LAYER_MEDIA.to_string(),
    };
    let fetcher =
        OciLayerFetcher::with_config(client_config_for(&reg), LayerFetchOptions::default());
    let image = reg.image_ref("library/test", "v1");

    let tmp = tempfile::tempdir().expect("tempdir");
    let unpacked = tmp.path().join("unpacked");
    std::fs::create_dir_all(&unpacked).expect("create unpacked root");
    let cache = tmp.path().join("layer.tar.gz");

    let err = fetcher
        .fetch_and_unpack_layer(
            &image,
            &layer,
            &cache,
            &unpacked,
            &UnpackOptions::default(),
            &std::collections::HashSet::new(),
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, OciError::DigestMismatch { .. }),
        "expected DigestMismatch, got {err:?}"
    );
    assert!(
        !cache.exists(),
        "partial cache blob must be removed on digest mismatch"
    );
}

#[tokio::test]
async fn fetch_and_unpack_layer_handles_plain_tar_media_type() {
    let reg = HermeticRegistry::start().await;
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("plain.txt").expect("valid tar path");
    header.set_size(5);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b"howdy"[..]).expect("append");
    let layer_bytes = builder.into_inner().expect("finish tar");
    let media_type = "application/vnd.oci.image.layer.v1.tar";
    let layer_digest = reg
        .register_blob("library/test", media_type, &layer_bytes)
        .await;

    let layer = LayerDescriptor {
        digest: layer_digest,
        size: layer_bytes.len() as u64,
        media_type: media_type.to_string(),
    };
    let fetcher =
        OciLayerFetcher::with_config(client_config_for(&reg), LayerFetchOptions::default());
    let image = reg.image_ref("library/test", "v1");

    let tmp = tempfile::tempdir().expect("tempdir");
    let unpacked = tmp.path().join("unpacked");
    std::fs::create_dir_all(&unpacked).expect("create unpacked root");
    let cache = tmp.path().join("layer.tar");

    let report = fetcher
        .fetch_and_unpack_layer(
            &image,
            &layer,
            &cache,
            &unpacked,
            &UnpackOptions::default(),
            &std::collections::HashSet::new(),
        )
        .await
        .expect("fetch and unpack plain tar");

    assert_eq!(report.files_written, 1);
    assert_eq!(
        std::fs::read(unpacked.join("plain.txt")).expect("read"),
        b"howdy"
    );
    assert_eq!(std::fs::read(&cache).expect("read cache"), layer_bytes);
}

#[tokio::test]
async fn verify_sha256_digest_works_against_fixture_blob_bytes() {
    // Independent sanity check on the standalone verifier — the
    // bytes we built the fixture with hash to the digest the
    // fixture serves.
    let bytes = b"some-blob";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
    verify_sha256_digest(bytes, &digest).expect("self-consistent");
}
