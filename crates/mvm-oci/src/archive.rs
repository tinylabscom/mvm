//! OCI image-layout archive reader.
//!
//! Reads an OCI image layout — an `oci-layout` marker, an `index.json`, and
//! content-addressed `blobs/sha256/<hex>` blobs — out of a tar stream, with
//! every blob verified against the digest in its name and the manifest
//! selected for the requested platform. Pure and **filesystem-free** (the
//! caller hands a `Read` — a local file or stdin), so it keeps this crate's
//! no-host-filesystem invariant: it returns the digest-verified, ordered layer
//! blobs ready for the same hardened `unpack_layer` path the registry pull
//! uses. Traversal protection on layer *contents* stays in `unpack_layer`; this
//! reader only buffers blobs into an in-memory map keyed by exact digest, so a
//! hostile archive entry name can never escape onto the host here.

use std::collections::BTreeMap;
use std::io::Read;

use oci_client::manifest::OciManifest;
use serde::Deserialize;

use crate::layer::LayerDescriptor;
use crate::manifest::LinuxPlatform;
use crate::{OciError, verify_sha256_digest};

/// Hard cap on the total bytes buffered from one archive. Blobs are
/// content-addressed, so resolving index → manifest → layers means buffering;
/// this bounds a hostile archive's memory cost. 8 GiB is generous for a fat
/// local rootfs while refusing an obvious bomb. (`unpack_layer` enforces its
/// own per-layer decompressed cap downstream.)
const MAX_TOTAL_BLOB_BYTES: u64 = 8 * 1024 * 1024 * 1024;

const OCI_LAYOUT_FILE: &str = "oci-layout";
const INDEX_FILE: &str = "index.json";
const BLOBS_PREFIX: &str = "blobs/sha256/";
const SUPPORTED_LAYOUT_VERSION: &str = "1.0.0";
const IMAGE_MANIFEST_MEDIA: &str = "application/vnd.oci.image.manifest.v1+json";

/// A digest-verified OCI image read out of a local layout archive: the
/// manifest + config identity, the host-matching platform, and the ordered
/// layer blobs ready to feed `unpack_layer`.
#[derive(Debug, Clone)]
pub struct OciArchiveImage {
    /// `sha256:<hex>` of the selected image manifest.
    pub manifest_digest: String,
    /// `sha256:<hex>` of the image config blob.
    pub config_digest: String,
    /// `architecture` from the image config (`amd64`, `arm64`, …).
    pub architecture: String,
    /// `os` from the image config — always `linux` (others are refused).
    pub os: String,
    /// Layers in manifest order; each blob is digest-verified.
    pub layers: Vec<OciArchiveLayer>,
}

/// One layer's digest-verified compressed bytes plus its descriptor.
#[derive(Debug, Clone)]
pub struct OciArchiveLayer {
    pub descriptor: LayerDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct OciLayoutMarker {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: String,
}

/// The platform-relevant slice of an OCI image config blob.
#[derive(Deserialize)]
struct ImageConfigPlatform {
    architecture: String,
    os: String,
}

/// Read and verify an OCI image-layout archive from `reader`, selecting the
/// manifest that matches `platform`. Every blob is checked against the digest
/// in its name; the image config's `os`/`architecture` must be `linux` and
/// match the host platform (the wrong-architecture guard).
pub fn read_oci_archive<R: Read>(
    reader: R,
    platform: &LinuxPlatform,
) -> Result<OciArchiveImage, OciError> {
    let entries = read_tar_entries(reader)?;

    // oci-layout marker — present + a layout version we understand.
    let layout = entries
        .get(OCI_LAYOUT_FILE)
        .ok_or_else(|| OciError::Registry("OCI archive missing `oci-layout` marker".into()))?;
    let marker: OciLayoutMarker = serde_json::from_slice(layout)
        .map_err(|e| OciError::Registry(format!("parse oci-layout: {e}")))?;
    if marker.image_layout_version != SUPPORTED_LAYOUT_VERSION {
        return Err(OciError::Registry(format!(
            "unsupported OCI image layout version {:?} (want {SUPPORTED_LAYOUT_VERSION})",
            marker.image_layout_version
        )));
    }

    // index.json → the manifest descriptor for this platform.
    let index_bytes = entries
        .get(INDEX_FILE)
        .ok_or_else(|| OciError::Registry("OCI archive missing `index.json`".into()))?;
    let manifest_digest = select_manifest_digest(index_bytes, platform)?;

    // Manifest blob → config + layers.
    let manifest_bytes = blob(&entries, &manifest_digest)?;
    verify_sha256_digest(manifest_bytes, &manifest_digest)?;
    let OciManifest::Image(image) = serde_json::from_slice(manifest_bytes)
        .map_err(|e| OciError::Registry(format!("parse image manifest: {e}")))?
    else {
        return Err(OciError::Registry(
            "selected manifest is an image index, not an image manifest".into(),
        ));
    };
    if image.layers.is_empty() {
        return Err(OciError::Registry(
            "OCI image manifest has no layers".into(),
        ));
    }

    // Config blob → platform check (os must be linux, arch must match host).
    let config_digest = image.config.digest.clone();
    let config_bytes = blob(&entries, &config_digest)?;
    verify_sha256_digest(config_bytes, &config_digest)?;
    let config: ImageConfigPlatform = serde_json::from_slice(config_bytes)
        .map_err(|e| OciError::Registry(format!("parse image config: {e}")))?;
    if config.os != "linux" {
        return Err(OciError::Registry(format!(
            "OCI image targets os {:?}, not linux",
            config.os
        )));
    }
    if config.architecture != platform.architecture {
        return Err(OciError::Registry(format!(
            "OCI image architecture {:?} does not match host {:?}",
            config.architecture, platform.architecture
        )));
    }

    // Layer blobs in manifest order, each digest-verified.
    let mut layers = Vec::with_capacity(image.layers.len());
    for entry in &image.layers {
        let bytes = blob(&entries, &entry.digest)?;
        verify_sha256_digest(bytes, &entry.digest)?;
        layers.push(OciArchiveLayer {
            descriptor: LayerDescriptor {
                digest: entry.digest.clone(),
                size: entry.size as u64,
                media_type: entry.media_type.clone(),
            },
            bytes: bytes.to_vec(),
        });
    }

    Ok(OciArchiveImage {
        manifest_digest,
        config_digest,
        architecture: config.architecture,
        os: config.os,
        layers,
    })
}

/// Slurp every tar entry into a `path -> bytes` map, normalizing a leading
/// `./`. Only entries we resolve by exact key (`oci-layout`, `index.json`,
/// `blobs/sha256/<hex>`) are ever read back, so a hostile entry *name* cannot
/// reach the host filesystem — this reader never writes entries out. Total
/// buffered size is capped.
fn read_tar_entries<R: Read>(reader: R) -> Result<BTreeMap<String, Vec<u8>>, OciError> {
    let mut archive = tar::Archive::new(reader);
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total: u64 = 0;
    let tar_entries = archive
        .entries()
        .map_err(|e| OciError::Registry(format!("read OCI archive tar: {e}")))?;
    for entry in tar_entries {
        let mut entry = entry.map_err(|e| OciError::Registry(format!("OCI archive entry: {e}")))?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| OciError::Registry(format!("OCI archive entry path: {e}")))?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        let size = entry.header().size().unwrap_or(0);
        total = total.saturating_add(size);
        if total > MAX_TOTAL_BLOB_BYTES {
            return Err(OciError::Registry(format!(
                "OCI archive exceeds the {MAX_TOTAL_BLOB_BYTES}-byte buffer cap"
            )));
        }
        let mut bytes = Vec::with_capacity(size as usize);
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| OciError::Registry(format!("read OCI archive entry {path}: {e}")))?;
        out.insert(path, bytes);
    }
    Ok(out)
}

/// Look up a `sha256:<hex>` blob by its content address.
fn blob<'a>(entries: &'a BTreeMap<String, Vec<u8>>, digest: &str) -> Result<&'a [u8], OciError> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| OciError::Registry(format!("blob digest is not sha256: {digest}")))?;
    entries
        .get(&format!("{BLOBS_PREFIX}{hex}"))
        .map(Vec::as_slice)
        .ok_or_else(|| OciError::Registry(format!("OCI archive missing blob {digest}")))
}

/// Choose the image-manifest digest from `index.json` for `platform`. Prefers a
/// `linux/<arch>[/<variant>]` platform match; falls back to the sole manifest
/// when the index lists exactly one (single-arch archives often omit the
/// platform). The chosen manifest's config still gates architecture downstream.
fn select_manifest_digest(
    index_bytes: &[u8],
    platform: &LinuxPlatform,
) -> Result<String, OciError> {
    let OciManifest::ImageIndex(index) = serde_json::from_slice(index_bytes)
        .map_err(|e| OciError::Registry(format!("parse index.json: {e}")))?
    else {
        return Err(OciError::Registry(
            "index.json is an image manifest, not an image index".into(),
        ));
    };
    let image_manifests: Vec<_> = index
        .manifests
        .iter()
        .filter(|d| d.media_type == IMAGE_MANIFEST_MEDIA)
        .collect();
    if image_manifests.is_empty() {
        return Err(OciError::Registry(
            "index.json lists no image manifests".into(),
        ));
    }
    if let Some(matched) = image_manifests.iter().find(|entry| {
        entry.platform.as_ref().is_some_and(|p| {
            p.os.to_string() == "linux"
                && p.architecture.to_string() == platform.architecture
                && p.variant.as_deref() == platform.variant.as_deref()
        })
    }) {
        return Ok(matched.digest.clone());
    }
    if image_manifests.len() == 1 {
        return Ok(image_manifests[0].digest.clone());
    }
    let wanted = match &platform.variant {
        Some(v) => format!("linux/{}/{}", platform.architecture, v),
        None => format!("linux/{}", platform.architecture),
    };
    Err(OciError::Registry(format!(
        "OCI archive index has no manifest for {wanted}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    /// Build a minimal but valid single-arch OCI-layout archive (one layer)
    /// for the current host arch. Returns the tar bytes. Knobs let tests
    /// corrupt one facet at a time.
    struct ArchiveFixture {
        arch: String,
        os: String,
        include_layout: bool,
        include_index: bool,
        corrupt_layer_digest: bool,
        layout_version: String,
        /// Extra tar entries appended verbatim — used to prove hostile entry
        /// names are ignored, never written out or followed.
        extra_entries: Vec<(String, Vec<u8>)>,
    }

    impl Default for ArchiveFixture {
        fn default() -> Self {
            let p = LinuxPlatform::for_current_arch();
            Self {
                arch: p.architecture,
                os: "linux".to_string(),
                include_layout: true,
                include_index: true,
                corrupt_layer_digest: false,
                layout_version: SUPPORTED_LAYOUT_VERSION.to_string(),
                extra_entries: Vec::new(),
            }
        }
    }

    impl ArchiveFixture {
        fn build(&self) -> Vec<u8> {
            let layer = b"layer-bytes-pretend-tar-gz".to_vec();
            let layer_digest = digest_of(&layer);
            let config = format!(
                r#"{{"architecture":"{}","os":"{}","rootfs":{{"type":"layers","diff_ids":["{}"]}}}}"#,
                self.arch, self.os, layer_digest
            )
            .into_bytes();
            let config_digest = digest_of(&config);
            let manifest = format!(
                r#"{{"schemaVersion":2,"mediaType":"{IMAGE_MANIFEST_MEDIA}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{cfg_sz}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{lyr_sz}}}]}}"#,
                cfg_sz = config.len(),
                lyr_sz = layer.len(),
            )
            .into_bytes();
            let manifest_digest = digest_of(&manifest);
            let index = format!(
                r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"{IMAGE_MANIFEST_MEDIA}","digest":"{manifest_digest}","size":{mf_sz},"platform":{{"architecture":"{arch}","os":"linux"}}}}]}}"#,
                mf_sz = manifest.len(),
                arch = self.arch,
            )
            .into_bytes();

            let stored_layer_digest = if self.corrupt_layer_digest {
                digest_of(b"a-different-thing")
            } else {
                layer_digest.clone()
            };

            let mut builder = tar::Builder::new(Vec::new());
            let add = |b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]| {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, data).unwrap();
            };
            if self.include_layout {
                add(
                    &mut builder,
                    OCI_LAYOUT_FILE,
                    format!(r#"{{"imageLayoutVersion":"{}"}}"#, self.layout_version).as_bytes(),
                );
            }
            if self.include_index {
                add(&mut builder, INDEX_FILE, &index);
            }
            add(
                &mut builder,
                &format!(
                    "{BLOBS_PREFIX}{}",
                    manifest_digest.strip_prefix("sha256:").unwrap()
                ),
                &manifest,
            );
            add(
                &mut builder,
                &format!(
                    "{BLOBS_PREFIX}{}",
                    config_digest.strip_prefix("sha256:").unwrap()
                ),
                &config,
            );
            add(
                &mut builder,
                &format!(
                    "{BLOBS_PREFIX}{}",
                    stored_layer_digest.strip_prefix("sha256:").unwrap()
                ),
                &layer,
            );
            for (name, data) in &self.extra_entries {
                add(&mut builder, name, data);
            }
            builder.into_inner().unwrap()
        }
    }

    fn read(bytes: &[u8]) -> Result<OciArchiveImage, OciError> {
        read_oci_archive(bytes, &LinuxPlatform::for_current_arch())
    }

    #[test]
    fn unexpected_extra_entries_are_ignored() {
        // The reader resolves blobs only by exact digest key and performs no
        // filesystem writes. Padding the archive with unreferenced blobs, stray
        // files, and look-alike names changes nothing — the valid image still
        // parses unchanged and no unexpected entry is followed. (A hostile
        // traversal *name* is mooted structurally here: this reader writes
        // nothing to disk; layer-content traversal is rejected downstream by
        // `unpack_layer`.)
        let f = ArchiveFixture {
            extra_entries: vec![
                (
                    "blobs/sha256/unreferenced-blob".to_string(),
                    b"junk".to_vec(),
                ),
                ("a-stray-top-level-file".to_string(), b"junk".to_vec()),
                ("manifest.json".to_string(), b"{}".to_vec()),
                ("blobs/garbage".to_string(), b"junk".to_vec()),
            ],
            ..Default::default()
        };
        let img = read(&f.build()).expect("valid archive with extra entries still parses");
        assert_eq!(img.layers.len(), 1);
        assert_eq!(img.layers[0].bytes, b"layer-bytes-pretend-tar-gz");
    }

    #[test]
    fn reads_a_valid_single_arch_archive() {
        let img = read(&ArchiveFixture::default().build()).expect("valid archive parses");
        assert_eq!(img.os, "linux");
        assert_eq!(
            img.architecture,
            LinuxPlatform::for_current_arch().architecture
        );
        assert_eq!(img.layers.len(), 1);
        assert_eq!(img.layers[0].bytes, b"layer-bytes-pretend-tar-gz");
        assert!(img.manifest_digest.starts_with("sha256:"));
    }

    #[test]
    fn missing_oci_layout_marker_is_rejected() {
        let f = ArchiveFixture {
            include_layout: false,
            ..Default::default()
        };
        let err = read(&f.build()).unwrap_err().to_string();
        assert!(err.contains("oci-layout"), "got {err}");
    }

    #[test]
    fn unsupported_layout_version_is_rejected() {
        let f = ArchiveFixture {
            layout_version: "2.0.0".to_string(),
            ..Default::default()
        };
        let err = read(&f.build()).unwrap_err().to_string();
        assert!(err.contains("layout version"), "got {err}");
    }

    #[test]
    fn missing_index_is_rejected() {
        let f = ArchiveFixture {
            include_index: false,
            ..Default::default()
        };
        let err = read(&f.build()).unwrap_err().to_string();
        assert!(err.contains("index.json"), "got {err}");
    }

    #[test]
    fn layer_blob_digest_mismatch_is_rejected() {
        let f = ArchiveFixture {
            corrupt_layer_digest: true,
            ..Default::default()
        };
        // The layer blob is stored under a wrong digest name, so the
        // manifest's layer digest resolves to a missing blob.
        let err = read(&f.build()).unwrap_err().to_string();
        assert!(
            err.contains("missing blob") || err.contains("mismatch"),
            "got {err}"
        );
    }

    #[test]
    fn wrong_architecture_is_rejected() {
        let other = if LinuxPlatform::for_current_arch().architecture == "amd64" {
            "arm64"
        } else {
            "amd64"
        };
        let f = ArchiveFixture {
            arch: other.to_string(),
            ..Default::default()
        };
        let err = read(&f.build()).unwrap_err().to_string();
        assert!(err.contains("architecture"), "got {err}");
    }

    #[test]
    fn non_linux_os_is_rejected() {
        let f = ArchiveFixture {
            os: "windows".to_string(),
            ..Default::default()
        };
        let err = read(&f.build()).unwrap_err().to_string();
        assert!(err.contains("not linux"), "got {err}");
    }

    #[test]
    fn truncated_tar_is_rejected() {
        let full = ArchiveFixture::default().build();
        let err = read(&full[..full.len() / 2]).unwrap_err().to_string();
        assert!(!err.is_empty());
    }
}
