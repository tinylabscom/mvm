//! Local (non-registry) OCI sources: an on-disk `oci-archive:` file, an
//! archive streamed on stdin, or an already-unpacked `rootfs-dir:` tree.
//! Each ingests straight to a bootable rootfs with no network fetch.

use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;

use mvm_build::rootfs::MaterializeExt4Input;
use mvm_core::domain::manifest::canonical_key_for_path;
use mvm_fs::oci::{
    UnpackOptions, current_linux_platform, read_oci_archive, stream_oci_archive,
    unpack_layer_with_prior_paths,
};

use super::cache::sha256_hex;
use super::materialize::{
    materialize_overlay_lean_rootfs, materialize_run_rootfs, oci_runtime_tag,
    prepare_rootfs_only_tree,
};
use super::oci_types::{OciProvenance, ResolvedOciRunImage};
use super::pull_core::unpack_layer_bytes;

/// Ingest a local OCI image-layout archive (`oci-archive:<path>`) into a
/// bootable rootfs. Mirrors the registry pull's unpack → ext4 path with no
/// network: `read_oci_archive` digest-verifies every blob, then the same
/// hardened `unpack_layer` extracts each layer. Dev-only for now — `--prod`
/// still requires a registry reference + cosign (a local archive carries no
/// registry policy or signature to check yet). Re-ingests each run rather than
/// caching by reference (the archive has no stable registry identity).
pub(super) fn ingest_local_archive(
    cache_root: &Path,
    archive_path: &Path,
    supplied_reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    if prod {
        bail!(
            "`run --image --prod` requires a registry reference with cosign; \
             local OCI archives are dev-only for now"
        );
    }
    let file = fs::File::open(archive_path)
        .with_context(|| format!("open OCI archive {}", archive_path.display()))?;
    let source_descr = format!("OCI archive {}", archive_path.display());
    // Stream regular files (seekable) to avoid buffering every blob; fall back
    // to the buffered reader for pipes, stdin-style special files, etc.
    let metadata = file
        .metadata()
        .with_context(|| format!("stat OCI archive {}", archive_path.display()))?;
    if metadata.file_type().is_file() {
        ingest_archive_streamed(
            cache_root,
            BufReader::new(file),
            supplied_reference,
            "local_archive",
            &source_descr,
        )
    } else {
        ingest_archive_from_reader(
            cache_root,
            BufReader::new(file),
            supplied_reference,
            "local_archive",
            &source_descr,
        )
    }
}

/// Ingest an OCI image-layout archive streamed on stdin (`run --image -`). Same
/// digest-verified path as a file archive, for CI/agent pipelines that pipe an
/// archive in. Dev-only (see [`ingest_local_archive`]).
pub(super) fn ingest_stdin_archive(
    cache_root: &Path,
    supplied_reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    if prod {
        bail!(
            "`run --image --prod` requires a registry reference with cosign; \
             stdin OCI archives are dev-only for now"
        );
    }
    let stdin = std::io::stdin();
    ingest_archive_from_reader(
        cache_root,
        stdin.lock(),
        supplied_reference,
        "stdin_archive",
        "OCI archive on stdin",
    )
}

/// True for OCI layer media types that are gzip-compressed tarballs.
fn is_gzip_layer(media_type: &str) -> bool {
    media_type.ends_with("+gzip")
        || media_type.ends_with(".gzip")
        || media_type.contains("tar.gzip")
}

/// Stream a seekable local OCI archive straight to unpacked layers without
/// buffering every blob in memory. This mirrors [`ingest_archive_from_reader`]
/// but uses [`stream_oci_archive`], which builds an entry offset map and then
/// hands each layer blob to the hardened unpacker as a sized stream.
fn ingest_archive_streamed<R: Read + std::io::Seek>(
    cache_root: &Path,
    reader: R,
    supplied_reference: &str,
    source_label: &str,
    source_descr: &str,
) -> Result<ResolvedOciRunImage> {
    let platform = current_linux_platform();
    let unpacked_parent = cache_root.join("unpacked");
    fs::create_dir_all(&unpacked_parent)
        .with_context(|| format!("create {}", unpacked_parent.display()))?;
    let tmp_unpack = tempfile::Builder::new()
        .prefix("streaming-")
        .tempdir_in(&unpacked_parent)
        .with_context(|| "create temporary unpack directory")?;
    let tmp_path = tmp_unpack.path().to_path_buf();

    let mut prior_layer_paths = std::collections::HashSet::<PathBuf>::new();
    let mut deferred_nodes = Vec::new();
    let metadata = stream_oci_archive(reader, &platform, |descriptor, raw| {
        let report = if is_gzip_layer(&descriptor.media_type) {
            unpack_layer_with_prior_paths(
                GzDecoder::new(raw),
                &tmp_path,
                &UnpackOptions::default(),
                &prior_layer_paths,
            )
        } else {
            unpack_layer_with_prior_paths(
                raw,
                &tmp_path,
                &UnpackOptions::default(),
                &prior_layer_paths,
            )
        }
        .map_err(|e| mvm_fs::oci::OciError::Registry(e.to_string()))?;
        if !report.refused.is_empty() {
            return Err(mvm_fs::oci::OciError::Registry(format!(
                "layer {} refused entries: {:?}",
                descriptor.digest, report.refused
            )));
        }
        prior_layer_paths.extend(report.paths_written);
        deferred_nodes.extend(report.deferred_nodes);
        Ok(())
    })
    .with_context(|| format!("stream {source_descr}"))?;

    let manifest_hex = sha256_hex(&metadata.manifest_digest)?;
    let unpacked_root = unpacked_parent.join(&manifest_hex);
    if unpacked_root.exists() {
        fs::remove_dir_all(&unpacked_root)
            .with_context(|| format!("remove stale unpacked root {}", unpacked_root.display()))?;
    }
    fs::rename(&tmp_path, &unpacked_root).with_context(|| {
        format!(
            "rename unpack directory {} to {}",
            tmp_path.display(),
            unpacked_root.display()
        )
    })?;

    let rootfs_rel = format!(
        "rootfs/{manifest_hex}-{}/rootfs.ext4",
        oci_runtime_tag(cache_root)
    );
    let rootfs_abs = cache_root.join(&rootfs_rel);
    let rootfs_only_tree =
        prepare_rootfs_only_tree(cache_root, &unpacked_root, &metadata.manifest_digest)?;
    super::cache::write_deferred_nodes(cache_root, &metadata.manifest_digest, &deferred_nodes)?;
    materialize_overlay_lean_rootfs(
        cache_root,
        &unpacked_root,
        &rootfs_abs,
        &metadata.manifest_digest,
        deferred_nodes,
    )?;

    let provenance = OciProvenance {
        schema_version: 1,
        source: source_label.to_string(),
        supplied_reference: supplied_reference.to_string(),
        canonical_reference: metadata.manifest_digest.clone(),
        registry: String::new(),
        repository: String::new(),
        tag: None,
        resolved_digest: metadata.manifest_digest.clone(),
        layer_digests: metadata
            .layer_descriptors
            .iter()
            .map(|d| d.digest.clone())
            .collect(),
        trust_policy: "local-archive-digest-verified".to_string(),
        verification_status: "content-digest-verified (dev)".to_string(),
    };
    Ok(ResolvedOciRunImage {
        reference: metadata.manifest_digest.clone(),
        resolved_digest: metadata.manifest_digest,
        rootfs_path: rootfs_abs,
        unpacked_root: Some(rootfs_only_tree),
        pulled: true,
        provenance,
        auth_source: None,
    })
}

/// Shared archive-ingest core: digest-verify the archive from `reader`, unpack
/// every layer through the hardened `unpack_layer`, materialize the ext4
/// rootfs, and build a `ResolvedOciRunImage` with local-source provenance. The
/// file and stdin callers differ only in where the bytes come from and the
/// provenance `source` label.
pub(super) fn ingest_archive_from_reader<R: Read>(
    cache_root: &Path,
    reader: R,
    supplied_reference: &str,
    source_label: &str,
    source_descr: &str,
) -> Result<ResolvedOciRunImage> {
    let image = read_oci_archive(reader, &current_linux_platform())
        .with_context(|| format!("read {source_descr}"))?;

    let manifest_hex = sha256_hex(&image.manifest_digest)?;
    let unpacked_root = cache_root.join("unpacked").join(&manifest_hex);
    if unpacked_root.exists() {
        fs::remove_dir_all(&unpacked_root)
            .with_context(|| format!("remove stale unpacked root {}", unpacked_root.display()))?;
    }
    fs::create_dir_all(&unpacked_root)
        .with_context(|| format!("create {}", unpacked_root.display()))?;
    let mut prior_layer_paths = std::collections::HashSet::new();
    let mut deferred_nodes = Vec::new();
    for layer in &image.layers {
        let report = unpack_layer_bytes(
            &layer.descriptor,
            &layer.bytes,
            &unpacked_root,
            &prior_layer_paths,
        )
        .with_context(|| format!("unpack layer {}", layer.descriptor.digest))?;
        prior_layer_paths.extend(report.paths_written);
        deferred_nodes.extend(report.deferred_nodes);
    }

    let rootfs_rel = format!(
        "rootfs/{manifest_hex}-{}/rootfs.ext4",
        oci_runtime_tag(cache_root)
    );
    let rootfs_abs = cache_root.join(&rootfs_rel);
    let rootfs_only_tree =
        prepare_rootfs_only_tree(cache_root, &unpacked_root, &image.manifest_digest)?;
    super::cache::write_deferred_nodes(cache_root, &image.manifest_digest, &deferred_nodes)?;
    materialize_overlay_lean_rootfs(
        cache_root,
        &unpacked_root,
        &rootfs_abs,
        &image.manifest_digest,
        deferred_nodes,
    )?;

    let provenance = OciProvenance {
        schema_version: 1,
        source: source_label.to_string(),
        supplied_reference: supplied_reference.to_string(),
        canonical_reference: image.manifest_digest.clone(),
        registry: String::new(),
        repository: String::new(),
        tag: None,
        resolved_digest: image.manifest_digest.clone(),
        layer_digests: image
            .layers
            .iter()
            .map(|l| l.descriptor.digest.clone())
            .collect(),
        trust_policy: "local-archive-digest-verified".to_string(),
        verification_status: "content-digest-verified (dev)".to_string(),
    };
    Ok(ResolvedOciRunImage {
        reference: image.manifest_digest.clone(),
        resolved_digest: image.manifest_digest,
        rootfs_path: rootfs_abs,
        unpacked_root: Some(rootfs_only_tree),
        pulled: true,
        provenance,
        auth_source: None,
    })
}

/// Ingest an already-unpacked rootfs directory (`run --image rootfs-dir:<path>`)
/// straight into an ext4 rootfs — no layers to unpack. A bare tree carries no
/// OCI manifest/config, so there is no digest or signature to verify; it is
/// therefore **dev-only** (`--prod` is refused) and the wrong-architecture
/// guard falls back to probing a representative ELF binary's machine type
/// against the host. `materialize_ext4` reads the directory read-only.
pub(super) fn ingest_rootfs_dir(
    cache_root: &Path,
    rootfs_dir: &Path,
    supplied_reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    if prod {
        bail!(
            "`run --image --prod` requires a registry reference with cosign; an \
             unpacked rootfs directory carries no provenance to verify"
        );
    }
    if !rootfs_dir.is_dir() {
        bail!(
            "rootfs directory not found or not a directory: {}",
            rootfs_dir.display()
        );
    }
    // A bare tree has no manifest architecture, so probe a representative ELF
    // binary and reject a cross-arch tree before paying for materialization.
    if let (Some(found), Some(host)) = (probe_rootfs_elf_machine(rootfs_dir), host_elf_machine())
        && found != host
    {
        bail!(
            "rootfs directory targets a different CPU architecture \
             (ELF e_machine {found}, host expects {host})"
        );
    }

    let key = canonical_key_for_path(rootfs_dir)
        .with_context(|| format!("canonicalize rootfs dir {}", rootfs_dir.display()))?;
    let tree_size = mvm_build::run_image::unpacked_tree_size(rootfs_dir)
        .with_context(|| format!("measure rootfs dir {}", rootfs_dir.display()))?;
    let rootfs_rel = format!("rootfs/{key}/rootfs.ext4");
    let rootfs_abs = cache_root.join(&rootfs_rel);
    materialize_run_rootfs(&MaterializeExt4Input::new(
        rootfs_dir.to_path_buf(),
        rootfs_abs.clone(),
        tree_size,
    ))
    .context("materialize rootfs.ext4 from directory")?;

    let provenance = OciProvenance {
        schema_version: 1,
        source: "rootfs_dir".to_string(),
        supplied_reference: supplied_reference.to_string(),
        canonical_reference: rootfs_dir.display().to_string(),
        registry: String::new(),
        repository: String::new(),
        tag: None,
        resolved_digest: String::new(),
        layer_digests: Vec::new(),
        trust_policy: "rootfs-dir-unverified".to_string(),
        verification_status: "no-provenance (dev)".to_string(),
    };
    Ok(ResolvedOciRunImage {
        reference: supplied_reference.to_string(),
        resolved_digest: String::new(),
        rootfs_path: rootfs_abs,
        // rootfs-dir is a niche dev path (no digest); boot it as block ext4.
        unpacked_root: None,
        pulled: true,
        provenance,
        auth_source: None,
    })
}

/// ELF `e_machine` for the host CPU, or `None` for an architecture we don't
/// map (in which case the rootfs-dir arch guard is skipped rather than
/// guessing). `EM_X86_64` = 62, `EM_AARCH64` = 183.
fn host_elf_machine() -> Option<u16> {
    if cfg!(target_arch = "x86_64") {
        Some(62)
    } else if cfg!(target_arch = "aarch64") {
        Some(183)
    } else {
        None
    }
}

/// Probe a few representative binaries in `rootfs_dir` and return the first
/// one's ELF `e_machine`. `None` when none is present/readable as ELF (a tree
/// with no probe-able binary can't be arch-checked — dev-only, so we don't
/// block on it).
fn probe_rootfs_elf_machine(rootfs_dir: &Path) -> Option<u16> {
    const CANDIDATES: &[&str] = &[
        "bin/sh",
        "bin/busybox",
        "bin/bash",
        "usr/bin/env",
        "sbin/init",
    ];
    for candidate in CANDIDATES {
        let path = rootfs_dir.join(candidate);
        if let Ok(bytes) = read_elf_header(&path)
            && let Some(machine) = elf_machine(&bytes)
        {
            return Some(machine);
        }
    }
    None
}

/// Read just enough of a file to inspect its ELF header (cheap; never slurps a
/// whole binary).
fn read_elf_header(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = [0u8; 20];
    let mut file = fs::File::open(path)?;
    let n = file.read(&mut buf)?;
    Ok(buf[..n].to_vec())
}

/// Parse the ELF `e_machine` (offset 18, endianness per `EI_DATA`) from a
/// header. `None` if the bytes aren't an ELF header.
fn elf_machine(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 20 || bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    let m = [bytes[18], bytes[19]];
    match bytes[5] {
        1 => Some(u16::from_le_bytes(m)),
        2 => Some(u16::from_be_bytes(m)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use sha2::{Digest, Sha256};
    use std::io::Cursor;
    use tar::{Builder, EntryType, Header};

    #[test]
    fn local_archive_prod_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ingest_local_archive(
            tmp.path(),
            Path::new("/does/not/matter.tar"),
            "oci-archive:/does/not/matter.tar",
            true,
        )
        .expect_err("prod local archive must be refused");
        assert!(err.to_string().contains("prod"), "got {err}");
    }

    #[test]
    fn local_archive_missing_file_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("nope.tar");
        let err = ingest_local_archive(tmp.path(), &missing, "oci-archive:nope.tar", false)
            .expect_err("missing archive must error");
        assert!(err.to_string().contains("open OCI archive"), "got {err}");
    }

    #[test]
    fn local_archive_malformed_is_rejected() {
        // Fails inside read_oci_archive (no oci-layout / index) before any
        // materialize, so no builder VM is needed to exercise the reject path.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bad = tmp.path().join("bad.tar");
        std::fs::write(&bad, b"definitely not a valid tar archive").unwrap();
        let err = ingest_local_archive(tmp.path(), &bad, "oci-archive:bad.tar", false)
            .expect_err("malformed archive must be rejected");
        assert!(!err.to_string().is_empty());
    }

    fn digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    fn add_tar_entry(builder: &mut Builder<Vec<u8>>, name: &str, body: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, body)
            .expect("append tar entry");
    }

    fn traversal_layer_gzip() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let gz = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = Builder::new(gz);
            tar.mode(tar::HeaderMode::Deterministic);

            let mut bad = Header::new_gnu();
            bad.set_size(1);
            bad.set_mode(0o644);
            bad.set_mtime(0);
            bad.set_entry_type(EntryType::Regular);
            let name_bytes = b"../escape";
            let name_field = bad.as_old_mut().name.as_mut_slice();
            name_field[..name_bytes.len()].copy_from_slice(name_bytes);
            bad.set_cksum();
            tar.append(&bad, &b"x"[..]).expect("append traversal entry");
            tar.finish().expect("finish layer tar");
        }
        buf
    }

    fn oci_archive_with_layer(layer: &[u8]) -> Vec<u8> {
        let platform = current_linux_platform();
        let layer_digest = digest_of(layer);
        let config = format!(
            r#"{{"architecture":"{}","os":"linux","rootfs":{{"type":"layers","diff_ids":["{}"]}}}}"#,
            platform.architecture, layer_digest
        )
        .into_bytes();
        let config_digest = digest_of(&config);
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{config_size}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{layer_size}}}]}}"#,
            config_size = config.len(),
            layer_size = layer.len()
        )
        .into_bytes();
        let manifest_digest = digest_of(&manifest);
        let index = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{manifest_size},"platform":{{"architecture":"{}","os":"linux"}}}}]}}"#,
            platform.architecture,
            manifest_size = manifest.len()
        )
        .into_bytes();

        let mut builder = Builder::new(Vec::new());
        add_tar_entry(
            &mut builder,
            "oci-layout",
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        );
        add_tar_entry(&mut builder, "index.json", &index);
        add_tar_entry(
            &mut builder,
            &format!(
                "blobs/sha256/{}",
                manifest_digest
                    .strip_prefix("sha256:")
                    .expect("manifest digest prefix")
            ),
            &manifest,
        );
        add_tar_entry(
            &mut builder,
            &format!(
                "blobs/sha256/{}",
                config_digest
                    .strip_prefix("sha256:")
                    .expect("config digest prefix")
            ),
            &config,
        );
        add_tar_entry(
            &mut builder,
            &format!(
                "blobs/sha256/{}",
                layer_digest
                    .strip_prefix("sha256:")
                    .expect("layer digest prefix")
            ),
            layer,
        );
        builder.into_inner().expect("finish OCI archive")
    }

    #[test]
    fn local_archive_layer_traversal_is_rejected_by_hardened_unpack() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let archive = oci_archive_with_layer(&traversal_layer_gzip());
        let err = ingest_archive_from_reader(
            tmp.path(),
            Cursor::new(archive),
            "oci-archive:traversal.tar",
            "local_archive",
            "OCI archive with traversal layer",
        )
        .expect_err("local archive ingest must reject traversal entries");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refused") || msg.contains("traversal"),
            "got {msg}"
        );
    }

    #[test]
    fn local_archive_streaming_layer_traversal_is_rejected() {
        // The seekable file path now uses stream_oci_archive, which must still
        // reject traversal entries via the same hardened unpack_layer.
        let tmp = tempfile::tempdir().expect("tempdir");
        let archive_path = tmp.path().join("traversal.tar");
        let archive = oci_archive_with_layer(&traversal_layer_gzip());
        std::fs::write(&archive_path, archive).unwrap();
        let err = ingest_local_archive(
            tmp.path(),
            &archive_path,
            "oci-archive:traversal.tar",
            false,
        )
        .expect_err("streaming local archive ingest must reject traversal entries");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refused") || msg.contains("traversal"),
            "got {msg}"
        );
    }

    #[test]
    fn stdin_archive_prod_is_refused() {
        // prod bails before any stdin read.
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ingest_stdin_archive(tmp.path(), "-", true)
            .expect_err("prod stdin archive must be refused");
        assert!(err.to_string().contains("prod"), "got {err}");
    }

    fn fake_elf(machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // little-endian
        b[6] = 1; // version
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type ET_EXEC
        b[18..20].copy_from_slice(&machine.to_le_bytes());
        b
    }

    #[test]
    fn elf_machine_parses_le_and_rejects_non_elf() {
        assert_eq!(elf_machine(&fake_elf(62)), Some(62));
        assert_eq!(elf_machine(&fake_elf(183)), Some(183));
        assert_eq!(elf_machine(b"definitely not an elf!"), None);
    }

    #[test]
    fn rootfs_dir_prod_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ingest_rootfs_dir(tmp.path(), tmp.path(), "rootfs-dir:.", true)
            .expect_err("prod rootfs dir must be refused");
        assert!(err.to_string().contains("prod"), "got {err}");
    }

    #[test]
    fn rootfs_dir_missing_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("nope");
        let err = ingest_rootfs_dir(tmp.path(), &missing, "rootfs-dir:nope", false)
            .expect_err("missing rootfs dir must error");
        assert!(err.to_string().contains("directory"), "got {err}");
    }

    #[test]
    fn rootfs_dir_wrong_arch_is_rejected() {
        // The guard is a no-op on hosts we don't map; skip there.
        let Some(host) = host_elf_machine() else {
            return;
        };
        let wrong = if host == 62 { 183 } else { 62 };
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("sh"), fake_elf(wrong)).unwrap();
        let err = ingest_rootfs_dir(tmp.path(), tmp.path(), "rootfs-dir:.", false)
            .expect_err("cross-arch rootfs must be rejected before materialize");
        assert!(err.to_string().contains("architecture"), "got {err}");
    }

    #[test]
    fn archive_from_reader_rejects_malformed() {
        // The shared file/stdin core rejects a garbage stream inside
        // read_oci_archive, before any materialize (no builder VM needed).
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ingest_archive_from_reader(
            tmp.path(),
            Cursor::new(b"not a valid oci archive".to_vec()),
            "-",
            "stdin_archive",
            "OCI archive on stdin",
        )
        .expect_err("malformed stdin archive must be rejected");
        assert!(!err.to_string().is_empty());
    }
}
