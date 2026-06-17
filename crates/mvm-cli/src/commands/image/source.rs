//! Image source classification — the entry seam that decides whether an
//! `--image` / `mvm.toml image =` value is a registry reference or a local
//! source (OCI-layout archive file, stdin stream, or unpacked rootfs
//! directory).
//!
//! Registry refs flow to the existing `mvm_oci::ImageReference` + pull path
//! (the only source that touches the network); local sources route to the
//! same hardened unpack / provenance / ext4 materialization without a fetch.
//!
//! Classification is purely **prefix-driven** (skopeo-style transports) so it
//! is deterministic and never probes the filesystem — `alpine:3.20` stays a
//! registry ref despite the colon. Existence, architecture, and traversal
//! checks are the ingest step's job, not classification's.

use std::path::PathBuf;

use anyhow::{Result, bail};

/// Reserved transport prefix for a local OCI-layout archive file.
const OCI_ARCHIVE: &str = "oci-archive:";
/// Reserved transport prefix for an already-unpacked rootfs directory.
const ROOTFS_DIR: &str = "rootfs-dir:";

/// Where an `--image` value's bytes come from. Every variant routes to the
/// same downstream unpack / provenance / ext4 path; only acquisition differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum ImageSource {
    /// A registry reference (`alpine:3.20`, `ghcr.io/x/y@sha256:…`). Parsed
    /// downstream by `mvm_oci::ImageReference`; the only network-fetching
    /// source.
    Registry(String),
    /// A local OCI-layout archive file (`oci-archive:PATH`).
    OciArchive(PathBuf),
    /// An OCI-layout archive streamed on stdin (`-` or `oci-archive:-`).
    Stdin,
    /// An already-unpacked rootfs directory (`rootfs-dir:PATH`).
    RootfsDir(PathBuf),
}

impl ImageSource {
    /// Classify a `--image` / `image =` value. Prefix-driven and
    /// filesystem-free: `oci-archive:` / `rootfs-dir:` are reserved
    /// transports, `-` is a stdin archive, and everything else is a registry
    /// reference (so `alpine:3.20` and `ghcr.io/x:y` stay registry refs
    /// despite the colon). Empty input — or a transport with no locator — is
    /// an error.
    pub(in crate::commands) fn classify(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            bail!("image source must not be empty");
        }
        if input == "-" {
            return Ok(Self::Stdin);
        }
        if let Some(rest) = input.strip_prefix(OCI_ARCHIVE) {
            if rest == "-" {
                return Ok(Self::Stdin);
            }
            if rest.is_empty() {
                bail!("`{OCI_ARCHIVE}` requires a path");
            }
            return Ok(Self::OciArchive(PathBuf::from(rest)));
        }
        if let Some(rest) = input.strip_prefix(ROOTFS_DIR) {
            if rest.is_empty() {
                bail!("`{ROOTFS_DIR}` requires a path");
            }
            return Ok(Self::RootfsDir(PathBuf::from(rest)));
        }
        Ok(Self::Registry(input.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_is_a_registry_reference() {
        assert_eq!(
            ImageSource::classify("alpine").unwrap(),
            ImageSource::Registry("alpine".to_string())
        );
    }

    #[test]
    fn tagged_and_digested_refs_stay_registry_despite_the_colon() {
        // The colon in a tag/digest must not be mistaken for a transport.
        assert_eq!(
            ImageSource::classify("alpine:3.20").unwrap(),
            ImageSource::Registry("alpine:3.20".to_string())
        );
        assert_eq!(
            ImageSource::classify("ghcr.io/foo/bar@sha256:abc").unwrap(),
            ImageSource::Registry("ghcr.io/foo/bar@sha256:abc".to_string())
        );
        assert!(matches!(
            ImageSource::classify("registry.local:5000/x:v1").unwrap(),
            ImageSource::Registry(_)
        ));
    }

    #[test]
    fn oci_archive_prefix_yields_a_local_archive_path() {
        assert_eq!(
            ImageSource::classify("oci-archive:/tmp/img.tar").unwrap(),
            ImageSource::OciArchive(PathBuf::from("/tmp/img.tar"))
        );
    }

    #[test]
    fn rootfs_dir_prefix_yields_a_directory_path() {
        assert_eq!(
            ImageSource::classify("rootfs-dir:/var/lib/rootfs").unwrap(),
            ImageSource::RootfsDir(PathBuf::from("/var/lib/rootfs"))
        );
    }

    #[test]
    fn dash_is_a_stdin_archive() {
        assert_eq!(ImageSource::classify("-").unwrap(), ImageSource::Stdin);
        assert_eq!(
            ImageSource::classify("oci-archive:-").unwrap(),
            ImageSource::Stdin
        );
    }

    #[test]
    fn input_is_trimmed() {
        assert_eq!(
            ImageSource::classify("  alpine  ").unwrap(),
            ImageSource::Registry("alpine".to_string())
        );
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(ImageSource::classify("").is_err());
        assert!(ImageSource::classify("   ").is_err());
    }

    #[test]
    fn transport_without_a_locator_is_rejected() {
        let oci = ImageSource::classify("oci-archive:")
            .unwrap_err()
            .to_string();
        assert!(oci.contains("oci-archive:"), "got {oci}");
        let dir = ImageSource::classify("rootfs-dir:")
            .unwrap_err()
            .to_string();
        assert!(dir.contains("rootfs-dir:"), "got {dir}");
    }

    #[test]
    fn each_input_maps_to_its_variant() {
        use ImageSource::*;
        assert!(matches!(
            ImageSource::classify("alpine").unwrap(),
            Registry(_)
        ));
        assert!(matches!(
            ImageSource::classify("oci-archive:/x.tar").unwrap(),
            OciArchive(_)
        ));
        assert!(matches!(
            ImageSource::classify("rootfs-dir:/x").unwrap(),
            RootfsDir(_)
        ));
        assert!(matches!(ImageSource::classify("-").unwrap(), Stdin));
    }
}
