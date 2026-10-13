//! Which cached OCI images were pulled most recently — the history a bare
//! `mvmctl pool warm` warms from.
//!
//! The source is the OCI cache index and its `fetched_at` stamp. Every image
//! a user has pulled is there, whether by `image pull` or by a
//! `machine run --image` that had to fetch it, and reading it costs one file
//! read on an explicit command rather than a write on every launch. A run of
//! an image that was already cached does not move it up: launches record
//! nothing here, and adding a write to the launch path to change that would
//! cost every run to serve this one command.

use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};

use super::oci_types::CachedOciImage;

/// References of the cached images, newest pull first, each once.
pub(in crate::commands) fn recent_image_references(cache_root: &Path) -> Result<Vec<String>> {
    let index = super::cache::load_index(cache_root)?;
    Ok(newest_first(&index.images))
}

/// Order by `fetched_at`, newest first. Two writers stamp it with different
/// RFC 3339 precisions, so the stamps are parsed rather than compared as
/// strings; one that does not parse sorts last instead of hiding the rest.
fn newest_first(images: &[CachedOciImage]) -> Vec<String> {
    let mut stamped: Vec<(Option<DateTime<Utc>>, &str)> = images
        .iter()
        .map(|image| {
            let at = DateTime::parse_from_rfc3339(&image.fetched_at)
                .ok()
                .map(|t| t.with_timezone(&Utc));
            (at, image.reference.as_str())
        })
        .collect();
    stamped.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    let mut out: Vec<String> = Vec::with_capacity(stamped.len());
    for (_, reference) in stamped {
        if !out.iter().any(|seen| seen == reference) {
            out.push(reference.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(reference: &str, fetched_at: &str) -> CachedOciImage {
        CachedOciImage {
            reference: reference.to_string(),
            registry: "docker.io".to_string(),
            repository: "library/x".to_string(),
            tag: None,
            resolved_digest: "sha256:00".to_string(),
            fetched_at: fetched_at.to_string(),
            manifest_path: "manifests/x.json".to_string(),
            config_path: None,
            rootfs_path: None,
            runtime_tag: None,
            claims_path: None,
            verification_receipt_path: None,
            layers: Vec::new(),
        }
    }

    #[test]
    fn newest_pull_comes_first_across_stamp_precisions() {
        let images = [
            image("alpine", "2026-10-01T00:00:00Z"),
            image("python:3.12", "2026-10-03T00:00:00.123456789+00:00"),
            image("nginx", "2026-10-02T00:00:00Z"),
        ];
        assert_eq!(newest_first(&images), ["python:3.12", "nginx", "alpine"]);
    }

    #[test]
    fn an_unparseable_stamp_sorts_last_and_a_reference_appears_once() {
        let images = [
            image("broken", "yesterday"),
            image("alpine", "2026-10-01T00:00:00Z"),
            image("alpine", "2026-09-01T00:00:00Z"),
        ];
        assert_eq!(newest_first(&images), ["alpine", "broken"]);
    }

    #[test]
    fn an_absent_index_is_no_history() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(recent_image_references(tmp.path()).unwrap().is_empty());
    }

    #[test]
    fn the_index_on_disk_is_read_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let index = super::super::oci_types::OciCacheIndex {
            images: vec![
                image("alpine", "2026-10-01T00:00:00Z"),
                image("nginx", "2026-10-02T00:00:00Z"),
            ],
            ..Default::default()
        };
        super::super::cache::save_index(tmp.path(), &index).unwrap();
        assert_eq!(
            recent_image_references(tmp.path()).unwrap(),
            ["nginx", "alpine"]
        );
    }
}
