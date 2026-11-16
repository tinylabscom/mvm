//! `mvmctl image inspect` — show provenance for a cached OCI image.

use std::io::Write;
use std::path::Path;

use anyhow::Result;

pub(super) fn run(cache_root: &Path, reference: &str, json: bool, digest_ref: bool) -> Result<()> {
    if digest_ref {
        write_digest_reference(&mut std::io::stdout().lock(), cache_root, reference)?;
    } else if json {
        crate::json_out::emit_json(&mvm_client::cli_image::inspect_json(cache_root, reference)?)?;
    } else {
        mvm_client::cli_image::render_inspect(cache_root, reference)?;
    }
    Ok(())
}

fn write_digest_reference(
    writer: &mut impl Write,
    cache_root: &Path,
    reference: &str,
) -> Result<()> {
    let reference = mvm_client::cli_image::inspect_digest_reference(cache_root, reference)?;
    writeln!(writer, "{reference}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_reference_output_is_one_line_and_validation_errors_write_nothing() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let mut image = serde_json::json!({
            "reference": "alpine:3.20",
            "registry": "docker.io",
            "repository": "library/alpine",
            "tag": "3.20",
            "resolved_digest": digest,
            "fetched_at": "2026-05-18T00:00:00Z",
            "manifest_path": "manifests/alpine.json"
        });
        let cache = tempfile::tempdir().unwrap();
        let publish = |image: &serde_json::Value| {
            std::fs::write(
                cache.path().join("index.json"),
                serde_json::to_vec(&serde_json::json!({
                    "schema_version": 1,
                    "images": [image],
                }))
                .unwrap(),
            )
            .unwrap();
        };
        publish(&image);
        let mut output = Vec::new();
        write_digest_reference(&mut output, cache.path(), "alpine:3.20").unwrap();
        assert_eq!(
            output,
            format!("docker.io/library/alpine@{digest}\n").as_bytes()
        );
        for invalid in ["", "sha256:abc", "sha256:\n"] {
            image["resolved_digest"] = invalid.into();
            publish(&image);
            let mut output = Vec::new();
            assert!(write_digest_reference(&mut output, cache.path(), "alpine:3.20").is_err());
            assert!(output.is_empty());
        }
        image["resolved_digest"] = digest.into();
        image["repository"] = "library/alpine\n".into();
        publish(&image);
        let mut output = Vec::new();
        assert!(write_digest_reference(&mut output, cache.path(), "alpine:3.20").is_err());
        assert!(output.is_empty());
    }
}
