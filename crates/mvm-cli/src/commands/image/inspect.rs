//! `mvmctl image inspect` — show provenance for a cached OCI image.

use std::io::Write;
use std::path::Path;

use anyhow::Result;

pub(super) fn run(cache_root: &Path, reference: &str, json: bool, digest_ref: bool) -> Result<()> {
    let output = super::inspect_image(cache_root, reference)?;
    if digest_ref {
        write_digest_reference(&mut std::io::stdout().lock(), &output.image)?;
    } else if json {
        crate::json_out::emit_json(&output)?;
    } else {
        super::render_inspect(&output);
    }
    Ok(())
}

fn write_digest_reference(
    writer: &mut impl Write,
    image: &super::oci_types::CachedOciImage,
) -> Result<()> {
    let reference = image.digest_reference()?;
    writeln!(writer, "{reference}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_reference_output_is_one_line_and_validation_errors_write_nothing() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let mut image: super::super::oci_types::CachedOciImage =
            serde_json::from_value(serde_json::json!({
                "reference": "alpine:3.20",
                "registry": "docker.io",
                "repository": "library/alpine",
                "tag": "3.20",
                "resolved_digest": digest,
                "fetched_at": "2026-05-18T00:00:00Z",
                "manifest_path": "manifests/alpine.json"
            }))
            .unwrap();
        let mut output = Vec::new();
        write_digest_reference(&mut output, &image).unwrap();
        assert_eq!(
            output,
            format!("docker.io/library/alpine@{digest}\n").as_bytes()
        );
        for invalid in ["", "sha256:abc", "sha256:\n"] {
            image.resolved_digest = invalid.to_string();
            let mut output = Vec::new();
            assert!(write_digest_reference(&mut output, &image).is_err());
            assert!(output.is_empty());
        }
        image.resolved_digest = digest;
        image.repository.push('\n');
        let mut output = Vec::new();
        assert!(write_digest_reference(&mut output, &image).is_err());
        assert!(output.is_empty());
    }
}
