use crate::ir::Source;

/// Bundle the source tree at `path` (relative to the manifest dir).
/// Default include is `["**"]`.
pub fn local_path(path: impl Into<String>) -> Source {
    Source::LocalPath {
        path: path.into(),
        include: vec!["**".to_string()],
        exclude: Vec::new(),
    }
}

/// Reference a Nix derivation expression.
pub fn nix_derivation(expr: impl Into<String>) -> Source {
    Source::NixDerivation { expr: expr.into() }
}

/// Reference a digest-pinned OCI image as the bundled source.
pub fn oci_image(reference: impl Into<String>, digest: impl Into<String>) -> Source {
    Source::OciImage {
        reference: reference.into(),
        digest: digest.into(),
    }
}
