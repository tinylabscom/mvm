use crate::ir::Image;

/// Build the runtime image from a list of Nix package attribute paths.
pub fn nix_packages<I, S>(packages: I) -> Image
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Image::NixPackages {
        packages: packages.into_iter().map(Into::into).collect(),
    }
}

/// Build the runtime image from a digest-pinned OCI base.
pub fn oci_base(reference: impl Into<String>, digest: impl Into<String>) -> Image {
    Image::OciBase {
        reference: reference.into(),
        digest: digest.into(),
    }
}
