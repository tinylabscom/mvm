//! `mvmctl pack download` — fetch a pack version into the cache without
//! changing which version is active.
//!
//! No pack class has a release-fetch today, so every class refuses explicitly
//! rather than pretending to do something. The builder image, the one class
//! that used to have one, is a member of the signed image set this build's
//! image lock pins: `mvmctl bootstrap` fetches it and verifies it against that
//! root, and a CLI release no longer carries it as a pack.

use anyhow::{Result, bail};

use mvm_core::packs::PackKind;

use super::PackKindArg;

pub(in crate::commands) fn run(kind: PackKindArg) -> Result<()> {
    not_fetchable(kind.to_pack_kind())
}

/// Shared refusal for `download` and `update`. Specific per class rather than
/// a generic "not implemented" — a caller should never wonder whether this is
/// a bug or a known gap, and the builder class has somewhere real to point.
pub(in crate::commands) fn not_fetchable(kind: PackKind) -> Result<()> {
    let label = match kind {
        PackKind::Builder => bail!(
            "the builder pack is not fetchable — the builder image is a member of the \
             signed image set this mvmctl's image lock pins, not a release pack; \
             `mvmctl bootstrap` fetches it and verifies it against that set"
        ),
        PackKind::Runtime => "runtime",
        PackKind::ImageProject => "dev-image",
        PackKind::Extension => "extension",
    };
    bail!(
        "{label} pack download is not yet fetchable — {label} release-fetch is not wired \
         yet (no pack class has a publish/fetch path today)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builder_refusal_points_at_bootstrap() {
        let error = not_fetchable(PackKind::Builder)
            .expect_err("the builder pack has no release fetch")
            .to_string();

        assert!(error.contains("image set"), "{error}");
        assert!(error.contains("mvmctl bootstrap"), "{error}");
    }

    #[test]
    fn every_other_class_refuses_under_its_own_name() {
        for (kind, label) in [
            (PackKind::Runtime, "runtime"),
            (PackKind::ImageProject, "dev-image"),
            (PackKind::Extension, "extension"),
        ] {
            let error = not_fetchable(kind)
                .expect_err("no pack class is fetchable")
                .to_string();
            assert!(error.starts_with(label), "{error}");
        }
    }
}
