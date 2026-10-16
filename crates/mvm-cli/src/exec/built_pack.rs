//! Early shape checks for a typed built-pack launch, before preparation.

use anyhow::{Result, ensure};
use mvm_client::admission::AssetSpec;

use super::ImageSource;

pub(super) fn validate_shape(
    image: &ImageSource,
    assets: &[AssetSpec],
    warm_pool_size: u32,
    has_admission: bool,
) -> Result<()> {
    let ImageSource::RegistryPack { pin } = image else {
        return Ok(());
    };
    ensure!(
        warm_pool_size == 0,
        "built registry images require cold launch; warm pool and snapshot claims are not bound"
    );
    ensure!(
        has_admission,
        "built registry images require signed-plan admission"
    );
    ensure!(
        assets
            .iter()
            .any(|asset| matches!(asset, AssetSpec::RegistryPack(selected) if selected == pin)),
        "built registry image is missing its exact signed-plan asset pin"
    );
    Ok(())
}

pub(super) fn require_handoff(image: &ImageSource, has_runtime_owner: bool) -> Result<()> {
    ensure!(
        !matches!(image, ImageSource::RegistryPack { .. }) || has_runtime_owner,
        "built registry image requires a typed final admitted-image handoff"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::{packs::Sha256Hex, registry_pack::PackPin};

    fn pin(bytes: &[u8]) -> PackPin {
        PackPin::new(
            "runtime/python@1.1.0".parse().unwrap(),
            Sha256Hex::from_bytes(bytes),
        )
        .unwrap()
    }

    #[test]
    fn built_shape_requires_cold_admission_and_its_exact_pin() {
        let selected = pin(b"selected");
        let image = ImageSource::RegistryPack {
            pin: selected.clone(),
        };
        let assets = [AssetSpec::RegistryPack(selected)];
        validate_shape(&image, &assets, 0, true).unwrap();
        assert!(validate_shape(&image, &assets, 1, true).is_err());
        assert!(validate_shape(&image, &assets, 0, false).is_err());
        assert!(validate_shape(&image, &[], 0, true).is_err());
        assert!(
            validate_shape(&image, &[AssetSpec::RegistryPack(pin(b"other"))], 0, true).is_err()
        );
        assert!(require_handoff(&image, false).is_err());
        require_handoff(&image, true).unwrap();
    }

    #[test]
    fn ordinary_source_keeps_existing_factory_and_warm_behavior() {
        let image = ImageSource::Template("ordinary".into());
        validate_shape(&image, &[], 4, false).unwrap();
        require_handoff(&image, false).unwrap();
    }
}
