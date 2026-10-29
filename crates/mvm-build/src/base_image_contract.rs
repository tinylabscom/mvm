//! Read-only validation of authenticated Linux base-image declarations.

use std::path::Path;

use anyhow::{Context, Result, bail};

/// Check the root marker against the authenticated Linux-base declaration.
/// Legacy sets predate this marker. Reads ext4 without mounting or following links.
pub fn verify_base_image_contract(
    image: &Path,
    compatibility: &mvm_core::image_set::ImageSetCompatibility,
) -> Result<()> {
    let Some(version) = compatibility.base_image_contract else {
        return Ok(());
    };
    if version != mvm_core::image_set::BaseImageContract::LINUX_LAYER {
        bail!("unsupported base-image contract {version}");
    }
    let tree = mvm_fs::tree_diff::Ext4Tree::open(image)
        .context("open authenticated base root filesystem")?;
    let marker = tree
        .read_regular_file_no_symlinks(
            mvm_core::image_set::BASE_IMAGE_CONTRACT_MARKER.trim_start_matches('/'),
            16,
        )
        .context("read base-image contract marker without symlinks")?;
    if marker != format!("{version}\n").as_bytes() {
        bail!("base-image contract marker does not match authenticated declaration {version}");
    }
    let filesystem = ext4_view::Ext4::load_from_path(image)
        .context("read base-image contract marker metadata")?;
    let metadata = filesystem
        .symlink_metadata(mvm_core::image_set::BASE_IMAGE_CONTRACT_MARKER)
        .context("read base-image contract marker mode")?;
    if u32::from(metadata.mode()) & 0o7777 != 0o444 {
        bail!("base-image contract marker must have exact mode 0444");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::image_set::{BaseImageContract, ImageSetCompatibility};
    use mvm_fs::ext4::{Node, Owner};

    fn compatibility(contract: Option<BaseImageContract>) -> ImageSetCompatibility {
        ImageSetCompatibility {
            guest_agent_protocol: None,
            builder_cache_contract: 5,
            builder_boot_abi: None,
            base_image_contract: contract,
        }
    }

    fn check_marker(bytes: &[u8], mode: u16, link: bool) -> Result<()> {
        let root = tempfile::tempdir().unwrap();
        let mut nodes: Vec<_> = ["/etc", "/etc/mvm"]
            .into_iter()
            .map(|path| Node::Dir {
                path: path.into(),
                mode: 0o755,
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            })
            .collect();
        let marker = "/etc/mvm/base-image-contract";
        nodes.push(if link {
            Node::Symlink {
                path: marker.into(),
                target: "actual-marker".into(),
                owner: Owner::ROOT,
            }
        } else {
            Node::File {
                path: marker.into(),
                mode,
                data: bytes.into(),
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            }
        });
        let image = root.path().join("root.ext4");
        std::fs::write(
            &image,
            mvm_fs::ext4::build_image(nodes, &Default::default()).unwrap(),
        )
        .unwrap();
        verify_base_image_contract(&image, &compatibility(Some(BaseImageContract::LINUX_LAYER)))
    }

    #[test]
    fn legacy_contract_needs_no_image_and_unknown_contract_refuses() {
        let absent = Path::new("absent-base-image");
        verify_base_image_contract(absent, &compatibility(None)).unwrap();
        let error =
            verify_base_image_contract(absent, &compatibility(Some(BaseImageContract::new(99))))
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported base-image contract")
        );
    }

    #[test]
    fn marker_requires_exact_bytes_and_readonly_mode() {
        check_marker(b"1\n", 0o444, false).unwrap();
        for bytes in [b"1".as_slice(), b"1\r\n", b"2\n", b""] {
            assert!(check_marker(bytes, 0o444, false).is_err());
        }
        for mode in [0o644, 0o400, 0o4444] {
            assert!(check_marker(b"1\n", mode, false).is_err());
        }
    }

    #[test]
    fn marker_symlink_is_refused_inside_the_image() {
        assert!(check_marker(b"1\n", 0o444, true).is_err());
    }
}
