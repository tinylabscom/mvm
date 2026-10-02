use super::stage0_cache::validate_builder_vm_stage0_artifacts;
use super::*;

#[cfg(test)]
pub(super) fn first_nameserver_from_resolv_conf(body: &str) -> Option<String> {
    mvm_agentd::guest_net::first_nameserver_from_resolv_conf(body)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Stage0InputOverride {
    pub input_path: String,
    pub guest_path: String,
}

#[cfg(test)]
pub(super) fn stage0_build_conf_contents(
    build_attr: &str,
    output_mode: &str,
    resolver: Option<&str>,
    workspace_archive: Option<&str>,
    offline: bool,
    input_overrides: &[Stage0InputOverride],
) -> String {
    let mut out =
        format!("MVM_STAGE0_BUILD_ATTR={build_attr}\nMVM_STAGE0_OUTPUT_MODE={output_mode}\n");
    if let Some(resolver) = resolver {
        out.push_str(&format!("MVM_STAGE0_RESOLVER={resolver}\n"));
    }
    if let Some(workspace_archive) = workspace_archive {
        out.push_str(&format!(
            "MVM_STAGE0_WORKSPACE_ARCHIVE={workspace_archive}\n"
        ));
    }
    if offline {
        out.push_str("MVM_STAGE0_OFFLINE=1\n");
    }
    for (idx, override_) in input_overrides.iter().enumerate() {
        out.push_str(&format!(
            "MVM_STAGE0_OVERRIDE_INPUT_{idx}={}={}\n",
            override_.input_path, override_.guest_path
        ));
    }
    out
}

/// Prepare the builder VM image for the images the caller selected.
///
/// With a local image checkout selected, the builder VM is the checkout
/// pair's `builder-vm` target, built once through the shared local-image-set
/// build and installed from the local image cache. With the selector unset,
/// it is the builder image the image lock pins, fetched and verified. A local
/// build asked for without a checkout is refused rather than answered with
/// the fetched image, which is exactly what the caller asked not to have.
#[cfg(feature = "builder-vm")]
pub(in crate::commands) const MVM_ALLOW_LOCAL_BUILDER_ENV: &str = "MVM_ALLOW_LOCAL_BUILDER_BUILD";

#[cfg(feature = "builder-vm")]
fn local_builder_build_opted_in(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

/// Decide whether to build the builder VM from a local checkout or fetch the
/// published image. This logic is intentionally small and pure so unit tests can
/// drive it without touching the filesystem or CI-bound network I/O.
#[cfg(feature = "builder-vm")]
fn decide_builder_image_acquisition(
    allow_local_build: bool,
    env_override: Option<mvm_build::boot_image_select::BootImageAcquisition>,
    has_local_checkout: bool,
) -> Result<mvm_build::boot_image_select::BootImageAcquisition> {
    use mvm_build::boot_image_select::BootImageAcquisition;
    // Env override wins. `fetch` is always honoured. `build` must be explicitly
    // allowed and backed by a local checkout; otherwise refuse rather than
    // silently falling back.
    if let Some(BootImageAcquisition::Fetch) = env_override {
        return Ok(BootImageAcquisition::Fetch);
    }
    if let Some(BootImageAcquisition::Build) = env_override {
        if !allow_local_build {
            return Err(mvm_build::image_source::ImageConstructionRefused::new(
                "the builder VM image",
            )
            .into());
        }
        if !has_local_checkout {
            return Err(mvm_build::image_source::ImageConstructionRefused::new(
                "the builder VM image",
            )
            .into());
        }
        return Ok(BootImageAcquisition::Build);
    }

    // No explicit override: default to building only when the operator has
    // opted in and a local checkout is present; otherwise fetch the published
    // image.
    if allow_local_build && has_local_checkout {
        Ok(BootImageAcquisition::Build)
    } else {
        Ok(mvm_build::boot_image_select::BootImageAcquisition::Fetch)
    }
}

pub(in crate::commands) fn bootstrap_builder_vm_image() -> Result<()> {
    #[cfg(feature = "builder-vm")]
    {
        // Operator opt-in: only the documented value `1` permits building the
        // builder VM from a local image checkout.
        let allow_local_build =
            local_builder_build_opted_in(std::env::var_os(MVM_ALLOW_LOCAL_BUILDER_ENV).as_deref());
        let env_override = mvm_build::boot_image_select::resolve_env_override();
        let checkout = selected_local_checkout()?;
        let has_checkout = checkout.is_some();

        match decide_builder_image_acquisition(allow_local_build, env_override, has_checkout) {
            Ok(mvm_build::boot_image_select::BootImageAcquisition::Build) => {
                // Safe to unwrap: the decision only returns Build when a
                // checkout exists and was permitted.
                bootstrap_builder_vm_image_from_local_pair(&checkout.expect("checkout present"))?;
            }
            Ok(mvm_build::boot_image_select::BootImageAcquisition::Fetch) => {
                bootstrap_tool_builder_vm_image()?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    #[cfg(not(feature = "builder-vm"))]
    bootstrap_tool_builder_vm_image()
}

/// The local image checkout the selector names, if that is the selected
/// source. A configured path that does not resolve is an error here, never a
/// quiet fall-through to the released set.
pub(crate) fn selected_local_checkout()
-> Result<Option<mvm_build::image_source::LocalImageCheckout>> {
    use mvm_build::image_source::resolve_current_source;
    Ok(selected_local_checkout_from(resolve_current_source()?))
}

pub(super) fn selected_local_checkout_from(
    source: mvm_build::image_source::ImageSource,
) -> Option<mvm_build::image_source::LocalImageCheckout> {
    use mvm_build::image_source::ImageSource;
    match source {
        ImageSource::LocalCheckout(checkout) => Some(checkout),
        ImageSource::Released => None,
    }
}

/// Prepare the builder-VM image the local image-set build itself runs in:
/// the published builder image the image lock pins.
///
/// Exempt from the image source selector: an image-set build runs inside
/// this builder, so routing it through the pair's `builder-vm` target would
/// recurse — building the builder image would need the builder image.
pub(in crate::commands) fn bootstrap_tool_builder_vm_image() -> Result<()> {
    #[cfg(feature = "builder-vm")]
    return bootstrap_builder_vm_image_with(
        || {
            mvm_build::builder_vm_bootstrap::maybe_reexec_builder_vm_bootstrap_helper()
                .map_err(anyhow::Error::from)
        },
        bootstrap_tool_builder_vm_image_in_process,
    );

    #[cfg(not(feature = "builder-vm"))]
    bootstrap_tool_builder_vm_image_in_process()
}

/// Serve the builder-VM cache from the pair's `builder-vm` target: build it
/// through the shared local-image-set path when the pair changed, install the
/// verified entry under a fingerprint naming both checkouts, and answer an
/// unchanged pair from the installed cache.
#[cfg(feature = "builder-vm")]
fn bootstrap_builder_vm_image_from_local_pair(
    checkout: &mvm_build::image_source::LocalImageCheckout,
) -> Result<()> {
    use mvm_build::image_source::{FlakeAttr, ImageBuildRole, ImageBuildTarget};
    let target = ImageBuildTarget {
        role: ImageBuildRole::BuilderVm,
        attr: FlakeAttr::new("default").expect("default is a valid flake attribute"),
    };
    let build = super::local_pair::ensure_pair_built(checkout, target)?;
    let fingerprint = super::local_pair::pair_fingerprint(&build.key);
    let arch = builder_vm_host_arch();
    let out_dir = std::path::Path::new(&mvm_core::config::mvm_cache_dir())
        .join("builder-vm")
        .join(arch);
    if super::stage0_cache::local_pair_cache_ready(&out_dir, &fingerprint) {
        crate::ui::info(&format!(
            "Builder VM image already cached at {}.",
            out_dir.display()
        ));
        return Ok(());
    }
    super::local_pair::install_pair_builder_vm(&build.entry, arch, &fingerprint)
}

#[cfg(feature = "builder-vm")]
fn bootstrap_builder_vm_image_with(
    maybe_reexec: impl FnOnce() -> Result<bool>,
    bootstrap_in_process: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if maybe_reexec()? {
        return Ok(());
    }
    bootstrap_in_process()
}

fn bootstrap_tool_builder_vm_image_in_process() -> Result<()> {
    let arch = builder_vm_host_arch();
    let out_dir = format!("{}/builder-vm/{arch}", mvm_core::config::mvm_cache_dir());
    if validate_builder_vm_stage0_artifacts(std::path::Path::new(&out_dir)).is_ok() {
        ui::info(&format!("Builder VM image already cached at {out_dir}."));
        return Ok(());
    }
    perform_builder_vm_download_published(arch, &out_dir)
}

#[cfg(all(test, feature = "builder-vm"))]
mod bootstrap_helper_routing_tests {
    use super::bootstrap_builder_vm_image_with;
    use std::cell::Cell;

    #[test]
    fn completed_source_helper_skips_in_process_bootstrap() {
        let called = Cell::new(false);

        bootstrap_builder_vm_image_with(
            || Ok(true),
            || {
                called.set(true);
                Ok(())
            },
        )
        .expect("completed helper should satisfy bootstrap");

        assert!(!called.get(), "bootstrap must not run twice");
    }

    #[test]
    fn matching_source_helper_bootstraps_in_process() {
        let called = Cell::new(false);

        bootstrap_builder_vm_image_with(
            || Ok(false),
            || {
                called.set(true);
                Ok(())
            },
        )
        .expect("matching helper should bootstrap in process");

        assert!(called.get(), "matching helper must perform bootstrap");
    }

    #[test]
    fn helper_resolution_error_prevents_bootstrap() {
        let called = Cell::new(false);

        let error = bootstrap_builder_vm_image_with(
            || anyhow::bail!("helper build failed"),
            || {
                called.set(true);
                Ok(())
            },
        )
        .expect_err("helper errors must fail closed");

        assert!(error.to_string().contains("helper build failed"));
        assert!(!called.get(), "bootstrap must not bypass a helper error");
    }
}

pub(super) fn builder_vm_host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// Fetch the builder image the image lock pins into `out_dir`. It is a member
/// of the signed image set, so the fetch verifies it against that root.
fn perform_builder_vm_download_published(arch: &str, out_dir: &str) -> Result<()> {
    ui::info("Builder VM image not in cache; downloading the builder image the image lock pins...");
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating builder-vm cache dir {out_dir}"))?;
    download_builder_vm_image(arch, out_dir).context("downloading the builder VM image")
}

#[cfg(all(test, feature = "builder-vm"))]
mod decide_tests {
    use super::*;
    use mvm_build::boot_image_select::BootImageAcquisition;
    use std::ffi::OsStr;

    #[test]
    fn local_builder_build_requires_the_documented_opt_in_value() {
        assert!(local_builder_build_opted_in(Some(OsStr::new("1"))));
        assert!(!local_builder_build_opted_in(None));
        assert!(!local_builder_build_opted_in(Some(OsStr::new("0"))));
        assert!(!local_builder_build_opted_in(Some(OsStr::new("true"))));
    }

    #[test]
    fn default_fetches_when_not_allowed() {
        let got = decide_builder_image_acquisition(false, None, true).unwrap();
        assert_eq!(got, BootImageAcquisition::Fetch);
    }

    #[test]
    fn allows_build_when_opted_in_and_checkout_present() {
        let got = decide_builder_image_acquisition(true, None, true).unwrap();
        assert_eq!(got, BootImageAcquisition::Build);
    }

    #[test]
    fn env_override_fetch_wins() {
        let got = decide_builder_image_acquisition(false, Some(BootImageAcquisition::Fetch), true)
            .unwrap();
        assert_eq!(got, BootImageAcquisition::Fetch);
        let got2 = decide_builder_image_acquisition(true, Some(BootImageAcquisition::Fetch), true)
            .unwrap();
        assert_eq!(got2, BootImageAcquisition::Fetch);
    }

    #[test]
    fn env_override_build_requires_allow_and_checkout() {
        // Not allowed -> refused
        let err = decide_builder_image_acquisition(false, Some(BootImageAcquisition::Build), true)
            .unwrap_err();
        assert!(err.to_string().contains("the builder VM image"));

        // Allowed but no checkout -> refused
        let err2 = decide_builder_image_acquisition(true, Some(BootImageAcquisition::Build), false)
            .unwrap_err();
        assert!(err2.to_string().contains("the builder VM image"));

        // Allowed and checkout present -> build
        let ok = decide_builder_image_acquisition(true, Some(BootImageAcquisition::Build), true)
            .unwrap();
        assert_eq!(ok, BootImageAcquisition::Build);
    }
}
