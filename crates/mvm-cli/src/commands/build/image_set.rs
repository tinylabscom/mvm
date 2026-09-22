//! `mvmctl build image-set <role>` — build one target of the image checkout
//! named by `MVM_IMAGES_DIR` inside the builder VM, against the mvm checkout
//! this binary was compiled from, and publish it to the local image cache.
//!
//! It lives under `build` beside `kernel`, `runtime-overlay` and
//! `sdk-sidecar`, which build members of the same image set from the in-tree
//! flakes; `image` acquires and manages images and builds none.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_build::image_source::{FlakeAttr, ImageBuildRole};
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// The image role to build: builder-vm, default-tenant, rootless-tenant or runtime-overlay.
    #[arg(value_parser = parse_role)]
    role: ImageBuildRole,

    /// The flake attribute under the role (`sdk-sidecar-image` and
    /// `sdk-sidecar-image-musl` select the SDK sidecars under runtime-overlay).
    #[arg(long, default_value = "default", value_parser = parse_attr)]
    attr: FlakeAttr,
}

fn parse_role(value: &str) -> Result<ImageBuildRole, String> {
    value.parse()
}

fn parse_attr(value: &str) -> Result<FlakeAttr, String> {
    FlakeAttr::new(value)
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    #[cfg(feature = "builder-vm")]
    {
        build::run(args)
    }
    #[cfg(not(feature = "builder-vm"))]
    {
        let _ = args;
        anyhow::bail!(
            "building a local image set requires the `builder-vm` feature; rebuild the binary \
             with that feature enabled"
        )
    }
}

#[cfg(feature = "builder-vm")]
mod build {
    use anyhow::{Context, Result, bail};
    use mvm_build::artifact_acquisition::compiled_channel;
    use mvm_build::image_source::{
        ImageBuildTarget, ImageSource, MVM_IMAGES_DIR_ENV, PairBuild, configured_images_dir,
        resolve_image_source,
    };

    use super::Args;
    use crate::commands::env::builder_vm::ensure_pair_built;
    use crate::ui;

    pub(super) fn run(args: Args) -> Result<()> {
        let target = ImageBuildTarget {
            role: args.role,
            attr: args.attr,
        };
        let configured = configured_images_dir().with_context(|| {
            format!(
                "{MVM_IMAGES_DIR_ENV} is not set; name the mvm-images checkout to build from \
                 (for example `MVM_IMAGES_DIR=../mvm-images bin/dev build image-set {}`)",
                target.role
            )
        })?;
        let ImageSource::LocalCheckout(images) =
            resolve_image_source(compiled_channel(), Some(&configured))?
        else {
            bail!("{MVM_IMAGES_DIR_ENV} did not select a local image checkout");
        };
        let build = ensure_pair_built(&images, target)?;
        report(&build);
        Ok(())
    }

    fn report(build: &PairBuild) {
        let note = if build.built {
            "built and published"
        } else {
            "already built from these checkouts"
        };
        let entry = &build.entry;
        ui::success(&format!("{}: {note}", entry.key.target));
        ui::info(&format!("  entry:  {}", entry.dir.display()));
        ui::info(&format!("  images: {}", entry.key.checkouts.images));
        ui::info(&format!("  mvm:    {}", entry.key.checkouts.mvm));
        for artifact in &entry.set.artifacts {
            ui::info(&format!("  {} {}", artifact.role, artifact.path.display()));
        }
    }
}
