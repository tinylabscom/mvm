//! `mvmctl dev image-set <role>` — build one target of the image checkout
//! named by `MVM_IMAGES_DIR` inside the builder VM, against the mvm checkout
//! this binary was compiled from, and publish it to the local image cache.
//!
//! It lives under `dev` beside `kernel`, which builds a member of the same
//! image set; `image` acquires and manages images and builds none. The runtime
//! overlay and SDK sidecars are not image-set members: `dev runtime-overlay`
//! and `dev sdk-sidecar` assemble them from a guest runtime.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_build::image_source::{FlakeAttr, ImageBuildRole};
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// The image role to build: builder-vm, default-tenant or rootless-tenant.
    #[arg(value_parser = parse_role)]
    role: ImageBuildRole,

    /// The flake attribute under the role (`dev` selects the writable
    /// default-tenant image).
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
    build::run(args)
}

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
                 (for example `MVM_IMAGES_DIR=../mvm-images bin/dev dev image-set {}`)",
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
        ui::info(&format!("  images: {}", entry.key.images));
        ui::info(&format!("  mvm:    {}", entry.key.mvm));
        if let mvm_build::image_source::MvmSourceIdentity::ConsumedInputs(_) = entry.key.mvm
            && let Some(mvm) = &entry.set.checkouts.mvm
        {
            ui::info(&format!("          built at {mvm}"));
        }
        for artifact in &entry.set.artifacts {
            ui::info(&format!("  {} {}", artifact.role, artifact.path.display()));
        }
    }
}
