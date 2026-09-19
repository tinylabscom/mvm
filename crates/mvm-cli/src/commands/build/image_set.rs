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
    /// The image role to build: builder-vm, default-tenant or runtime-overlay.
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
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, bail};
    use mvm_build::artifact_acquisition::compiled_channel;
    use mvm_build::image_source::{
        CacheLookup, CachedImageSet, EmitRequest, EntryContext, ImageBuildTarget, ImageSource,
        KeyInputs, LocalImageCache, LocalImageCacheKey, LocalImageCheckout, MVM_IMAGES_DIR_ENV,
        PublishOutcome, TargetContract, build_host_binaries, configured_images_dir, contract_for,
        emit_local_manifest, mvm_source_checkout, render_build_script, resolve_image_source,
        stage_work_tree,
    };
    use mvm_core::arch::GuestArch;

    use super::Args;
    use crate::commands::env::builder_vm::{ShellJobBuilder, bootstrap_builder_vm_image};
    use crate::ui;

    /// Everything one build is about.
    struct Pair {
        images: LocalImageCheckout,
        mvm_root: PathBuf,
        target: ImageBuildTarget,
        contract: &'static TargetContract,
        arch: GuestArch,
    }

    impl Pair {
        fn ctx(&self) -> EntryContext<'_> {
            EntryContext {
                images: &self.images,
                mvm_checkout: &self.mvm_root,
                roles: self.contract.set_roles,
            }
        }

        fn key(&self) -> Result<LocalImageCacheKey> {
            Ok(LocalImageCacheKey::derive(&KeyInputs {
                images: &self.images,
                mvm_checkout: &self.mvm_root,
                target: &self.target,
                arch: self.arch,
            })?)
        }
    }

    pub(super) fn run(args: Args) -> Result<()> {
        let target = ImageBuildTarget {
            role: args.role,
            attr: args.attr,
        };
        let pair = select_pair(target)?;
        let cache = LocalImageCache::open_default();
        let key = pair.key()?;
        match cache.lookup(&key, &pair.ctx())? {
            CacheLookup::Hit(entry) => {
                report(&pair, &entry, "already built from these checkouts");
                return Ok(());
            }
            CacheLookup::Evicted { reason } => {
                ui::warn(&format!(
                    "evicted a cached {} that failed verification: {reason}",
                    pair.target
                ));
            }
            CacheLookup::Miss => {}
        }
        let builder = shell_job_builder()?;
        let outcome = build_and_publish(&pair, &cache, &key, builder)?;
        let note = match &outcome {
            PublishOutcome::Published(_) => "built and published",
            PublishOutcome::AlreadyPresent(_) => "built; a concurrent build published it first",
        };
        report(&pair, outcome.entry(), note);
        Ok(())
    }

    /// The selected image checkout, the mvm checkout this binary was built
    /// from, and what building `target` produces.
    fn select_pair(target: ImageBuildTarget) -> Result<Pair> {
        let channel = compiled_channel();
        let configured = configured_images_dir().with_context(|| {
            format!(
                "{MVM_IMAGES_DIR_ENV} is not set; name the mvm-images checkout to build from \
                 (for example `MVM_IMAGES_DIR=../mvm-images bin/dev build image-set {}`)",
                target.role
            )
        })?;
        let ImageSource::LocalCheckout(images) = resolve_image_source(channel, Some(&configured))?
        else {
            bail!("{MVM_IMAGES_DIR_ENV} did not select a local image checkout");
        };
        let mvm_root = mvm_source_checkout(channel).context(
            "a local image set is built against the mvm checkout this binary was compiled \
             from, and that checkout is no longer on disk",
        )?;
        let contract = contract_for(&target)?;
        Ok(Pair {
            images,
            mvm_root,
            target,
            contract,
            arch: GuestArch::host(),
        })
    }

    /// Only a builder that runs shell jobs in its own image can build a local
    /// image set; any other is refused by name.
    fn shell_job_builder() -> Result<ShellJobBuilder> {
        let choice = mvm_build::builder_backend_select::resolve_choice();
        ShellJobBuilder::for_choice(choice).with_context(|| {
            format!(
                "the {choice:?} builder has no shell-job path to build a local image set on; \
                 select `--builder hvf` or `--builder firecracker`"
            )
        })
    }

    fn build_and_publish(
        pair: &Pair,
        cache: &LocalImageCache,
        key: &LocalImageCacheKey,
        builder: ShellJobBuilder,
    ) -> Result<PublishOutcome> {
        bootstrap_builder_vm_image()
            .with_context(|| format!("preparing the {} builder image", builder.name()))?;
        let host_bins = if pair.contract.needs_host_binaries {
            ui::info("Building the builder's host binaries from the mvm checkout...");
            Some(build_host_binaries(
                pair.images.root(),
                &pair.mvm_root,
                pair.arch,
            )?)
        } else {
            None
        };

        let scratch = scratch_dir()?;
        let work = scratch.path().join("work");
        let out = scratch.path().join("out");
        std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
        stage_work_tree(
            pair.images.root(),
            &pair.mvm_root,
            host_bins.as_deref(),
            &work,
        )?;
        // The staged copies must be of the trees the key names; an edit while
        // they were being copied would publish one tree's bytes under another's
        // identity.
        if &pair.key()? != key {
            bail!("a checkout changed while it was being staged for the build; run it again");
        }

        ui::info(&format!(
            "Building {} for {} in the {} builder from {}...",
            pair.target,
            pair.arch,
            builder.name(),
            pair.images.root().display()
        ));
        builder.run(&mvm_build::libkrun_builder::BuilderShellJob {
            work_dir: work,
            artifact_out: out.clone(),
            script: render_build_script(&pair.target, pair.arch, pair.contract),
            extra_disks: Vec::new(),
        })?;

        let staged = cache.stage(key)?;
        emit_local_manifest(&EmitRequest {
            images_root: pair.images.root(),
            mvm_root: &pair.mvm_root,
            arch: pair.arch,
            builder_cache_contract: mvm_build::libkrun_builder::BUILDER_VM_CACHE_CONTRACT_VERSION,
            built: &out,
            out: staged.dir(),
            contract: pair.contract,
        })?;
        Ok(cache.publish(staged, &pair.ctx())?)
    }

    /// Mutable scratch for one build, removed when the build returns. It sits
    /// in the mvm cache rather than inside either checkout, whose identity it
    /// would otherwise change.
    fn scratch_dir() -> Result<tempfile::TempDir> {
        let parent = Path::new(&mvm_core::config::mvm_cache_dir()).join("local-image-builds");
        std::fs::create_dir_all(&parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        tempfile::Builder::new()
            .prefix("build-")
            .tempdir_in(&parent)
            .with_context(|| format!("creating a build directory in {}", parent.display()))
    }

    fn report(pair: &Pair, entry: &CachedImageSet, note: &str) {
        ui::success(&format!(
            "{} for {} ({}): {note}",
            pair.target,
            pair.arch,
            entry.tier()
        ));
        ui::info(&format!("  entry:  {}", entry.dir.display()));
        ui::info(&format!("  images: {}", entry.key.checkouts.images));
        ui::info(&format!("  mvm:    {}", entry.key.checkouts.mvm));
        for artifact in &entry.set.artifacts {
            ui::info(&format!("  {} {}", artifact.role, artifact.path.display()));
        }
    }
}
