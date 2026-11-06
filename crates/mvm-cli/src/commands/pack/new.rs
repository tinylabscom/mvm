//! Create an unpublished policy-pack source for a reviewed registry pull request.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use mvm_core::registry_pack::PackReference;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Pack coordinate to draft (no version)
    #[arg(value_name = "namespace/name")]
    pub reference: PackReference,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let root = std::env::current_dir().context("resolving current directory")?;
    let source = create(&root, &args.reference)?;
    println!("Draft created in {}", source.display());
    println!("Edit the policy and README, then open a reviewed pull request to publish it.");
    Ok(())
}

fn create(root: &Path, reference: &PackReference) -> Result<PathBuf> {
    let namespace = reference.namespace();
    let name = reference.name();
    if reference.version().is_some() {
        bail!("use namespace/name without a version; the draft starts at 0.1.0");
    }
    // The registry's publishing identity is trusted by default for these namespaces, so a
    // submitted pack must not land in them (mvm-packs #103).
    if matches!(namespace, "mvm" | "agent" | "runtime") {
        bail!("{namespace} is reserved for first-party packs; choose another namespace");
    }
    let valid = |part: &str| {
        part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    if !valid(namespace) || !valid(name) {
        bail!("namespace and name must start with a lowercase letter and contain only a-z, 0-9, -");
    }

    let sources = root.join("pack-sources");
    if !sources.is_dir() || sources.is_symlink() {
        bail!(
            "run this command from the pack registry checkout (pack-sources/ must be a directory)"
        );
    }
    let parent = sources.join(namespace);
    if parent.is_symlink() {
        bail!("pack source paths must not be symlinks");
    }
    if !parent.exists() {
        fs::create_dir(&parent)
            .with_context(|| format!("creating namespace directory {}", parent.display()))?;
    } else if !parent.is_dir() {
        bail!("namespace path {} is not a directory", parent.display());
    }

    let source = parent.join(name);
    fs::create_dir(&source).with_context(|| {
        format!(
            "creating {} (refusing to overwrite an existing pack)",
            source.display()
        )
    })?;
    fs::create_dir(source.join("pack"))
        .with_context(|| format!("creating payload directory in {}", source.display()))?;
    fs::write(
        source.join("pack.toml"),
        "version = \"0.1.0\"\ndescription = \"Describe what this policy permits.\"\n",
    )
    .with_context(|| format!("writing pack.toml in {}", source.display()))?;
    fs::write(
        source.join("pack/group.toml"),
        "description = \"Describe what this policy permits.\"\nrequired = false\n\n\
         [network]\nallow = []\n",
    )
    .with_context(|| format!("writing group.toml in {}", source.display()))?;
    fs::write(
        source.join("pack/README.md"),
        format!(
            "## Purpose\n\nDescribe when to use `{namespace}/{name}`.\n\n\
             ## Setup\n\nDescribe any credentials an operator may choose to configure; never include values.\n\n\
             ## Use\n\nDescribe a real use case. This policy pack is not a runnable image.\n"
        ),
    )
    .with_context(|| format!("writing README.md in {}", source.display()))?;
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(value: &str) -> PackReference {
        value.parse().expect("valid reference")
    }

    #[test]
    fn creates_unprivileged_draft_and_refuses_overwrite() {
        let root = tempfile::tempdir().expect("temp directory");
        fs::create_dir(root.path().join("pack-sources")).expect("source root");
        let source = create(root.path(), &reference("acme/example")).expect("create draft");
        assert!(
            fs::read_to_string(source.join("pack.toml"))
                .expect("pack metadata")
                .contains("version = \"0.1.0\"")
        );
        assert!(
            fs::read_to_string(source.join("pack/group.toml"))
                .expect("group policy")
                .contains("allow = []")
        );
        assert!(
            fs::read_to_string(source.join("pack/README.md"))
                .expect("readme")
                .contains("never include values")
        );
        assert!(create(root.path(), &reference("acme/example")).is_err());
        assert!(create(root.path(), &reference("acme/example@1.0.0")).is_err());
        for reserved in ["mvm", "agent", "runtime"] {
            assert!(create(root.path(), &reference(&format!("{reserved}/example"))).is_err());
        }
    }

    #[test]
    fn refuses_non_registry_checkout_and_symlinked_namespace() {
        let root = tempfile::tempdir().expect("temp directory");
        assert!(create(root.path(), &reference("acme/example")).is_err());
        let sources = root.path().join("pack-sources");
        fs::create_dir(&sources).expect("source root");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.path(), sources.join("acme"))
                .expect("symlink namespace");
            assert!(create(root.path(), &reference("acme/example")).is_err());
            assert!(!root.path().join("pack").exists());
        }
    }
}
