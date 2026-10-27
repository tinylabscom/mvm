//! `mvmctl backend remove <name>` — remove the component files the table
//! lists for a backend. State directories, caches, audit logs and any VM
//! created with the backend stay behind; the command says so and names them.
//! The host's install-time default is refused while no other viable backend
//! could take over.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use super::layout::managed_install;
use crate::host_binaries::backend_components::{
    ComponentKind, component_files_present, detect_install_default_for, live_host, row_for_name,
    viable_for,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// The backend to remove, by its stable label (e.g. `libkrun`)
    pub name: String,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let row = row_for_name(&args.name).with_context(|| {
        format!(
            "unknown backend {:?} — known backends: {}",
            args.name,
            crate::host_binaries::backend_components::component_table()
                .iter()
                .map(|row| row.backend.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let name = row.backend.as_str();
    if row.files.is_empty() {
        println!(
            "{name} ships no host components; nothing to remove. It stays selectable with \
             `--hypervisor {name}`."
        );
        return Ok(());
    }
    let install = managed_install()?;
    if !component_files_present(row, std::slice::from_ref(&install.release_dir)) {
        println!("{name} is not installed; nothing to remove.");
        return Ok(());
    }

    let host = live_host().context("this build has no release archive target")?;
    if detect_install_default_for(&host) == Some(row.backend) {
        let successor = viable_for(&host).iter().any(|other| {
            other.backend != row.backend
                && (other.files.is_empty()
                    || component_files_present(other, std::slice::from_ref(&install.release_dir)))
        });
        if let Some(refusal) = removal_refusal(name, successor) {
            bail!("{refusal}");
        }
    }

    for file in row.files {
        remove_path(&install.release_dir.join(file.path), file.kind)
            .with_context(|| format!("removing {}", file.path))?;
    }
    for file in row
        .files
        .iter()
        .filter(|file| file.kind == ComponentKind::Binary)
    {
        remove_install_link(&install, file.path)?;
    }

    let state = mvm_core::config::mvm_home();
    println!("Removed backend component: {name}.");
    println!("State, caches, the audit log and any VM created with {name} remain under {state}.");
    mvm_core::audit_emit!(ConfigChange, "verb=backend.remove backend={name}");
    Ok(())
}

/// The refusal for removing the host's install-time default: allowed only
/// when another viable backend is already usable (its files are staged, or it
/// has none). Pure so the policy is unit-testable.
fn removal_refusal(name: &str, successor_installed: bool) -> Option<String> {
    if successor_installed {
        return None;
    }
    Some(format!(
        "{name} is the default backend on this host and no other installed backend \
         can serve it — nothing removed. Install another first with \
         `mvmctl backend add <name>`."
    ))
}

/// Delete one component path: directories recursively, files directly.
/// Missing paths are already the end state.
fn remove_path(path: &std::path::Path, kind: ComponentKind) -> Result<()> {
    match kind {
        ComponentKind::Directory => {
            if path.symlink_metadata().is_ok() {
                std::fs::remove_dir_all(path)
                    .with_context(|| format!("removing {}", path.display()))?;
            }
        }
        ComponentKind::Binary | ComponentKind::Data => {
            if path.symlink_metadata().is_ok() {
                std::fs::remove_file(path)
                    .with_context(|| format!("removing {}", path.display()))?;
            }
        }
    }
    Ok(())
}

/// Remove the PATH-directory link for a removed binary — but only when it is
/// the link install.sh's scheme made: a symlink pointing through `current`.
fn remove_install_link(install: &super::layout::ManagedInstall, name: &str) -> Result<()> {
    let link = install.install_dir.join(name);
    let expected = install.lib_dir.join("current").join(name);
    let Ok(existing) = std::fs::read_link(&link) else {
        return Ok(());
    };
    if existing == expected {
        std::fs::remove_file(&link).with_context(|| format!("removing {}", link.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::removal_refusal;

    #[test]
    fn removing_the_default_needs_an_installed_successor() {
        assert!(removal_refusal("hvf", false).is_some());
        assert!(removal_refusal("hvf", true).is_none());
    }

    #[test]
    fn the_refusal_names_the_backend_and_the_way_forward() {
        let refusal = removal_refusal("libkrun", false).expect("refused without a successor");
        assert!(refusal.contains("libkrun"), "{refusal}");
        assert!(refusal.contains("mvmctl backend add"), "{refusal}");
        assert!(refusal.contains("nothing removed"), "{refusal}");
    }
}
