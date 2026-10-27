//! `mvmctl backend add <name>` — fetch this install's own release archive,
//! verify it (checksum manifest + release-workflow signature, nothing
//! skippable), and place the backend's component files from it. A component
//! is a path set inside the already-signed archive, so every byte placed is
//! covered by the same trust root as the first install. Idempotent: a fully
//! staged backend is reported, not re-fetched.

use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use mvm_vmm::host::shell::run_host;

use super::layout::{ManagedInstall, managed_install};
use crate::host_binaries::backend_components::{
    BackendComponentSet, ComponentKind, component_files_present, live_host, not_available_reason,
    row_for_name, viable_for,
};
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// The backend to add, by its stable label (e.g. `libkrun`)
    pub name: String,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let row = row_for_name(&args.name).with_context(|| {
        format!(
            "unknown backend {:?} — known backends: {}",
            args.name,
            known_names()
        )
    })?;
    let host = live_host().context("this build has no release archive target")?;
    if let Some(reason) = not_available_reason(row, &host) {
        bail!(
            "backend {} is not supported on this host: {reason}. Valid here: {}",
            row.backend.as_str(),
            valid_here(&host)
        );
    }
    if row.files.is_empty() {
        println!(
            "{} ships no host components; nothing to install.",
            row.backend.as_str()
        );
        return Ok(());
    }
    if !viable_for(&host)
        .iter()
        .any(|viable| viable.backend == row.backend)
    {
        bail!(
            "backend {} is not offered on this host. Valid here: {}",
            row.backend.as_str(),
            valid_here(&host)
        );
    }

    let install = managed_install()?;
    if component_files_present(row, std::slice::from_ref(&install.release_dir)) {
        println!(
            "{} is already installed ({}).",
            row.backend.as_str(),
            install.release_dir.display()
        );
        return Ok(());
    }

    let extracted = fetch_verified_release(&install, host.target)?;
    let archive_root = extracted.path().join(format!("mvmctl-{}", host.target));
    for file in row.files {
        let source = archive_root.join(file.path);
        if !source.exists() {
            bail!(
                "the verified {} archive does not carry {}; the release is incomplete",
                install.tag,
                file.path
            );
        }
    }

    let sudo = !crate::update::is_writable(&install.release_dir);
    if sudo {
        ui::warn("the install directory needs elevated permissions; using sudo");
    }
    for file in row.files {
        place(
            &archive_root.join(file.path),
            &install.release_dir.join(file.path),
            file.kind,
            sudo,
        )
        .with_context(|| format!("placing {}", file.path))?;
    }
    for file in row
        .files
        .iter()
        .filter(|file| file.kind == ComponentKind::Binary)
    {
        link_into_install_dir(&install, file.path, sudo)
            .with_context(|| format!("linking {}", file.path))?;
    }
    sign_placed_binaries(row, &install)?;

    println!(
        "Installed backend component: {} (from the verified {} archive).",
        row.backend.as_str(),
        install.tag
    );
    mvm_core::audit_emit!(
        ConfigChange,
        "verb=backend.add backend={} release={}",
        row.backend.as_str(),
        install.tag
    );
    Ok(())
}

fn known_names() -> String {
    crate::host_binaries::backend_components::component_table()
        .iter()
        .map(|row| row.backend.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn valid_here(host: &crate::host_binaries::backend_components::HostFacts) -> String {
    let names: Vec<_> = viable_for(host)
        .iter()
        .map(|row| row.backend.as_str())
        .collect();
    if names.is_empty() {
        "none — no backend supports this host".to_string()
    } else {
        names.join(", ")
    }
}

/// Download, checksum-verify and signature-verify this install's own release
/// archive, then extract it under a temporary directory kept alive for the
/// caller. The same in-process verifier and the same tag as the install; no
/// skip hatch.
fn fetch_verified_release(
    install: &ManagedInstall,
    target: &'static str,
) -> Result<tempfile::TempDir> {
    let tmp = tempfile::tempdir().context("failed to create a temporary directory")?;
    crate::update::download_release(&install.tag, target, tmp.path())
        .with_context(|| format!("downloading the {} release archive", install.tag))?;
    let archive_name = format!("mvmctl-{target}.tar.gz");
    let archive_path = tmp.path().join(&archive_name);
    crate::update::verify_checksum(&install.tag, &archive_name, &archive_path)?;
    crate::update::verify_signature(&install.tag, &archive_name, &archive_path)?;
    let output = run_host(
        "tar",
        &[
            "xzf",
            archive_path.to_str().context("archive path is not UTF-8")?,
            "-C",
            tmp.path().to_str().context("temp dir is not UTF-8")?,
        ],
    )?;
    if !output.status.success() {
        bail!("failed to extract the verified archive");
    }
    Ok(tmp)
}

/// Place one component file or directory at its path in the release
/// directory, replacing what the path held.
fn place(source: &Path, destination: &Path, kind: ComponentKind, sudo: bool) -> Result<()> {
    if sudo {
        let run = |args: &[&str]| -> Result<()> {
            let output = run_host("sudo", args)?;
            if !output.status.success() {
                bail!("sudo {:?} failed", args);
            }
            Ok(())
        };
        run(&[
            "rm",
            "-rf",
            destination.to_str().context("destination is not UTF-8")?,
        ])?;
        run(&[
            "cp",
            "-R",
            source.to_str().context("source is not UTF-8")?,
            destination.to_str().context("destination is not UTF-8")?,
        ])?;
        return Ok(());
    }
    match kind {
        ComponentKind::Directory => {
            if destination.exists() {
                std::fs::remove_dir_all(destination)
                    .with_context(|| format!("removing {}", destination.display()))?;
            }
            crate::update::copy_dir_recursive(source, destination)?;
        }
        ComponentKind::Binary | ComponentKind::Data => {
            std::fs::copy(source, destination).with_context(|| {
                format!("copying {} to {}", source.display(), destination.display())
            })?;
            if kind == ComponentKind::Binary {
                set_executable(destination)?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod +x {}", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Link a placed binary into the PATH directory through `current`, the way
/// install.sh's `link_release` does: staged link, then a single rename.
#[cfg(unix)]
fn link_into_install_dir(install: &ManagedInstall, name: &str, sudo: bool) -> Result<()> {
    let target = install.lib_dir.join("current").join(name);
    let link = install.install_dir.join(name);
    let staged = install.install_dir.join(format!("{name}.mvm-backend-new"));
    let link_existing = std::fs::symlink_metadata(&link).is_ok();
    if link_existing {
        let points_here = std::fs::read_link(&link).is_ok_and(|existing| existing == target);
        if points_here {
            return Ok(());
        }
        if !link.is_symlink() {
            bail!(
                "refusing to replace {}: install.sh did not create it. Move it aside and re-run.",
                link.display()
            );
        }
    }
    if sudo {
        let run = |args: &[&str]| -> Result<()> {
            let output = run_host("sudo", args)?;
            if !output.status.success() {
                bail!("sudo {:?} failed", args);
            }
            Ok(())
        };
        run(&[
            "rm",
            "-f",
            staged.to_str().context("staged link path is not UTF-8")?,
        ])?;
        run(&[
            "ln",
            "-s",
            target.to_str().context("link target is not UTF-8")?,
            staged.to_str().context("staged link path is not UTF-8")?,
        ])?;
        // `mv` follows a destination that is a link to a directory, so the
        // no-follow flag is required: `-T` on GNU and BusyBox, `-h` on BSD
        // and macOS (same dance as install.sh's replace_link).
        let staged_s = staged.to_str().context("staged link path is not UTF-8")?;
        let link_s = link.to_str().context("link path is not UTF-8")?;
        if run_host("sudo", &["mv", "-T", "-f", staged_s, link_s])
            .map(|output| output.status.success())
            .unwrap_or(false)
            || run_host("sudo", &["mv", "-h", "-f", staged_s, link_s])
                .map(|output| output.status.success())
                .unwrap_or(false)
        {
            return Ok(());
        }
        run(&["rm", "-f", staged_s])?;
        bail!("could not link {}", link.display());
    }
    std::os::unix::fs::symlink(&target, &staged)
        .with_context(|| format!("creating {}", staged.display()))?;
    if let Err(error) = std::fs::rename(&staged, &link) {
        let _ = std::fs::remove_file(&staged);
        return Err(error).with_context(|| format!("renaming onto {}", link.display()));
    }
    Ok(())
}

/// install.sh installs exist only on unix; a component link cannot be made
/// anywhere else.
#[cfg(not(unix))]
fn link_into_install_dir(_install: &ManagedInstall, name: &str, _sudo: bool) -> Result<()> {
    bail!("backend component {name} cannot be linked on this platform")
}

/// macOS: a placed supervisor must carry its hypervisor entitlement before
/// the first launch, exactly as install.sh's signing step guarantees at
/// install time. A released supervisor already carries it and is left alone.
#[cfg(target_os = "macos")]
fn sign_placed_binaries(row: &BackendComponentSet, install: &ManagedInstall) -> Result<()> {
    let targets: Vec<_> = row
        .files
        .iter()
        .filter(|file| file.kind == ComponentKind::Binary)
        .map(|file| mvm_vmm::host::codesign::SignTarget {
            path: install.release_dir.join(file.path),
            required: mvm_vmm::host::codesign::RequiredEntitlement::Hypervisor,
        })
        .collect();
    if targets.is_empty() {
        return Ok(());
    }
    let mut problems = Vec::new();
    for report in mvm_vmm::host::codesign::sign_targets(&targets) {
        if let Some(error) = report.error {
            problems.push(format!("{}: {error}", report.path.display()));
        }
    }
    if !problems.is_empty() {
        bail!("codesign failed: {}", problems.join("; "));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn sign_placed_binaries(_row: &BackendComponentSet, _install: &ManagedInstall) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_binaries::backend_components::row_for;
    use mvm_core::vm_backend::BackendKind;

    fn fake_install() -> (tempfile::TempDir, ManagedInstall) {
        let root = tempfile::tempdir().unwrap();
        let lib = root.path().join("lib");
        let release = lib.join("1-v9.9.9");
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(&release, lib.join("current")).unwrap();
        (
            root,
            ManagedInstall {
                release_dir: release,
                lib_dir: lib,
                install_dir: bin,
                tag: "v9.9.9".to_string(),
            },
        )
    }

    #[test]
    fn place_copies_files_and_directories_and_replaces_them() {
        let (_root, install) = fake_install();
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("lib");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("nested/libkrunfw.5.dylib"), b"v1").unwrap();

        let destination = install.release_dir.join("lib");
        place(&source, &destination, ComponentKind::Directory, false).unwrap();
        assert_eq!(
            std::fs::read(destination.join("nested/libkrunfw.5.dylib")).unwrap(),
            b"v1"
        );

        // Re-placement replaces rather than merges: a file the new set drops
        // must not linger.
        std::fs::write(destination.join("stale.dylib"), b"old").unwrap();
        place(&source, &destination, ComponentKind::Directory, false).unwrap();
        assert!(!destination.join("stale.dylib").exists());
    }

    #[test]
    fn a_component_binary_lands_executable() {
        let (_root, install) = fake_install();
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("mvm-libkrun-supervisor");
        std::fs::write(&source, b"#!/bin/sh\n").unwrap();

        let destination = install.release_dir.join("mvm-libkrun-supervisor");
        place(&source, &destination, ComponentKind::Binary, false).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0o111
            );
        }
    }

    #[test]
    fn link_into_install_dir_points_through_current_and_is_idempotent() {
        let (_root, install) = fake_install();
        link_into_install_dir(&install, "mvm-libkrun-supervisor", false).unwrap();
        let link = install.install_dir.join("mvm-libkrun-supervisor");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            install.lib_dir.join("current/mvm-libkrun-supervisor")
        );
        // A second run recognises its own link.
        link_into_install_dir(&install, "mvm-libkrun-supervisor", false).unwrap();
    }

    #[test]
    fn link_into_install_dir_refuses_a_file_it_did_not_make() {
        let (_root, install) = fake_install();
        let link = install.install_dir.join("mvm-libkrun-supervisor");
        std::fs::write(&link, b"someone else's binary").unwrap();
        let error = link_into_install_dir(&install, "mvm-libkrun-supervisor", false)
            .expect_err("a regular file in the way is refused");
        assert!(format!("{error:#}").contains("did not create"), "{error:#}");
        assert_eq!(std::fs::read(&link).unwrap(), b"someone else's binary");
    }

    #[test]
    fn link_into_install_dir_replaces_a_stale_symlink() {
        let (_root, install) = fake_install();
        let link = install.install_dir.join("mvm-libkrun-supervisor");
        std::os::unix::fs::symlink(
            install.lib_dir.join("0-v0.0.0/mvm-libkrun-supervisor"),
            &link,
        )
        .unwrap();
        link_into_install_dir(&install, "mvm-libkrun-supervisor", false).unwrap();
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            install.lib_dir.join("current/mvm-libkrun-supervisor")
        );
        // No staging link left behind.
        assert!(
            !install
                .install_dir
                .join("mvm-libkrun-supervisor.mvm-backend-new")
                .exists()
        );
    }

    /// The no-op answers hold before any install-layout question: they are
    /// what a hermetic host (no install.sh layout) can always rely on.
    #[test]
    fn componentless_backends_have_nothing_to_add() {
        assert!(row_for(BackendKind::Wasm).files.is_empty());
        assert!(row_for(BackendKind::Qemu).files.is_empty());
        assert!(row_for(BackendKind::Firecracker).files.is_empty());
        assert!(!row_for(BackendKind::Libkrun).files.is_empty());
    }
}
