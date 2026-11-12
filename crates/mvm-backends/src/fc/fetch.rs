//! Fetching the pinned Firecracker into the user's own cache.
//!
//! A source build, or a host that never installed a release archive, has no
//! Firecracker beside `mvmctl`. Bootstrap then downloads the release named by
//! `firecracker.lock` into `<mvm cache>/firecracker/<version>/`, which belongs
//! to the invoking user, so nothing here needs elevation. The tarball is held
//! to its pinned digest before anything is unpacked, and the extracted binary
//! to its pinned size and digest before it is moved into place.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use mvm_core::arch::GuestArch;
use mvm_core::crypto::verified_digest::sha256_file_verified;
use mvm_core::firecracker_lock::{FirecrackerArchPin, firecracker_lock};

const INSTALLED_NAME: &str = "firecracker";

/// Where a fetched Firecracker for the locked version lives.
pub fn cache_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("firecracker")
        .join(&firecracker_lock().version)
}

/// Download the locked release for this host and install its Firecracker into
/// [`cache_dir`]. Returns the installed path.
pub fn install_locked() -> Result<PathBuf> {
    let lock = firecracker_lock();
    let arch = GuestArch::host();
    install_pinned(&cache_dir(), lock.pin(arch), &lock.tarball_url(arch), &curl)
}

/// Resolve the Firecracker to launch, fetching the pinned release first when
/// none is shipped or cached. A host that never ran bootstrap, such as a source
/// build, then still boots its first guest. Only an absent binary triggers the
/// fetch: one that is present and wrong is an error, never replaced silently.
pub fn resolve_or_fetch() -> Result<super::binary::ResolvedFirecracker> {
    resolve_or_fetch_with(super::binary::resolve_for_host, || {
        eprintln!(
            "[mvm] No Firecracker ships with this mvmctl; fetching the pinned release (first use only)..."
        );
        install_locked().map(|_| ())
    })
}

fn resolve_or_fetch_with(
    resolve: impl Fn() -> Result<super::binary::ResolvedFirecracker, super::binary::ResolveError>,
    fetch: impl FnOnce() -> Result<()>,
) -> Result<super::binary::ResolvedFirecracker> {
    match resolve() {
        Ok(found) => Ok(found),
        Err(super::binary::ResolveError::NotFound { .. }) => {
            fetch()?;
            resolve().map_err(Into::into)
        }
        Err(other) => Err(other.into()),
    }
}

/// Fetch `url` into `dest` over HTTPS only.
fn curl(url: &str, dest: &Path) -> Result<()> {
    let status = mvm_core::env_hygiene::helper_command("curl")
        .args(["--fail", "--silent", "--show-error", "--location"])
        .args(["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2"])
        .arg("--output")
        .arg(dest)
        .arg(url)
        .status()
        .context("running curl")?;
    ensure!(status.success(), "downloading {url} failed ({status})");
    Ok(())
}

/// Verify and install one pinned release. `fetch` supplies the tarball so the
/// checks can be exercised without a network.
fn install_pinned(
    dest_dir: &Path,
    pin: &FirecrackerArchPin,
    url: &str,
    fetch: &dyn Fn(&str, &Path) -> Result<()>,
) -> Result<PathBuf> {
    mvm_core::config::create_private_dir(dest_dir)
        .with_context(|| format!("creating {}", dest_dir.display()))?;
    let scratch = tempfile::tempdir_in(dest_dir).context("creating a scratch directory")?;
    let tarball = scratch.path().join("release.tgz");
    fetch(url, &tarball)?;

    let found = sha256_file_verified(&tarball).context("hashing the downloaded tarball")?;
    if found != pin.tarball_sha256.as_str() {
        bail!(
            "the downloaded Firecracker tarball is {found}, but this release pins {}; refusing it",
            pin.tarball_sha256.as_str()
        );
    }

    let status = mvm_core::env_hygiene::helper_command("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(scratch.path())
        .arg(&pin.binary)
        .status()
        .context("running tar")?;
    ensure!(status.success(), "unpacking the Firecracker tarball failed");

    let extracted = scratch.path().join(&pin.binary);
    let meta = std::fs::symlink_metadata(&extracted)
        .with_context(|| format!("{} is not in the tarball", pin.binary))?;
    ensure!(meta.is_file(), "{} is not a regular file", pin.binary);
    ensure!(
        meta.len() == pin.binary_size,
        "the extracted Firecracker is {} bytes, but this release pins {}",
        meta.len(),
        pin.binary_size
    );
    let found = sha256_file_verified(&extracted).context("hashing the extracted binary")?;
    ensure!(
        found == pin.binary_sha256.as_str(),
        "the extracted Firecracker is {found}, but this release pins {}",
        pin.binary_sha256.as_str()
    );

    std::fs::set_permissions(&extracted, std::fs::Permissions::from_mode(0o755))?;
    let installed = dest_dir.join(INSTALLED_NAME);
    std::fs::rename(&extracted, &installed)
        .with_context(|| format!("installing {}", installed.display()))?;
    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::packs::Sha256Hex;

    const BINARY: &[u8] = b"\x7fELF stand-in firecracker\n";
    const MEMBER: &str = "release-v0/firecracker-v0-x86_64";

    /// A real `.tgz` holding `BINARY` at `MEMBER`, and the pin that names it.
    fn release(dir: &Path) -> (PathBuf, FirecrackerArchPin) {
        let root = dir.join("release-v0");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(dir.join(MEMBER), BINARY).unwrap();
        let tarball = dir.join("fixture.tgz");
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(dir)
            .arg(MEMBER)
            .status()
            .unwrap();
        assert!(status.success());
        let pin = FirecrackerArchPin {
            tarball: "fixture.tgz".into(),
            tarball_sha256: Sha256Hex::from_bytes(&std::fs::read(&tarball).unwrap()),
            binary: MEMBER.into(),
            binary_sha256: Sha256Hex::from_bytes(BINARY),
            binary_size: BINARY.len() as u64,
        };
        (tarball, pin)
    }

    fn copy_from(src: PathBuf) -> impl Fn(&str, &Path) -> Result<()> {
        move |_, dest| {
            std::fs::copy(&src, dest)?;
            Ok(())
        }
    }

    #[test]
    fn a_tarball_matching_its_pin_installs_an_executable_user_owned_binary() {
        let src = tempfile::tempdir().unwrap();
        let (tarball, pin) = release(src.path());
        let dest = tempfile::tempdir().unwrap();
        let dest_dir = dest.path().join("firecracker/v0");
        let path = install_pinned(&dest_dir, &pin, "https://x/y", &copy_from(tarball)).unwrap();
        assert_eq!(path, dest_dir.join("firecracker"));
        assert_eq!(std::fs::read(&path).unwrap(), BINARY);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        let leftovers: Vec<_> = std::fs::read_dir(&dest_dir).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "scratch space is removed");
    }

    #[test]
    fn a_tarball_that_misses_its_digest_is_refused_and_nothing_is_installed() {
        let src = tempfile::tempdir().unwrap();
        let (tarball, mut pin) = release(src.path());
        pin.tarball_sha256 = Sha256Hex::from_bytes(b"something else");
        let dest = tempfile::tempdir().unwrap();
        let err = install_pinned(dest.path(), &pin, "u", &copy_from(tarball)).unwrap_err();
        assert!(err.to_string().contains("refusing it"), "{err}");
        assert!(!dest.path().join("firecracker").exists());
    }

    #[test]
    fn a_binary_that_misses_its_digest_is_refused_even_inside_a_matching_tarball() {
        let src = tempfile::tempdir().unwrap();
        let (tarball, mut pin) = release(src.path());
        pin.binary_sha256 = Sha256Hex::from_bytes(b"another binary");
        let dest = tempfile::tempdir().unwrap();
        let err = install_pinned(dest.path(), &pin, "u", &copy_from(tarball)).unwrap_err();
        assert!(err.to_string().contains("pins"), "{err}");
        assert!(!dest.path().join("firecracker").exists());
    }

    mod first_use {
        use super::super::*;
        use crate::fc::binary::{FirecrackerOrigin, ResolveError, ResolvedFirecracker};
        use std::cell::Cell;

        fn found() -> ResolvedFirecracker {
            ResolvedFirecracker {
                path: "/c/firecracker".into(),
                origin: FirecrackerOrigin::Shipped,
            }
        }

        fn missing() -> ResolveError {
            ResolveError::NotFound { searched: vec![] }
        }

        #[test]
        fn a_present_binary_is_used_and_nothing_is_fetched() {
            let fetched = Cell::new(false);
            let got = resolve_or_fetch_with(
                || Ok(found()),
                || {
                    fetched.set(true);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(got, found());
            assert!(!fetched.get());
        }

        #[test]
        fn an_absent_binary_is_fetched_once_then_resolved() {
            let fetched = Cell::new(0);
            let resolved = Cell::new(0);
            let got = resolve_or_fetch_with(
                || {
                    resolved.set(resolved.get() + 1);
                    if resolved.get() == 1 {
                        Err(missing())
                    } else {
                        Ok(found())
                    }
                },
                || {
                    fetched.set(fetched.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(got, found());
            assert_eq!((fetched.get(), resolved.get()), (1, 2));
        }

        #[test]
        fn a_binary_that_is_present_and_wrong_is_never_replaced_by_a_fetch() {
            let fetched = Cell::new(false);
            let err = resolve_or_fetch_with(
                || {
                    Err(ResolveError::DigestMismatch {
                        path: "/c/firecracker".into(),
                        expected: "a".into(),
                        found: "b".into(),
                    })
                },
                || {
                    fetched.set(true);
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(!fetched.get());
            assert!(err.to_string().contains("pin"), "{err}");
        }

        #[test]
        fn a_failed_fetch_is_reported_and_not_retried() {
            let err =
                resolve_or_fetch_with(|| Err(missing()), || anyhow::bail!("offline")).unwrap_err();
            assert!(err.to_string().contains("offline"), "{err}");
        }
    }

    #[test]
    fn a_failed_download_installs_nothing() {
        let dest = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (_, pin) = release(src.path());
        let fetch = |_: &str, _: &Path| -> Result<()> { bail!("offline") };
        assert!(install_pinned(dest.path(), &pin, "u", &fetch).is_err());
        assert!(!dest.path().join("firecracker").exists());
    }
}
