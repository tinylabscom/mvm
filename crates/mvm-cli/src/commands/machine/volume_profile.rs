//! Which `--mount`/`--volume` specs a persistent machine accepts under its
//! profile.

use anyhow::{Result, anyhow, bail};

use super::RunProfile;
use crate::commands::shared::{VolumeSpec, parse_volume_spec};

/// Why a persistent machine refuses a host-directory volume.
///
/// There is no live host-directory share on a persistent machine: a directory
/// reaches a guest only as an ext4 snapshot, and a persistent machine takes
/// one only when it is registered with `machine volume mount`. The spec-time
/// gate and the boot-time check both word their refusal here, so what
/// `machine create` says and what `machine start` says cannot drift.
///
/// The registration command needs an absolute `--host`, so a relative
/// directory is rendered absolute against the working directory it was named
/// from.
pub(super) fn persistent_dir_share_refusal(host_dir: &str, guest_mount: &str) -> String {
    let host = std::path::absolute(host_dir)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| host_dir.to_string());
    format!(
        "persistent machine volume '{host_dir}' -> '{guest_mount}' cannot be attached: a \
         persistent machine cannot attach a live host directory. Use a disk image \
         (`HOST.img:/GUEST:SIZE[:rw]`), or snapshot the directory and register it with \
         `mvmctl machine volume mount <machine> --volume <name> --host {host} \
         --guest {guest_mount} [--rw]`"
    )
}

/// Refuse any volume a persistent machine cannot take under `profile`.
/// `machine run` (persistent), `machine create`, and `machine start` all call
/// this, so every entry point accepts exactly the same specs.
///
/// A host directory is refused under every profile, read-only included: a
/// persistent machine has no live host-directory share, so accepting one here
/// would only move the failure to boot. A disk image
/// (`HOST.img:/GUEST:SIZE:rw`) is the guest's own ext4 file, so any profile
/// that accepts volumes accepts it writable. Where in the guest a disk may
/// mount is the guest mount allow-list's decision, not this one's: it is
/// checked separately for every spec.
pub(super) fn enforce_volume_profile(profile: RunProfile, raw_specs: &[String]) -> Result<()> {
    let grants = profile.grants();
    let name = profile.as_str();
    if !grants.host_shares && !raw_specs.is_empty() {
        bail!("--profile {name} does not allow volumes (--mount/--volume)");
    }
    for raw in raw_specs {
        match parse_volume_spec(raw)? {
            VolumeSpec::DirShare {
                host_dir,
                guest_mount,
                ..
            } => bail!(persistent_dir_share_refusal(&host_dir, &guest_mount)),
            VolumeSpec::Disk {
                read_only: false, ..
            } if !grants.writable_disk_images => bail!(
                "volume {raw:?} requests a writable disk image, which --profile {name} does not grant"
            ),
            VolumeSpec::Disk { .. } => {}
        }
    }
    Ok(())
}

/// [`enforce_volume_profile`] for a stored spec, which carries its profile by
/// name.
///
/// A spec saved before the gate existed, or edited by hand, reaches
/// `machine start` without having passed it. An unrecognised profile name
/// refuses rather than being matched against whichever preset a string
/// comparison happened to miss.
pub(super) fn enforce_persisted_volume_profile(profile: &str, raw_specs: &[String]) -> Result<()> {
    if raw_specs.is_empty() {
        return Ok(());
    }
    let parsed = RunProfile::from_name(profile)
        .ok_or_else(|| anyhow!("machine spec carries an unrecognised profile {profile:?}"))?;
    enforce_volume_profile(parsed, raw_specs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A persistent machine refuses a host directory under every profile that
    /// accepts volumes, read-only and writable alike, and the refusal names
    /// both ways to get data in: a disk image and a registered snapshot.
    #[test]
    fn a_host_directory_is_refused_under_every_profile() {
        for profile in RunProfile::ALL
            .into_iter()
            .filter(|p| p.grants().host_shares)
        {
            for spec in ["/h/src:/work", "/h/src:/work:ro", "/h/src:/work:rw"] {
                let message = enforce_volume_profile(profile, &[spec.to_string()])
                    .expect_err("a persistent machine takes no host directory")
                    .to_string();
                let name = profile.as_str();
                assert!(
                    message.contains("cannot attach a live host directory"),
                    "{name} {spec}: {message}"
                );
                assert!(
                    message.contains("`HOST.img:/GUEST:SIZE[:rw]`"),
                    "{name} {spec}: {message}"
                );
                assert!(
                    message.contains(
                        "mvmctl machine volume mount <machine> --volume <name> --host /h/src \
                         --guest /work"
                    ),
                    "{name} {spec}: {message}"
                );
            }
        }
    }

    /// Restrictive refuses before looking at the shape, so its message is
    /// about the profile, not the directory.
    #[test]
    fn restrictive_refuses_a_directory_as_a_volume_first() {
        let message = enforce_volume_profile(RunProfile::Restrictive, &["/h:/work".to_string()])
            .expect_err("restrictive takes no volume")
            .to_string();
        assert!(message.contains("does not allow volumes"), "{message}");
    }

    /// The registration command needs an absolute `--host`; a relative
    /// directory in the spec is rendered absolute in the suggestion.
    #[test]
    fn the_refusal_suggests_an_absolute_host_directory() {
        let message = persistent_dir_share_refusal("./src", "/work");
        assert!(message.contains("'./src' -> '/work'"), "{message}");
        let host = message
            .split_once("--host ")
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .expect("the suggestion names a --host");
        assert!(std::path::Path::new(host).is_absolute(), "{message}");
        assert!(host.ends_with("src"), "{message}");
    }

    #[test]
    fn a_disk_image_is_accepted_writable_under_standard() {
        enforce_volume_profile(
            RunProfile::Standard,
            &["/h/state.img:/data:20G:rw".to_string()],
        )
        .expect("standard grants a writable disk image");
    }

    /// A stored spec is checked by its profile name, and a name nobody
    /// recognises refuses rather than defaulting.
    #[test]
    fn a_persisted_spec_is_checked_by_profile_name() {
        let dir = vec!["/h/src:/work:ro".to_string()];
        let message = enforce_persisted_volume_profile("dev", &dir)
            .expect_err("a stored directory share refuses at start")
            .to_string();
        assert!(
            message.contains("cannot attach a live host directory"),
            "{message}"
        );
        let disk = vec!["/h/state.img:/data:1G:rw".to_string()];
        enforce_persisted_volume_profile("standard", &disk).expect("standard takes a disk");
        let message = enforce_persisted_volume_profile("restrictive", &disk)
            .expect_err("a stored restrictive spec with a volume refuses")
            .to_string();
        assert!(message.contains("does not allow volumes"), "{message}");
        let message = enforce_persisted_volume_profile("dev-mode", &disk)
            .expect_err("an unknown profile refuses")
            .to_string();
        assert!(message.contains("unrecognised profile"), "{message}");
        enforce_persisted_volume_profile("dev-mode", &[])
            .expect("a spec with no volume has nothing to check");
    }
}
