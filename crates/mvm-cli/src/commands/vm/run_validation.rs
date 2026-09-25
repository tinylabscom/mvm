//! What a run's flags refuse before anything is pulled or booted: the
//! profile's grants, and what `--prod` rules out.

use anyhow::Result;

use super::exec::{RunArgs, RunProfile};

/// What `--prod` rules out before anything is pulled or booted.
///
/// A production image is sealed and boots the production agent profile, which
/// serves no DevOnly verb. The dev profile would hand the guest those verbs.
/// An ad-hoc command after `--` is one (`Exec`), and so is a launch document,
/// which is dispatched the same way: the guest would refuse either only after
/// the pull and the boot.
fn validate_prod_run(args: &RunArgs) -> Result<()> {
    if !args.prod {
        return Ok(());
    }
    if matches!(args.profile, RunProfile::Dev) {
        anyhow::bail!(
            "--prod cannot be combined with --profile dev: a production run boots the sealed \
             image with the production agent profile, and the dev profile would grant it the \
             DevOnly verbs production withholds"
        );
    }
    if !args.argv.is_empty() || args.launch_plan.is_some() {
        anyhow::bail!(
            "--prod refuses an ad-hoc command: a sealed production image serves no DevOnly \
             verbs, and a command after `--` or a `--launch-plan` is dispatched as one. Omit \
             the command to run the OCI image's declared entrypoint"
        );
    }
    Ok(())
}

pub(super) fn validate_run_profile(args: &RunArgs) -> Result<()> {
    if let Some(reference) = args.image.as_deref() {
        super::super::image::ensure_prod_digest_pin(reference, args.prod)?;
    }
    let grants = args.profile.grants();
    let name = args.profile.as_str();

    if grants.needs_acknowledgement && std::env::var_os("MVM_ACK_PERMISSIVE_RUN").is_none() {
        anyhow::bail!(
            "--profile permissive requires MVM_ACK_PERMISSIVE_RUN=1 so broad local execution is explicit"
        );
    }

    validate_prod_run(args)?;

    if !grants.env && !args.env.is_empty() {
        anyhow::bail!("--profile {name} does not allow --env");
    }
    if !grants.host_shares && !(args.mounts.is_empty() && args.outputs.is_empty()) {
        anyhow::bail!("--profile {name} does not allow --mount or --output");
    }

    for spec in &args.mounts {
        // Only the *directory* shape is refused `rw`, and only because a
        // granted directory is materialized into a throwaway image at boot: a
        // write would land in that image, be discarded with the VM, and never
        // reach the directory the user named. Refusing is the honest answer.
        //
        // A sized disk is the opposite. Its host path is what the caller
        // named, `materialize_disk_volume` creates it there if absent, and it
        // outlives the VM — so a write is exactly as durable as the caller
        // asked for.
        //
        // These were refused together by accident, not by design. The check
        // was introduced parsing `parse_dir_share_spec` and could only ever
        // see directories; widening the loop to `parse_volume_spec` extended a
        // directory-specific rule to disks without revisiting it, and the
        // message it carried ("transient live shares are read-only") described
        // only the case it was written for.
        //
        // Whether a writable disk is granted at all is the profile table's
        // answer, read here rather than restated.
        match super::shared::parse_volume_spec(spec)? {
            super::shared::VolumeSpec::DirShare {
                read_only: false, ..
            } => anyhow::bail!(
                "--mount '{spec}' requests rw, but a transient directory snapshot is read-only. \
                 Writes to the snapshot would not reach the host directory. Use a sized disk \
                 (`HOST:/GUEST:SIZE:rw`) or register a persistent machine volume."
            ),
            super::shared::VolumeSpec::Disk {
                read_only: false, ..
            } if !grants.writable_disk_images => anyhow::bail!(
                "--mount '{spec}' requests a writable disk image, which --profile {name} does not grant"
            ),
            super::shared::VolumeSpec::DirShare {
                read_only: true, ..
            }
            | super::shared::VolumeSpec::Disk { .. } => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_args(profile: RunProfile) -> RunArgs {
        RunArgs {
            profile,
            timeout: Some(60),
            argv: vec!["/bin/true".to_string()],
            ..Default::default()
        }
    }

    /// `--prod` with the dev profile would boot the sealed image with the dev
    /// agent profile; it is refused before anything is pulled.
    #[test]
    fn prod_refuses_the_dev_profile() {
        let mut args = run_args(RunProfile::Dev);
        args.argv.clear();
        args.prod = true;
        let err = validate_prod_run(&args).expect_err("--prod --profile dev must refuse");
        assert!(err.to_string().contains("--profile dev"), "{err}");
        args.prod = false;
        assert!(
            validate_prod_run(&args).is_ok(),
            "the dev profile alone is fine"
        );
    }

    /// An ad-hoc command — after `--` or in a launch document — is a DevOnly
    /// verb a sealed image refuses; `--prod` refuses it up front.
    #[test]
    fn prod_refuses_an_ad_hoc_command_or_launch_document() {
        let mut args = run_args(RunProfile::Standard);
        args.prod = true;
        let err = validate_prod_run(&args).expect_err("--prod -- <cmd> must refuse");
        let msg = err.to_string();
        assert!(msg.contains("refuses an ad-hoc command"), "{msg}");
        assert!(msg.contains("declared entrypoint"), "{msg}");

        args.argv.clear();
        args.launch_plan = Some("plan.json".to_string());
        assert!(
            validate_prod_run(&args).is_err(),
            "a launch document is dispatched as a command too"
        );

        args.launch_plan = None;
        assert!(
            validate_prod_run(&args).is_ok(),
            "--prod with no command of its own is not refused here"
        );
    }

    const PINNED_IMAGE: &str = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A production run can persist data: a writable disk image is the
    /// guest's own ext4 file, so `--prod` accepts it under the default
    /// profile without unsealing anything.
    #[test]
    fn prod_accepts_a_writable_disk_image() {
        let mut args = run_args(RunProfile::Standard);
        args.argv.clear();
        args.prod = true;
        args.image = Some(PINNED_IMAGE.to_string());
        args.mounts.push("/h/state.img:/data:20G:rw".to_string());
        validate_run_profile(&args).expect("--prod must accept a writable disk image");
    }

    /// What `--prod` gains is the disk, not the directory: a writable
    /// directory share is refused exactly as it is without `--prod`.
    #[test]
    fn prod_still_refuses_a_writable_directory_share() {
        let mut args = run_args(RunProfile::Standard);
        args.argv.clear();
        args.prod = true;
        args.image = Some(PINNED_IMAGE.to_string());
        args.mounts.push("/h/src:/work:rw".to_string());
        let message = validate_run_profile(&args)
            .expect_err("--prod must refuse a writable directory share")
            .to_string();
        assert!(message.contains("directory snapshot"), "{message}");
    }

    /// Restrictive refuses every `--mount`, a writable disk image included.
    #[test]
    fn restrictive_refuses_a_writable_disk_image() {
        let mut args = run_args(RunProfile::Restrictive);
        args.mounts.push("/h/state.img:/data:20G:rw".to_string());
        let message = validate_run_profile(&args)
            .expect_err("restrictive must refuse any mount")
            .to_string();
        assert!(message.contains("does not allow --mount"), "{message}");
    }

    #[test]
    fn prod_mutable_image_refusal_precedes_ad_hoc_command_refusal() {
        let mut args = run_args(RunProfile::Standard);
        args.prod = true;
        args.image = Some("alpine:latest".to_string());

        let message = validate_run_profile(&args)
            .expect_err("a mutable production image must be refused")
            .to_string();

        assert!(
            message.contains("requires a digest-pinned reference"),
            "{message}"
        );
    }
}
