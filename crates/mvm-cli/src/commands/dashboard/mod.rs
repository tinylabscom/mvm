//! `mvmctl dashboard` — launch the local mvm-studio server.
//!
//! A dev and demo surface. It must never become an alternate production or
//! fleet-control path, which is why [`posture`] refuses anything that is not
//! an unambiguous local dev environment before any artifact is even resolved.
//!
//! What lives here and what does not:
//!
//! - [`locate`] decides *which file* may be executed. Two fixed locations, no
//!   symlink, no group- or world-writable artifact or directory.
//! - [`posture`] decides *whether* to launch at all.
//! - The version/capability handshake and the private readiness channel are
//!   the server's half of the contract and are tracked upstream in
//!   `mvm-studio#18`. Until that contract is frozen this command resolves,
//!   validates, and refuses — it does not spawn.
//!
//! That last point is deliberate. Spawning against an unfrozen handshake would
//! mean shipping a success path that cannot be verified against a real server,
//! and the failure paths are where every security requirement in the issue
//! lives.

pub mod locate;
pub mod posture;

use anyhow::{Result, bail};
use clap::Args as ClapArgs;

use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Check the install and the environment, then report; never spawn.
    ///
    /// This is the only mode today. The spawn half needs the server's
    /// version/capability handshake, which is frozen upstream in
    /// `mvm-studio#18`, and a launch path that cannot be verified against a
    /// real server is not worth shipping.
    #[arg(long, default_value_t = true)]
    pub check: bool,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    // Posture first, before any path is resolved or any file is read: whether
    // a dashboard may run here is a property of the environment, and an
    // unsafe environment should not even reach the question of which artifact
    // it would have launched.
    let posture = posture::classify(
        std::env::var_os("MVM_PRODUCTION").is_some(),
        std::env::var_os("MVM_FLEET").is_some(),
        std::env::var_os("MVM_DEV").is_some(),
    );
    if let Err(refusal) = posture::admit(posture) {
        bail!("{refusal}");
    }

    let exe = std::env::current_exe()?;
    let bin_dir = mvm_core::config::mvm_bin_dir();
    let server = match locate::locate_studio_server(&exe, &bin_dir) {
        Ok(path) => path,
        Err(err) => bail!("{err}"),
    };

    ui::success(&format!(
        "mvm-studio server found and passed the launch checks: {}",
        server.display()
    ));
    if args.check {
        ui::info(
            "Not starting it: the version/capability handshake is the server's half of \
             the contract and is still being frozen upstream (mvm-studio#18). \
             This command validates the install and the environment today.",
        );
    }
    Ok(())
}
