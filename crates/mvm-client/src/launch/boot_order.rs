//! Everything a boot waits on is prepared before its plan is admitted.
//!
//! Admission starts the plan's validity window, and the agent verb grant the
//! host mints from the plan expires with it (`not_after = valid_until`). Any
//! slow step that runs between admission and boot spends that window. A cold
//! build of the runtime overlay is exactly such a step. One took 446 s, and
//! the guest then refused activation with a bare `VerbNotAuthorized`, because
//! the grant had expired before the kernel came up.
//!
//! The fix is the order, not a longer window. Preparation runs first. The
//! admission that starts the window runs immediately before the boot that
//! consumes it, so the window measures the boot and not the build.

use anyhow::Result;

/// Run `prepare` on `config`, then `admit`. Admission is never started before
/// preparation has finished, and a failed preparation admits nothing, so no
/// plan is signed or recorded for a boot that could not have happened.
pub fn admit_after_preparation<C, A>(
    config: &mut C,
    prepare: impl FnOnce(&mut C) -> Result<()>,
    admit: impl FnOnce(&mut C) -> Result<A>,
) -> Result<A> {
    prepare(config)?;
    admit(config)
}

#[cfg(test)]
mod tests;
