//! Which transport `mvmctl run` takes: an SDK mode chosen by `--mode`, the
//! `--dev` / `--prod` aliases or `MVM_SDK_MODE`, or — when none is asked for —
//! the transient sandbox runner over the trailing argv.

use anyhow::Result;

use super::{RunArgs, RunMode, SdkTransportArgs};

/// Resolve the `mvmctl run` transport mode from the explicit
/// `--mode` flag, the friendly `--dev` / `--prod` aliases, and the
/// `MVM_SDK_MODE` env-var override. Returns `Ok(None)` when no SDK
/// mode was requested — in that case the verb falls back to the
/// transient-sandbox runner over the trailing argv.
///
/// Env-var precedence matches `mvmctl build compile`: `MVM_SDK_MODE`
/// supersedes any flag-only override so a wrapper script can pin a
/// mode without the user retyping `--mode`.
pub(in crate::commands) fn resolve_run_mode(
    sdk: &SdkTransportArgs,
    run: &RunArgs,
) -> Result<Option<RunMode>> {
    if let Ok(env_mode) = std::env::var(mvm_sdk::env::MVM_SDK_MODE_ENV) {
        // The SDK modes do not go through the image run, so `--prod` would be
        // dropped without a word; refuse the pair instead.
        if run.prod {
            anyhow::bail!(
                "--prod is not honoured by an SDK run mode, and {}={env_mode} selects one; \
                 unset it to run a production image",
                mvm_sdk::env::MVM_SDK_MODE_ENV
            );
        }
        return Ok(Some(parse_env_run_mode(&env_mode)?));
    }
    if sdk.dev {
        if run.prod {
            anyhow::bail!("--dev selects the SDK live mode, which does not honour --prod");
        }
        return Ok(Some(RunMode::Live));
    }
    if run.prod {
        if run.image.is_some() {
            return Ok(None);
        }
        anyhow::bail!(
            "`mvmctl run --prod` (alias for --mode record) redirects to `mvmctl build compile`, where \
             record is the default mode. Re-run as `mvmctl build compile <script>` (the trailing argv \
             on `mvmctl run` is for the live sandbox runner, not for SDK record-mode)."
        );
    }
    match sdk.mode {
        None => Ok(None),
        Some(RunMode::Live) => Ok(Some(RunMode::Live)),
        Some(RunMode::Record) => anyhow::bail!(
            "`mvmctl run --mode record` is unsupported — `mvmctl build compile` is the record-mode verb \
             (record is the default; pass the script as the positional entry)."
        ),
        Some(RunMode::Plan) => Ok(Some(RunMode::Plan)),
    }
}

fn parse_env_run_mode(raw: &str) -> Result<RunMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "live" => Ok(RunMode::Live),
        "plan" => Ok(RunMode::Plan),
        "record" => anyhow::bail!(
            "MVM_SDK_MODE=record on `mvmctl run` is unsupported — `mvmctl build compile` is the \
             record-mode verb (record is its default)."
        ),
        other => anyhow::bail!(
            "MVM_SDK_MODE={other:?} is not recognized; expected one of: live, plan, record"
        ),
    }
}
