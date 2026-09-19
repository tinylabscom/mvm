//! Guest-side fixed-method CDP screencast bridge.
//!
//! A guest browser launcher connects Chrome's NUL-framed debugging pipe to
//! this process's stdin/stdout. Display frames leave over the dedicated host
//! vsock connection; stdout carries only commands constructed by the fixed
//! allow-list in `display_bridge`.

use std::io::BufReader;

use anyhow::{Context, Result, bail};
use mvm_agentd::display_bridge::bridge_session;
use mvm_agentd::vsock::{DEFAULT_TIMEOUT_SECS, DISPLAY_PORT, connect_host_vsock};

fn main() -> Result<()> {
    let step_id = parse_args(std::env::args().skip(1))?;
    let host = connect_host_vsock(DISPLAY_PORT, DEFAULT_TIMEOUT_SECS)
        .context("connect the view-only display frame sink")?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    bridge_session(BufReader::new(stdin.lock()), stdout.lock(), host, step_id)
        .context("bridge the fixed-method screencast")
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Option<String>> {
    let mut args = args.into_iter();
    let Some(flag) = args.next() else {
        return Ok(None);
    };
    if flag != "--step-id" {
        bail!("usage: mvm-display-bridge [--step-id <agent-step>]");
    }
    let Some(step_id) = args.next() else {
        bail!("--step-id requires a value");
    };
    if args.next().is_some() {
        bail!("usage: mvm-display-bridge [--step-id <agent-step>]");
    }
    Ok(Some(step_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_allow_only_an_optional_agent_step() {
        assert_eq!(parse_args(Vec::<String>::new()).unwrap(), None);
        assert_eq!(
            parse_args(["--step-id".into(), "step-2".into()]).unwrap(),
            Some("step-2".into())
        );
        assert!(parse_args(["--listen".into()]).is_err());
        assert!(parse_args(["--step-id".into()]).is_err());
    }
}
