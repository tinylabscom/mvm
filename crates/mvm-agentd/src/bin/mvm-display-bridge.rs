//! Guest-side fixed-method CDP screencast bridge.
//!
//! A guest browser launcher connects Chrome's NUL-framed debugging pipe to
//! this process's stdin/stdout. Display frames leave over the dedicated host
//! vsock connection; stdout carries only commands constructed by the fixed
//! allow-list in `display_bridge`. With `--input`, display input the host
//! admitted arrives through the agent's FIFO and becomes fixed CDP input
//! commands; without it the bridge reads no input at all.

use std::io::BufReader;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mvm_agentd::display_bridge::{SharedCdpWriter, bridge_session};
use mvm_agentd::display_input::{DISPLAY_INPUT_FIFO, FifoInput};
use mvm_agentd::vsock::{DEFAULT_TIMEOUT_SECS, DISPLAY_PORT, connect_host_vsock};

const USAGE: &str = "usage: mvm-display-bridge [--step-id <agent-step>] [--input]";

/// How often a bridge started before its first input waits for the FIFO.
const FIFO_POLL: Duration = Duration::from_millis(250);

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    step_id: Option<String>,
    input: bool,
}

fn main() -> Result<()> {
    let args = parse_args(std::env::args().skip(1))?;
    let host = connect_host_vsock(DISPLAY_PORT, DEFAULT_TIMEOUT_SECS)
        .context("connect the view-only display frame sink")?;
    let input: Option<Box<dyn std::io::BufRead + Send>> = args.input.then(|| {
        Box::new(BufReader::new(FifoInput::new(
            DISPLAY_INPUT_FIFO,
            FIFO_POLL,
        ))) as Box<dyn std::io::BufRead + Send>
    });
    let stdin = std::io::stdin();
    bridge_session(
        BufReader::new(stdin.lock()),
        SharedCdpWriter::new(std::io::stdout()),
        host,
        args.step_id,
        input,
    )
    .context("bridge the fixed-method screencast")
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut parsed = Args::default();
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--step-id" if parsed.step_id.is_none() => {
                let Some(step_id) = args.next() else {
                    bail!("--step-id requires a value");
                };
                parsed.step_id = Some(step_id);
            }
            "--input" if !parsed.input => parsed.input = true,
            _ => bail!("{USAGE}"),
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_allow_only_an_optional_agent_step_and_input() {
        assert_eq!(parse_args(Vec::<String>::new()).unwrap(), Args::default());
        assert_eq!(
            parse_args(["--step-id".into(), "step-2".into()]).unwrap(),
            Args {
                step_id: Some("step-2".into()),
                input: false,
            }
        );
        assert_eq!(
            parse_args(["--input".into(), "--step-id".into(), "s".into()]).unwrap(),
            Args {
                step_id: Some("s".into()),
                input: true,
            }
        );
        assert!(parse_args(["--listen".into()]).is_err());
        assert!(parse_args(["--step-id".into()]).is_err());
        assert!(parse_args(["--input".into(), "--input".into()]).is_err());
    }
}
