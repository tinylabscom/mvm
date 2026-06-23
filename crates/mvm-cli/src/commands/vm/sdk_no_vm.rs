//! Host-side SDK wrapper dispatch.
//!
//! Runs the workload wrapper directly on the host: no VM boot, no vsock, no
//! Nix. This keeps the SDK's fast local-dispatch regression path available
//! without restoring the retired public `invoke` command.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use std::io::Write;
use std::process::{Command, Stdio};

const ONESHOT_PY: &str = include_str!("../../../../../nix/wrappers/python/oneshot.py");
const ONESHOT_MJS: &str = include_str!("../../../../../nix/wrappers/node/oneshot.mjs");

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Wrapper language.
    #[arg(long, value_name = "LANGUAGE")]
    pub language: Option<String>,
    /// Importable user module.
    #[arg(long, value_name = "MODULE")]
    pub module: Option<String>,
    /// Function name inside the module.
    #[arg(long, value_name = "FUNCTION")]
    pub function: Option<String>,
    /// Payload serialization format.
    #[arg(long, value_name = "FORMAT", default_value = "json")]
    pub format: String,
    /// Directory that should be importable as the user source root.
    #[arg(long = "source-path", value_name = "PATH")]
    pub source_path: Option<String>,
    /// Stdin payload: a file path, or `-` for mvmctl's own stdin.
    #[arg(long, value_name = "PATH")]
    pub stdin: Option<String>,
}

#[derive(Debug)]
struct NoVmConfig<'a> {
    language: &'a str,
    module: &'a str,
    function: &'a str,
    format: &'a str,
    source_path: &'a str,
}

impl<'a> NoVmConfig<'a> {
    fn from_args(args: &'a Args) -> Result<Self> {
        let missing = |name: &str| -> anyhow::Error {
            anyhow::anyhow!(
                "__sdk-no-vm requires --{name}. The SDK passes \
                 --language/--module/--function/--format/--source-path \
                 when MVM_NO_VM=1."
            )
        };
        Ok(Self {
            language: args
                .language
                .as_deref()
                .ok_or_else(|| missing("language"))?,
            module: args.module.as_deref().ok_or_else(|| missing("module"))?,
            function: args
                .function
                .as_deref()
                .ok_or_else(|| missing("function"))?,
            format: args.format.as_str(),
            source_path: args
                .source_path
                .as_deref()
                .ok_or_else(|| missing("source-path"))?,
        })
    }
}

pub(in crate::commands) fn run(args: &Args) -> Result<()> {
    let stdin_bytes = super::invoke::read_stdin_payload(args.stdin.as_deref())?;
    let exit_code = run_wrapper(args, stdin_bytes)?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn run_wrapper(args: &Args, stdin_bytes: Vec<u8>) -> Result<i32> {
    let cfg = NoVmConfig::from_args(args)?;
    if cfg.format != "json" && cfg.format != "msgpack" {
        bail!(
            "__sdk-no-vm: unsupported --format {:?} (must be \"json\" or \"msgpack\")",
            cfg.format
        );
    }

    let tmp = tempfile::tempdir().context("creating tempdir for __sdk-no-vm")?;

    let wrapper_json_path = tmp.path().join("wrapper.json");
    let wrapper_json = serde_json::to_vec(&serde_json::json!({
        "module": cfg.module,
        "function": cfg.function,
        "format": cfg.format,
        "working_dir": cfg.source_path,
        "mode": "dev",
    }))
    .context("serializing wrapper.json")?;
    std::fs::write(&wrapper_json_path, &wrapper_json)
        .with_context(|| format!("writing {}", wrapper_json_path.display()))?;

    let (wrapper_path, interpreter) = match cfg.language {
        "python" => {
            let path = tmp.path().join("wrapper.py");
            std::fs::write(&path, ONESHOT_PY)
                .with_context(|| format!("writing {}", path.display()))?;
            (path, "python3")
        }
        "node" => {
            let path = tmp.path().join("wrapper.mjs");
            std::fs::write(&path, ONESHOT_MJS)
                .with_context(|| format!("writing {}", path.display()))?;
            (path, "node")
        }
        other => bail!(
            "__sdk-no-vm: unsupported --language {other:?}. Built-in wrappers \
             ship for `python` and `node`; wasm requires the VM path."
        ),
    };

    let mut cmd = Command::new(interpreter);
    cmd.arg(&wrapper_path);
    cmd.env("MVM_WRAPPER_CONFIG_PATH", &wrapper_json_path);
    match cfg.language {
        "python" => {
            cmd.env("PYTHONPATH", cfg.source_path);
        }
        "node" => {
            cmd.env("NODE_PATH", cfg.source_path);
        }
        _ => unreachable!("language was validated above"),
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning {interpreter}; is it on PATH?"))?;

    if let Some(mut child_stdin) = child.stdin.take()
        && !stdin_bytes.is_empty()
    {
        let _ = child_stdin.write_all(&stdin_bytes);
    }

    let status = child.wait().context("waiting on wrapper subprocess")?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_args() -> Args {
        Args {
            language: None,
            module: None,
            function: None,
            format: "json".to_string(),
            source_path: None,
            stdin: None,
        }
    }

    #[test]
    fn from_args_requires_language() {
        let args = empty_args();
        let err = NoVmConfig::from_args(&args).unwrap_err();
        assert!(err.to_string().contains("--language"), "{err}");
    }

    #[test]
    fn from_args_requires_module() {
        let mut args = empty_args();
        args.language = Some("python".to_string());
        let err = NoVmConfig::from_args(&args).unwrap_err();
        assert!(err.to_string().contains("--module"), "{err}");
    }

    #[test]
    fn from_args_requires_function() {
        let mut args = empty_args();
        args.language = Some("python".to_string());
        args.module = Some("m".to_string());
        let err = NoVmConfig::from_args(&args).unwrap_err();
        assert!(err.to_string().contains("--function"), "{err}");
    }

    #[test]
    fn from_args_requires_source_path() {
        let mut args = empty_args();
        args.language = Some("python".to_string());
        args.module = Some("m".to_string());
        args.function = Some("f".to_string());
        let err = NoVmConfig::from_args(&args).unwrap_err();
        assert!(err.to_string().contains("--source-path"), "{err}");
    }

    #[test]
    fn from_args_succeeds_when_all_present() {
        let mut args = empty_args();
        args.language = Some("python".to_string());
        args.module = Some("m".to_string());
        args.function = Some("f".to_string());
        args.source_path = Some("/tmp/src".to_string());
        let cfg = NoVmConfig::from_args(&args).unwrap();
        assert_eq!(cfg.language, "python");
        assert_eq!(cfg.module, "m");
        assert_eq!(cfg.function, "f");
        assert_eq!(cfg.format, "json");
        assert_eq!(cfg.source_path, "/tmp/src");
    }

    #[test]
    fn embedded_wrappers_contain_envelope_marker() {
        assert!(ONESHOT_PY.contains("MVM_ENVELOPE: "));
        assert!(ONESHOT_MJS.contains("MVM_ENVELOPE: "));
    }

    #[test]
    fn embedded_wrappers_honor_env_override() {
        assert!(ONESHOT_PY.contains("MVM_WRAPPER_CONFIG_PATH"));
        assert!(ONESHOT_MJS.contains("MVM_WRAPPER_CONFIG_PATH"));
    }
}
