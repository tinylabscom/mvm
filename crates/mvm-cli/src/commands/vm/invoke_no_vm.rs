//! `mvmctl invoke --no-vm` — dev shortcut.
//!
//! Runs the workload's wrapper script directly on the host (no VM
//! boot, no vsock, no Nix). Exercises
//! the full SDK wire contract end-to-end:
//!
//! 1. Encoded `[args, kwargs]` arrives on mvmctl's stdin.
//! 2. mvmctl writes a temp `wrapper.json` carrying the per-call IR
//!    bits (`module`, `function`, `format`, `working_dir`).
//! 3. mvmctl writes the language's wrapper source (embedded via
//!    `include_str!` from `nix/wrappers/<lang>/oneshot.{py,mjs}`)
//!    to a temp file.
//! 4. mvmctl spawns the interpreter (`python3` / `node`) with
//!    `MVM_WRAPPER_CONFIG_PATH` pointing at the temp wrapper.json
//!    and `PYTHONPATH` / `NODE_PATH` rooted at the user's
//!    `--source-path`.
//! 5. Stdin / stdout / stderr stream through unmodified. The
//!    wrapper's exit code becomes mvmctl's exit code so a
//!    `RemoteError` envelope on stderr surfaces the same shape the
//!    in-VM path produces.
//!
//! Not for production — the in-VM hardening (seccomp, RLIMIT_CORE,
//! mount-namespace isolation, dm-verity rootfs) all live on the
//! VM side. This path is for SDK iteration, CI smoke, and dev
//! loops on machines without Linux/KVM/Lima.

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::process::{Command, Stdio};

use super::invoke::Args;

/// Python wrapper sources baked into the binary at compile time so
/// `--no-vm` works on any host without needing the user to install
/// the `nix/wrappers/` tree separately. Same files the Nix factory
/// inlines into the rootfs at `/usr/lib/mvm/wrappers/runner`.
const ONESHOT_PY: &str = include_str!("../../../../../nix/wrappers/python/oneshot.py");
const ONESHOT_MJS: &str = include_str!("../../../../../nix/wrappers/node/oneshot.mjs");

/// Validated payload of the `--no-vm` flag set. Built up front so
/// `run` can emit clear per-field errors before any subprocess
/// spawns.
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
                "--no-vm requires --{name}. Hint: the SDK should pass \
                 --language/--module/--function/--format/--source-path \
                 when MVM_NO_VM=1; or pass them yourself for ad-hoc \
                 dispatch."
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

/// Entry point. Returns the wrapper's exit code; the caller maps
/// that to `process::exit` so the SDK sees the same shape it would
/// see from a real `mvmctl invoke`.
pub(super) fn run(args: &Args, stdin_bytes: Vec<u8>) -> Result<i32> {
    let cfg = NoVmConfig::from_args(args)?;
    if cfg.format != "json" && cfg.format != "msgpack" {
        bail!(
            "--no-vm: unsupported --format {:?} (must be \"json\" or \
             \"msgpack\")",
            cfg.format
        );
    }

    let tmp = tempfile::tempdir().context("creating tempdir for --no-vm")?;

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
            let p = tmp.path().join("wrapper.py");
            std::fs::write(&p, ONESHOT_PY).with_context(|| format!("writing {}", p.display()))?;
            (p, "python3")
        }
        "node" => {
            let p = tmp.path().join("wrapper.mjs");
            std::fs::write(&p, ONESHOT_MJS).with_context(|| format!("writing {}", p.display()))?;
            (p, "node")
        }
        other => bail!(
            "--no-vm: unsupported --language {other:?}. Built-in wrappers \
             ship for `python` and `node`; wasm requires the VM path."
        ),
    };

    let mut cmd = Command::new(interpreter);
    cmd.arg(&wrapper_path);
    cmd.env("MVM_WRAPPER_CONFIG_PATH", &wrapper_json_path);
    // Make the user's source tree importable. Python wrapper sets
    // sys.path itself based on `working_dir`; we set PYTHONPATH /
    // NODE_PATH as belt-and-suspenders so a custom wrapper that
    // skips that step still resolves the module.
    match cfg.language {
        "python" => {
            cmd.env("PYTHONPATH", cfg.source_path);
        }
        "node" => {
            cmd.env("NODE_PATH", cfg.source_path);
        }
        _ => unreachable!("already validated above"),
    }
    cmd.stdin(Stdio::piped());
    // Stdout / stderr inherit so the SDK's parser sees the wrapper's
    // raw bytes (envelope marker on stderr, return payload on
    // stdout). No mvmctl-side buffering = same shape as the in-VM
    // path's `mvmctl invoke` does.
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning {interpreter}; is it on PATH?"))?;

    if let Some(mut child_stdin) = child.stdin.take()
        && !stdin_bytes.is_empty()
        && child_stdin.write_all(&stdin_bytes).is_err()
    {
        // Broken pipe = child died early. Wait for it to surface
        // the real error on stderr; don't synthesize one here.
    }
    drop(child.stdin.take());

    let status = child.wait().context("waiting on wrapper subprocess")?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_args() -> Args {
        Args {
            manifest: "ignored".to_string(),
            stdin: None,
            timeout: 30,
            cpus: 2,
            memory_mib: 512,
            from_workload_ir: None,
            fresh: false,
            reset: false,
            attach: false,
            keep_alive: false,
            keep_alive_dev: false,
            session: None,
            r#fn: None,
            no_vm: true,
            language: None,
            module: None,
            function: None,
            format: "json".to_string(),
            source_path: None,
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
        // Sanity: the embedded sources must keep the wire contract
        // markers the SDK parses (`MVM_ENVELOPE:` prefix on stderr).
        // If a future wrapper rewrite drops the marker, this test
        // catches it before it ships.
        assert!(
            ONESHOT_PY.contains("MVM_ENVELOPE: "),
            "python wrapper lost its envelope marker"
        );
        assert!(
            ONESHOT_MJS.contains("MVM_ENVELOPE: "),
            "node wrapper lost its envelope marker"
        );
    }

    #[test]
    fn embedded_wrappers_honor_env_override() {
        // The wrappers must read MVM_WRAPPER_CONFIG_PATH; otherwise
        // --no-vm can't point them at the temp config file. If a
        // future edit reverts the override, the run() path would
        // silently read /etc/mvm/wrapper.json instead.
        assert!(
            ONESHOT_PY.contains("MVM_WRAPPER_CONFIG_PATH"),
            "python wrapper no longer honors MVM_WRAPPER_CONFIG_PATH"
        );
        assert!(
            ONESHOT_MJS.contains("MVM_WRAPPER_CONFIG_PATH"),
            "node wrapper no longer honors MVM_WRAPPER_CONFIG_PATH"
        );
    }
}
