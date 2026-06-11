//! `mvm-runtime` — in-guest entrypoint for function-call
//! workloads.
//!
//! The agent (mvm `RunEntrypoint`) execs this binary with stdin piped
//! in. It loads `/etc/mvm/runtime.json`, applies prod hardening, then
//! exec's the language interpreter (`python3`/`node`) with the matching
//! dispatch fragment from `/usr/lib/mvm/runtime/dispatch.{py,mjs}`,
//! piping the captured stdin to the child.
//!
//! On every error path the runtime emits a sanitized envelope on
//! stderr (`{kind, error_id, message}`) and exits 1. The SDK caller's
//! `f.remote(...)` parses that envelope to surface a structured error.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use mvm_guest::runner::{
    DEFAULT_CONFIG_PATH, DEFAULT_DISPATCH_DIR, ErrorEnvelope, ErrorKind, RuntimeConfig,
    STDIN_CAP_BYTES,
    config::Language,
    hardening::{StdinReadError, apply_prod_hardening, read_stdin_capped},
};

const EXIT_OK: i32 = 0;
const EXIT_ERR: i32 = 1;

fn main() {
    // Hardening before anything else — in particular, before any
    // stdin byte is read or any allocation big enough to hold a
    // payload happens.
    if let Err(e) = apply_prod_hardening() {
        emit_envelope(ErrorKind::Internal, "could not apply prod hardening");
        eprintln!(
            "{{\"diag\":\"prctl PR_SET_DUMPABLE failed: {}\"}}",
            e.kind()
        );
        std::process::exit(EXIT_ERR);
    }

    let exit_code = match run() {
        Ok(code) => code,
        Err(()) => EXIT_ERR,
    };
    std::process::exit(exit_code);
}

fn run() -> Result<i32, ()> {
    let config_path =
        env::var("MVM_RUNTIME_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let dispatch_dir =
        env::var("MVM_RUNTIME_DISPATCH_DIR").unwrap_or_else(|_| DEFAULT_DISPATCH_DIR.to_string());

    let config = match fs::read(&config_path) {
        Ok(bytes) => match RuntimeConfig::from_slice(&bytes) {
            Ok(cfg) => cfg,
            Err(_) => {
                emit_envelope(ErrorKind::ConfigInvalid, "runtime.json failed to parse");
                return Err(());
            }
        },
        Err(_) => {
            emit_envelope(ErrorKind::ConfigInvalid, "runtime.json could not be read");
            return Err(());
        }
    };

    let stdin = match read_stdin_capped(io::stdin().lock(), STDIN_CAP_BYTES) {
        Ok(buf) => buf,
        Err(StdinReadError::CapExceeded) => {
            emit_envelope(
                ErrorKind::StdinTooLarge,
                "stdin payload exceeds the runtime cap",
            );
            return Err(());
        }
        Err(StdinReadError::Io(_)) => {
            emit_envelope(ErrorKind::Io, "reading stdin failed");
            return Err(());
        }
    };

    dispatch(&config, &dispatch_dir, &stdin)
}

fn dispatch(config: &RuntimeConfig, dispatch_dir: &str, stdin: &[u8]) -> Result<i32, ()> {
    let fragment = PathBuf::from(dispatch_dir).join(config.language.dispatch_filename());
    let mut cmd = Command::new(config.language.interpreter());
    populate_argv(&mut cmd, config.language, &fragment);
    cmd.env("MVM_MODULE", &config.module);
    cmd.env("MVM_FUNCTION", &config.function);
    cmd.env("MVM_FORMAT", config.format.as_str());
    cmd.env("MVM_SOURCE_PATH", &config.source_path);
    cmd.stdin(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            emit_envelope(
                ErrorKind::SpawnFailed,
                "could not spawn language interpreter",
            );
            return Err(());
        }
    };

    if let Some(child_stdin) = child.stdin.as_mut()
        && child_stdin.write_all(stdin).is_err()
    {
        emit_envelope(ErrorKind::Io, "writing stdin to dispatch child failed");
        let _ = child.kill();
        return Err(());
    }
    drop(child.stdin.take());

    let status = match child.wait() {
        Ok(s) => s,
        Err(_) => {
            emit_envelope(ErrorKind::Io, "waiting on dispatch child failed");
            return Err(());
        }
    };

    if status.success() {
        Ok(EXIT_OK)
    } else {
        emit_envelope(
            ErrorKind::ChildFailed,
            "dispatched function exited non-zero",
        );
        Err(())
    }
}

fn populate_argv(cmd: &mut Command, kind: Language, fragment: &PathBuf) {
    match kind {
        // `python3 <fragment>` — the fragment reads `MVM_*` env
        // vars and stdin to pick up its inputs.
        Language::Python => {
            cmd.arg(fragment);
        }
        // `node <fragment>` — same shape; `.mjs` extension makes Node
        // load it as ESM without needing `--input-type`.
        Language::Node => {
            cmd.arg(fragment);
        }
        // `wasmtime run <fragment>` — fragment is the .wasm. WASI
        // Preview 1 host functions provide stdin/stdout/exit. The
        // module is responsible for its own decode/dispatch/encode
        // — mvm cannot enforce wire-contract conformance on
        // arbitrary user-provided WASM.
        Language::Wasm => {
            cmd.arg("run");
            cmd.arg(fragment);
        }
    }
}

fn emit_envelope(kind: ErrorKind, message: &'static str) {
    let envelope = ErrorEnvelope::new(kind, message);
    // Use direct writes to bypass any panic-on-stderr-broken-pipe
    // behaviour. The agent captures stderr.
    let line = envelope.to_jsonl();
    let _ = io::stderr().write_all(line.as_bytes());
}
