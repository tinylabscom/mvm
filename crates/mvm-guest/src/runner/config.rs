//! Typed shape of `/etc/mvm/runtime.json`.
//!
//! The file is baked into the rootfs at image build time via mvm's
//! `mkGuest extraFiles` mechanism; nothing is decided at call time
//! except the args bytes that come in over stdin (build-time-everything
//! invariant, ADR-0009).
//!
//! Fields mirror the IR's `Entrypoint::Function` variant; the source
//! of truth is `mvm-ir/src/workload.rs` and the JSON Schema regen
//! lane keeps them in lockstep.

use serde::{Deserialize, Serialize};

/// Closed enum: the language interpreter the runtime dispatches into.
/// Mirrors the languages mvm has Nix factories for — additions to
/// this enum land alongside additions to mvm's
/// `SUPPORTED_LANGUAGES` allowlist (per ADR-0010 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    Node,
    /// WASI Preview 1 module hosted by `wasmtime`. The factory bakes
    /// the user-provided `.wasm` and a tiny shell script that does
    /// `wasmtime run <module>` — the WASM module itself satisfies the
    /// stdin → fn → stdout wire contract via WASI host functions
    /// provided by wasmtime. Generic across any compile-to-WASM
    /// language (Rust, Go, Zig, AssemblyScript, .NET NativeAOT-LLVM,
    /// Kotlin/Wasm, …) per ADR-0010 §4.
    Wasm,
}

impl Language {
    /// Argv[0] of the language interpreter (or runtime). Resolved via
    /// PATH on the guest; the Nix factories ensure the relevant
    /// binary is on PATH inside the rootfs.
    pub fn interpreter(self) -> &'static str {
        match self {
            Self::Python => "python3",
            Self::Node => "node",
            Self::Wasm => "wasmtime",
        }
    }

    /// Filename of the dispatch fragment under
    /// `/usr/lib/mvm/runtime/`. The factories bake exactly the
    /// fragment matching the IR-declared language; the runtime never
    /// chooses among alternatives at call time.
    ///
    /// For WASM the user-provided `.wasm` IS the dispatch fragment;
    /// the filename returned here is the conventional name the
    /// factory bakes it under (it can be overridden at the factory
    /// level by passing a different `module` value through the IR).
    pub fn dispatch_filename(self) -> &'static str {
        match self {
            Self::Python => "dispatch.py",
            Self::Node => "dispatch.mjs",
            Self::Wasm => "dispatch.wasm",
        }
    }
}

/// Closed enum: serialization format for stdin args + stdout return.
/// Code-executing serializer formats are forbidden by ADR-0009.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Json,
    Msgpack,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Msgpack => "msgpack",
        }
    }
}

/// Parsed `/etc/mvm/runtime.json`.
///
/// `deny_unknown_fields` is intentional: a runtime.json from a future
/// schema with new fields should fail loud, not silently ignore them
/// — the runtime is the load-bearing security boundary; surprises here
/// are bugs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub language: Language,
    pub module: String,
    pub function: String,
    pub format: Format,
    /// Where the bundled user source tree was placed in the rootfs by
    /// the `preStart` hook. Pushed into `PYTHONPATH` (Python) or
    /// `NODE_PATH` (Node) so the dispatch fragment can resolve
    /// `import <module>`.
    pub source_path: String,
}

impl RuntimeConfig {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_minimal_python_config() {
        let json = br#"{
            "language": "python",
            "module": "adder",
            "function": "add",
            "format": "json",
            "source_path": "/app"
        }"#;
        let cfg = RuntimeConfig::from_slice(json).unwrap();
        assert_eq!(cfg.language, Language::Python);
        assert_eq!(cfg.module, "adder");
        assert_eq!(cfg.function, "add");
        assert_eq!(cfg.format, Format::Json);
        assert_eq!(cfg.source_path, "/app");
    }

    #[test]
    fn rejects_unknown_field() {
        let json = br#"{
            "language": "python", "module": "m", "function": "f",
            "format": "json", "source_path": "/app", "extra": 1
        }"#;
        let err = RuntimeConfig::from_slice(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn rejects_unknown_runtime_value() {
        let json = br#"{
            "language": "rust", "module": "m", "function": "f",
            "format": "json", "source_path": "/app"
        }"#;
        assert!(RuntimeConfig::from_slice(json).is_err());
    }

    #[test]
    fn rejects_unknown_format_value() {
        let json = br#"{
            "language": "node", "module": "m", "function": "f",
            "format": "yaml", "source_path": "/app"
        }"#;
        assert!(RuntimeConfig::from_slice(json).is_err());
    }

    #[test]
    fn interpreter_and_dispatch_filename_are_stable() {
        assert_eq!(Language::Python.interpreter(), "python3");
        assert_eq!(Language::Node.interpreter(), "node");
        assert_eq!(Language::Python.dispatch_filename(), "dispatch.py");
        assert_eq!(Language::Node.dispatch_filename(), "dispatch.mjs");
    }
}
