# mkWasmFunctionService — bake a WASM (WASI Preview 1) function-call
# workload.
#
# ADR-0010 §4 backlog item, promoted here as the long-tail multi-language
# unlock: any language with a "compile to WASM" toolchain (Rust, Go,
# Zig, AssemblyScript, .NET NativeAOT-LLVM, Kotlin/Wasm, …) becomes
# supportable through this single generic factory.
#
# Design difference from mkPython / mkNode:
#
#   The Python and Node factories bake an inline interpreter wrapper
#   that handles the wire contract (read stdin → decode → call user
#   function → encode → write stdout, sanitized envelope on error).
#
#   For WASM, the user's `.wasm` module IS the wrapper. WASI Preview 1
#   modules compile to a self-contained executable that has access to
#   stdin/stdout via WASI host functions — wasmtime provides them.
#   The factory's job is just to bake `wasmtime` plus the user-provided
#   `.wasm` and wire mvmctl's per-call stdin/stdout into wasmtime.
#
# This matches what Cloudflare Workers, Fastly Compute@Edge, and Spin
# do — accept a .wasm and let the user provide whatever toolchain they
# prefer to produce it.
#
# Inputs:
#   pkgs        — nixpkgs.legacyPackages.<system>
#   workloadId  — workload id from the IR
#   module      — IR entrypoint.module — interpreted as the relative
#                 path of the .wasm file inside the bundled source
#                 tree (e.g. "main.wasm" for a top-level module, or
#                 "build/release.wasm" for a built artifact).
#   function    — IR entrypoint.function — captured for wrapper-config
#                 visibility but unused by wasmtime; WASI command-style
#                 modules execute their `_start` export. Convention:
#                 set to "_start" or to the WASM export name the user
#                 wants documented (the factory does NOT route by it).
#   format      — IR entrypoint.format — captured in wrapper config;
#                 the WASM module is responsible for honoring it on
#                 stdin/stdout. mvmforge does not enforce wire-format
#                 conformance for WASM modules.
#   appPkg      — derivation built from the bundled user source
#                 (per ADR-0008). The .wasm at `module` lives here.
#   sourcePath  — absolute path inside the rootfs where the user
#                 source tree lives (default "/app").
#
# Outputs (record):
#   extraFiles      — passed straight to mvm's `mkGuest extraFiles`
#   servicePackages — `wasmtime` (plus appPkg, added by the caller)
#   service         — `services.<workloadId>` entry for mkGuest
#
# Hardening posture:
#
#   wasmtime provides the sandbox. WASM modules cannot make arbitrary
#   syscalls — only WASI Preview 1 imports the module declares
#   (file system access via `--dir` mounts, env, stdin/stdout).
#   The factory's `wasmtime run` invocation grants ONLY:
#     - stdin/stdout/stderr piped from mvmctl
#     - one read-only directory mount: ${sourcePath} (so the module
#       can find any data files it ships alongside the .wasm)
#   No network, no extra fs paths, no env beyond what mvm sets per call.
#   This is more locked down than the Python/Node factories by default
#   — extending it requires the user to declare grants in IR.

{
  pkgs,
  workloadId,
  module,
  function,
  format,
  appPkg,
  sourcePath ? "/app",
}:

let
  wasmtime = pkgs.wasmtime;

  runtimeJson = builtins.toJSON {
    language = "wasm";
    inherit module function format;
    source_path = sourcePath;
  };

  # Tiny shell wrapper at /usr/lib/mvm/wrappers/runner. Per-call mvm
  # invokes this; it execs wasmtime against the user's .wasm. The
  # WASM module reads stdin via WASI fd_read, writes via WASI
  # fd_write, exits via WASI proc_exit. mvmctl captures stdout/stderr
  # and exit code unchanged.
  runnerScript = ''
    #!${pkgs.stdenv.shell}
    set -eu

    MODULE_PATH="${sourcePath}/${module}"
    if [ ! -r "$MODULE_PATH" ]; then
      printf '{"kind":"config_invalid","error_id":"%010x","message":"wasm module not found at %s"}\n' \
        $(($(date +%s%N) / 1000000 & 0xffffffff)) \
        "$MODULE_PATH" >&2
      exit 1
    fi

    # `wasmtime run` honors WASI Preview 1. `--dir` grants a read-only
    # mount of the source path so the module can find sidecar files
    # (data, configs) it ships alongside. No network, no extra env,
    # no host fs leakage beyond ${sourcePath}.
    exec ${wasmtime}/bin/wasmtime run \
      --dir="${sourcePath}::/" \
      "$MODULE_PATH"
  '';

in
{
  extraFiles = {
    "/etc/mvm/entrypoint" = {
      content = "/usr/lib/mvm/wrappers/runner";
      mode = "0644";
    };
    "/usr/lib/mvm/wrappers/runner" = {
      content = runnerScript;
      mode = "0755";
    };
    "/etc/mvm/runtime.json" = {
      content = runtimeJson;
      mode = "0644";
    };
  };

  servicePackages = [ wasmtime ];

  service = {
    command = pkgs.writeShellScript "${workloadId}-noop" ''
      #!${pkgs.stdenv.shell}
      exec ${pkgs.coreutils}/bin/sleep infinity
    '';
    preStart = pkgs.writeShellScript "${workloadId}-prestart" ''
      set -eu
      mkdir -p "$(dirname ${sourcePath})"
      ln -sfn ${appPkg} ${sourcePath}
    '';
    env = { };
  };
}
