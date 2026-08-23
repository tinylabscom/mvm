#!/usr/bin/env python3
"""Headless-Chromium smoke suite for the WebLinux demo.

Runs a short sequence of guest commands through the same page harness as
`run-qemu-wasm-demo-chromium.py`, but only uses commands known to be stable
inside the QEMU-Wasm browser engine.  In particular, host-bound traffic via
SLIRP currently triggers a worker divide-by-zero in the Emscripten socket
emulation layer, so this suite exercises loopback networking and the
allow-host /etc/hosts plumbing instead.
"""
import json
import os
import subprocess
import sys

DEMO_SCRIPT = os.path.join(os.path.dirname(__file__), "run-qemu-wasm-demo-chromium.py")


def run_case(demo_dir: str, chrome_bin: str, command: str, allow_host: str = "") -> dict:
    """Run a single command through the demo harness and return its result dict."""
    args = [sys.executable, DEMO_SCRIPT, demo_dir, chrome_bin, command]
    if allow_host:
        args.append(allow_host)
    proc = subprocess.run(args, capture_output=True, text=True, timeout=150)
    marker = "=== RESULT ==="
    pos = proc.stdout.rfind(marker)
    if pos == -1:
        raise RuntimeError(f"no result block for command {command!r}\n{proc.stdout}\n{proc.stderr}")
    raw = proc.stdout[pos + len(marker):].strip()
    return json.loads(raw)


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <staged-demo-dir> <chrome-binary>", file=sys.stderr)
        sys.exit(2)

    demo_dir = sys.argv[1]
    chrome_bin = sys.argv[2]

    cases = [
        ("ps", "", "init"),
        ("top -n1", "", "Mem"),
        ("tree", "", "├── bin"),
        ("ping -c1 127.0.0.1", "", "0% packet loss"),
        ("cat /etc/hosts", "demo.mvm.local", "10.0.2.2 demo.mvm.local"),
    ]

    results = []
    failed = False
    for command, allow_host, expected in cases:
        print(f"\n>>> running: {command!r} (allowHost={allow_host!r})", file=sys.stderr)
        try:
            result = run_case(demo_dir, chrome_bin, command, allow_host)
        except Exception as exc:
            print(f"FAIL: {command!r} raised {exc}", file=sys.stderr)
            failed = True
            results.append({"command": command, "success": False, "error": str(exc)})
            continue

        stderr_path = result.get("stderr_file")
        log = ""
        if stderr_path and os.path.isfile(stderr_path):
            with open(stderr_path, "r", errors="replace") as fh:
                log = fh.read()

        ok = result.get("success") is True and expected in log
        if not ok:
            failed = True
            print(f"FAIL: {command!r} success={result.get('success')} expected={expected!r}", file=sys.stderr)
        else:
            print(f"PASS: {command!r} ({result.get('marker_time_seconds'):.2f}s to ready)", file=sys.stderr)

        results.append({
            "command": command,
            "success": ok,
            "status": result.get("status"),
            "marker_time_seconds": result.get("marker_time_seconds"),
            "total_elapsed_seconds": result.get("total_elapsed_seconds"),
            "stderr_file": stderr_path,
        })

    summary = {
        "success": not failed,
        "passed": sum(1 for r in results if r.get("success")),
        "failed": sum(1 for r in results if not r.get("success")),
        "results": results,
    }
    print("\n=== SUITE RESULT ===")
    print(json.dumps(summary, indent=2))
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
