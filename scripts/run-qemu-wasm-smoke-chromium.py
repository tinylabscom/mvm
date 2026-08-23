#!/usr/bin/env python3
"""Serve the QEMU-Wasm smoke pack and boot it under headless Chromium.

Captures Chromium's console log from stderr and reports the time to the
QEMU-WASM-SMOKE-READY marker along with peak process RSS.
"""
import json
import os
import re
import signal
import subprocess
import sys
import time

CONSOLE_RE = re.compile(r':INFO:CONSOLE:\d+\] "([^"]*)"')
MARKER = "SMOKE-RESULT: READY"
TIMEOUT_RE = "SMOKE-RESULT: TIMEOUT"
ABORT_RE = "SMOKE-RESULT: ABORT"
ERROR_RE = "SMOKE-RESULT: ERROR"


def start_server(pack_dir: str, port: int) -> subprocess.Popen:
    script = os.path.join(os.path.dirname(__file__), "serve-qemu-wasm-smoke-pack.py")
    proc = subprocess.Popen(
        [sys.executable, script, str(port), pack_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line:
            print(line.strip())
            if "Serving" in line:
                return proc
        if proc.poll() is not None:
            break
    raise RuntimeError("pack server failed to start")


def start_chrome(chrome_bin: str, user_data_dir: str, port: int) -> subprocess.Popen:
    url = f"http://127.0.0.1:{port}/"
    args = [
        chrome_bin,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--remote-allow-origins=*",
        "--enable-logging=stderr",
        "--log-level=0",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir={user_data_dir}",
        url,
    ]
    return subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def get_rss_kib(pid: int) -> int:
    """Return total RSS in KiB for process tree rooted at pid."""
    total = 0
    try:
        result = subprocess.run(
            ["pgrep", "-P", str(pid)],
            capture_output=True,
            text=True,
            check=False,
        )
        pids = {pid}
        for line in result.stdout.strip().splitlines():
            if line:
                try:
                    pids.add(int(line))
                except ValueError:
                    pass
        # Recursively gather descendants.
        changed = True
        while changed:
            changed = False
            for known in list(pids):
                res = subprocess.run(
                    ["pgrep", "-P", str(known)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                for line in res.stdout.strip().splitlines():
                    if line:
                        try:
                            if int(line) not in pids:
                                pids.add(int(line))
                                changed = True
                        except ValueError:
                            pass
        for p in pids:
            try:
                out = subprocess.run(
                    ["ps", "-o", "rss=", "-p", str(p)],
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip()
                if out:
                    # macOS ps rss is bytes; Linux ps rss is KiB. Normalize to KiB.
                    rss = int(out)
                    if rss > 1024 * 1024 * 1024:
                        # Looks like bytes (unreasonably large KiB); convert.
                        rss = rss // 1024
                    total += rss
            except Exception:
                pass
    except Exception:
        pass
    return total


def run_test(pack_dir: str, chrome_bin: str, port: int = 8765, timeout: float = 600):
    user_data_base = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".mvm-test", "chromium-user-data")
    )
    os.makedirs(user_data_base, exist_ok=True)
    import tempfile
    user_data_dir = tempfile.mkdtemp(prefix="run-", dir=user_data_base)

    server = start_server(pack_dir, port)
    chrome = start_chrome(chrome_bin, user_data_dir, port)

    start_time = time.monotonic()
    marker_time = None
    result_status = None
    console_lines = []
    peak_rss_kib = 0
    memory_samples = []

    try:
        while True:
            elapsed = time.monotonic() - start_time
            if elapsed > timeout:
                result_status = "TIMEOUT"
                break

            # Poll stderr with a short timeout so we can sample RSS too.
            import select
            ready, _, _ = select.select([chrome.stderr], [], [], 1.0)
            if ready:
                line = chrome.stderr.readline()
                if line:
                    stripped = line.rstrip()
                    if stripped:
                        # Print raw stderr for visibility.
                        print(stripped)
                    match = CONSOLE_RE.search(stripped)
                    if match:
                        text = match.group(1)
                        console_lines.append(text)
                        if MARKER in text and marker_time is None:
                            marker_time = elapsed
                            result_status = "READY"
                            break
                        if TIMEOUT_RE in text:
                            result_status = "GUEST_TIMEOUT"
                            break
                        if ABORT_RE in text or ERROR_RE in text:
                            result_status = "FAIL"
                            break

            # Sample RSS every ~2 seconds.
            if int(elapsed) % 2 == 0:
                rss = get_rss_kib(chrome.pid)
                if rss > peak_rss_kib:
                    peak_rss_kib = rss
                memory_samples.append({"elapsed": round(elapsed, 2), "rss_kib": rss})

            if chrome.poll() is not None:
                result_status = "CHROME_EXITED"
                break
    finally:
        for p in (chrome, server):
            try:
                p.send_signal(signal.SIGTERM)
            except Exception:
                pass
        # Give them a moment, then force kill.
        time.sleep(1)
        for p in (chrome, server):
            try:
                if p.poll() is None:
                    p.kill()
            except Exception:
                pass

    return {
        "success": result_status == "READY",
        "status": result_status,
        "marker_time_seconds": marker_time,
        "total_elapsed_seconds": time.monotonic() - start_time,
        "peak_rss_kib": peak_rss_kib,
        "memory_samples": memory_samples,
        "console_lines": console_lines,
    }


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <pack-dir> <chromium-bin> [port] [timeout-seconds]", file=sys.stderr)
        sys.exit(2)
    pack_dir = sys.argv[1]
    chrome_bin = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8765
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 600.0
    result = run_test(pack_dir, chrome_bin, port, timeout)
    print("\n=== RESULT ===")
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()
