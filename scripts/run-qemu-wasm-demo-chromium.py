#!/usr/bin/env python3
"""Headless-Chromium harness for the WebLinux demo page."""
import json
import os
import re
import signal
import subprocess
import sys
import time
import tempfile

PORT = 8766

def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <staged-demo-dir> <chrome-binary> [exec-command] [allow-host]", file=sys.stderr)
        sys.exit(2)

    demo_dir = sys.argv[1]
    chrome_bin = sys.argv[2]
    exec_cmd = sys.argv[3] if len(sys.argv) > 3 else "ps"
    allow_host = sys.argv[4] if len(sys.argv) > 4 else ""

    subprocess.run(["pkill", "-9", "-f", "Google Chrome for Testing"], capture_output=True)
    for pid in subprocess.run(["lsof", "-ti", f":{PORT}"], capture_output=True, text=True).stdout.strip().split():
        try:
            os.kill(int(pid), signal.SIGKILL)
        except Exception:
            pass
    time.sleep(0.5)

    serve_py = os.path.join(os.path.dirname(__file__), "..", "web", "weblinux-demo", "serve.py")
    server = subprocess.Popen([sys.executable, serve_py, demo_dir, str(PORT)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)

    url = f"http://127.0.0.1:{PORT}/?autorun=1&exec={exec_cmd}"
    if allow_host:
        url += f"&allowHost={allow_host}"

    chrome_args = [
        chrome_bin,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--remote-allow-origins=*",
        "--enable-logging=stderr",
        "--log-level=0",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir=/tmp/chrome-user-data-demo-{int(time.time())}",
        url,
    ]
    start = time.perf_counter()
    stderr_path = os.path.join(tempfile.gettempdir(), f"demo-chrome-{int(start)}.log")
    with open(stderr_path, "w") as errfile:
        chrome = subprocess.Popen(chrome_args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        marker_seen_at = None
        try:
            for line in chrome.stderr:
                errfile.write(line)
                sys.stdout.write(line)
                sys.stdout.flush()
                if "DEMO-RESULT: READY" in line and marker_seen_at is None:
                    marker_seen_at = time.perf_counter()
                    deadline = marker_seen_at + 10
                if marker_seen_at and time.perf_counter() > deadline:
                    break
                if time.perf_counter() - start > 120:
                    print("--- timeout ---")
                    break
        finally:
            chrome.terminate()
            try:
                chrome.wait(timeout=5)
            except subprocess.TimeoutExpired:
                chrome.kill()
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()

    total = time.perf_counter() - start
    with open(stderr_path, "r") as f:
        all_err = f.read()
    console_lines = [re.sub(r"^.*\[INFO:CONSOLE:\d+\] \"", "", l).strip().rstrip('",')
                     for l in all_err.splitlines() if "[INFO:CONSOLE:" in l and "[demo]" in l]
    result = {
        "success": marker_seen_at is not None,
        "status": "READY" if marker_seen_at else "TIMEOUT",
        "marker_time_seconds": (marker_seen_at - start) if marker_seen_at else None,
        "total_elapsed_seconds": total,
        "command": exec_cmd,
        "allow_host": allow_host,
        "stderr_file": stderr_path,
        "console_lines": console_lines[-50:],
    }
    print("\n=== RESULT ===")
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["success"] else 1)

if __name__ == "__main__":
    main()
