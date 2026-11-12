#!/usr/bin/env python3
"""Opt-in, credential-free native HVF witness for the published Claude bundle.

Run with MVM_TEST_PUBLIC_CLAUDE_NATIVE=1 and --help for the required local inputs.
The private test home is retained on success and failure; never use a real key.
"""

import argparse
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


ARCHIVE_SHA256 = "c23235a61debb050a80cfa3e2a93f58de812c409c9ad58c1638fd4d609b377d6"
AUTHOR_KEY_SHA256 = "b29ae91c7cbf09b08c3e9291d0a6655ba39b456f5249248d055d7b9d16feaa23"
FAKE_SECRET = b"test-only-no-network\n"


class Blocked(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Blocked(message)


def digest(stream):
    hashed = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        hashed.update(chunk)
    return hashed.hexdigest()


def checked_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            f"input is not a single-link regular file: {path}")


def sandbox_policy():
    return '(version 1)\n(allow default)\n(deny network-outbound (remote ip "*:*"))\n'


def prove_offline(socket_path):
    for family, address in ((socket.AF_INET, ("1.1.1.1", 443)),
                            (socket.AF_INET, ("127.0.0.1", 443)),
                            (socket.AF_INET6, ("2606:4700:4700::1111", 443))):
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            try:
                connection.connect(address)
            except OSError as error:
                require(error.errno in (errno.EPERM, errno.EACCES),
                        f"IP probe failed for a reason other than sandbox denial: {error}")
            else:
                raise Blocked("sandbox permitted outbound IP")
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(socket_path))
            peer, _ = listener.accept()
            peer.close()
    print("IP_DENIED_UNIX_ALLOWED")


def inventory(output, name):
    machines = json.loads(output)
    require(isinstance(machines, list), "machine inventory is not an array")
    matching = [machine for machine in machines
                if isinstance(machine, dict) and machine.get("name") == name]
    require(len(matching) == 1, "expected exactly one owned machine in inventory")
    return matching[0]


def archive_only(bundles, before):
    extracted = bundles / ARCHIVE_SHA256
    uses = bundles / f".{ARCHIVE_SHA256}.uses"
    compressed = bundles / f"{ARCHIVE_SHA256}.mvmpkg.gz"
    require(not extracted.exists(), "extracted bundle remains after confirmed stop")
    require(uses.is_dir() and not any(uses.iterdir()), "bundle-use claim remains")
    checked_file(compressed)
    with compressed.open("rb") as stream:
        require(digest(stream) == before, "compressed archive changed during boot")
    with gzip.open(compressed, "rb") as stream:
        require(digest(stream) == ARCHIVE_SHA256, "retained archive bytes changed")


def run(args):
    require(os.environ.get("MVM_TEST_PUBLIC_CLAUDE_NATIVE") == "1",
            "set MVM_TEST_PUBLIC_CLAUDE_NATIVE=1 to opt into native boot")
    require(platform.system() == "Darwin" and platform.machine() == "arm64",
            "this witness requires native macOS arm64 HVF")
    for path in (args.archive, args.author_key, args.revocation_document,
                 args.revocation_bundle):
        checked_file(path)
    archive, author = args.archive.resolve(), args.author_key.resolve()
    revocations = (args.revocation_document.resolve(), args.revocation_bundle.resolve())
    require(archive.stat().st_size == 333637632, "published archive size mismatch")
    require(all(path.stat().st_size <= 16 * 1024 * 1024 for path in revocations),
            "signed revocation input exceeds 16 MiB")
    with archive.open("rb") as stream:
        require(digest(stream) == ARCHIVE_SHA256, "published archive digest mismatch")
    require(author.stat().st_size == 32, "author key must be 32 raw bytes")
    with author.open("rb") as stream:
        require(digest(stream) == AUTHOR_KEY_SHA256, "published author key mismatch")

    bins = args.bin_dir.resolve()
    cli = bins / "mvmctl"
    for binary, entitlement in (("mvmctl", "com.apple.security.virtualization"),
                                ("mvm-hvf-supervisor", "com.apple.security.hypervisor")):
        path = bins / binary
        require(path.is_file() and os.access(path, os.X_OK), f"missing binary: {path}")
        subprocess.run(["codesign", "--verify", "--strict", str(path)], check=True,
                       capture_output=True)
        details = subprocess.run(["codesign", "-d", "--entitlements", "-", str(path)],
                                 check=True, capture_output=True, text=True)
        require(re.search(r"\[Key\]\s+" + re.escape(entitlement)
                          + r"\s+\[Value\]\s+\[Bool\] true",
                          details.stdout + details.stderr),
                f"{binary} lacks its required entitlement")
    require((bins / "mvm-network-endpoint").is_file(), "missing network endpoint")

    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="mvm-public-claude-native-", dir="/tmp")).resolve()
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    name = "public-claude-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    home = root / "home"
    for directory in ("mvm", "cache", "config", "tmp"):
        (home / directory).mkdir(mode=0o700, parents=True)
    policy = evidence / "recipient.sb"
    policy.write_text(sandbox_policy())
    env = {
        "HOME": str(home), "MVM_HOME": str(home / "mvm"),
        "XDG_CACHE_HOME": str(home / "cache"), "XDG_CONFIG_HOME": str(home / "config"),
        "TMPDIR": str(home / "tmp"), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "MVM_SECRET_STORE_BACKEND": "file",
        "MVM_HVF_SUPERVISOR_PATH": str(bins / "mvm-hvf-supervisor"),
        "MVM_SUBSTITUTION_ENDPOINT_PATH": str(bins / "mvm-network-endpoint"),
    }
    sandbox = ["/usr/bin/sandbox-exec", "-f", str(policy)]
    report = {"status": "blocked", "machine_name": name, "archive_sha256": ARCHIVE_SHA256,
              "author_key_id": AUTHOR_KEY_SHA256[:32], "commands": []}
    attempted = False

    def command(label, argv, *, timeout=120, input_bytes=None):
        started = time.monotonic()
        with (evidence / f"{label}.stdout").open("wb") as stdout, \
                (evidence / f"{label}.stderr").open("wb") as stderr:
            process = subprocess.Popen(sandbox + [str(arg) for arg in argv],
                                       env=env, cwd=root, stdin=subprocess.PIPE
                                       if input_bytes is not None else subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                process.communicate(input=input_bytes, timeout=timeout)
            except BaseException as error:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGINT)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=10)
                if isinstance(error, subprocess.TimeoutExpired):
                    raise Blocked(f"{label} exceeded {timeout}s") from error
                raise
        report["commands"].append({"label": label, "exit": process.returncode,
                                   "seconds": round(time.monotonic() - started, 2)})
        require(process.returncode == 0, f"{label} failed (see private evidence)")
        return (evidence / f"{label}.stdout").read_text(errors="replace")

    def mvm(label, *argv, timeout=120, input_bytes=None):
        return command(label, [cli, *argv], timeout=timeout, input_bytes=input_bytes)

    bundles = home / "mvm/bundles"
    try:
        command("sandbox-probe", [sys.executable, "-c",
                "import importlib.util,sys; s=importlib.util.spec_from_file_location("
                "'witness',sys.argv[1]); m=importlib.util.module_from_spec(s); "
                "s.loader.exec_module(m); m.prove_offline(sys.argv[2])",
                str(Path(__file__).resolve()), str(root / "probe.sock")], timeout=15)
        require("IP_DENIED_UNIX_ALLOWED" in
                (evidence / "sandbox-probe.stdout").read_text(), "offline proof missing")
        mvm("trust", "trust", "add", author)
        mvm("revocations", "image", "revocations", "update",
            "--document", revocations[0], "--bundle", revocations[1])
        mvm("fake-secret", "secret", "set", "ANTHROPIC_API_KEY",
            "--provider", "anthropic", "--value", "-", input_bytes=FAKE_SECRET)
        mvm("install", "bundle", "install", archive, timeout=1200)
        cached = bundles / f"{ARCHIVE_SHA256}.mvmpkg.gz"
        checked_file(cached)
        with cached.open("rb") as stream:
            before = digest(stream)
        require(not (bundles / ARCHIVE_SHA256).exists(), "install did not leave archive-only idle")
        report["idle_before_kib"] = int(subprocess.check_output(["du", "-sk", bundles]).split()[0])
        attempted = True
        mvm("run", "machine", "run", "-d", "--name", name, "--ttl", "15m",
            "--hypervisor", "hvf", "--profile", "standard",
            "--secret", "ANTHROPIC_API_KEY", "--allow-host", "api.anthropic.com:443",
            "--no-build", archive, timeout=1800)
        running = inventory(mvm("running", "machine", "ps", "--all", "--json"), name)
        require(running.get("status") == "running" and running.get("last_started_at")
                and running.get("backend") == "hvf", "guest-ready machine is not running")
        report["started_at"] = running["last_started_at"]
        report["active_kib"] = int(subprocess.check_output(["du", "-sk", bundles]).split()[0])
        mvm("stop", "machine", "stop", name, "--yes", timeout=180)
        attempted = False
        stopped = inventory(mvm("stopped", "machine", "ps", "--all", "--json"), name)
        require(stopped.get("status") == "stopped", "machine not stopped")
        archive_only(bundles, before)
        report["idle_after_kib"] = int(subprocess.check_output(["du", "-sk", bundles]).split()[0])
        report["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        report["blocker"] = f"{type(error).__name__}: {error}"
    finally:
        if attempted:
            try:
                mvm("cleanup-stop", "machine", "stop", name, "--yes", timeout=180)
            except (Exception, KeyboardInterrupt) as error:
                report["cleanup_error"] = f"{type(error).__name__}: {error}"
        (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "evidence": str(evidence),
                      "blocker": report.get("blocker")}))
    return 0 if report["status"] == "passed" else 1


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path,
                        help="directory containing source-matched, signed mvmctl and HVF helpers")
    parser.add_argument("--archive", required=True, type=Path,
                        help="local published agent/claude@2.0.1 .mvmpkg")
    parser.add_argument("--author-key", required=True, type=Path,
                        help="local 32-byte public publisher key")
    parser.add_argument("--revocation-document", required=True, type=Path,
                        help="local published signed revocation document")
    parser.add_argument("--revocation-bundle", required=True, type=Path,
                        help="signature bundle for the revocation document")
    args = parser.parse_args()
    try:
        return run(args)
    except (Blocked, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"blocked before native boot: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
