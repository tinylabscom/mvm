#!/usr/bin/env python3
"""Platform-aware dev-tier package witness; never builds binaries or seals prod images.

With previously prepared, source-matched host binaries:
  python3 scripts/check-oci-bundle-smoke.py --backend hvf --bin-dir "$CARGO_TARGET_DIR/debug"

--self-test never invokes mvmctl. Live artifacts remain in a new private /tmp
directory. Only evidence/ is for review: producer/ contains private signing keys.
Linux requires root (use explicit sudo -n), KVM, and --linux-test-environment
unless invoked by the repository GCP runner. That runner provisions Firecracker
and jailer, NOT mvmctl or its helpers; provision --bin-dir separately first.
Its dev-env target directory resolves to /opt/mvm/.mvm-test/target. After
separately arranging source-matched Linux binaries in its debug/ directory:
  just lab::gcp-kvm python3 scripts/check-oci-bundle-smoke.py --backend firecracker --bin-dir /opt/mvm/.mvm-test/target/debug
This command needs operator authorization for billing and source transfer.
Linux proves fresh HOME/install-path isolation, not producer filesystem denial.
Production admission and enforced Linux producer-file denial are separate witnesses.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


LIMIT = 2 * 1024 * 1024
IMAGE = "docker.io/library/alpine:3.20"
BACKENDS = ("hvf", "firecracker", "libkrun", "qemu")
SYSTEM_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


class Blocked(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Blocked(message)


def reject_overrides(env):
    forbidden = [
        key for key in env
        if key.startswith("MVM_") and (
            ("SKIP" in key and ("VERIFY" in key or "SIGN" in key))
            or key in {
                "MVM_MATERIALIZE_BUILDER_VM", "MVM_ALLOW_LOCAL_BUILDER_BUILD",
                "MVM_IMAGES_DIR", "MVM_BOOT_IMAGE",
            }
        )
    ]
    require(not forbidden, "refusing verification/build overrides: " + ", ".join(forbidden))


def policy(producer):
    # Deny IPv4/IPv6 TCP/UDP including loopback proxies; retain AF_UNIX IPC.
    return (
        '(version 1)\n(allow default)\n'
        '(deny network-outbound (remote ip "*:*"))\n'
        f'(deny file-read* (subpath {json.dumps(str(producer.resolve()))}))\n'
    )


PROBE = r"""
import errno, os, socket, sys
for family, address in [
    (socket.AF_INET, ("1.1.1.1", 443)),
    (socket.AF_INET, ("127.0.0.1", 443)),
    (socket.AF_INET6, ("2606:4700:4700::1111", 443)),
]:
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(family, kind) as s:
            s.settimeout(1)
            try:
                s.connect(address)
            except OSError as e:
                if e.errno not in (errno.EPERM, errno.EACCES):
                    raise SystemExit("not a policy denial: " + str(e))
            else:
                raise SystemExit("IP outbound was permitted")
path = sys.argv[1]
with socket.socket(socket.AF_UNIX) as listener:
    listener.bind(path)
    listener.listen(1)
    listener.settimeout(2)
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(2)
        client.connect(path)
        peer, _ = listener.accept()
        with peer:
            client.sendall(b"x")
            assert peer.recv(1) == b"x"
os.unlink(path)
try:
    open(sys.argv[2], "rb")
except OSError as e:
    if e.errno not in (errno.EPERM, errno.EACCES):
        raise
else:
    raise SystemExit("producer read was permitted")
print("IP_DENIED_UNIX_ALLOWED_PRODUCER_DENIED")
"""


LINUX_PROBE = r"""
import errno, fcntl, os, socket, struct, sys
from pathlib import Path
assert os.readlink("/proc/self/ns/net") == sys.argv[1], "wrong namespace"
assert socket.if_nameindex() == [(1, "lo")], "unexpected network interface"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    flags = fcntl.ioctl(s, 0x8913, struct.pack("256s", b"lo"))
    assert not struct.unpack_from("H", flags, 16)[0] & 1, "loopback is UP"
ipv4_routes = Path("/proc/net/route").read_text()
assert all(not line.strip() or line.split()[0] == "Iface"
           for line in ipv4_routes.splitlines()), "IPv4 route: " + repr(ipv4_routes)
for line in Path("/proc/net/ipv6_route").read_text().splitlines():
    fields = line.split()
    assert int(fields[8], 16) & 0x200, "non-reject IPv6 route"
for family, address in [
    (socket.AF_INET, ("1.1.1.1", 443)),
    (socket.AF_INET, ("127.0.0.1", 443)),
    (socket.AF_INET6, ("2606:4700:4700::1111", 443)),
    (socket.AF_INET6, ("::1", 443)),
]:
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        try:
            s = socket.socket(family, kind)
        except OSError as e:
            if family == socket.AF_INET6 and e.errno == errno.EAFNOSUPPORT:
                continue
            raise
        with s:
            s.settimeout(1)
            try:
                s.connect(address)
            except OSError as e:
                if e.errno not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL,
                                   errno.EPERM, errno.EACCES):
                    raise SystemExit(f"not isolation evidence for {family}/{kind}/{address}: {e}")
            else:
                raise SystemExit("IP was permitted")
a, b = socket.socketpair(socket.AF_UNIX)
with a, b:
    a.settimeout(2)
    b.settimeout(2)
    a.sendall(b"x")
    assert b.recv(1) == b"x"
print("NO_IP_INTERFACES_OR_ROUTES_UNIX_ALLOWED")
"""


class LinuxNamespace:
    """One anonymous namespace, held by an owned process, never host networking."""

    def __init__(self):
        self.proc = None

    def start(self, env, report):
        unshare = shutil.which("unshare", path=SYSTEM_PATH)
        nsenter = shutil.which("nsenter", path=SYSTEM_PATH)
        require(unshare and nsenter, "requires util-linux unshare and nsenter")
        self.proc = subprocess.Popen(
            [unshare, "--net", "--", sys.executable, "-c",
             "import os,sys; print(os.readlink('/proc/self/ns/net'), flush=True); "
             "sys.stdin.buffer.read()"],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        with selectors.DefaultSelector() as selector:
            selector.register(self.proc.stdout, selectors.EVENT_READ)
            require(bool(selector.select(10)), "unshare readiness timed out")
            identity = os.read(self.proc.stdout.fileno(), 4096).decode().strip()
        require(re.fullmatch(r"net:\[\d+\]", identity) is not None,
                f"unshare failed: {identity}")
        require(identity != os.readlink("/proc/self/ns/net"), "unshare retained host network")
        report["network_namespace"] = identity
        return [nsenter, f"--net=/proc/{self.proc.pid}/ns/net", "--"], identity

    def close(self):
        if self.proc is not None:
            self.proc.stdin.close()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
            finally:
                self.proc.stdout.close()


def validate_platform(backend, system, machine, linux_test_environment, uid):
    if backend == "hvf":
        require(system == "Darwin" and machine == "arm64",
                "hvf requires native macOS arm64; no skip/fallback")
    else:
        require(system == "Linux" and machine in ("x86_64", "aarch64"),
                "non-HVF witness requires Linux x86_64/aarch64 with KVM")
        require(linux_test_environment,
                "Linux witness requires repository GCP runner or --linux-test-environment")
        require(uid == 0, "Linux witness requires root; explicitly invoke with sudo -n")


def required_binaries(backend):
    return ("mvmctl", "mvm-network-endpoint") + {
        "hvf": ("mvm-hvf-supervisor",),
        "libkrun": ("mvm-libkrun-supervisor",),
        "firecracker": (),
        "qemu": (),
    }[backend]


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def installed_snapshot(directory):
    require(directory.is_dir(), "content-addressed install directory absent")
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), "installed asset is a symlink")
        if path.is_file():
            stat = path.stat()
            result[str(path.relative_to(directory))] = {
                "sha256": digest(path), "inode": stat.st_ino,
                "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            }
    require(bool(result), "empty bundle install")
    return result


def require_reused_install(initial, current):
    require(all(current.get(name) == value for name, value in initial.items()),
            "installed content was rewritten")
    # Admission may create its ordinary hash memoization files on first use.
    # Those are not signed payloads; every originally installed file must still
    # retain its exact bytes, inode, size, and modification time.
    added = current.keys() - initial.keys()
    require(all(name.endswith(".sha256cache")
                and name.removesuffix(".sha256cache") in initial for name in added),
            "unexpected file added to installed bundle")


class Runner:
    def __init__(self, evidence, report):
        self.evidence, self.report = evidence, report

    def run(self, label, argv, env, timeout=120):
        argv = [str(arg) for arg in argv]
        record = {"label": label, "argv": argv, "timeout_seconds": timeout,
                  "mvm_home": env.get("MVM_HOME")}
        self.report["commands"].append(record)
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        started = time.monotonic()
        proc = subprocess.Popen(
            argv, cwd=self.evidence, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        record["pid"] = proc.pid
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
                selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    remaining = timeout - (time.monotonic() - started)
                    require(remaining > 0, f"{label}: timed out")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buf = buffers[key.data]
                        room = LIMIT - len(buf)
                        buf.extend(chunk[:room])
                        require(len(chunk) <= room, f"{label}: output limit exceeded")
                proc.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
        except BaseException:
            # Kill the owned group even when its leader exited but a child still
            # holds a pipe. Do this before poll/wait can reap the leader.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=10)
            raise
        finally:
            # This group was created here, never discovered by process name.
            # Native machine teardown follows separately even on cancellation.
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)
            proc.stdout.close()
            proc.stderr.close()
            record["returncode"] = proc.returncode
            record["elapsed_seconds"] = round(time.monotonic() - started, 3)
            for stream, data in buffers.items():
                path = self.evidence / f"{label}.{stream}"
                path.write_bytes(data)
                record[stream] = path.name
        require(proc.returncode == 0,
                f"{label}: exit {proc.returncode}; see bounded command logs")
        return {key: value.decode("utf-8", errors="replace") for key, value in buffers.items()}


def isolated_env(home, bins, backend):
    # No inherited proxy, credentials, MVM cache overrides, config, or bypasses.
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin" if backend == "hvf" else SYSTEM_PATH,
           "LANG": "en_US.UTF-8",
           "HOME": str(home), "MVM_HOME": str(home / "mvm"),
           "XDG_CACHE_HOME": str(home / "cache"),
           "XDG_CONFIG_HOME": str(home / "config"),
           "TMPDIR": str(home / "tmp"),
           "MVM_SUBSTITUTION_ENDPOINT_PATH": str(bins / "mvm-network-endpoint")}
    if backend in ("hvf", "libkrun"):
        env[f"MVM_{backend.upper()}_SUPERVISOR_PATH"] = str(bins / f"mvm-{backend}-supervisor")
    for path in ("mvm", "cache", "config", "tmp"):
        (home / path).mkdir(mode=0o700, parents=True)
    return env


def live(args):
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix=f"mvm-{args.backend}-bundle-", dir="/tmp")).resolve()
    evidence = root / "evidence"
    evidence.mkdir()
    report = {"status": "blocked", "scope": f"{args.backend}-dev-not-production",
              "backend": args.backend,
              "root": str(root), "commands": [], "cleanup": []}
    runner = Runner(evidence, report)
    print(f"Evidence: {evidence}\nPrivate producer retained; do not publish {root / 'producer'}")
    active = []
    recipient_env = None
    offline = []
    cli = None
    namespace = LinuxNamespace()
    try:
        reject_overrides(os.environ)
        validate_platform(args.backend, platform.system(), platform.machine(),
                          args.linux_test_environment
                          or bool(os.environ.get("MVM_GCP_KVM_RESULTS_DIR")), os.geteuid())
        bins = Path(args.bin_dir).resolve()
        for name in required_binaries(args.backend):
            require((bins / name).is_file() and os.access(bins / name, os.X_OK),
                    f"missing executable: {bins / name}; provision binaries, no host builds")
        cli = bins / "mvmctl"
        producer = root / "producer"
        recipient = root / "recipient"
        producer_env = isolated_env(producer, bins, args.backend)
        recipient_env = isolated_env(recipient, bins, args.backend)
        report["isolation"] = {"producer": str(producer), "recipient": str(recipient),
                               "recipient_initially_empty": True,
                               "producer_file_denial_enforced": args.backend == "hvf"}
        sentinel = producer / "read-denial-probe"
        sentinel.write_text("not a secret\n")
        if args.backend == "hvf":
            require(shutil.which("sandbox-exec") and shutil.which("codesign"),
                    "missing sandbox-exec or codesign")
            sandbox = evidence / "recipient.sb"
            sandbox.write_text(policy(producer))
            offline = ["/usr/bin/sandbox-exec", "-f", sandbox]
            probe_argv = [sys.executable, "-c", PROBE, recipient / "probe.sock", sentinel]
            probe_marker = "IP_DENIED_UNIX_ALLOWED_PRODUCER_DENIED"
            runner.run("supervisor-signature", ["/usr/bin/codesign", "--verify",
                       "--strict", bins / "mvm-hvf-supervisor"], producer_env)
        else:
            kvm = Path("/dev/kvm")
            require(kvm.exists() and stat.S_ISCHR(kvm.stat().st_mode)
                    and os.access(kvm, os.R_OK | os.W_OK), "requires accessible /dev/kvm")
            runner.run("kvm-api", [sys.executable, "-c",
                       "import fcntl,os; fd=os.open('/dev/kvm',os.O_RDWR); "
                       "assert fcntl.ioctl(fd,0xAE00,0)==12; os.close(fd)"],
                       recipient_env, timeout=15)
            tools = {"firecracker": ("firecracker", "jailer"),
                     "libkrun": (), "qemu": (f"qemu-system-{platform.machine()}",)}[args.backend]
            report["backend_executables"] = {}
            for name in tools:
                path = shutil.which(name, path=SYSTEM_PATH)
                require(path, f"missing {name}; use repository test environment provisioning")
                report["backend_executables"][name] = path
            if args.backend == "qemu":
                require(os.access("/dev/vhost-vsock", os.R_OK | os.W_OK),
                        "qemu requires accessible /dev/vhost-vsock")
            offline, identity = namespace.start(recipient_env, report)
            probe_argv = [sys.executable, "-c", LINUX_PROBE, identity]
            probe_marker = "NO_IP_INTERFACES_OR_ROUTES_UNIX_ALLOWED"
            report["isolation"]["limitation"] = (
                "Linux producer files remain readable to root; proof is fresh HOME, "
                "public-only handoff and unchanged installed paths, not filesystem denial. "
                "Enforced denial requires a repository-supported confinement launcher."
            )
        probe = runner.run("sandbox-probe", offline + probe_argv, recipient_env, timeout=15)
        require(probe_marker in probe["stdout"], "offline isolation proof absent")
        archive = evidence / "alpine.mvmpkg"
        debug = evidence / "build-report.json"
        built = runner.run("bundle-build", [cli, "bundle", "build", "--image", IMAGE,
                           "--out", archive, "--debug-out", debug], producer_env,
                           timeout=args.build_timeout)
        match = re.search(r"^OCI digest: (sha256:[0-9a-f]{64})$", built["stdout"], re.M)
        require(match is not None, "build did not report resolved OCI digest")
        package_sha = digest(archive)
        summary = json.loads(debug.read_text())
        require(summary["bundle_sha256"] == package_sha, "debug/package digest mismatch")
        require(summary["manifest"]["schema_version"] == 4, "expected schema 4 package")
        report.update(package_sha256=package_sha, source_oci_digest=match.group(1))
        # Existing trust surface exports this PUBLIC file. Never open the seed.
        public = Path(producer_env["MVM_HOME"]) / "keys" / "host-signer.pub"
        require(not public.is_symlink() and public.stat().st_size == 32,
                "missing raw 32-byte host signer public key")
        public_copy = evidence / "publisher.pub"
        public_copy.write_bytes(public.read_bytes())
        runner.run("trust-add", offline + [cli, "trust", "add", public_copy], recipient_env)
        runner.run("bundle-verify", offline + [cli, "bundle", "fetch", archive, "--json"],
                   recipient_env)
        runner.run("bundle-install", offline + [cli, "bundle", "install", archive],
                   recipient_env)
        installed = Path(recipient_env["MVM_HOME"]) / "bundles" / package_sha
        initial = installed_snapshot(installed)
        report["installed_assets"] = initial
        for attempt in ("first", "repeat"):
            name = f"bundle-{root.name.rsplit('-', 1)[-1]}-{attempt}"
            marker = f"{args.backend.upper()}_OCI_BUNDLE_{attempt.upper()}_OK"
            active.append(name)
            output = runner.run(attempt, offline + [
                cli, "machine", "run", "--name", name, "--hypervisor", args.backend,
                "--manifest", archive, "--", "/bin/sh", "-c", f"printf '%s\\n' {marker}",
            ], recipient_env, timeout=args.run_timeout)
            require(marker in output["stdout"].splitlines(), f"{attempt}: guest marker absent")
            require(f"bundle {package_sha} is already installed" in output["stderr"],
                    f"{attempt}: missing verified content-addressed reuse evidence")
            require(str(producer) not in output["stdout"] + output["stderr"],
                    f"{attempt}: runtime output references producer")
            runner.run(f"{attempt}-stop", offline + [
                cli, "machine", "stop", name, "--yes"], recipient_env)
            active.remove(name)
            report["cleanup"].append({"name": name, "status": "stopped"})
            require_reused_install(initial, installed_snapshot(installed))
            report[attempt] = {"marker": marker, "exit_code": 0, "install_unchanged": True}
        probe = runner.run("sandbox-probe-after", offline + probe_argv,
                           recipient_env, timeout=15)
        require(probe_marker in probe["stdout"], "offline isolation changed during witness")
        report["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        report["blocker"] = str(error) or type(error).__name__
    finally:
        for name in active:
            try:
                runner.run(f"cleanup-{name}", offline + [
                    cli, "machine", "stop", name, "--yes"], recipient_env, timeout=60)
                report["cleanup"].append({"name": name, "status": "stopped"})
            except (Exception, KeyboardInterrupt) as error:
                report["cleanup"].append({"name": name, "status": "FAILED", "error": str(error)})
                report["status"] = "blocked"
        try:
            namespace.close()
        except (Exception, KeyboardInterrupt) as error:
            report["cleanup"].append({"namespace": "FAILED", "error": str(error)})
            report["status"] = "blocked"
        (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        results = os.environ.get("MVM_GCP_KVM_RESULTS_DIR")
        if results:
            # The remote runner downloads this directory; never copy private homes.
            shutil.copytree(evidence, Path(results) / root.name)
    print(json.dumps({"status": report["status"], "report": str(evidence / "report.json"),
                      "blocker": report.get("blocker")}))
    return 0 if report["status"] == "passed" else 1


class HelperTests(unittest.TestCase):
    def test_cli_backend_required_and_validated(self):
        for args in ([], ["--backend", "linux-kvm"], ["--backend", "unknown"]):
            result = subprocess.run([sys.executable, __file__, *args],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)

    def test_namespace_lifecycle_without_unshare(self):
        for identity, ready, succeeds in [
            (b"net:[123]\n", True, True),
            (b"net:[456]\n", True, False),
            (b"unshare: Operation not permitted\n", True, False),
            (b"", False, False),
        ]:
            namespace = LinuxNamespace()
            report = {}
            process = mock.MagicMock(pid=42)
            selector = mock.MagicMock()
            selector.__enter__.return_value.select.return_value = [True] if ready else []
            with mock.patch.object(shutil, "which", side_effect=lambda name, **kw: "/usr/bin/" + name), \
                    mock.patch.object(subprocess, "Popen", return_value=process) as spawn, \
                    mock.patch.object(selectors, "DefaultSelector", return_value=selector), \
                    mock.patch.object(os, "read", return_value=identity), \
                    mock.patch.object(os, "readlink", return_value="net:[456]"):
                try:
                    if succeeds:
                        prefix, found = namespace.start({}, report)
                        self.assertEqual(prefix, ["/usr/bin/nsenter", "--net=/proc/42/ns/net", "--"])
                        self.assertEqual(found, "net:[123]")
                        self.assertEqual(report["network_namespace"], found)
                    else:
                        with self.assertRaises(Blocked):
                            namespace.start({}, report)
                finally:
                    namespace.close()
                self.assertEqual(spawn.call_args.args[0][:3], ["/usr/bin/unshare", "--net", "--"])
                process.stdin.close.assert_called_once()
                process.wait.assert_called_once_with(timeout=10)

    def test_platform_gates(self):
        validate_platform("hvf", "Darwin", "arm64", False, 501)
        for backend in BACKENDS[1:]:
            validate_platform(backend, "Linux", "x86_64", True, 0)
            validate_platform(backend, "Linux", "aarch64", True, 0)
            for system, arch, opted_in, uid in [
                ("Darwin", "arm64", True, 0), ("Linux", "x86_64", False, 0),
                ("Linux", "x86_64", True, 1000), ("Linux", "i686", True, 0),
            ]:
                with self.assertRaises(Blocked):
                    validate_platform(backend, system, arch, opted_in, uid)
        with self.assertRaises(Blocked):
            validate_platform("hvf", "Linux", "aarch64", True, 0)
        with self.assertRaises(Blocked):
            validate_platform("hvf", "Darwin", "x86_64", False, 501)

    def test_helper_requirements_and_homes(self):
        self.assertNotIn("linux-kvm", BACKENDS)
        self.assertIn("mvm-hvf-supervisor", required_binaries("hvf"))
        self.assertIn("mvm-libkrun-supervisor", required_binaries("libkrun"))
        self.assertNotIn("mvm-hvf-supervisor", required_binaries("firecracker"))
        with tempfile.TemporaryDirectory(dir="/tmp") as temp:
            root = Path(temp)
            for backend in BACKENDS:
                home = root / backend
                env = isolated_env(home, Path("/prepared/bin"), backend)
                self.assertEqual(env["HOME"], str(home))
                self.assertEqual(env["MVM_HOME"], str(home / "mvm"))
                self.assertEqual(list((home / "mvm").iterdir()), [])
                self.assertNotIn("HTTP_PROXY", env)
                self.assertNotIn("CARGO_HOME", env)
                if backend != "hvf":
                    self.assertNotIn("MVM_HVF_SUPERVISOR_PATH", env)

    def test_linux_probe_without_linux_syscalls(self):
        import errno
        import socket
        import struct
        import types

        def run_probe(*, flags=0, interfaces=None, route=False,
                      route_text="Iface\tDestination\tGateway\tFlags\n",
                      connect_errno=errno.ENETUNREACH):
            fake_socket = mock.MagicMock()
            for name in ("AF_INET", "AF_INET6", "AF_UNIX", "SOCK_STREAM", "SOCK_DGRAM"):
                setattr(fake_socket, name, getattr(socket, name))
            fake_socket.if_nameindex.return_value = interfaces or [(1, "lo")]
            sock = fake_socket.socket.return_value
            sock.__enter__.return_value = sock
            sock.connect.side_effect = (
                OSError(connect_errno, "probe") if connect_errno is not None else None
            )
            a, b = mock.MagicMock(), mock.MagicMock()
            b.recv.return_value = b"x"
            fake_socket.socketpair.return_value = a, b
            routes = {"/proc/net/route": route_text + ("external\n" if route else ""),
                      "/proc/net/ipv6_route": "0 00 0 00 0 0 0 0 00200200 lo\n"}
            fake_path = lambda path: types.SimpleNamespace(read_text=lambda: routes[path])
            modules = {
                "socket": fake_socket,
                "fcntl": types.SimpleNamespace(ioctl=lambda *args: b"\0" * 16
                                               + struct.pack("H", flags) + b"\0" * 238),
                "os": types.SimpleNamespace(readlink=lambda path: "net:[123]"),
                "sys": types.SimpleNamespace(argv=["probe", "net:[123]"]),
                "pathlib": types.SimpleNamespace(Path=fake_path),
            }
            with mock.patch.dict(sys.modules, modules):
                exec(compile(LINUX_PROBE, "<linux-probe>", "exec"), {"print": lambda *args: None})
            return fake_socket

        sockets = run_probe()
        self.assertEqual(sockets.socket.return_value.connect.call_count, 8)
        sockets = run_probe(connect_errno=errno.EADDRNOTAVAIL)
        self.assertEqual(sockets.socket.return_value.connect.call_count, 8)
        for empty_table in ("", "\n", "Iface\tDestination\tGateway\tFlags\n\n"):
            sockets = run_probe(route_text=empty_table)
            self.assertEqual(sockets.socket.return_value.connect.call_count, 8)
        for values in ({"flags": 1}, {"interfaces": [(1, "lo"), (2, "eth0")]},
                       {"route": True}):
            with self.assertRaises(AssertionError):
                run_probe(**values)
        for error in (errno.ECONNREFUSED, errno.ETIMEDOUT, None):
            with self.assertRaises(SystemExit):
                run_probe(connect_errno=error)

    def test_overrides(self):
        reject_overrides({"MVM_HOME": "/tmp/ignored"})
        for key in ("MVM_SKIP_COSIGN_VERIFY", "MVM_SKIP_HASH_VERIFY",
                    "MVM_MATERIALIZE_BUILDER_VM", "MVM_ALLOW_LOCAL_BUILDER_BUILD"):
            with self.assertRaises(Blocked):
                reject_overrides({key: "0"})

    def test_policy(self):
        text = policy(Path('/tmp/a"b'))
        self.assertIn('(remote ip "*:*")', text)
        self.assertIn('a\\"b', text)
        self.assertNotIn("deny network*", text)

    def test_runner_and_snapshot(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temp:
            directory = Path(temp)
            runner = Runner(directory, {"commands": []})
            env = {"PATH": "/usr/bin:/bin"}
            out = runner.run("ok", [sys.executable, "-c", "print('ok')"], env)
            self.assertEqual(out["stdout"], "ok\n")
            with self.assertRaises(Blocked):
                runner.run("fail", [sys.executable, "-c", "raise SystemExit(3)"], env)
            with self.assertRaises(Blocked):
                runner.run("timeout", [sys.executable, "-c",
                           "import signal; signal.pause()"], env, timeout=0.1)
            with self.assertRaises(Blocked):
                runner.run("overflow", [sys.executable, "-c",
                           f"import sys; sys.stdout.write('x' * {LIMIT + 1})"], env)
            self.assertEqual((directory / "overflow.stdout").stat().st_size, LIMIT)
            before = installed_snapshot(directory)
            self.assertEqual(before, installed_snapshot(directory))
            require_reused_install(before, {**before, "ok.stdout.sha256cache": {}})
            with self.assertRaises(Blocked):
                require_reused_install(before, {**before, "ok.stdout": {}})
            with self.assertRaises(Blocked):
                require_reused_install(before, {**before, "unknown.sha256cache": {}})
            (directory / "new").write_text("changed")
            self.assertNotEqual(before, installed_snapshot(directory))


def interrupted(signum, _frame):
    raise KeyboardInterrupt(f"received signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=BACKENDS, required=True)
    parser.add_argument("--linux-test-environment", action="store_true",
                        help="confirm this is an explicitly supplied Linux KVM test/dev host")
    parser.add_argument("--bin-dir", default=str(Path(os.environ.get(
        "CARGO_TARGET_DIR", "target")) / "debug"))
    parser.add_argument("--build-timeout", type=int, default=900)
    parser.add_argument("--run-timeout", type=int, default=240)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(HelperTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    require(args.build_timeout > 0 and args.run_timeout > 0, "timeouts must be positive")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    return live(args)


if __name__ == "__main__":
    sys.exit(main())
