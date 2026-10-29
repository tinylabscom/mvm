#!/usr/bin/env python3
"""Native SDK pack witness; invoke only on an explicitly authorized KVM host.

This is a test driver, not a cloud lifecycle or a source-build helper.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HELLO = "pack-build-native-sdk-witness"
REVISION = re.compile(r"[0-9a-f]{40}")
LIMIT = 2 * 1024 * 1024
STREAM_LIMIT = 16 * 1024 * 1024
TAMPER_SOURCE_LIMIT = 16 * 1024 ** 3
TAMPER_EXPANDED_LIMIT = 16 * 1024 ** 3
TAMPER_OUTPUT_LIMIT = 16 * 1024 ** 3
TAMPER_SECONDS = 60
TAMPER_REFUSAL = r'artifact [^\r\n]*rootfs\.ext4 sha256 mismatch: manifest says [0-9a-f]{64}, actual [0-9a-f]{64}'
SEALED_REFUSAL = re.escape("the run needs development-only agent verbs (an interactive, ad-hoc command, or dev-profile launch), but the bundle is sealed-prod")
RUNTIME_REFUSAL = re.escape("the published OCI guest runtime is not prepared; run `mvmctl bootstrap` first")


def require_hello(output):
    if HELLO not in output.decode("utf-8", errors="replace").splitlines():
        raise RuntimeError("archive entrypoint did not emit the SDK fixture's hello line")


def walk_error(error):
    raise error


def regular_reader(path):
    """Open each path component without following links, including parents."""
    path = Path(path).absolute()
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        result = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=fd)
        if not stat.S_ISREG(os.fstat(result).st_mode):
            os.close(result)
            raise ValueError("evidence is not a regular file")
        return os.fdopen(result, "rb")
    finally:
        os.close(fd)


def bounded_run(argv, *, cwd, env, timeout, on_start=None, **unused):
    """Drain both pipes independently; overflow is never positive evidence."""
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    if on_start is not None:
        on_start(process.pid)
    deadline = time.monotonic() + timeout
    retained = {process.stdout: bytearray(), process.stderr: bytearray()}
    overflow = False
    selector = selectors.DefaultSelector()
    for pipe in retained:
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _ in selector.select(min(remaining, 1)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                data = retained[key.fileobj]
                capacity = STREAM_LIMIT - len(data)
                data.extend(chunk[:capacity])
                overflow |= len(chunk) > capacity
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        result = subprocess.CompletedProcess(argv, process.returncode,
                                             bytes(retained[process.stdout]),
                                             bytes(retained[process.stderr]))
        result.overflow = overflow
        return result
    except subprocess.TimeoutExpired as error:
        error.stdout = bytes(retained[process.stdout])
        error.stderr = bytes(retained[process.stderr])
        # Only the session created by this invocation is signalled.
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
        raise
    finally:
        selector.close()
        for pipe in retained:
            pipe.close()


def digest(path, deadline=None):
    h = hashlib.sha256()
    deadline = deadline if deadline is not None else time.monotonic() + 60
    with regular_reader(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            if time.monotonic() > deadline:
                raise ValueError("disk hash deadline exceeded")
            h.update(chunk)
    return h.hexdigest()


def members(path, wanted, deadline=None):
    """Read bounded regular members, never extract or follow archive links."""
    found = {}
    deadline = deadline if deadline is not None else time.monotonic() + 60
    with regular_reader(path) as stream:
        for index in range(4097):
            header = stream.read(512)
            if header == b"\0" * 512:
                break
            if len(header) != 512:
                raise ValueError("incomplete raw tar header")
            if index >= 4096 or time.monotonic() > deadline:
                raise ValueError("tar header/deadline bound exceeded")
            member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE,
                               tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                raise ValueError("extended tar headers not accepted for evidence")
            name = member.name.removeprefix("./")
            if name in wanted:
                if name in found or not member.isfile() or member.size > LIMIT:
                    raise ValueError(f"unsafe or duplicate evidence member: {name}")
                found[name] = stream.read(member.size)
                if len(found[name]) != member.size:
                    raise ValueError("incomplete evidence member")
                stream.seek((-member.size) % 512, os.SEEK_CUR)
            else:
                stream.seek(((member.size + 511) // 512) * 512, os.SEEK_CUR)
    return found


def guard(binary):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("requires native x86_64 Linux")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("requires readable and writable /dev/kvm")
    if not shutil.which("firecracker"):
        raise RuntimeError("requires the existing runner's pinned Firecracker")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("mvmctl must be an explicit existing executable")


def source_identity(expected):
    result = bounded_run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                         cwd=ROOT, env={"PATH": os.environ.get("PATH", "")}, timeout=30)
    if result.returncode or result.overflow:
        raise RuntimeError("source identity command failed or overflowed")
    actual = result.stdout.decode("ascii").strip()
    if actual != expected:
        raise RuntimeError("source revision B does not match the executing checkout HEAD")
    paths = [
        "scripts/pack-build-native.py", "scripts/pack-build-native-fixture.py",
        "crates/mvm-sdk/sdks/python/mvm/packs.py",
        "crates/mvm-cli/src/commands/pack/build.rs",
        "crates/mvm-build/src/pipeline/dev_build.rs",
        "crates/mvm-build/src/pipeline/frozen.rs",
        "crates/mvm-build/src/builder_vm_runtime.rs",
    ]
    return {"revision": actual,
            "source_sha256": {path: digest(ROOT / path) for path in paths},
            "git_argv": ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            "git_exit": result.returncode}


class Commands:
    def __init__(self, binary, evidence, run=bounded_run):
        self.binary = str(binary)
        self.evidence = evidence
        self.run_process = run
        self.sequence = 0
        self.sessions = {}

    def call(self, home, label, args, *, refusal=None, timeout=1800):
        self.sequence += 1
        prefix = self.evidence / f"{self.sequence:02d}-{label}"
        argv = [self.binary, *map(str, args)]
        # No ambient MVM_HOME, runtime selectors, cloud credentials or paid API keys.
        env = {key: os.environ[key] for key in ("PATH", "LANG", "TERM") if key in os.environ}
        env.update(HOME=str(home / "user"), MVM_HOME=str(home),
                   XDG_CACHE_HOME=str(home / "xdg-cache"), NO_COLOR="1",
                   RUST_LOG="info", MVM_BUILDER_BACKEND="firecracker")
        (home / "user").mkdir(parents=True, exist_ok=True)
        record = {"argv": argv, "cwd": str(ROOT), "home": str(home),
                  "started_unix": time.time(), "timeout_seconds": timeout}
        try:
            def started(pid):
                self.sessions.setdefault(str(home), set()).add(pid)
                record["owned_session"] = pid
            result = self.run_process(argv, cwd=ROOT, env=env,
                                      timeout=timeout, on_start=started)
            prefix.with_suffix(".stdout").write_bytes(result.stdout[:STREAM_LIMIT])
            prefix.with_suffix(".stderr").write_bytes(result.stderr[:STREAM_LIMIT])
            record["exit"] = result.returncode
            record["stream_overflow"] = (getattr(result, "overflow", False) or
                                         len(result.stdout) > STREAM_LIMIT or
                                         len(result.stderr) > STREAM_LIMIT)
            if record["stream_overflow"]:
                raise RuntimeError(f"{label}: command stream overflow")
            text = result.stderr.decode("utf-8", errors="replace")
            if refusal is None and result.returncode != 0:
                raise RuntimeError(f"{label}: exit {result.returncode}")
            if refusal is not None:
                if result.returncode == 0 or not re.search(refusal, text, re.I):
                    raise RuntimeError(f"{label}: did not observe the expected refusal")
            return result.stdout
        except subprocess.TimeoutExpired as error:
            record["failure"] = "timeout"
            prefix.with_suffix(".stdout").write_bytes((error.stdout or b"")[:STREAM_LIMIT])
            prefix.with_suffix(".stderr").write_bytes((error.stderr or b"")[:STREAM_LIMIT])
            raise
        except Exception as error:
            record["failure"] = str(error)
            raise
        finally:
            record["finished_unix"] = time.time()
            prefix.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n")


def snapshot_files(home):
    result = {}
    deadline = time.monotonic() + 60
    roots = ("cache", "xdg-cache", "oci", "runtime", "guest-runtime", "images",
             "user/.cache", "user/.mvm")
    user = home / "user"
    if user.is_symlink():
        raise RuntimeError("private user home is a symlink")
    for name in roots:
        if len(result) >= 4096 or time.monotonic() > deadline:
            raise RuntimeError("cache inventory bound exceeded")
        root = home / name
        try:
            root.lstat()
            exists = True
        except FileNotFoundError:
            exists = False
        result[name] = {"exists": exists, "type": "missing"}
        if not exists:
            continue
        pending = [root]
        while pending:
            if len(result) >= 4096 or time.monotonic() > deadline:
                raise RuntimeError("cache inventory bound exceeded")
            path = pending.pop()
            mode = path.lstat().st_mode
            key = str(path.relative_to(home))
            entry = {"exists": True}
            if stat.S_ISLNK(mode):
                entry.update(type="symlink", symlink=os.readlink(path))
            elif stat.S_ISREG(mode):
                entry.update(type="regular", sha256=digest(path, deadline))
            elif stat.S_ISDIR(mode):
                entry["type"] = "directory"
                # Opening parents and the directory without following links also
                # fails closed if a directory is replaced during the inventory.
                with directory_reader(path) as fd:
                    with os.scandir(fd) as children:
                        for child in children:
                            if (len(result) + len(pending) >= 4096 or
                                    time.monotonic() > deadline):
                                raise RuntimeError("cache inventory bound exceeded")
                            pending.append(path / child.name)
            else:
                raise RuntimeError("unsupported cache inventory entry type")
            result[key] = entry
    return result


def require_sealed_artifact(output, archive):
    if len(output) > LIMIT:
        raise RuntimeError("check-artifact output exceeds evidence bound")
    checked = json.loads(output)
    if not isinstance(checked, dict):
        raise RuntimeError("check-artifact output is not an object")
    expected = {"verified": True, "runnable_here": True, "arch": "x86_64",
                "bundle_sha256": digest(archive)}
    for key, value in expected.items():
        if key not in checked or type(checked[key]) is not type(value) or checked[key] != value:
            raise RuntimeError(f"check-artifact missing or unexpected {key}")
    posture = checked.get("posture")
    if not isinstance(posture, dict):
        raise RuntimeError("check-artifact has no posture")
    for key, value in {"profile": "sealed-prod", "verity_protected": True,
                       "egress": "deny-all", "volumes": False}.items():
        if key not in posture or type(posture[key]) is not type(value) or posture[key] != value:
            raise RuntimeError(f"check-artifact missing or unexpected posture.{key}")
    return checked


def collect_builder_candidates(home, evidence, prefix="builder-candidate"):
    """Retain observations, not a verdict inferred from 'newest' files.

    All candidates are recorded. Existing APIs don't expose the Nix-resolved
    mvm node; none is silently promoted into locked-revision-consumption proof.
    """
    observations = []
    deadline = time.monotonic() + 60
    retained = 0
    disks = 0
    for directory, dirs, files in os.walk(home, followlinks=False, onerror=walk_error):
        if time.monotonic() > deadline:
            raise ValueError("candidate collection deadline exceeded")
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("symlink candidate parent")
        if "input.img" not in files:
            continue
        disk = Path(directory) / "input.img"
        disks += 1
        if disks > 32:
            raise ValueError("candidate disk bound exceeded")
        data = members(disk, {"work/flake.nix", "job/cmd.sh"}, deadline=deadline)
        if not data:
            continue
        index = len(observations)
        target = evidence / f"{prefix}-{index}"
        target.mkdir()
        for name, content in data.items():
            retained += len(content)
            if retained > 64 * 1024 * 1024:
                raise ValueError("aggregate evidence bound exceeded")
            (target / name.replace("/", "-")).write_bytes(content)
        record = {"input_disk": str(disk), "input_disk_sha256": digest(disk, deadline),
                  "members": {name: hashlib.sha256(value).hexdigest()
                              for name, value in data.items()},
                  "association": "unobserved", "resolved_mvm_revision": None}
        for name in ("fc-config.json", "config.json", "console.log",
                     "out/result", "out/meta", "out/store-path"):
            source = disk.parent / name
            if source.exists() or source.is_symlink():
                with regular_reader(source) as stream:
                    content = stream.read(LIMIT + 1)
                if len(content) > LIMIT:
                    raise ValueError("adjacent evidence exceeds bound")
                retained += len(content)
                if retained > 64 * 1024 * 1024:
                    raise ValueError("aggregate evidence bound exceeded")
                (target / name.replace("/", "-")).write_bytes(content)
                if time.monotonic() > deadline:
                    raise ValueError("candidate collection deadline exceeded")
        observations.append(record)
    return observations


def directory_reader(path):
    """Return an owned directory descriptor without following any component."""
    from contextlib import contextmanager

    @contextmanager
    def opened():
        absolute = Path(path).absolute()
        fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in absolute.parts[1:]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                os.close(fd)
                fd = child
            yield fd
        finally:
            os.close(fd)
    return opened()


def tamper(source, destination):
    """Bounded raw-tar copy: change one payload byte, never parse extensions."""
    deadline = time.monotonic() + TAMPER_SECONDS

    def check():
        if time.monotonic() > deadline:
            raise ValueError("tamper deadline exceeded")

    with regular_reader(source) as original:
        size = os.fstat(original.fileno()).st_size
        if size > TAMPER_SOURCE_LIMIT:
            raise ValueError("tamper source byte budget exceeded")
        headers = []
        expanded = 0
        changed_offset = None
        while True:
            check()
            offset = original.tell()
            header = original.read(512)
            if header == b"\0" * 512:
                if original.read(512) != b"\0" * 512:
                    raise ValueError("incomplete raw tar terminator")
                break
            if len(header) != 512 or len(headers) >= 4096:
                raise ValueError("raw tar header bound exceeded")
            entry = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            if entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
                raise ValueError("unsupported raw tar header type")
            padded = ((entry.size + 511) // 512) * 512
            expanded += entry.size
            if (entry.size < 0 or expanded > TAMPER_EXPANDED_LIMIT or
                    original.tell() + padded > size or
                    (entry.isdir() and entry.size != 0)):
                raise ValueError("tamper expanded byte budget or source size exceeded")
            headers.append((offset, header))
            if changed_offset is None and entry.isfile() and entry.name.endswith("rootfs.ext4"):
                if not entry.size:
                    raise ValueError("empty rootfs")
                changed_offset = original.tell()
            original.seek(padded, os.SEEK_CUR)
        # Validate trailing bytes in chunks too; no hidden second archive.
        while original.tell() < size:
            check()
            chunk = original.read(min(1024 * 1024, size - original.tell()))
            if not chunk:
                raise ValueError("raw tar truncated during scan")
            if any(chunk):
                raise ValueError("nonzero raw tar trailer")
        if os.fstat(original.fileno()).st_size != size:
            raise ValueError("raw tar size changed during scan")
        if changed_offset is None:
            raise ValueError("archive has no rootfs.ext4 payload to tamper")
        if size > TAMPER_OUTPUT_LIMIT:
            raise ValueError("tamper output byte budget exceeded")
        destination = Path(destination)
        with directory_reader(destination.parent) as parent:
            owned = None
            try:
                fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW, 0o600, dir_fd=parent)
                owned = os.fstat(fd)
                with os.fdopen(fd, "wb") as altered:
                    # Revalidate scanned headers before copying from the same fd.
                    for offset, header in headers:
                        check()
                        original.seek(offset)
                        if original.read(512) != header:
                            raise ValueError("raw tar changed during scan")
                    original.seek(0)
                    copied = 0
                    while copied < size:
                        check()
                        chunk = original.read(min(1024 * 1024, size - copied))
                        if not chunk:
                            raise ValueError("raw tar truncated during rewrite")
                        if copied <= changed_offset < copied + len(chunk):
                            index = changed_offset - copied
                            chunk = chunk[:index] + bytes([chunk[index] ^ 1]) + chunk[index + 1:]
                        if copied + len(chunk) > TAMPER_OUTPUT_LIMIT:
                            raise ValueError("tamper output byte budget exceeded")
                        altered.write(chunk)
                        copied += len(chunk)
                    check()
            except BaseException:
                if owned is not None:
                    current = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                        os.unlink(destination.name, dir_fd=parent)
                raise


def workflow(commands, workspace, evidence, revision):
    producer = workspace / "producer"
    consumer = workspace / "consumer"
    empty = workspace / "no-runtime"
    for home in (producer, consumer, empty):
        home.mkdir()
        if any(value["exists"] for value in snapshot_files(home).values()):
            raise RuntimeError(f"{home.name}: unexpected initial cache/runtime state")
    initial = snapshot_files(empty)
    if any(value["exists"] for value in initial.values()):
        raise RuntimeError("no-runtime home has unexpected initial cache/runtime state")
    (evidence / "no-runtime-initial.json").write_text(json.dumps(initial, indent=2) + "\n")
    authored = workspace / "authored"
    sdk = ROOT / "crates/mvm-sdk/sdks/python"
    sys.path.insert(0, str(sdk))
    fixture_spec = importlib.util.spec_from_file_location(
        "native_fixture", ROOT / "scripts/pack-build-native-fixture.py")
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    spec = fixture.author(authored)
    lock = authored / "pack.lock.json"
    archive = evidence / "native-hello.mvmpkg"
    commands.call(producer, "executable-version", ["--version"])
    commands.call(producer, "producer-bootstrap", ["bootstrap"])
    commands.call(producer, "lock", ["pack", "lock", spec, "--mvm-revision", revision,
                                    "--out", lock])
    input_observation = evidence / "frozen-input-observation.json"
    commands.call(producer, "build", ["build", spec, "--lock", lock,
                                     "--out", archive, "--hypervisor", "firecracker",
                                     "--input-observation", input_observation])
    if input_observation.exists() or input_observation.is_symlink():
        with regular_reader(input_observation) as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise RuntimeError("input observation exceeds 1 MiB")
        diagnostic = json.loads(raw)
        if not isinstance(diagnostic, dict):
            raise RuntimeError("input observation is not an object")
    observations = collect_builder_candidates(producer, evidence)
    shutil.copyfile(spec, evidence / "pack.json")
    shutil.copyfile(lock, evidence / "pack.lock.json")
    public_key = evidence / "test-publisher.pub"
    shutil.copyfile(producer / "keys/host-signer.pub", public_key)
    # Make the producer source unavailable, not merely unused by convention.
    shutil.rmtree(authored)
    commands.call(consumer, "unknown-key", ["bundle", "fetch", archive, "--json"],
                  refusal=r"trust store has no entry for key_id")
    commands.call(consumer, "consumer-bootstrap", ["bootstrap"])
    commands.call(consumer, "trust", ["trust", "add", public_key])
    trusted = list((consumer / "trusted-publishers").glob("*.pub"))
    if len(trusted) != 1 or trusted[0].read_bytes() != public_key.read_bytes():
        raise RuntimeError("consumer trust must contain only the test publisher")
    commands.call(consumer, "verify", ["bundle", "fetch", archive, "--json"])
    checked = require_sealed_artifact(commands.call(
        consumer, "check-artifact", ["machine", "check-artifact", archive, "--json",
                                     "--backend", "firecracker"]), archive)
    if (consumer / "templates").exists() and any((consumer / "templates").iterdir()):
        raise RuntimeError("consumer unexpectedly has a template/build slot registry")
    isolation = {"producer_home": str(producer), "consumer_home": str(consumer),
                 "no_runtime_home": str(empty), "authored_source_removed": not authored.exists(),
                 "consumer_template_slots": [],
                 "trusted_publishers": [path.name for path in trusted]}
    (evidence / "consumer-isolation.json").write_text(json.dumps(isolation, indent=2) + "\n")
    # The archive path uses the normal verified/admitted entrypoint route.
    output = commands.call(consumer, "run", ["machine", "run", "--manifest", archive,
                                            "--hypervisor", "firecracker", "--entrypoint"])
    require_hello(output)
    modified = evidence / "tampered.mvmpkg"
    tamper(archive, modified)
    commands.call(consumer, "tampered", ["bundle", "fetch", modified, "--json"],
                  refusal=TAMPER_REFUSAL)
    commands.call(consumer, "sealed-ad-hoc", [
        "machine", "run", "--manifest", archive, "--hypervisor", "firecracker",
        "--", "echo", "forbidden-ad-hoc"],
        refusal=SEALED_REFUSAL)
    commands.call(empty, "empty-trust", ["trust", "add", public_key])
    commands.call(empty, "empty-verify", ["bundle", "fetch", archive, "--json"])
    before = snapshot_files(empty)
    for runtime in ("cache/guest-agent", "cache/oci/guest-agent",
                    "cache/guest-runtime", "cache/oci/guest-runtime"):
        path = empty / runtime
        if path.exists() or path.is_symlink():
            raise RuntimeError("verification unexpectedly prepared a guest runtime")
    (evidence / "no-runtime-before.json").write_text(json.dumps(before, indent=2) + "\n")
    try:
        commands.call(empty, "no-runtime", [
            "machine", "run", "--manifest", archive, "--hypervisor", "firecracker",
            "--entrypoint"], refusal=RUNTIME_REFUSAL)
    finally:
        after = snapshot_files(empty)
        (evidence / "no-runtime-after.json").write_text(json.dumps(after, indent=2) + "\n")
    if after != before:
        raise RuntimeError("NoPreparedRuntime refusal acquired or modified runtime/cache artifacts")
    commands.call(producer, "producer-audit", ["trust", "audit", "verify"])
    commands.call(consumer, "consumer-audit", ["trust", "audit", "verify"])
    commands.call(empty, "empty-audit", ["trust", "audit", "verify"])
    return {"PreparedRuntime": "workflow-observed",
            "NoPreparedRuntime": "refusal-observed",
            "locked_revision_consumption": "unobserved",
            "missing_binding": "Raw input/config/job/result/output staging association has not been established; product diagnostic is not an execution credential",
            "builder_candidates": observations, "archive_sha256": digest(archive),
            "artifact_preview": checked}


def owned_processes(home, proc=Path("/proc"), sessions=()):
    """Fail closed on unreadable inventory; compare PID starttime across reads."""
    if not (proc / "self/stat").exists():
        raise RuntimeError("Linux process verification unavailable")
    owned = []
    identities = {}
    entries = [entry for entry in proc.iterdir() if entry.name.isdigit()]
    deadline = time.monotonic() + 30
    for entry in entries:
        if time.monotonic() > deadline:
            raise RuntimeError("process verification deadline exceeded")
        try:
            first = (entry / "stat").read_text()
            # comm may contain spaces and parentheses; fields start after final ')'.
            fields = first[first.rindex(")") + 2:].split()
            start = fields[19]
            identities[entry.name] = start
            environment = (entry / "environ").read_bytes()
            command = (entry / "cmdline").read_bytes()
            second = (entry / "stat").read_text()
            if second[second.rindex(")") + 2:].split()[19] != start:
                raise RuntimeError(f"PID identity changed during inventory: {entry.name}")
            marker = b"MVM_HOME=" + os.fsencode(home)
            scoped = marker in environment.split(b"\0")
            scoped |= any(os.fsencode(home) in arg for arg in command.split(b"\0"))
            scoped |= int(fields[3]) in sessions
            if scoped and fields[0] != "Z":
                owned.append({"pid": int(entry.name), "starttime": start})
        except FileNotFoundError:
            # A vanished PID is not an empty proof: inventory must be retried.
            raise RuntimeError(f"process vanished during inventory: {entry.name}")
    final_entries = [entry for entry in proc.iterdir() if entry.name.isdigit()]
    if {entry.name for entry in final_entries} != set(identities):
        raise RuntimeError("process census changed during verification")
    for entry in final_entries:
        if time.monotonic() > deadline:
            raise RuntimeError("process verification deadline exceeded")
        final = (entry / "stat").read_text()
        if final[final.rindex(")") + 2:].split()[19] != identities[entry.name]:
            raise RuntimeError(f"PID identity changed at final verification: {entry.name}")
    return owned


def cleanup(commands, workspace, verify=None):
    failures = []
    for name in ("producer", "consumer", "no-runtime"):
        home = workspace / name
        if not home.exists():
            continue
        try:
            # --all is scoped to an invocation-owned MVM_HOME, never ambient state.
            commands.call(home, f"cleanup-{name}", ["machine", "stop", "--all", "--yes"],
                          timeout=120)
        except Exception as error:
            failures.append(f"{name}: {error}")
        try:
            remaining = (verify(home) if verify is not None else owned_processes(
                home, sessions=getattr(commands, "sessions", {}).get(str(home), ())))
            if remaining:
                failures.append(f"{name}: owned live runtime processes remain: {remaining}")
        except Exception as error:
            failures.append(f"{name}: teardown-unverified: {error}")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mvmctl", type=Path, required=True)
    parser.add_argument("--mvm-revision", required=True)
    parser.add_argument("--source-revision", required=True,
                        help="full executing source checkout revision B, different from locked A")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--build-transcript", type=Path, required=True,
                        help="exact separately authorized remote compilation transcript")
    args = parser.parse_args()
    if not REVISION.fullmatch(args.mvm_revision) or not REVISION.fullmatch(args.source_revision):
        parser.error("both revisions must be full lowercase 40-character commits")
    if args.mvm_revision == args.source_revision:
        parser.error("locked revision A must differ from executing source checkout B")
    binary = args.mvmctl.resolve(strict=True)
    guard(binary)
    identity = source_identity(args.source_revision)
    os.umask(0o077)
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    evidence = evidence / "pack-build-native"
    evidence.mkdir(exist_ok=False)
    with regular_reader(args.build_transcript) as stream:
        transcript = stream.read(STREAM_LIMIT + 1)
    if not transcript or len(transcript) > STREAM_LIMIT:
        raise RuntimeError("build transcript empty or exceeds 16 MiB")
    (evidence / "authorized-build-transcript.log").write_bytes(transcript)
    report = {"status": "failed", "client_class": "ExplicitBinary",
              "binary": str(binary), "binary_sha256": digest(binary),
              "executing_source": identity,
              "build_transcript_sha256": hashlib.sha256(transcript).hexdigest(),
              "compilation_linkage": "operator transcript retained; not inferred or attested",
              "locked_revision": args.mvm_revision,
              "locked_revision_consumption": "unobserved"}
    workspace = Path(tempfile.mkdtemp(prefix="pack-build-native-")).resolve(strict=True)
    commands = Commands(binary, evidence)
    exit_code = 1
    try:
        report.update(workflow(commands, workspace, evidence, args.mvm_revision))
        # Functional evidence is not the requested resolved-input proof.
        report["status"] = "workflow-complete-revision-proof-unobserved"
        exit_code = 2
    except Exception as error:
        report["failure"] = str(error)
        try:
            report["failure_builder_candidates"] = collect_builder_candidates(
                workspace / "producer", evidence, prefix="failure-builder-candidate")
        except Exception as observation_error:
            report["failure_observation_error"] = str(observation_error)
    finally:
        failures = cleanup(commands, workspace)
        if failures:
            report["cleanup"] = {"failures": failures, "retained_workspace": str(workspace)}
            report["status"] = "teardown-unverified"
            exit_code = 1
        else:
            shutil.rmtree(workspace)
            report["cleanup"] = "independent process inventory empty; invocation-owned homes removed"
        (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
