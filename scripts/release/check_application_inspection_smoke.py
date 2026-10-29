#!/usr/bin/env python3
"""Real CLI inspection over production keyless verification and independent bundle trust.

Only the existing signing workflow supplies signatures. This program does not
sign, enroll inferred trust, execute an archive, or authorize a launch.
The malformed configured revocation-trust case is not a signed-feed witness.
Inspection preserves protected consumer state while retaining mandatory signed
command auditing. The existing CLI verifier authenticates each inspection tail;
its final self-outcome and resistance to an off-host rewrite are not attested.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


OPERATOR_FEED_IDENTITY = (
    "https://github.com/tinylabscom/mvm-packs/"
    ".github/workflows/publish.yml@refs/heads/main"
)
OPERATOR_FEED_ISSUER = "https://token.actions.githubusercontent.com"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def contained(root, relative):
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(p in (".", "..") for p in path.parts):
        raise ValueError("fixture path must be a contained relative path")
    result = root / path
    for entry in [result, *result.parents]:
        if entry == root.parent:
            break
        if entry.is_symlink():
            raise ValueError("fixture path must not traverse a symlink")
    return result


# Every command appends its own invocation record here; that is the one file
# allowed to change, and only by growing (see Smoke.inspect).
AUDIT_LOG = "audit/local.jsonl"


def audit_log(root):
    path = root / AUDIT_LOG
    return path.read_bytes() if path.exists() else b""


def snapshot(root):
    """Hash names, types, modes and bytes; never serialize consumer contents."""
    entries = {}
    for path in sorted(root.rglob("*")):
        if path.relative_to(root).as_posix() == AUDIT_LOG:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("consumer state contains a symlink")
        name = path.relative_to(root).as_posix()
        if stat.S_ISREG(metadata.st_mode):
            entries[name] = [stat.S_IMODE(metadata.st_mode), digest(path.read_bytes())]
        elif stat.S_ISDIR(metadata.st_mode):
            entries[name] = [stat.S_IMODE(metadata.st_mode), "directory"]
        else:
            raise ValueError("consumer state contains a special file")
    return entries


def snapshot_changes(before, after):
    """Report bounded changed metadata, never file contents or an entire home."""
    names = sorted(
        name for name in before.keys() | after.keys()
        if before.get(name) != after.get(name)
    )
    entries = []
    for name in names[:32]:
        identity = (
            {"relative_path": name} if len(name.encode()) <= 512
            else {"relative_path_sha256": digest(name.encode())}
        )
        entries.append({
            **identity, "before": before.get(name), "after": after.get(name),
        })
    return {"changed_count": len(names), "changes": entries, "truncated": len(names) > 32}


def protected_state(entries):
    # Only this single chain may append. Keys, trust, pins, installed files,
    # audit-directory metadata and every other audit file remain protected.
    return {name: value for name, value in entries.items() if name != "audit/local.jsonl"}


def read_audit_input(path, maximum):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or not 0 < info.st_size <= maximum
        ):
            raise ValueError("audit input type/owner/link/size refused")
        data = stream.read(maximum + 1)
        current = os.fstat(stream.fileno())
    identity = (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))
    observed = path.lstat()
    if (
        len(data) != info.st_size or current.st_size != info.st_size
        or (observed.st_dev, observed.st_ino, stat.S_IMODE(observed.st_mode)) != identity
        or not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1
    ):
        raise ValueError("audit input changed during its bounded read")
    return data, identity


def assert_audit_append(before, after, verb, outcome):
    """Check the expected suffix; canonical CLI verification authenticates it later."""
    if not before.endswith(b"\n") or not after.startswith(before):
        raise ValueError("audit chain lost its original prefix")
    prefix = before.splitlines()
    suffix = after[len(before):].splitlines()
    if not all(prefix) or len(suffix) != 2 or not after.endswith(b"\n"):
        raise ValueError("audit command must append exactly two complete records")

    def unique_fields(pairs):
        fields = {}
        for key, value in pairs:
            if key in fields:
                raise ValueError("ambiguous audit record")
            fields[key] = value
        return fields

    for line, event in zip(suffix, (f"cmd.{verb}.invoked", f"cmd.{verb}.{outcome}")):
        entry = json.loads(line, object_pairs_hook=unique_fields)["entry"]
        labels = entry["labels"]
        expected_labels = {"category", "verb"}
        if event.endswith(".invoked"):
            expected_labels.add("pid")
            if not isinstance(labels.get("pid"), str) or not re.fullmatch(r"[1-9][0-9]*", labels["pid"]):
                raise ValueError("audit invocation lacks its process label")
        elif outcome == "failed":
            expected_labels.add("error")
            if not isinstance(labels.get("error"), str):
                raise ValueError("audit failure lacks its error label")
        if (
            entry["event"] != event or entry["tenant"] != "local"
            or labels.get("category") != "cmd" or labels.get("verb") != verb
            or set(labels) != expected_labels
        ):
            raise ValueError("audit suffix describes another command, tenant or outcome")
    return len(prefix) + 2


def assert_verified_audit(result, home, inspected_entries):
    # The verifier audits its invocation BEFORE LocalAuditReader verifies the
    # chain. Its final self-outcome is appended afterwards and is not covered.
    chain = home / "audit/local.jsonl"
    expected = [
        f"[mvm] audit chain '{chain}' verifies clean: {inspected_entries + 1} entries",
        "[mvm] No published audit roots, so nothing attests the log was only appended to. "
        "Roots are published at admission and exit.",
        "[mvm] No readable off-host witness configured (MVM_AUDIT_WITNESS), so a rewrite "
        "by this host is undetectable from here.",
    ]
    if result.returncode != 0 or result.stderr or result.stdout.decode("utf-8").splitlines() != expected:
        raise ValueError("canonical audit verification did not cover the exact inspection tail")
    return inspected_entries + 1


def assert_inspection(document, fixture):
    expected = {
        "kind": "application",
        "reference": fixture["reference"],
        "manifest_sha256": fixture["manifest_sha256"],
        "signer_identity": fixture["identity"],
        "signer_issuer": "https://token.actions.githubusercontent.com",
        "guest_arch": "aarch64",
        "verification_scope": "descriptor_and_bundle_archive",
        "bundle": fixture["bundle"],
    }
    for field, value in expected.items():
        if document.get(field) != value:
            raise ValueError(f"inspection identity mismatch: {field}")


def closed_environment(home, scratch, catalog):
    return {
        "PATH": os.defpath,
        "HOME": str(scratch / "home"),
        "TMPDIR": str(scratch / "tmp"),
        "MVM_HOME": str(home),
        "MVM_PACK_REGISTRY": catalog.as_uri(),
        "LANG": "C.UTF-8",
        "NO_COLOR": "1",
    }


def assert_refusal(result, case, home, fixture):
    """Require the production error stage, not a crash or arbitrary failure."""
    if result.returncode == 0:
        raise ValueError(f"{case} unexpectedly accepted")
    if result.returncode != 1 or result.stdout.strip():
        raise ValueError(f"{case} did not return a clean verification refusal")
    text = result.stderr.decode("utf-8", errors="strict")
    if re.search(r"panicked at|Usage:|unexpected argument|thread ['\"]", text):
        raise ValueError(f"{case} crashed or failed command parsing")
    roots = [line[7:] for line in text.splitlines() if line.startswith("Error: ")]
    if len(roots) != 1:
        raise ValueError(f"{case} has no unique production error")
    lines = [re.sub(r"^\d+: ", "", line.strip()) for line in text.splitlines()]
    reference = fixture["reference"]
    if case in ("pin", "descriptor"):
        pinned = "0" * 64 if case == "pin" else fixture["manifest_sha256"]
        actual = (
            fixture["manifest_sha256"] if case == "pin"
            else fixture["tampered_manifest_sha256"]
        )
        expected = (
            f'pack manifest digest drift for {reference}: '
            f'pinned Sha256Hex("{pinned}"), got Sha256Hex("{actual}")'
        )
        valid, stage = roots[0] == expected, "descriptor-pin"
    elif case == "version":
        expected = (
            "pack runtime/inspection-fixture requested version 1.0.0, "
            "but the lock pins 9.0.0"
        )
        valid, stage = roots[0] == expected, "exact-version-pin"
    elif case in ("signature", "publisher"):
        # Both controlled mutations reach the same real keyless verifier.
        # Parse errors and a disabled/uninitialized verifier are not this stage.
        valid = re.fullmatch(
            r"registry-pack signature is invalid: signature is invalid: "
            r"signature verification failed: .+",
            roots[0],
        ) is not None
        stage = "descriptor-signature" if case == "signature" else "current-publisher-policy"
    elif case == "malformed-revocation-trust":
        path = contained(home, fixture["paths"]["revocation_trust"])
        valid = (
            roots[0] == (
                f"registry-pack revocation trust at {path} is invalid: "
                "TOML parse error at line 1, column 18"
            )
            and "invalid type: boolean `false`, expected u32" in lines
        )
        stage = "malformed-configured-revocation-trust"
    elif case == "missing-revocation-trust":
        path = contained(home, fixture["paths"]["revocation_trust"])
        valid = roots[0] == f"registry-pack revocation trust is not configured at {path}"
        stage = "mandatory-operator-revocation-trust"
    elif case == "missing-revocation-feed":
        valid = roots[0] == (
            "registry-pack revocation cache is missing; a signed feed must be fetched"
        )
        stage = "mandatory-current-operator-feed"
    elif case == "same-revocation-signer":
        path = contained(home, fixture["paths"]["revocation_trust"])
        valid = roots[0] == (
            f"registry-pack revocation trust at {path} is invalid: "
            "release identity must differ from the pack signer"
        )
        stage = "independent-revocation-signer"
    elif case in ("bundle-key", "archive", "missing-archive"):
        expected = {
            "bundle-key": f'trust store has no entry for key_id {fixture["bundle"]["key_id"]}',
            "archive": "application archive digest differs from its descriptor",
            "missing-archive": "application archive I/O failed: No such file or directory (os error 2)",
        }[case]
        valid = (
            roots[0] == (
                f"reverifying local application bundle for {reference}; "
                f"use `mvmctl pull {reference}` to acquire a missing archive"
            )
            and expected in lines
        )
        stage = {
            "bundle-key": "independent-bundle-key",
            "archive": "descriptor-archive-digest",
            "missing-archive": "missing-bound-archive",
        }[case]
    else:
        raise ValueError("unknown refusal contract")
    if not valid:
        raise ValueError(f"{case} failed at an unrelated stage")
    return stage


def public_diagnostic(data, private_paths):
    """Emit bounded, path/secret-redacted diagnostics, not a consumer tree."""
    text = data[:16384].decode("utf-8", errors="replace")
    for path in sorted(map(str, private_paths), key=len, reverse=True):
        text = text.replace(path, "[private-path]")
    lines = []
    in_key = False
    for line in text.splitlines():
        if "-----BEGIN " in line and "KEY-----" in line:
            in_key = True
        sensitive = re.search(r"private[ _-]?key|secret|password|token", line, re.I)
        lines.append("[redacted sensitive diagnostic]" if in_key or sensitive else line)
        if "-----END " in line and "KEY-----" in line:
            in_key = False
    return "\n".join(lines)[:16384]


class Smoke:
    def __init__(self, cli, output, catalog, fixture):
        self.cli = cli
        self.output = output
        self.catalog = catalog
        self.fixture = fixture
        self.records = []
        self.context = {}
        self.audit_identity = None

    def capture_audit_identity(self, home):
        public_key, _ = read_audit_input(contained(home, "keys/host-signer.pub"), 32)
        if len(public_key) != 32:
            raise ValueError("setup audit public key has the wrong size")
        self.audit_identity = public_key

    def check_protected_state(self, name, before, after):
        if protected_state(before) != protected_state(after):
            self.records.append({
                "name": name + "-state-mutation",
                **snapshot_changes(protected_state(before), protected_state(after)),
            })
            raise ValueError(name + " mutated protected consumer state")

    def audit_snapshot(self, home):
        if self.audit_identity is None:
            raise ValueError("setup audit identity was not independently captured")
        public_key, _ = read_audit_input(contained(home, "keys/host-signer.pub"), 32)
        if public_key != self.audit_identity:
            raise ValueError("setup audit identity changed")
        return read_audit_input(contained(home, "audit/local.jsonl"), 2 * 1024 * 1024)

    def report(self, outcome, error=None):
        report = {
            **self.context, "schema_version": 1, "outcome": outcome, "error": error,
            "scope": "synthetic publisher policy; not official registry, release, boot or launch",
            "open_witnesses": [
                "genuine signed revoked-feed refusal for a matching descriptor",
                "default-registry descriptor/feed publisher independence",
                "application launch and teardown",
            ],
            "records": self.records,
        }
        (self.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True), flush=True)
        return report

    def command(self, name, home, arguments):
        work = self.output / name
        work.mkdir()
        (work / "home").mkdir()
        (work / "tmp").mkdir()
        argv = [str(self.cli), *arguments]
        try:
            result = subprocess.run(
                argv, cwd=work, env=closed_environment(home, work, self.catalog),
                capture_output=True, timeout=120, check=False,
            )
        except subprocess.TimeoutExpired as error:
            (work / "stdout").write_bytes(error.stdout or b"")
            (work / "stderr").write_bytes(error.stderr or b"")
            record = {
                "name": name, "argv": argv, "exit": None, "error": "timeout",
                "stdout_sha256": digest(error.stdout or b""),
                "stderr_sha256": digest(error.stderr or b""),
                "diagnostic": public_diagnostic(error.stderr or b"", [home.parent, work]),
            }
            (work / "status.json").write_text(json.dumps(record) + "\n")
            self.records.append(record)
            raise
        for stream in ("stdout", "stderr"):
            data = getattr(result, stream)
            (work / stream).write_bytes(data[:1024 * 1024])
        record = {
            "name": name, "argv": argv, "exit": result.returncode,
            "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr),
            "stdout_size": len(result.stdout), "stderr_size": len(result.stderr),
            "diagnostic": public_diagnostic(result.stderr, [home.parent, work]),
        }
        (work / "status.json").write_text(json.dumps(record, indent=2) + "\n")
        self.records.append(record)
        if max(len(result.stdout), len(result.stderr)) > 1024 * 1024:
            raise ValueError("CLI output exceeded retained-output bound")
        return result

    def inspect(self, label, home, accepted):
        for verb in ("info", "verify"):
            name = f"{label}-{verb}"
            before = snapshot(home)
            audit_before, identity = self.audit_snapshot(home)
            result = self.command(
                name, home,
                ["pack", verb, self.fixture["reference"], "--json"],
            )
            if accepted:
                if result.returncode != 0:
                    raise ValueError(f"{label}-{verb} unexpectedly refused; see retained stderr")
                assert_inspection(json.loads(result.stdout), self.fixture)
            else:
                stage = assert_refusal(result, label, home, self.fixture)
                self.records.append({"name": f"{label}-{verb}-classification", "stage": stage})
            after = snapshot(home)
            self.check_protected_state(name, before, after)
            audit_after, current_identity = self.audit_snapshot(home)
            if current_identity != identity:
                raise ValueError(name + " replaced the audit file or changed its mode")
            inspected_entries = assert_audit_append(
                audit_before, audit_after, "pack", "completed" if accepted else "failed",
            )
            verification = self.command(
                name + "-audit-verification", home,
                ["--verbose", "trust", "audit", "verify", "--tenant", "local"],
            )
            self.check_protected_state(name + "-audit-verification", before, snapshot(home))
            audit_final, final_identity = self.audit_snapshot(home)
            if final_identity != identity:
                raise ValueError("canonical audit verifier replaced its chain or changed its mode")
            assert_audit_append(audit_after, audit_final, "audit", "completed")
            verified_entries = assert_verified_audit(verification, home, inspected_entries)
            self.records.append({
                "name": name + "-audited-state",
                "reference": self.fixture["reference"],
                "state_before_sha256": digest(json.dumps(protected_state(before), sort_keys=True).encode()),
                "state_after_sha256": digest(json.dumps(protected_state(snapshot(home)), sort_keys=True).encode()),
                "audit_before_sha256": digest(audit_before),
                "inspection_tail_sha256": digest(audit_after),
                "audit_after_verifier_sha256": digest(audit_final),
                "verified_entries": verified_entries,
                "audit_setup_public_key_sha256": digest(self.audit_identity),
                "verifier_final_self_outcome_covered": False,
            })


def mutate(home, fixture, case, wrong_signature):
    paths = {key: contained(home, value) for key, value in fixture["paths"].items()}
    descriptor = paths["registry_cache"] / fixture["manifest_sha256"] / "manifest.json"
    signature = descriptor.with_name("manifest.sigstore.json")
    if case == "pin":
        text = paths["lock"].read_text()
        changed = text.replace(fixture["manifest_sha256"], "0" * 64)
        if text == changed:
            raise ValueError("pin mutation did not change the pin")
        paths["lock"].write_text(changed)
        # Keep readable original bytes at the altered address so this tests the
        # digest check rather than counting an unrelated missing-file error.
        shutil.copytree(descriptor.parent, paths["registry_cache"] / ("0" * 64))
    elif case == "version":
        text = paths["lock"].read_text()
        changed = text.replace(fixture["reference"], "runtime/inspection-fixture@9.0.0")
        if text == changed:
            raise ValueError("version mutation did not change the pin")
        paths["lock"].write_text(changed)
    elif case == "descriptor":
        descriptor.write_bytes(descriptor.read_bytes() + b" ")
    elif case == "signature":
        wrong_bytes = wrong_signature.read_bytes()
        if wrong_bytes == signature.read_bytes():
            raise ValueError("signature mutation did not change the bundle")
        signature.write_bytes(wrong_bytes)
    elif case == "publisher":
        text = paths["policy"].read_text()
        changed = text.replace(fixture["identity"], "https://example.test/untrusted-workflow")
        if text == changed:
            raise ValueError("publisher mutation did not change policy")
        paths["policy"].write_text(changed)
    elif case == "bundle-key":
        paths["bundle_key"].unlink()
    elif case == "archive":
        data = bytearray(paths["archive"].read_bytes())
        data[len(data) // 2] ^= 1
        paths["archive"].write_bytes(data)
    elif case == "missing-archive":
        paths["archive"].unlink()
    elif case == "malformed-revocation-trust":
        paths["revocation_trust"].parent.mkdir(parents=True, exist_ok=True)
        paths["revocation_trust"].parent.chmod(0o700)
        paths["revocation_trust"].write_text("schema_version = false\n")
        paths["revocation_trust"].chmod(0o600)
    elif case == "missing-revocation-trust":
        paths["revocation_trust"].unlink()
    elif case == "missing-revocation-feed":
        for name in ("feed.json", "checkpoint.json"):
            paths["revocation_trust"].with_name(name).unlink()
    elif case == "same-revocation-signer":
        paths["revocation_trust"].write_text(
            "schema_version = 1\n"
            f"issuer = {json.dumps(OPERATOR_FEED_ISSUER)}\n"
            f"accepted_identities = [{json.dumps(fixture['identity'])}]\n"
        )
    else:
        raise ValueError(f"unknown refusal case: {case}")


CASES = (
    "pin", "version", "descriptor", "signature", "publisher",
    "bundle-key", "archive", "missing-archive", "malformed-revocation-trust",
    "missing-revocation-trust", "missing-revocation-feed", "same-revocation-signer",
)

def configure_operator_trust(home, fixture):
    """Explicit disposable operator policy, never inferred from the descriptor."""
    if fixture["identity"] == OPERATOR_FEED_IDENTITY:
        raise ValueError("synthetic descriptor and operator-feed publishers must differ")
    path = contained(home, fixture["paths"]["revocation_trust"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    contents = (
        "schema_version = 1\n"
        f"issuer = {json.dumps(OPERATOR_FEED_ISSUER)}\n"
        f"accepted_identities = [{json.dumps(OPERATOR_FEED_IDENTITY)}]\n"
    ).encode()
    with os.fdopen(os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    ), "wb") as stream:
        stream.write(contents)


def run(args):
    fixture_root = args.fixture_dir.resolve(strict=True)
    cli = args.cli.resolve(strict=True)
    wrong_signature = args.wrong_signature.resolve(strict=True)
    fixture = json.loads((fixture_root / "fixture.json").read_text())
    if fixture["schema_version"] != 1:
        raise ValueError("unknown fixture schema")
    if len(args.source_sha) != 40 or any(c not in "0123456789abcdef" for c in args.source_sha):
        raise ValueError("source SHA must be a full Git object identity")
    if re.fullmatch(r"[0-9a-f]{40}", args.revocation_source_sha) is None:
        raise ValueError("revocation source SHA must be a full Git object identity")
    feed_document, _ = read_audit_input(args.revocation_document, 1024 * 1024)
    feed_bundle, _ = read_audit_input(args.revocation_bundle, 1024 * 1024)
    descriptor = (fixture_root / "manifest.json").read_bytes()
    archive = (fixture_root / "application.mvmpkg").read_bytes()
    if digest(descriptor) != fixture["manifest_sha256"]:
        raise ValueError("fixture descriptor digest mismatch")
    fixture["tampered_manifest_sha256"] = digest(descriptor + b" ")
    if digest(archive) != fixture["bundle"]["archive_sha256"]:
        raise ValueError("fixture archive digest mismatch")
    if len(archive) != fixture["bundle"]["archive_size"]:
        raise ValueError("fixture archive size mismatch")
    args.out_dir.mkdir(mode=0o700)
    output = args.out_dir.resolve(strict=True)
    catalog = output / "catalog"
    pack = catalog / "packs/runtime/inspection-fixture/1.0.0"
    pack.mkdir(parents=True)
    shutil.copyfile(fixture_root / "manifest.json", pack / "manifest.json")
    shutil.copyfile(fixture_root / "manifest.sigstore.json", pack / "manifest.sigstore.json")
    (catalog / "index.json").write_text(json.dumps({
        "schema_version": 2, "packs": [{
            "namespace": "runtime", "name": "inspection-fixture",
            "description": "Nonbootable cryptographic inspection smoke",
            "versions": [{"version": "1.0.0", "manifest_sha256": digest(descriptor)}],
        }],
    }))
    smoke = Smoke(cli, output, catalog, fixture)
    smoke.context = {
        "source_sha": args.source_sha, "cli_sha256": digest(cli.read_bytes()),
        "fixture": fixture,
        "operator_feed": {
            "source_sha": args.revocation_source_sha,
            "document_sha256": digest(feed_document), "document_size": len(feed_document),
            "bundle_sha256": digest(feed_bundle), "bundle_size": len(feed_bundle),
            "identity": OPERATOR_FEED_IDENTITY, "issuer": OPERATOR_FEED_ISSUER,
            "scope": "explicit synthetic consumer operator policy; not default registry trust",
        },
    }
    try:
        emit_public_fixture(fixture_root)
        exercise(
            smoke, fixture_root, wrong_signature,
            args.revocation_document.absolute(), args.revocation_bundle.absolute(),
        )
    except Exception as error:
        # The hosted runner does not upload private result directories. Publish
        # the bounded status/hash/redacted diagnostic report before aborting.
        smoke.report("FAIL", {
            "type": type(error).__name__,
            "detail": public_diagnostic(str(error).encode(), [fixture_root, output]),
        })
        raise
    smoke.report("PASS")


def emit_public_fixture(fixture_root):
    # Deliberately bounded public allowlist, not a recursive home/artifact upload.
    for name in (
        "fixture.json", "manifest.json", "manifest.sigstore.json",
        "bundle-author.pub", "application.mvmpkg",
    ):
        data = (fixture_root / name).read_bytes()
        if len(data) > 1024 * 1024:
            raise ValueError("public fixture exceeded emission bound")
        print(json.dumps({
            "public_fixture": name, "size": len(data), "sha256": digest(data),
            "base64": base64.b64encode(data).decode("ascii"),
        }))


def exercise(smoke, fixture_root, wrong_signature, revocation_document, revocation_bundle):
    fixture = smoke.fixture
    # All consumer homes and their contents stay private and are never emitted.
    with tempfile.TemporaryDirectory(prefix="application-inspection-") as temporary:
        private = Path(temporary)
        baseline = private / "baseline"
        shutil.copytree(fixture_root / "consumer-home", baseline)
        for key in fixture["paths"].values():
            contained(baseline, key)
        configure_operator_trust(baseline, fixture)
        setup = [
            [
                "pack", "registry", "revocations", "update",
                "--document", str(revocation_document), "--bundle", str(revocation_bundle),
            ],
            ["bundle", "install", str(fixture_root / "application.mvmpkg"), "--prod"],
            ["pull", fixture["reference"], "--json"],
        ]
        for number, argv in enumerate(setup):
            result = smoke.command(f"setup-{number}", baseline, argv)
            if result.returncode != 0:
                raise ValueError("fixture setup refused; see retained stderr")
        smoke.capture_audit_identity(baseline)
        smoke.inspect("positive", baseline, True)
        for case in CASES:
            home = private / case
            shutil.copytree(baseline, home)
            mutate(home, fixture, case, wrong_signature)
            smoke.inspect(case, home, False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "fixture-dir", "wrong-signature", "out-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("revocation-document", "revocation-bundle"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--revocation-source-sha", required=True)
    parser.add_argument("--source-sha", required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
