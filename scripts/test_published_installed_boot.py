#!/usr/bin/env python3
"""Tests for the installed-bytes comparison in published-installed-boot.py."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("published-installed-boot.py")
spec = importlib.util.spec_from_file_location("published_installed_boot", SCRIPT)
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)

DARWIN = "aarch64-apple-darwin"
LINUX = "x86_64-unknown-linux-gnu"


def macho(code, signature, trailing=b""):
    """A thin 64-bit Mach-O: header, __LINKEDIT, LC_CODE_SIGNATURE, code, signature."""
    dataoff = 32 + 72 + 16 + len(code)
    header = struct.pack("<IiiIIIII", boot.MH_MAGIC_64, 0x0100000C, 0, 2, 2, 88, 0, 0)
    linkedit = struct.pack("<II16sQQQQiiII", boot.LC_SEGMENT_64, 72, b"__LINKEDIT",
                           0, len(signature), dataoff, len(signature), 1, 1, 0, 0)
    sigcmd = struct.pack("<IIII", boot.LC_CODE_SIGNATURE, 16, dataoff, len(signature))
    return header + linkedit + sigcmd + code + signature + trailing


def tarball(path, members, target):
    with tarfile.open(path, "w:gz") as tar:
        root = tarfile.TarInfo(f"mvmctl-{target}")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        for name, data in members.items():
            info = tarfile.TarInfo(f"mvmctl-{target}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


class UnsignedDigest(unittest.TestCase):
    CODE = bytes(range(256)) * 2

    def test_a_resigned_file_has_the_same_digest_but_other_bytes(self):
        original = macho(self.CODE, b"S" * 100)
        resigned = macho(self.CODE, b"T" * 140)
        self.assertNotEqual(original, resigned)
        self.assertIsNotNone(boot.unsigned_macho_digest(original))
        self.assertEqual(boot.unsigned_macho_digest(original),
                         boot.unsigned_macho_digest(resigned))

    def test_a_changed_code_byte_changes_the_digest(self):
        changed = bytearray(self.CODE)
        changed[10] ^= 1
        self.assertNotEqual(boot.unsigned_macho_digest(macho(self.CODE, b"S" * 100)),
                            boot.unsigned_macho_digest(macho(bytes(changed), b"S" * 100)))

    def test_a_changed_header_byte_outside_the_masked_fields_changes_the_digest(self):
        data = bytearray(macho(self.CODE, b"S" * 100))
        data[4] ^= 1  # cputype
        self.assertNotEqual(boot.unsigned_macho_digest(macho(self.CODE, b"S" * 100)),
                            boot.unsigned_macho_digest(bytes(data)))

    def test_bytes_after_the_signature_are_not_described(self):
        self.assertIsNone(boot.unsigned_macho_digest(
            macho(self.CODE, b"S" * 100, trailing=b"hidden")))

    def test_anything_that_is_not_a_thin_macho_is_not_described(self):
        for data in (b"", b"\x7fELF" + bytes(60), b"#!/bin/sh\n", boot.MH_MAGIC_64.to_bytes(4, "little")):
            self.assertIsNone(boot.unsigned_macho_digest(data), data[:8])

    def test_a_macho_without_a_signature_command_is_not_described(self):
        data = bytearray(macho(self.CODE, b"S" * 100))
        struct.pack_into("<I", data, 32 + 72, 0x2)  # LC_SYMTAB in place of LC_CODE_SIGNATURE
        self.assertIsNone(boot.unsigned_macho_digest(bytes(data)))


class InstalledMatches(unittest.TestCase):
    def check(self, installed, published, unsigned):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mvmctl"
            path.write_bytes(installed)
            return boot.installed_matches(path, hashlib.sha256(published).hexdigest(), unsigned)

    def test_identical_bytes_match(self):
        data = macho(b"C" * 300, b"S" * 100)
        self.assertTrue(self.check(data, data, None))

    def test_a_resigned_file_matches_only_with_its_unsigned_digest(self):
        published = macho(b"C" * 300, b"S" * 100)
        installed = macho(b"C" * 300, b"T" * 140)
        digest = boot.unsigned_macho_digest(published)
        self.assertTrue(self.check(installed, published, digest))
        self.assertFalse(self.check(installed, published, None))

    def test_changed_code_never_matches(self):
        published = macho(b"C" * 300, b"S" * 100)
        installed = macho(b"D" * 300, b"S" * 100)
        self.assertFalse(self.check(installed, published, boot.unsigned_macho_digest(published)))


class InstalledHashes(unittest.TestCase):
    TAG = "v1"

    def layout(self, tmp, installed_cli, target):
        home = (Path(tmp) / "home").resolve()
        base = home / ".local/bin"
        (base / "guest-runtime").mkdir(parents=True)
        archives = Path(tmp) / "archives"
        archives.mkdir()
        published = macho(b"C" * 300, b"S" * 100)
        tarball(archives / f"mvmctl-{target}.tar.gz",
                {"mvmctl": published, "README.md": b"hi\n"}, target)
        runtime = b"guest runtime"
        (archives / f"mvm-guest-bins-{self.TAG}.tar.gz").write_bytes(runtime)
        (base / "guest-runtime" / f"mvm-guest-bins-{self.TAG}.tar.gz").write_bytes(runtime)
        (base / "mvmctl").write_bytes(installed_cli)
        (base / "README.md").write_bytes(b"hi\n")
        return home, archives

    def run_case(self, installed_cli, target):
        with tempfile.TemporaryDirectory() as tmp:
            home, archives = self.layout(tmp, installed_cli, target)
            return boot.installed_hashes(home, archives, target, self.TAG)

    def test_an_unmodified_install_passes_on_either_platform(self):
        published = macho(b"C" * 300, b"S" * 100)
        for target in (DARWIN, LINUX):
            with self.subTest(target=target):
                paths = {item["path"] for item in self.run_case(published, target)}
                self.assertIn("mvmctl", paths)

    def test_a_resigned_install_passes_on_macos(self):
        self.run_case(macho(b"C" * 300, b"T" * 140), DARWIN)

    def test_a_resigned_install_is_refused_off_macos(self):
        with self.assertRaisesRegex(ValueError, "installed entrypoint mismatch"):
            self.run_case(macho(b"C" * 300, b"T" * 140), LINUX)

    def test_a_modified_cli_is_refused_on_macos(self):
        with self.assertRaisesRegex(ValueError, "installed entrypoint mismatch"):
            self.run_case(macho(b"X" * 300, b"S" * 100), DARWIN)


# The components table published in the v0.28.0-rc.5 macOS archive.
COMPONENTS = (
    '# mvm backend component table — generated from BACKEND_COMPONENT_TABLE; do not edit\n'
    'firecracker\tx86_64-unknown-linux-gnu\t-\t-\tyes\tyes\tyes\tdir:firecracker\n'
    'firecracker\taarch64-unknown-linux-gnu\t-\t-\tyes\tyes\tyes\tdir:firecracker\n'
    'libkrun\taarch64-apple-darwin\t13\t26\tno\tyes\tyes\tbin:mvm-libkrun-supervisor dir:lib dir:licenses dir:sources file:SOURCE-OFFER.txt file:SOURCE-PINS\n'
    'qemu\tx86_64-unknown-linux-gnu\t-\t-\tno\tno\tyes\t-\n'
    'qemu\taarch64-unknown-linux-gnu\t-\t-\tno\tno\tyes\t-\n'
    'mock\t-\t-\t-\tno\tno\tno\t-\n'
    'hvf\taarch64-apple-darwin\t26\t-\tno\tyes\tyes\tbin:mvm-hvf-supervisor\n'
    'wasm\tx86_64-unknown-linux-gnu\t-\t-\tno\tno\tno\t-\n'
    'wasm\taarch64-unknown-linux-gnu\t-\t-\tno\tno\tno\t-\n'
    'wasm\taarch64-apple-darwin\t-\t-\tno\tno\tno\t-\n'
    'web-linux\t-\t-\t-\tno\tno\tno\t-\n'
    'apple-container\taarch64-apple-darwin\t26\t-\tno\tno\tno\t-\n'
)

LIBKRUN_TIER = ["mvm-libkrun-supervisor", "lib", "licenses", "sources",
                "SOURCE-OFFER.txt", "SOURCE-PINS"]


class PrunedPayloads(unittest.TestCase):
    def test_the_hvf_host_drops_exactly_the_libkrun_tier(self):
        self.assertEqual(boot.pruned_payloads(COMPONENTS, DARWIN, "hvf"), LIBKRUN_TIER)

    def test_a_libkrun_host_drops_the_hvf_supervisor_instead(self):
        self.assertEqual(boot.pruned_payloads(COMPONENTS, DARWIN, "libkrun"),
                         ["mvm-hvf-supervisor"])

    def test_a_linux_host_drops_nothing_because_no_other_backend_owns_files(self):
        self.assertEqual(boot.pruned_payloads(COMPONENTS, LINUX, "firecracker"), [])

    def test_an_archive_without_a_table_drops_nothing(self):
        self.assertEqual(boot.pruned_payloads(None, DARWIN, "hvf"), [])
        self.assertEqual(boot.pruned_payloads("# only a comment\n", DARWIN, "hvf"), [])

    def test_a_directory_drops_what_is_under_it_and_nothing_that_merely_shares_a_prefix(self):
        pruned = boot.pruned_payloads(COMPONENTS, DARWIN, "hvf")
        for name in ("lib", "lib/libkrun.1.dylib", "licenses/COPYING", "mvm-libkrun-supervisor"):
            self.assertTrue(boot.is_pruned(name, pruned), name)
        for name in ("libmvm_hostlib.dylib", "library", "mvm-hvf-supervisor", "mvmctl"):
            self.assertFalse(boot.is_pruned(name, pruned), name)


class InstalledWithAPrunedBackend(unittest.TestCase):
    TAG = "v1"

    def install(self, tmp, drop=(), extra_installed=()):
        home = (Path(tmp) / "home").resolve()
        base = home / ".local/bin"
        (base / "guest-runtime").mkdir(parents=True)
        archives = Path(tmp) / "archives"
        archives.mkdir()
        cli = macho(b"C" * 300, b"S" * 100)
        members = {"mvmctl": cli, "components.tsv": COMPONENTS.encode(),
                   "mvm-hvf-supervisor": b"supervisor", "mvm-libkrun-supervisor": b"libkrun",
                   "lib/libkrun.1.dylib": b"dylib", "SOURCE-PINS": b"pins"}
        tarball(archives / f"mvmctl-{DARWIN}.tar.gz", members, DARWIN)
        runtime = b"guest runtime"
        (archives / f"mvm-guest-bins-{self.TAG}.tar.gz").write_bytes(runtime)
        (base / "guest-runtime" / f"mvm-guest-bins-{self.TAG}.tar.gz").write_bytes(runtime)
        for name, data in members.items():
            if name in drop or boot.is_pruned(name, LIBKRUN_TIER):
                continue
            (base / name).write_bytes(data)
        for name in extra_installed:
            (base / name).parent.mkdir(parents=True, exist_ok=True)
            (base / name).write_bytes(members[name])
        return home, archives

    def check(self, backend, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            home, archives = self.install(tmp, **kwargs)
            return boot.installed_hashes(home, archives, DARWIN, self.TAG, backend)

    def test_the_hvf_install_without_the_libkrun_tier_passes(self):
        paths = {item["path"] for item in self.check("hvf")}
        self.assertIn("mvm-hvf-supervisor", paths)
        self.assertFalse(paths & set(LIBKRUN_TIER), paths)
        self.assertNotIn("lib/libkrun.1.dylib", paths)

    def test_without_a_backend_nothing_is_excused_and_the_gap_is_named(self):
        with self.assertRaisesRegex(ValueError, "installed payload missing: "):
            self.check(None)

    def test_a_file_the_backend_keeps_must_still_be_there(self):
        with self.assertRaisesRegex(ValueError,
                                    "installed payload missing: mvm-hvf-supervisor"):
            self.check("hvf", drop=("mvm-hvf-supervisor",))

    def test_a_libkrun_host_must_have_the_libkrun_tier_and_not_the_hvf_supervisor(self):
        with self.assertRaisesRegex(ValueError, "installed payload missing: "):
            self.check("libkrun")


class QualificationTests(unittest.TestCase):
    def test_exact_older_and_current_tiers(self):
        for major in (13, 14, 15, 25, 26, 27):
            backend = "libkrun" if major < 26 else "hvf"
            expected = boot.qualification(f"mac{major}", major, backend)
            with patch.object(boot.platform, "system", return_value="Darwin"), \
                 patch.object(boot.platform, "machine", return_value="arm64"), \
                 patch.object(boot.subprocess, "check_output",
                              side_effect=[f"{major}.1\n", "test-build\n"]):
                host = boot.host_observation(DARWIN, expected)
            self.assertEqual(host["macos_major"], major)
            self.assertEqual(host["macos_build"], "test-build")
            boot.validate_host(host, DARWIN, expected)
            with self.assertRaisesRegex(ValueError, "tier"):
                boot.qualification("wrong", major, "hvf" if backend == "libkrun" else "libkrun")

    def test_wrong_host_refused_before_download(self):
        for system, machine, major, explicit in (
            ("Darwin", "x86_64", 13, True), ("Linux", "arm64", 13, True),
            ("Darwin", "arm64", 27, True), ("Darwin", "arm64", 13, False),
        ):
            with self.subTest(system=system, machine=machine, major=major), \
                 tempfile.TemporaryDirectory() as tmp, \
                 patch.object(boot, "identity", return_value={}), \
                 patch.object(boot.platform, "system", return_value=system), \
                 patch.object(boot.platform, "machine", return_value=machine), \
                 patch.object(boot.subprocess, "check_output", side_effect=[str(major), "build"]), \
                 patch.object(boot, "authenticate") as authenticate:
                args = SimpleNamespace(tag="v1", target=DARWIN, out=Path(tmp) / "out")
                if explicit:
                    args.lane_name, args.expected_macos_major, args.expected_backend = "mac13", 13, "libkrun"
                with self.assertRaises(ValueError):
                    boot.lane(args)
                authenticate.assert_not_called()
                self.assertFalse(args.out.exists())

    def test_incomplete_or_duplicate_configuration_refused(self):
        for values in (("mac13", None, "libkrun"), (None, 13, "libkrun"),
                       ("mac13", 13, None), ("bad/name", 13, "libkrun")):
            with self.assertRaises(ValueError):
                boot.qualification(*values)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            boot.required_qualifications(["mac13:13:libkrun"] * 2)

    def test_missing_failed_duplicate_and_mismatched_diagnostics_refused(self):
        valid = diagnostic_text("libkrun")
        self.assertEqual(boot.observed_backend(valid, "libkrun"), "libkrun")
        for text in ("", valid + valid, diagnostic_text("hvf"),
                     diagnostic_text(None), diagnostic_text("libkrun", False)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                boot.observed_backend(text, "libkrun")

    def test_all_four_boots_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            for checks in ([], boot.BOOT_CHECKS[:-1], boot.BOOT_CHECKS * 2):
                (path / "boot-results.jsonl").write_text(
                    "".join(json.dumps(check) + "\n" for check in checks))
                with self.assertRaises(ValueError):
                    boot.boot_checks(path)

    def test_lane_requires_observation_and_scrubs_overrides(self):
        for actual in ("libkrun", "hvf", None):
            with self.subTest(actual=actual), tempfile.TemporaryDirectory() as tmp:
                args = SimpleNamespace(tag="v1", target=DARWIN, out=Path(tmp) / "out",
                                       lane_name="mac13", expected_macos_major=13,
                                       expected_backend="libkrun")

                def smoke(*command, env):
                    self.assertEqual(command, ("sh", "scripts/smoke-fresh-install.sh", "v1"))
                    self.assertEqual(env["MVM_SMOKE_NO_HOMEBREW"], "1")
                    self.assertEqual(env["MVM_SMOKE_BACKEND_EVIDENCE"], "1")
                    self.assertNotIn("MVM_HYPERVISOR", env)
                    self.assertNotIn("MVM_SMOKE_ARCHIVE", env)
                    home = Path(env["MVM_SMOKE_TEMP_PARENT"]) / "s.abc/home"
                    home.mkdir(parents=True)
                    Path(env["MVM_SMOKE_STATE_FILE"]).write_text(str(home) + "\n")
                    out = Path(env["MVM_SMOKE_OUT"])
                    out.mkdir()
                    (out / "transcript.log").write_text(
                        diagnostic_text(actual) if actual else "\nPASS: fixture\n")
                    (out / "boot-results.jsonl").write_text(
                        "".join(json.dumps(check) + "\n" for check in boot.BOOT_CHECKS))

                with patch.object(boot, "identity", return_value={}), \
                     patch.object(boot, "host_observation", return_value={
                         "system": "Darwin", "machine": "arm64", "macos_major": 13,
                         "macos_version": "13.1", "macos_build": "fixture"}), \
                     patch.object(boot, "authenticate", return_value=[]), \
                     patch.object(boot, "installed_hashes", return_value=[]), \
                     patch.object(boot, "run", side_effect=smoke), \
                     patch.object(boot, "stop_owned") as cleanup, \
                     patch.dict(boot.os.environ, {"MVM_HYPERVISOR": "hvf",
                                                 "MVM_SMOKE_ARCHIVE": "unverified"}):
                    if actual == "libkrun":
                        boot.lane(args)
                        report = json.loads((args.out / "lane.json").read_text())
                        self.assertEqual(report["boots"][0]["diagnostics_selected_backend"], actual)
                    else:
                        with self.assertRaises(ValueError):
                            boot.lane(args)
                        self.assertFalse((args.out / "lane.json").exists())
                    cleanup.assert_called_once()


def diagnostic_text(backend, ok=True):
    return ("\nMVM_BACKEND_DIAGNOSTICS_BEGIN\n" +
            json.dumps({"all_ok": ok, "security_posture": {"backend": backend}}) +
            "\nMVM_BACKEND_DIAGNOSTICS_END\nPASS: fixture only\n")


class AggregateTests(unittest.TestCase):
    def fixture(self, tmp, qualifications=None):
        root = Path(tmp)
        assets = root / "assets"
        assets.mkdir()
        targets = [DARWIN] if qualifications else list(boot.LANES)
        for target in targets:
            members = {"mvmctl": b"cli"}
            if target == DARWIN:
                members.update({"components.tsv": COMPONENTS.encode(),
                                "mvm-hvf-supervisor": b"hvf",
                                "mvm-libkrun-supervisor": b"libkrun"})
            tarball(assets / f"mvmctl-{target}.tar.gz", members, target)
        (assets / "mvm-guest-bins-v1.tar.gz").write_bytes(b"runtime")
        authenticated = sorted(
            [{"name": p.name, "sha256": boot.sha(p)} for p in assets.iterdir()],
            key=lambda a: a["name"])
        entries = ([(DARWIN, boot.qualification(*q)) for q in qualifications]
                   if qualifications else [(target, None) for target in targets])
        lanes = root / "lanes"
        for index, (target, qualification) in enumerate(entries):
            arch, backend, system, machine = boot.LANES[target]
            major = qualification["macos_major"] if qualification else 27
            backend = qualification["backend"] if qualification else backend
            directory = lanes / str(index)
            smoke = directory / "smoke"
            smoke.mkdir(parents=True)
            transcript = smoke / "transcript.log"
            transcript.write_text(diagnostic_text(backend))
            (smoke / "boot-results.jsonl").write_text(
                "".join(json.dumps(check) + "\n" for check in boot.BOOT_CHECKS))
            hashes = boot.payload_hashes(assets / f"mvmctl-{target}.tar.gz", target)
            pruned = boot.pruned_payloads(COMPONENTS, target, backend)
            hashes = {n: h for n, h in hashes.items() if not boot.is_pruned(n, pruned)}
            hashes["guest-runtime/mvm-guest-bins-v1.tar.gz"] = boot.sha(assets / "mvm-guest-bins-v1.tar.gz")
            host = {"system": system, "machine": machine}
            if system == "Darwin":
                host.update(macos_major=major, macos_version=f"{major}.1", macos_build="test")
            record = {"host_target": target, "guest_arch": arch, "backend": backend,
                      "diagnostics_selected_backend": backend, "host": host,
                      "no_homebrew": major < 26, "result": "success",
                      "checks": boot.BOOT_CHECKS,
                      "installed": [{"path": n, "sha256": h} for n, h in sorted(hashes.items())],
                      "transcript": {"path": "smoke/transcript.log", "sha256": boot.sha(transcript)}}
            if qualification:
                record["qualification"] = qualification
            (directory / "lane.json").write_text(json.dumps({
                "boots": [record], "assets": [a for a in authenticated if a["name"] in
                    (f"mvmctl-{target}.tar.gz", "mvm-guest-bins-v1.tar.gz")]}))
        args = SimpleNamespace(tag="v1", lanes=lanes, assets=assets, out=root / "result.json",
                               required_lane=[f"{n}:{m}:{b}" for n, m, b in qualifications]
                               if qualifications else None)
        return args, authenticated

    def aggregate(self, args, assets):
        with patch.object(boot, "identity", return_value={}), \
             patch.object(boot, "authenticate", return_value=assets):
            boot.aggregate(args)

    def test_default_two_target_aggregate_and_pruned_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, assets = self.fixture(tmp)
            self.aggregate(args, assets)
            report = json.loads(args.out.read_text())
            self.assertEqual(len(report["boots"]), 2)
            self.assertNotIn("required_qualifications", report)

    def test_distinct_same_target_named_lanes(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, assets = self.fixture(tmp, [("mac13", 13, "libkrun"), ("mac27", 27, "hvf")])
            self.aggregate(args, assets)
            report = json.loads(args.out.read_text())
            self.assertEqual(len(report["required_qualifications"]), 2)
            self.assertEqual({b["host_target"] for b in report["boots"]}, {DARWIN})

    def test_incomplete_duplicate_wrong_or_unobserved_lanes_cannot_pass(self):
        for mutation in ("missing", "duplicate", "host", "backend", "no-homebrew",
                         "diagnostics", "defaults"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                args, assets = self.fixture(tmp, [("mac13", 13, "libkrun"), ("mac14", 14, "libkrun")])
                path = args.lanes / "1/lane.json"
                record = json.loads(path.read_text())
                item = record["boots"][0]
                if mutation == "missing":
                    path.unlink()
                elif mutation == "duplicate":
                    item["qualification"] = boot.qualification("mac13", 13, "libkrun")
                elif mutation == "host":
                    item["host"]["macos_major"] = 27
                elif mutation == "backend":
                    item["backend"] = "hvf"
                elif mutation == "no-homebrew":
                    item["no_homebrew"] = False
                elif mutation == "diagnostics":
                    item.pop("diagnostics_selected_backend")
                else:
                    args.required_lane = None
                if mutation != "missing":
                    path.write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    self.aggregate(args, assets)
                self.assertFalse(args.out.exists())


if __name__ == "__main__":
    unittest.main()
