"""Host-only mock filesystem tests; no Nix evaluation or native execution."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
import struct

SPEC = importlib.util.spec_from_file_location(
    "native_runtime", Path(__file__).parents[1] / "lib/native-runtime.py"
)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class NativeRuntime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.pkg = self.base / "pkg"
        (self.pkg / "lib").mkdir(parents=True)

    def elf(self, name, machine=183, package=None, soname=None, needed=()):
        path = (package or self.pkg) / "lib" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        soname = name if soname is None else soname
        strings = bytearray(b"\0")
        names = []
        for tag, value in ([(14, soname)] if soname else []) + [(1, n) for n in needed]:
            names.append((tag, len(strings)))
            strings.extend(value.encode() + b"\0")
        dynamic = [(5, 512), (10, len(strings))] + names + [(0, 0)]
        data = bytearray(512 + len(strings))
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", data, 16, 3)
        struct.pack_into("<H", data, 18, machine)
        struct.pack_into("<I", data, 20, 1)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<H", data, 52, 64)
        struct.pack_into("<HH", data, 54, 56, 2)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 4, 0, 0, 0, len(data), len(data), 8)
        struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 256, 256, 0, len(dynamic) * 16, len(dynamic) * 16, 8)
        for index, pair in enumerate(dynamic):
            struct.pack_into("<qQ", data, 256 + index * 16, *pair)
        data[512:] = strings
        path.write_bytes(data)
        return path

    def test_unused_program_header_ignores_undefined_fields(self):
        source = self.elf("ld-linux-aarch64.so.1")
        data = bytearray(source.read_bytes())
        struct.pack_into("<H", data, 56, 3)
        struct.pack_into(
            "<IIQQQQQQ", data, 176, 0, 0xffffffff,
            2**64 - 1, 2**64 - 1, 2**64 - 1, 2**64 - 1, 2**64 - 1, 3
        )
        source.write_bytes(data)
        aliases = runtime.plan("aarch64-linux", [self.pkg])
        self.assertEqual(aliases["lib/ld-linux-aarch64.so.1"], source)

    def test_both_interpreter_maps_and_install_preserve_bytes(self):
        for system, (loader, machine, directory) in runtime.GNU.items():
            with self.subTest(system=system):
                package = self.base / system
                source = self.elf(loader, machine, package)
                libc = self.elf("libc.so.6", machine, package)
                aliases = runtime.plan(system, [package])
                self.assertEqual(aliases[f"{directory}/{loader}"], source)
                self.assertEqual(aliases["lib/libc.so.6"], libc)
                root = self.base / f"root-{system}"
                root.mkdir()
                runtime.install(root, aliases)
                self.assertEqual((root / f"{directory}/{loader}").read_bytes(),
                                 source.read_bytes())
                self.assertTrue((root / "lib/libc.so.6").is_symlink())

    def test_missing_loader_and_unsupported_arch_fail(self):
        for system in runtime.GNU:
            with self.assertRaisesRegex(ValueError, "missing GNU interpreter"):
                runtime.plan(system, [self.pkg])
        with self.assertRaisesRegex(ValueError, "unsupported"):
            runtime.plan("riscv64-linux", [self.pkg])

    def test_ambiguity_is_not_iteration_order_dependent(self):
        self.elf("ld-linux-aarch64.so.1")
        self.elf("libc.so.6")
        other = self.base / "other"
        self.elf("libc.so.6", package=other)
        for roots in ([self.pkg, other], [other, self.pkg]):
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                runtime.plan("aarch64-linux", roots)

    def test_soname_alias_missing_dependency_and_soname_ambiguity(self):
        self.elf("ld-linux-aarch64.so.1")
        self.elf("versioned.so.1.2", soname="libexample.so.1", needed=["libmissing.so.1"])
        with self.assertRaisesRegex(ValueError, "missing runtime libraries: libmissing.so.1"):
            runtime.plan("aarch64-linux", [self.pkg])
        self.elf("libmissing.so.1")
        aliases = runtime.plan("aarch64-linux", [self.pkg])
        self.assertEqual(aliases["lib/libexample.so.1"], self.pkg / "lib/versioned.so.1.2")
        self.elf("different.so.2", soname="libexample.so.1")
        with self.assertRaisesRegex(ValueError, "ambiguous runtime SONAME"):
            runtime.plan("aarch64-linux", [self.pkg])

    def test_linker_scripts_are_not_runtime_aliases(self):
        self.elf("ld-linux-aarch64.so.1")
        self.elf("libc.so.6")
        script = self.pkg / "lib/libc.so"
        script.write_text("/* GNU ld script */\nGROUP ( libc.so.6 )\n")
        self.assertNotIn("lib/libc.so", runtime.plan("aarch64-linux", [self.pkg]))
        self.elf("libextra.so.1", needed=["libc.so"])
        with self.assertRaisesRegex(ValueError, "missing runtime libraries: libc.so"):
            runtime.plan("aarch64-linux", [self.pkg])
        script.write_bytes(b"\0garbage")
        with self.assertRaisesRegex(ValueError, "non-ELF"):
            runtime.plan("aarch64-linux", [self.pkg])

    def test_escape_wrong_arch_and_dangling_library_fail(self):
        outside = self.elf("outside", package=self.base / "outside")
        alias = self.pkg / "lib/libc.so.6"
        alias.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "escapes"):
            runtime.plan("aarch64-linux", [self.pkg])
        alias.unlink()
        self.elf("libc.so.6", machine=62)
        with self.assertRaisesRegex(ValueError, "incompatible"):
            runtime.plan("aarch64-linux", [self.pkg])
        alias.unlink()
        alias.symlink_to(self.pkg / "absent")
        with self.assertRaises(FileNotFoundError):
            runtime.plan("aarch64-linux", [self.pkg])

    def test_symlink_may_not_leave_closure_then_reenter(self):
        target = self.elf("real.so.6")
        outside = self.base / "outside-link"
        outside.symlink_to(target)
        (self.pkg / "lib/libc.so.6").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "escapes"):
            runtime.plan("aarch64-linux", [self.pkg])

    def test_intermediate_link_before_parent_is_not_normalized_away(self):
        target = self.elf("real.so.6")
        outside = self.base / "outside"
        outside.mkdir()
        (self.pkg / "lib/step").symlink_to(outside)
        alias = self.pkg / "lib/alias.so.6"
        alias.symlink_to("step/../real.so.6")
        with self.assertRaisesRegex(ValueError, "escapes"):
            runtime.closure_target(alias, [self.pkg])
        (self.pkg / "lib/step").unlink()
        (self.pkg / "nested/child").mkdir(parents=True)
        expected = self.pkg / "nested/real.so.6"
        expected.write_bytes(target.read_bytes())
        (self.pkg / "lib/step").symlink_to("../nested/child")
        self.assertEqual(runtime.closure_target(alias, [self.pkg]), expected)

    def test_symlink_cycle_and_parent_escape_are_bounded(self):
        alias = self.pkg / "lib/alias.so.6"
        alias.symlink_to("alias.so.6")
        with self.assertRaisesRegex(ValueError, "excessive"):
            runtime.closure_target(alias, [self.pkg])
        alias.unlink()
        alias.symlink_to("../../pkg/lib/alias.so.6")
        with self.assertRaisesRegex(ValueError, "escapes"):
            runtime.closure_target(alias, [self.pkg])

    def test_loader_and_library_soname_do_not_require_dependencies(self):
        for name in ("ld-linux-aarch64.so.1", "libc.so.6"):
            path = self.elf(name)
            self.assertEqual(runtime.dynamic_names(path, 183), (name, []))
        self.assertIn("lib/libc.so.6", runtime.plan("aarch64-linux", [self.pkg]))

    def test_malformed_elf_headers_and_segments(self):
        mutations = [
            (6, "<B", 0), (4, "<B", 1), (5, "<B", 2),
            (16, "<H", 2), (20, "<I", 0), (52, "<H", 0),
            (54, "<H", 0), (56, "<H", 0), (56, "<H", 65535),
            (32, "<Q", 0), (32, "<Q", 500),
            (64 + 32, "<Q", 10000), (64 + 40, "<Q", 1),
            (64 + 48, "<Q", 3), (64 + 16, "<Q", 2**64 - 1),
            (120, "<I", 0), (120 + 32, "<Q", 0),
            (120 + 32, "<Q", 17), (120 + 16, "<Q", 264),
        ]
        for offset, fmt, value in mutations:
            with self.subTest(offset=offset, value=value):
                path = self.elf("libc.so.6")
                data = bytearray(path.read_bytes())
                struct.pack_into(fmt, data, offset, value)
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    runtime.dynamic_names(path, 183)

    def test_dynamic_terminator_duplicates_and_names(self):
        for replacement, error in [
            ((1, 1), "unterminated"),
            ((5, 513), "conflicting"),
            ((10, 99), "conflicting"),
        ]:
            with self.subTest(replacement=replacement):
                path = self.elf("libc.so.6")
                data = bytearray(path.read_bytes())
                struct.pack_into("<qQ", data, 304, *replacement)
                # Extend through a new terminator for duplicate-tag cases.
                if replacement[0] in (5, 10):
                    struct.pack_into("<QQ", data, 152, 80, 80)
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, error):
                    runtime.dynamic_names(path, 183)
        for name in ("ld-linux-aarch64.so.1", "libc.so.6"):
            path = self.elf(name, soname="")
            with self.assertRaisesRegex(ValueError, "missing ELF SONAME"):
                runtime.dynamic_names(path, 183)
        for offset in (999, 0):
            path = self.elf("libc.so.6")
            data = bytearray(path.read_bytes())
            struct.pack_into("<Q", data, 296, offset)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                runtime.dynamic_names(path, 183)

    def test_overlapping_string_table_loads_are_rejected(self):
        for filesz in (0, 1, 11):
            with self.subTest(filesz=filesz):
                path = self.elf("libc.so.6")
                data = bytearray(path.read_bytes())
                struct.pack_into("<H", data, 56, 3)
                struct.pack_into("<IIQQQQQQ", data, 176,
                                 1, 4, 512, 512, 0, filesz, 11, 8)
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "string table"):
                    runtime.dynamic_names(path, 183)

    def test_string_table_tags_bounds_and_identical_duplicates(self):
        for offset, value in ((256, 99), (272, 99), (264, 999),
                              (280, 0), (280, 999)):
            with self.subTest(offset=offset, value=value):
                path = self.elf("libc.so.6")
                data = bytearray(path.read_bytes())
                struct.pack_into("<Q", data, offset, value)
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "string table"):
                    runtime.dynamic_names(path, 183)
        for tag, value in ((5, 512), (10, 11)):
            path = self.elf("libc.so.6")
            data = bytearray(path.read_bytes())
            struct.pack_into("<qQ", data, 304, tag, value)
            struct.pack_into("<QQ", data, 152, 80, 80)
            path.write_bytes(data)
            self.assertEqual(runtime.dynamic_names(path, 183), ("libc.so.6", []))

    def test_destination_collision_and_symlink_parent_fail(self):
        root = self.base / "root"
        (root / "lib").mkdir(parents=True)
        target = self.elf("libc.so.6")
        (root / "lib/libc.so.6").write_text("application owned")
        with self.assertRaisesRegex(ValueError, "collision"):
            runtime.install(root, {"lib/libc.so.6": target})
        (root / "lib/libc.so.6").unlink()
        (root / "lib").rmdir()
        (root / "lib").symlink_to(self.pkg / "lib")
        with self.assertRaisesRegex(ValueError, "parent is a symlink"):
            runtime.install(root, {"lib/libc.so.6": target})

    def test_static_factory_still_guards_all_alias_population(self):
        source = (Path(__file__).parents[1] / "lib/mk-guest.nix").read_text()
        self.assertIn("packages ? [ ]", source)
        self.assertIn("lib.optional nativeRuntimeEnabled (lib.getLib pkgs.glibc)", source)
        self.assertIn("rootPaths = nativeRuntimeRoots;", source)
        self.assertIn("${lib.optionalString nativeRuntimeEnabled ''", source)
        self.assertIn("== toString (lib.getLib pkgs.glibc)", source)
        # The roots stay out of the registered rootfs closure: an enabled
        # runtime means the pinned glibc is already registered through
        # `packages`, and the ext4 materializer retains the alias targets via
        # the absolute store-path symlinks the planner installs.
        self.assertNotIn("++ nativeRuntimeRoots", source)


if __name__ == "__main__":
    unittest.main()
