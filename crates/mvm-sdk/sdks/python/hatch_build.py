"""Hatchling build hook: platform-tag the wheel when it embeds the host library.

The publish workflow builds ``libmvm_hostlib`` per platform and copies it
into ``mvm/_native/`` before building. A wheel that carries the library
must be platform-tagged — a universal wheel would let another platform's
pip install a package whose transport file has the wrong format. A build
without the library (local development) stays universal: the SDK loaders
fall back to the library beside ``mvmctl``.

On Linux this hook can only say ``linux_<arch>``, which PyPI refuses: which
glibc or musl the library needs is a property of how it was linked, not of
the build host. The publish workflow therefore hands the wheel to auditwheel,
which reads the library's symbol versions and retags it ``manylinux_2_17`` or
``musllinux_1_2`` only if the library satisfies that policy.
"""

import os
import re
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_NATIVE_DIR = Path(__file__).resolve().parent / "mvm" / "_native"


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict) -> None:
        if version != "standard":
            return
        if not any(_NATIVE_DIR.glob("libmvm_hostlib.*")):
            return
        revision = os.environ.get("MVM_RELEASE_SOURCE_REV") or os.environ.get("GITHUB_SHA", "")
        if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
            raise RuntimeError("native wheels require the exact 40-hex build revision in MVM_RELEASE_SOURCE_REV or GITHUB_SHA")
        # python/ -> sdks/ -> mvm-sdk/ -> crates/ -> repository root.
        source = Path(__file__).resolve().parents[4] / "crates/deps/mvm-macho-sign"
        (_NATIVE_DIR / "LICENSE-MPL-2.0.txt").write_bytes((source / "LICENSE").read_bytes())
        (_NATIVE_DIR / "THIRD_PARTY_NOTICES.txt").write_text(
            "This native library contains mvm-macho-sign, modified MPL-2.0 Covered Software "
            "adapted from apple-codesign 0.29.0, Copyright Gregory Szorc.\n"
            "The included LICENSE-MPL-2.0.txt governs those files, not Apache-2.0 alone.\n"
            "Corresponding source, including modifications, is available under MPL-2.0 at:\n"
            f"https://github.com/tinylabscom/mvm/tree/{revision}/crates/deps/mvm-macho-sign\n",
            encoding="utf-8",
        )
        from packaging.tags import sys_tags

        # Same selection hatchling uses for its own infer-tag: the first
        # non-manylinux tag, with the macOS platform floor normalized.
        tag = next(
            t
            for t in sys_tags()
            if "manylinux" not in t.platform and "musllinux" not in t.platform
        )
        platform = tag.platform
        if sys.platform == "darwin":
            from hatchling.builders.macos import process_macos_plat_tag

            platform = process_macos_plat_tag(platform, compat=False)
        # The package is pure Python driving a ctypes-loaded library: the
        # interpreter and ABI stay universal, only the platform binds.
        build_data["tag"] = f"py3-none-{platform}"
        build_data["pure_python"] = False
