"""Hatchling build hook: platform-tag the wheel when it embeds the host library.

The publish workflow builds ``libmvm_hostlib`` per platform and copies it
into ``mvm/_native/`` before building. A wheel that carries the library
must be platform-tagged — a universal wheel would let another platform's
pip install a package whose transport file has the wrong format. A build
without the library (local development) stays universal: the SDK loaders
fall back to the library beside ``mvmctl``.
"""

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
