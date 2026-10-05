"""Smoke-test an installed ``mvm`` wheel against the library it carries.

Run with the interpreter of a fresh environment the wheel was installed
into, from outside the source tree, so ``import mvm`` cannot pick up the
checkout::

    python /path/to/smoke_installed.py

It proves the wheel works on this host, not just that it unpacked: the
package carries ``libmvm_hostlib`` under ``mvm/_native/``, the SDK's own
resolution picks that file, the dynamic loader accepts it (which is where a
wheel tagged for a libc older than the library needs fails), the ABI
negotiation succeeds, and one real call returns OK. Where ``/proc`` exists it
also checks the process mapped that exact file.
"""

import os
import sys

import mvm
from mvm import _hostlib


def main() -> None:
    if os.environ.get(_hostlib.LIB_PATH_ENV):
        sys.exit(f"{_hostlib.LIB_PATH_ENV} is set; the smoke must exercise package resolution")
    if "site-packages" not in mvm.__file__:
        sys.exit(f"imported mvm from {mvm.__file__}, not from an installed wheel")

    packaged = os.path.join(_hostlib.PACKAGED_DIR, _hostlib.library_file_name())
    if not os.path.isfile(packaged):
        sys.exit(f"the wheel installed without {packaged}")
    resolved = _hostlib.resolve_library_path(which=lambda _: None)
    if resolved != packaged:
        sys.exit(f"the SDK resolved {resolved}, not the packaged {packaged}")

    # Loads the library, declares its signatures, and refuses an ABI the
    # binding was not built for; then one call that needs no machine.
    lib = _hostlib._load()
    version = lib.mvm_hostlib_abi_version()
    mvm.set_approval_callback(None)

    if os.path.exists("/proc/self/maps"):
        with open("/proc/self/maps", encoding="utf-8") as maps:
            if os.path.realpath(packaged) not in maps.read():
                sys.exit(f"the SDK loaded a host library, but not {packaged}")

    print(f"loaded {packaged}, host ABI {version >> 16}.{version & 0xFFFF}")


if __name__ == "__main__":
    main()
