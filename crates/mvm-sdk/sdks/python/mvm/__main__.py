"""Subprocess emitter for the mvm Python SDK.

Honors the ADR-0002 SDK→host contract:

- The host invokes ``python -m mvm <entry.py>`` with the environment variable
  ``MVM_IR_OUT`` set to a file path.
- This module imports ``<entry.py>`` (which runs its registrations as a
  side-effect), serializes the resulting workload to canonical JSON, and writes
  it to the path named in ``MVM_IR_OUT``.
- Exits non-zero on any error. Does not write to other paths or to stdout/stderr
  during a successful emit.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import mvm


def _fail(msg: str, code: int = 1) -> "int":
    print(f"mvm.emit: {msg}", file=sys.stderr)
    return code


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return _fail("usage: python -m mvm <entry.py>", 2)
    out_path = os.environ.get("MVM_IR_OUT")
    if not out_path:
        return _fail("MVM_IR_OUT environment variable is not set", 2)

    entry = Path(argv[1]).resolve()
    if not entry.is_file():
        return _fail(f"entry file not found: {entry}", 2)

    mvm.reset()

    # Make sibling modules in the entry's directory importable. Without
    # this, an entry that does `from helpers import ...` (a normal
    # Python project layout — see examples/python/with-helpers/) fails
    # with `ModuleNotFoundError: No module named 'helpers'` during
    # `mvm emit`. The bundler reachability walker then has nothing
    # to follow, so the helper file would be silently dropped from the
    # bundle. We deliberately mirror what `python entry.py` already
    # does — it implicitly inserts the script's directory at sys.path[0].
    entry_dir = str(entry.parent)
    if entry_dir not in sys.path:
        sys.path.insert(0, entry_dir)

    spec = importlib.util.spec_from_file_location("__mvm_entry__", entry)
    if spec is None or spec.loader is None:
        return _fail(f"cannot load entry module from {entry}", 2)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        return _fail(f"loading {entry}: {exc.__class__.__name__}: {exc}", 1)

    try:
        ir_json = mvm.emit_json()
    except Exception as exc:
        return _fail(f"building workload: {exc.__class__.__name__}: {exc}", 1)

    Path(out_path).write_text(ir_json, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
