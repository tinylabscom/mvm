"""Minimal `@mvm.app(...)` example that declares Python deps — Plan 73 Followup D.

Mirrors `examples/python/hello-app/app.py` but adds a `dependencies=`
clause pointing at the bundled `uv.lock`. The compile pipeline walks the
AST statically and emits a `flake.nix` + `launch.json` that the build
pipeline (Followup B.2) then uses to install the locked deps inside the
builder VM into a sealed volume at `~/.mvm/volumes/deps/<hash>/`.

The lockfile pins `requests==2.32.3` — a recent release with hashes,
known to scan clean under pip-audit at the time this example was added.
The Followup D CI lane uses this example as the positive-path fixture.

  - `mvmctl build compile examples/python/hello-app-with-deps/app.py` walks
    the AST statically (no network, no VM) and emits flake.nix +
    launch.json + bundled src/.
  - `mvmctl build --deps examples/python/hello-app-with-deps/` would
    drive the install pipeline; that round-trip needs a working builder
    VM (Plan 72 W4/W5 cutover) so the Followup D CI lane stops short of
    it. The hand-sealed fixture step in the CI script exercises the
    inspect / verify / gate side end-to-end without spawning a VM.
"""

import mvm


@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
    env={"HELLO_BANNER": mvm.literal("hi from deps example")},
    dependencies=mvm.python_deps(lockfile="uv.lock", tool="uv"),
)
def greet(name: str) -> str:
    import requests  # noqa: F401 — sanity-imports the locked dep at boot.

    return f"hello {name}"
