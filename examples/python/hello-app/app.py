"""Minimal `@mvm.app(...)` example — port-plan Phase 8 follow-up.

Two routes from this file produce the same Workload IR:

  - `mvmctl build compile examples/python/hello-app/app.py` walks the AST
    statically and emits flake.nix + launch.json + bundled src/. The
    host never imports or executes this script.

  - `python app.py` (after `pip install ./sdks/python`) imports `mvm`,
    the decorator records the declaration, and the user can pipe
    `mvm.emit_json()` to disk for the same IR. This route runs the
    script and is useful for IDE introspection.

`mvmctl machine run --flake . --entrypoint` (after a build) dispatches `greet(name="ari")` over the function-entrypoint
protocol and returns the encoded string.
"""

import mvm


@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
    env={"HELLO_BANNER": mvm.literal("hi there")},
    before_start="export FOO=1",
)
def greet(name: str) -> str:
    return f"hello {name}"
