"""hello-env: the landing-page quickstart example.

`mvmctl build compile examples/python/hello-env/app.py --out /tmp/hello-env`
walks the AST statically and emits flake.nix + launch.json + bundled src/ —
the host never imports or executes this script. `mvmctl machine run --flake
/tmp/hello-env --entrypoint` then dispatches `main()` over the
function-entrypoint protocol; the env mapping is baked into the workload, so
the run prints the value below.

A bare string in `env={...}` is an explicit literal — `mvm.literal(...)` is
the equivalent spelled-out form (see `examples/python/hello-app/` for that
variant, and `mvm.secret(...)` for values that must never enter the guest).
"""

import os

import mvm


@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
    env={"NAME": "danny"},
    before_start="export FOO=1",
)
def main() -> None:
    print(f"hello {os.environ['NAME']}")
