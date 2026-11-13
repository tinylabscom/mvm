"""hello-env: the landing-page quickstart example.

`mvmctl dev compile examples/python/hello-env/app.py --out /tmp/hello-env`
walks the AST statically and emits flake.nix + launch.json + bundled src/ —
the host never imports or executes this script. `mvmctl machine run --flake
/tmp/hello-env --entrypoint` then dispatches `main()` over the
function-entrypoint protocol; the env mapping is baked into the workload, so
the run prints the value below.

An env value is always explicit: `mvm.literal(...)` for a literal (a bare
string is refused), and `mvm.secret(...)` for values that must never enter
the guest (see `examples/python/hello-app/` for both forms).
"""

import os

import mvm


@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
    env={"NAME": mvm.literal("danny")},
    before_start="export FOO=1",
)
def main() -> None:
    print(f"hello {os.environ['NAME']}")
