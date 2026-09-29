"""Launch-surface SDK fixture (Python).

Drives what a launch can carry beyond an image: a built template, a command
started once the machine is up with its environment, a one-shot
`Machine.run`, and a followed log stream. `_recording_hostlib` replaces the
library's one C call with a recorder, so no library loads and no VM boots.

The TypeScript twin (`typescript_launch.mjs`) performs the identical
sequence; the traces they produce are compared for cross-language parity.
"""

import _recording_hostlib  # noqa: F401  (installs the recorder)
import mvm

sandbox = mvm.Sandbox.create(
    "chromium",
    workload_id="bdd-launch",
    command=["/serve", "--port", "9222"],
    env={"MODE": "headless"},
)
sandbox.process.wait()
sandbox.kill()

result = mvm.Machine.run("docker.io/library/alpine:3.20", ["uname"], env={"LANG": "C"})
assert result.exit_code == 0 and result.stdout == "ok\n", result

logs = "".join(mvm.Machine("sdk-bdd-vm").logs(10, follow=True))
assert logs == "booted\n", logs
print("launch-ok")
