"""Live-mode runtime SDK fixture (Python).

Drives the imperative `Sandbox` surface with `MVM_SDK_MODE=live`. Every call
goes to the host library; `_recording_hostlib` replaces the library's one C
call with a recorder, so the scenario asserts the method trace with no
library loaded and no microVM booted.

The TypeScript twin (`typescript_live.mjs`) performs the identical sequence;
the traces they produce are compared for cross-language parity.
"""

import _recording_hostlib  # noqa: F401  (installs the recorder)
import mvm

sandbox = mvm.Sandbox.create(image="docker.io/library/python:3.12-slim", workload_id="bdd-live")
process = sandbox.commands.start(["python", "-c", "print('ok')"])
process.wait()
sandbox.files.write("/app/hello.txt", "hello")
sandbox.files.read("/app/hello.txt")
sandbox.files.list("/app")
sandbox.kill()
print("live-ok")
