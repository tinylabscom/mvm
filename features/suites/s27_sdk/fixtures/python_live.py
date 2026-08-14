"""Live-mode runtime SDK fixture (Python).

Drives the imperative `Sandbox` surface with `MVM_SDK_MODE=live`, so every
call shells to the `mvmctl` named by `MVM_CLI_BIN`. The scenario points that
at the recording double and asserts the resulting argv trace.

The TypeScript twin (`typescript_live.mjs`) performs the identical sequence;
the trace they produce is compared for cross-language parity.
"""

import mvm

sandbox = mvm.Sandbox.create("python-3.12", workload_id="bdd-live")
process = sandbox.commands.start(["python", "-c", "print('ok')"])
process.wait()
sandbox.files.write("/app/hello.txt", "hello")
sandbox.files.read("/app/hello.txt")
sandbox.files.list("/app")
sandbox.kill()
print("live-ok")
