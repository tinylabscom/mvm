"""Refusal-path fixture (Python).

Emits a JSON verdict per refusal the host-side SDK is supposed to enforce
*before* any CLI call. Each entry records whether the SDK refused and the
exception type it raised, so the scenario asserts the refusal rather than
merely the absence of a crash.
"""

import json
import os

import mvm

verdicts = {}

# A sealed (prod) machine must refuse the dev-only process verbs client-side.
# The recording double reports build_mode=prod for this fixture.
sandbox = mvm.Sandbox.create("python-3.12", workload_id="bdd-refusals")
try:
    sandbox.commands.start(["python", "-c", "print('ok')"])
    verdicts["sealed_commands_start"] = "admitted"
except mvm.SandboxDevOnly as exc:
    verdicts["sealed_commands_start"] = type(exc).__name__
    verdicts["sealed_commands_start_message"] = str(exc)

try:
    sandbox.files.write("/app/hello.txt", "hello")
    verdicts["sealed_files_write"] = "admitted"
except mvm.SandboxDevOnly as exc:
    verdicts["sealed_files_write"] = type(exc).__name__

# `plan` is the host CLI's mode, never an SDK-side transport.
os.environ["MVM_SDK_MODE"] = "plan"
mvm.reset_recording()
try:
    mvm.Sandbox.create("python-3.12", workload_id="bdd-plan")
    verdicts["plan_mode"] = "admitted"
except mvm.SandboxModeError as exc:
    verdicts["plan_mode"] = type(exc).__name__

os.environ["MVM_SDK_MODE"] = "not-a-mode"
mvm.reset_recording()
try:
    mvm.Sandbox.create("python-3.12", workload_id="bdd-bogus")
    verdicts["unknown_mode"] = "admitted"
except mvm.SandboxModeError as exc:
    verdicts["unknown_mode"] = type(exc).__name__

print(json.dumps(verdicts, sort_keys=True))
