// Refusal-path fixture (TypeScript). Twin of `python_refusals.py`.
import * as mvm from "../../../../crates/mvm-sdk/sdks/typescript/dist/index.js";

const verdicts = {};

const sandbox = mvm.Sandbox.create("python-3.12", { workloadId: "bdd-refusals" });
try {
  sandbox.commands.start(["python", "-c", "print('ok')"]);
  verdicts.sealed_commands_start = "admitted";
} catch (error) {
  verdicts.sealed_commands_start = error.constructor.name;
  verdicts.sealed_commands_start_message = error.message;
}

try {
  sandbox.files.write("/app/hello.txt", "hello");
  verdicts.sealed_files_write = "admitted";
} catch (error) {
  verdicts.sealed_files_write = error.constructor.name;
}

process.env.MVM_SDK_MODE = "plan";
mvm.resetRecording();
try {
  mvm.Sandbox.create("python-3.12", { workloadId: "bdd-plan" });
  verdicts.plan_mode = "admitted";
} catch (error) {
  verdicts.plan_mode = error.constructor.name;
}

process.env.MVM_SDK_MODE = "not-a-mode";
mvm.resetRecording();
try {
  mvm.Sandbox.create("python-3.12", { workloadId: "bdd-bogus" });
  verdicts.unknown_mode = "admitted";
} catch (error) {
  verdicts.unknown_mode = error.constructor.name;
}

console.log(JSON.stringify(verdicts, Object.keys(verdicts).sort()));
