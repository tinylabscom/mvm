import * as mvm from "../../../../crates/mvm-sdk/sdks/typescript/dist/index.js";

mvm.resetRecording();
const sandbox = mvm.Sandbox.create("python-3.12", { workloadId: "bdd-runtime" });
sandbox.commands.start(["python", "-c", "print('ok')"]);
sandbox.files.write("/app/hello.txt", "hello");
console.log(mvm.emitRecordingJson());
