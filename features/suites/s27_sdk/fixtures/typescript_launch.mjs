// Launch-surface SDK fixture (TypeScript).
//
// Twin of `python_launch.py`: the identical sequence — a built template with a
// command and its environment, a one-shot `Machine.run`, and a followed log
// stream — so the scenario can assert both languages make the same
// host-library calls in the same order. Imports the built artifact, as the
// live fixture does.
import "./_recording_hostlib.mjs";
import * as mvm from "../../../../crates/mvm-sdk/sdks/typescript/dist/index.js";

const sandbox = mvm.Sandbox.create("chromium", {
  workloadId: "bdd-launch",
  command: ["/serve", "--port", "9222"],
  env: { MODE: "headless" },
});
await sandbox.process.wait();
sandbox.kill();

const result = mvm.Machine.run("docker.io/library/alpine:3.20", ["uname"], { env: { LANG: "C" } });
if (result.exitCode !== 0 || result.stdout !== "ok\n") {
  throw new Error(`unexpected run result ${JSON.stringify(result)}`);
}

const logs = [...new mvm.Machine("sdk-bdd-vm").logs({ lines: 10, follow: true })].join("");
if (logs !== "booted\n") throw new Error(`unexpected logs ${JSON.stringify(logs)}`);
console.log("launch-ok");
