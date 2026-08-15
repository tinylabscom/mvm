// Live-mode runtime SDK fixture (TypeScript).
//
// Twin of `python_live.py`: the identical `Sandbox` sequence under
// `MVM_SDK_MODE=live`, so the scenario can assert both languages drive the
// CLI through the same verbs in the same order.
//
// Imports the built artifact rather than the sources, because the failure this
// guards against — `require` in an ESM package — only appears once TypeScript
// has emitted ESM. A source-level runner (vitest) supplies CJS interop and
// cannot see it.
import * as mvm from "../../../../crates/mvm-sdk/sdks/typescript/dist/index.js";

const sandbox = mvm.Sandbox.create("python-3.12", { workloadId: "bdd-live" });
const process_ = sandbox.commands.start(["python", "-c", "print('ok')"]);
process_.wait();
sandbox.files.write("/app/hello.txt", "hello");
sandbox.files.read("/app/hello.txt");
sandbox.files.list("/app");
sandbox.kill();
console.log("live-ok");
