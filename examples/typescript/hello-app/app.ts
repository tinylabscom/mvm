/**
 * Minimal `mvm.app({...})(fn)` example — port-plan Phase 8 follow-up.
 *
 * `mvmctl compile examples/typescript/hello-app/app.ts` walks this
 * file's AST statically and emits the same Workload IR a `node app.ts`
 * (with `mvm.emitJson()`) would. The host never executes the script —
 * the decorator is read, not run.
 */

import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
  resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
  env: { HELLO_BANNER: mvm.literal("hi there") },
  before_start: "export FOO=1",
})((name: string): string => `hello ${name}`);
