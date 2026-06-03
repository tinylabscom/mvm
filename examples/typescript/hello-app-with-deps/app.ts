/**
 * Minimal `mvm.app({...})(fn)` example that pulls an npm dependency.
 *
 * Mirrors `examples/typescript/hello-app/app.ts` but imports `is-number`
 * from node_modules. `mvmctl compile` walks the AST statically (the host
 * never runs the script); the bundled `package-lock.json` then drives a
 * reproducible build-time `node_modules` build (nixpkgs importNpmLock) inside
 * the builder VM. node_modules is baked into the read-only app image, so the
 * runtime resolves `/app/node_modules` natively — no boot-time install, no
 * runtime network.
 *
 * The SDK import is stripped from the guest bundle (the SDK never ships in
 * the rootfs); the `is-number` import survives.
 */

import * as mvm from "mvm-sdk";
import isNumber from "is-number";

export const greet = mvm.app({
  image: mvm.node_image({ node: "22" }),
  resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
})((name: string): string =>
  isNumber(name) ? `hello number ${name}` : `hello ${name}`,
);
