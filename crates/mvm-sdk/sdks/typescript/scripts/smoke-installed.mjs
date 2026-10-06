// Smoke-test an installed @runmvm/mvm against its platform package.
//
//   node smoke-installed.mjs <platform-key>
//
// Copy this file into the directory the packages were installed into and run
// it there: bare imports resolve from the importing file, so run from the
// checkout it would find the checkout's dependencies instead.
//
// It proves the published shape works on this host: the main package carries
// no library of its own, the platform package for <platform-key> is installed
// and holds one, and the SDK's own loader finds that library, negotiates the
// ABI with it, and makes a call that succeeds. Where /proc exists it also
// checks the process mapped that exact file, so a library found somewhere
// else cannot pass for it.

import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sandbox, setApprovalCallback } from "@runmvm/mvm";

const key = process.argv[2];
if (!key) {
  console.error("usage: smoke-installed.mjs <platform-key>");
  process.exit(2);
}
if (process.env.MVM_HOSTLIB_PATH) {
  throw new Error("MVM_HOSTLIB_PATH is set; the smoke must exercise package resolution");
}
if (typeof Sandbox?.create !== "function") {
  throw new Error("the installed SDK does not expose Sandbox.create");
}

// `exports` publishes only the entry point (dist/index.js), so the package
// root is found from it.
const mainRoot = path.dirname(path.dirname(fileURLToPath(import.meta.resolve("@runmvm/mvm"))));
if (existsSync(path.join(mainRoot, "native"))) {
  throw new Error(`${mainRoot} carries native/; the library belongs in the platform package`);
}

const platformRoot = path.dirname(
  fileURLToPath(import.meta.resolve(`@runmvm/mvm-${key}/package.json`)),
);
const libName = process.platform === "darwin" ? "libmvm_hostlib.dylib" : "libmvm_hostlib.so";
const libPath = path.join(platformRoot, libName);
if (!existsSync(libPath)) {
  throw new Error(`the platform package is missing ${libPath}`);
}

// Loads the library through the SDK's resolution order, refuses an ABI
// mismatch, then makes one real call. Clearing the approval callback needs
// no machine and changes nothing.
setApprovalCallback(null);

if (existsSync("/proc/self/maps")) {
  const mapped = readFileSync("/proc/self/maps", "utf8");
  if (!mapped.includes(realpathSync(libPath))) {
    throw new Error(`the SDK loaded a host library, but not ${libPath}`);
  }
}
console.log(`loaded ${libPath} and negotiated the host ABI`);
