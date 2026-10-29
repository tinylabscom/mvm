// Print the TypeScript SDK's public surface as sorted JSON. Twin of
// `python_surface.py`.
//
// Runtime keys, not declared types: an `export type` is erased by tsc and has
// no runtime presence, so a type-only name legitimately shows up as
// Python-only. Those are enumerated in `surface_divergence.json` rather than
// papered over.
import assert from "node:assert/strict";
import * as mvm from "../../../../crates/mvm-sdk/sdks/typescript/dist/index.js";

assert.equal(
  "RecoveryRequiredDetails" in mvm,
  false,
  "the readonly details type must not become a runtime constructor",
);
assert.equal(typeof mvm.MachineRecoveryRequiredError, "function");
const error = new mvm.MachineRecoveryRequiredError("surface fixture");
assert.ok(error instanceof mvm.HostLibraryError);
assert.equal(error.message, "surface fixture");
assert.equal("details" in error, false, "the normal constructor must not invent details");

console.log(JSON.stringify(Object.keys(mvm).sort()));
