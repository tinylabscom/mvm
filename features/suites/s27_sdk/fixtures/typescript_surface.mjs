// Print the TypeScript SDK's public surface as sorted JSON. Twin of
// `python_surface.py`.
//
// Runtime keys, not declared types: an `export type` is erased by tsc and has
// no runtime presence, so a type-only name legitimately shows up as
// Python-only. Those are enumerated in `surface_divergence.json` rather than
// papered over.
import * as mvm from "../../../../crates/mvm-sdk/sdks/typescript/dist/index.js";

console.log(JSON.stringify(Object.keys(mvm).sort()));
