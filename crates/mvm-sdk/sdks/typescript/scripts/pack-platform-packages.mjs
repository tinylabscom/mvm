#!/usr/bin/env node
// Assemble and pack the per-platform npm packages that carry libmvm_hostlib,
// and declare them as optional dependencies of the main package.
//
//   node scripts/pack-platform-packages.mjs --libs <dir> --out <dir>
//
// <libs>/<key>/ must hold the library for every key in PLATFORM_PACKAGES;
// a missing one is an error, because a release that silently dropped a
// platform would install on that host and then fail at the first call.
// Each package is packed into <out>/, and package.json in the current
// directory gains `optionalDependencies` naming every platform package at
// this version — written here rather than committed, so `npm ci` in a
// checkout never asks the registry for packages that a release has not
// published yet.
//
// The platform table and the library file names come from the compiled SDK
// (`npm run build` first), the same code the loader runs.

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import { libraryFileName } from "../dist/_hostlib.js";
import { PLATFORM_PACKAGES, platformPackageName } from "../dist/_platform.js";

const { values } = parseArgs({
  options: { libs: { type: "string" }, out: { type: "string" } },
});
if (!values.libs || !values.out) {
  console.error("usage: pack-platform-packages.mjs --libs <dir> --out <dir>");
  process.exit(2);
}

const mainPath = path.resolve("package.json");
const main = JSON.parse(readFileSync(mainPath, "utf8"));
const outDir = path.resolve(values.out);
const stageRoot = path.join(outDir, "platforms");
rmSync(stageRoot, { recursive: true, force: true });
mkdirSync(stageRoot, { recursive: true });

const missing = [];
const optionalDependencies = {};
for (const pkg of PLATFORM_PACKAGES) {
  const libName = libraryFileName(pkg.os);
  const lib = path.resolve(values.libs, pkg.key, libName);
  if (!existsSync(lib)) {
    missing.push(lib);
    continue;
  }
  const name = platformPackageName(pkg);
  const stage = path.join(stageRoot, pkg.key);
  mkdirSync(stage, { recursive: true });
  copyFileSync(lib, path.join(stage, libName));
  const manifest = {
    name,
    version: main.version,
    description: `libmvm_hostlib for ${main.name} on ${pkg.key}.`,
    license: main.license,
    repository: main.repository,
    homepage: main.homepage,
    os: [pkg.os],
    cpu: [pkg.cpu],
    ...(pkg.libc ? { libc: [pkg.libc] } : {}),
    files: [libName],
    publishConfig: main.publishConfig,
  };
  writeFileSync(path.join(stage, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(
    path.join(stage, "README.md"),
    `# ${name}\n\nThe in-process host library ${main.name} loads on ${pkg.key}. ` +
      `Install ${main.name}; npm selects this package for a matching host.\n`,
  );
  execFileSync("npm", ["pack", stage, "--pack-destination", outDir], { stdio: "inherit" });
  optionalDependencies[name] = main.version;
}

if (missing.length > 0) {
  console.error(`missing host libraries:\n  ${missing.join("\n  ")}`);
  process.exit(1);
}

main.optionalDependencies = optionalDependencies;
writeFileSync(mainPath, `${JSON.stringify(main, null, 2)}\n`);
console.log(`packed ${PLATFORM_PACKAGES.length} platform packages into ${outDir}`);
