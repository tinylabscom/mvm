import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export function publicationOrder(packages) {
  const mains = packages.filter((entry) => entry.name === "@runmvm/mvm");
  if (mains.length !== 1) throw new Error("expected exactly one main npm package");
  const main = mains[0];
  const platforms = main.optionalDependencies ?? {};
  const names = packages.map((entry) => entry.name);
  if (typeof main.version !== "string" || !main.version || !Object.keys(platforms).length ||
      new Set(names).size !== names.length || names.length !== Object.keys(platforms).length + 1) {
    throw new Error("npm platform package set is duplicated or incomplete");
  }
  for (const entry of packages) {
    if (entry !== main && (!entry.name.startsWith("@runmvm/mvm-") ||
        platforms[entry.name] !== entry.version || entry.version !== main.version)) {
      throw new Error(`unexpected or version-mismatched platform package: ${entry.name}`);
    }
  }
  return [...packages.filter((entry) => entry !== main)
    .sort((a, b) => a.name.localeCompare(b.name)), main];
}

export async function isPublished(entry, request = fetch) {
  const response = await request(
    `https://registry.npmjs.org/${encodeURIComponent(entry.name)}/${encodeURIComponent(entry.version)}`,
    { signal: AbortSignal.timeout(60_000), redirect: "error" },
  );
  if (response.status === 404) return false;
  if (response.status !== 200) throw new Error(`npm lookup for ${entry.name} returned HTTP ${response.status}`);
  const found = await response.json();
  if (found.name !== entry.name || found.version !== entry.version ||
      typeof found.dist?.integrity !== "string" || !found.dist.integrity) {
    throw new Error(`malformed npm version response for ${entry.name}`);
  }
  if (entry.name === "@runmvm/mvm") {
    const expected = Object.entries(entry.optionalDependencies ?? {}).sort();
    const actual = Object.entries(found.optionalDependencies ?? {}).sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error("published main package has different platform dependencies; a new SDK version is required");
    }
  }
  return true;
}

export async function publishPackages(packages, lookup = isPublished, publish = (entry) => {
  execFileSync("npm", ["publish", entry.file, "--provenance", "--access", "public"], { stdio: "inherit" });
}) {
  const ordered = publicationOrder(packages);
  // Registry failures and mismatched existing versions stop before any upload.
  const present = await Promise.all(ordered.map((entry) => lookup(entry)));
  for (let index = 0; index < ordered.length; index += 1) {
    const entry = ordered[index];
    if (present[index]) console.log(`${entry.name}@${entry.version} already published; skipping`);
    else await publish(entry);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const directory = process.argv[2] ?? "dist";
  const packages = readdirSync(directory).filter((file) => file.endsWith(".tgz")).map((file) => {
    const path = join(directory, file);
    const manifest = JSON.parse(execFileSync("tar", ["xzf", path, "-O", "package/package.json"], { encoding: "utf8" }));
    return { ...manifest, file: path };
  });
  await publishPackages(packages);
}
