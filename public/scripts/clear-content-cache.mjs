import { rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const defaultPublicRoot = dirname(dirname(scriptPath));

export async function clearContentCache(publicRoot = defaultPublicRoot) {
  await rm(join(publicRoot, ".astro", "data-store.json"), { force: true });
}

if (process.argv[1] === scriptPath) {
  await clearContentCache();
}
