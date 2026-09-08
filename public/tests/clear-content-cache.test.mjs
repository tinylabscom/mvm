import assert from "node:assert/strict";
import { access, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { clearContentCache } from "../scripts/clear-content-cache.mjs";

test("clearContentCache removes only Astro's generated content store", async () => {
  const publicRoot = await mkdtemp(join(tmpdir(), "mvm-docs-cache-"));
  const astroCache = join(publicRoot, ".astro");
  const dataStore = join(astroCache, "data-store.json");
  const generatedTypes = join(astroCache, "content.d.ts");

  try {
    await mkdir(astroCache);
    await writeFile(dataStore, "stale");
    await writeFile(generatedTypes, "keep");

    await clearContentCache(publicRoot);

    await assert.rejects(access(dataStore));
    await access(generatedTypes);
  } finally {
    await rm(publicRoot, { recursive: true, force: true });
  }
});

test("clearContentCache succeeds when no content store exists", async () => {
  const publicRoot = await mkdtemp(join(tmpdir(), "mvm-docs-cache-"));

  try {
    await clearContentCache(publicRoot);
  } finally {
    await rm(publicRoot, { recursive: true, force: true });
  }
});
