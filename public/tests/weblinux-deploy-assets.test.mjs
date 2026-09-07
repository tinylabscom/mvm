import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  assertWorkerStaticAssetLimits,
  assertWebLinuxDeployAssets,
  requiredWebLinuxDeployAssets,
} from "../scripts/check-weblinux-deploy-assets.mjs";

function withBuildDirectory(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mvm-weblinux-assets-"));
  try {
    run(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("accepts a complete non-empty WebLinux deployment bundle", () => {
  withBuildDirectory((directory) => {
    for (const relativePath of requiredWebLinuxDeployAssets) {
      const asset = path.join(directory, relativePath);
      fs.mkdirSync(path.dirname(asset), { recursive: true });
      fs.writeFileSync(asset, "present");
    }

    assert.doesNotThrow(() => assertWebLinuxDeployAssets(directory));
  });
});

test("rejects missing and empty WebLinux deployment assets", () => {
  withBuildDirectory((directory) => {
    const [emptyAsset] = requiredWebLinuxDeployAssets;
    const emptyPath = path.join(directory, emptyAsset);
    fs.mkdirSync(path.dirname(emptyPath), { recursive: true });
    fs.writeFileSync(emptyPath, "");

    assert.throws(
      () => assertWebLinuxDeployAssets(directory),
      /missing or empty WebLinux deployment assets/,
    );
  });
});

test("accepts Worker static assets within file count and size limits", () => {
  withBuildDirectory((directory) => {
    fs.writeFileSync(path.join(directory, "index.html"), "present");

    assert.doesNotThrow(() =>
      assertWorkerStaticAssetLimits(directory, {
        maxFileCount: 1,
        maxFileSizeBytes: 7,
      }),
    );
  });
});

test("rejects too many Worker static assets", () => {
  withBuildDirectory((directory) => {
    fs.writeFileSync(path.join(directory, "index.html"), "present");
    fs.writeFileSync(path.join(directory, "404.html"), "present");

    assert.throws(
      () =>
        assertWorkerStaticAssetLimits(directory, {
          maxFileCount: 1,
          maxFileSizeBytes: 25 * 1024 * 1024,
        }),
      /contain 2 files; limit is 1/,
    );
  });
});

test("rejects a Worker static asset above the per-file limit", () => {
  withBuildDirectory((directory) => {
    fs.writeFileSync(path.join(directory, "oversized.bin"), "too large");

    assert.throws(
      () =>
        assertWorkerStaticAssetLimits(directory, {
          maxFileCount: 20_000,
          maxFileSizeBytes: 4,
        }),
      /oversized\.bin \(9 bytes\)/,
    );
  });
});
