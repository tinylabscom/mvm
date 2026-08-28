import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
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
