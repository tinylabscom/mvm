import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const requiredWebLinuxDeployAssets = Object.freeze([
  "demo/weblinux/demo.js",
  "demo/weblinux/worker.js",
  "demo/weblinux/qemu-system-x86_64.js",
  "demo/weblinux/qemu-system-x86_64.wasm.gz",
  "demo/weblinux/pack.data.parts.json",
  "demo/weblinux/pack.data.part-000",
  "demo/weblinux/pack/kernel.img",
  "demo/weblinux/pack/rootfs.bin",
]);

export const workerStaticAssetLimits = Object.freeze({
  maxFileCount: 20_000,
  maxFileSizeBytes: 25 * 1024 * 1024,
});

function filesBelow(directory) {
  return fs.readdirSync(directory, { recursive: true, withFileTypes: true }).filter((entry) =>
    entry.isFile(),
  );
}

export function assertWorkerStaticAssetLimits(
  buildDirectory,
  limits = workerStaticAssetLimits,
) {
  const files = filesBelow(buildDirectory);
  if (files.length > limits.maxFileCount) {
    throw new Error(
      `Worker static assets contain ${files.length} files; limit is ${limits.maxFileCount}`,
    );
  }

  const oversized = files.flatMap((entry) => {
    const assetPath = path.join(entry.parentPath, entry.name);
    const size = fs.statSync(assetPath).size;
    return size > limits.maxFileSizeBytes
      ? [`${path.relative(buildDirectory, assetPath)} (${size} bytes)`]
      : [];
  });
  if (oversized.length > 0) {
    throw new Error(
      `Worker static assets exceed the ${limits.maxFileSizeBytes}-byte per-file limit:\n${oversized
        .map((asset) => `- ${asset}`)
        .join("\n")}`,
    );
  }
}

export function assertWebLinuxDeployAssets(buildDirectory) {
  const missing = requiredWebLinuxDeployAssets.filter((relativePath) => {
    try {
      return fs.statSync(path.join(buildDirectory, relativePath)).size === 0;
    } catch (error) {
      if (error?.code === "ENOENT") return true;
      throw error;
    }
  });

  if (missing.length > 0) {
    throw new Error(
      `missing or empty WebLinux deployment assets:\n${missing.map((asset) => `- ${asset}`).join("\n")}`,
    );
  }

  const demoDirectory = path.join(buildDirectory, "demo/weblinux");
  const unsplitPack = path.join(demoDirectory, "pack.data");
  if (fs.existsSync(unsplitPack)) {
    throw new Error("unsplit WebLinux preload must not be deployed: demo/weblinux/pack.data");
  }

  const manifestPath = path.join(demoDirectory, "pack.data.parts.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (
    !Number.isSafeInteger(manifest.size) ||
    manifest.size <= 0 ||
    !Array.isArray(manifest.parts) ||
    manifest.parts.length === 0 ||
    manifest.parts.some(
      (part) =>
        typeof part !== "string" || !/^pack\.data\.part-\d{3}$/.test(part),
    )
  ) {
    throw new Error("invalid WebLinux preload-parts manifest");
  }

  const actualSize = manifest.parts.reduce((total, part) => {
    const partPath = path.join(demoDirectory, part);
    try {
      return total + fs.statSync(partPath).size;
    } catch (error) {
      if (error?.code === "ENOENT") {
        throw new Error(`missing WebLinux preload part: demo/weblinux/${part}`);
      }
      throw error;
    }
  }, 0);
  if (actualSize !== manifest.size) {
    throw new Error(
      `WebLinux preload parts total ${actualSize} bytes; manifest declares ${manifest.size}`,
    );
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
  const buildDirectory = path.resolve(process.argv[2] ?? "dist");
  try {
    assertWebLinuxDeployAssets(buildDirectory);
    assertWorkerStaticAssetLimits(buildDirectory);
    console.log(`Worker deployment assets are complete and within limits: ${buildDirectory}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
