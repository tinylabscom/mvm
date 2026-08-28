import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const requiredWebLinuxDeployAssets = Object.freeze([
  "demo/weblinux/demo.js",
  "demo/weblinux/worker.js",
  "demo/weblinux/qemu-system-x86_64.js",
  "demo/weblinux/qemu-system-x86_64.wasm.gz",
  "demo/weblinux/pack/kernel.img",
  "demo/weblinux/pack/rootfs.bin",
]);

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
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
  const buildDirectory = path.resolve(process.argv[2] ?? "dist");
  try {
    assertWebLinuxDeployAssets(buildDirectory);
    console.log(`WebLinux deployment bundle is complete: ${buildDirectory}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
