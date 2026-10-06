/**
 * The platform-package table (`src/_platform.ts`) the loader and the publish
 * workflow share.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  detectLibc,
  MAIN_PACKAGE_NAME,
  PLATFORM_PACKAGES,
  platformPackageFor,
  platformPackageName,
} from "../src/_platform.js";

const PACKAGE_JSON = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "package.json",
);

describe("platform packages", () => {
  it("are named after the package that depends on them", () => {
    const manifest = JSON.parse(fs.readFileSync(PACKAGE_JSON, "utf8")) as { name: string };
    expect(MAIN_PACKAGE_NAME).toBe(manifest.name);
    for (const pkg of PLATFORM_PACKAGES) {
      expect(platformPackageName(pkg)).toBe(`${manifest.name}-${pkg.key}`);
    }
  });

  it("have unique keys that spell out os, cpu, and libc", () => {
    const keys = PLATFORM_PACKAGES.map((pkg) => pkg.key);
    expect(new Set(keys).size).toBe(keys.length);
    for (const pkg of PLATFORM_PACKAGES) {
      const libc = pkg.libc === "glibc" ? "-gnu" : pkg.libc === "musl" ? "-musl" : "";
      expect(pkg.key).toBe(`${pkg.os}-${pkg.cpu}${libc}`);
    }
  });

  it("distinguish libc on Linux and only there", () => {
    for (const pkg of PLATFORM_PACKAGES) {
      expect(pkg.libc !== undefined).toBe(pkg.os === "linux");
    }
  });

  it("map each host to exactly its own package", () => {
    expect(platformPackageFor("linux", "x64", "glibc")?.key).toBe("linux-x64-gnu");
    expect(platformPackageFor("linux", "x64", "musl")?.key).toBe("linux-x64-musl");
    expect(platformPackageFor("linux", "arm64", "glibc")?.key).toBe("linux-arm64-gnu");
    expect(platformPackageFor("linux", "arm64", "musl")?.key).toBe("linux-arm64-musl");
    expect(platformPackageFor("darwin", "arm64", undefined)?.key).toBe("darwin-arm64");
  });

  it("map an unpublished host to nothing", () => {
    expect(platformPackageFor("darwin", "x64", undefined)).toBeUndefined();
    expect(platformPackageFor("win32", "x64", undefined)).toBeUndefined();
    expect(platformPackageFor("linux", "riscv64", "glibc")).toBeUndefined();
    // A Linux host whose libc is unknown matches no Linux package rather
    // than guessing one.
    expect(platformPackageFor("linux", "x64", undefined)).toBeUndefined();
  });

  it("report no libc off Linux", () => {
    expect(detectLibc("darwin")).toBeUndefined();
    expect(detectLibc("win32")).toBeUndefined();
  });
});
