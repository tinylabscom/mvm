import * as fs from "node:fs";
import * as path from "node:path";

// Owned by the Rust registry (crates/mvm-sdk/src/env.rs) and generated
// into `_env/vars.ts`; re-exported so existing importers keep working.
export { MVM_CLI_BIN_ENV } from "./_env/vars.js";
import { MVM_CLI_BIN_ENV } from "./_env/vars.js";
export const SDK_CLI_CANDIDATES = ["mvmctl"] as const;

export function cliResolutionHint(): string {
  return `set ${MVM_CLI_BIN_ENV}=/path/to/mvmctl, or install \`mvmctl\` on PATH.`;
}

function isExecutableFile(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function pathEntries(): string[] {
  if (typeof process === "undefined") return [];
  const value = process.env.PATH;
  return value ? value.split(path.delimiter).filter((entry) => entry.length > 0) : [];
}

function platformCandidateNames(name: string): string[] {
  if (typeof process === "undefined" || process.platform !== "win32") {
    return [name];
  }
  const pathExt = process.env.PATHEXT?.split(";").filter((ext) => ext.length > 0) ?? [".EXE", ".CMD", ".BAT"];
  return pathExt.map((ext) => `${name}${ext}`);
}

function resolveOnPath(name: string): string | null {
  for (const entry of pathEntries()) {
    for (const candidate of platformCandidateNames(name)) {
      const full = path.join(entry, candidate);
      if (isExecutableFile(full)) {
        return full;
      }
    }
  }
  return null;
}

export function resolveCliBin(purpose: string): string {
  if (typeof process === "undefined") {
    throw new Error(`${purpose} requires the mvm CLI; ${cliResolutionHint()}`);
  }
  const explicit = process.env[MVM_CLI_BIN_ENV];
  if (explicit) {
    if (isExecutableFile(explicit)) {
      return explicit;
    }
    throw new Error(
      `${MVM_CLI_BIN_ENV} points at ${JSON.stringify(explicit)} but it is not an executable file; ${cliResolutionHint()}`,
    );
  }
  for (const candidate of SDK_CLI_CANDIDATES) {
    const found = resolveOnPath(candidate);
    if (found) {
      return found;
    }
  }
  throw new Error(`${purpose} requires the mvm CLI; ${cliResolutionHint()}`);
}
