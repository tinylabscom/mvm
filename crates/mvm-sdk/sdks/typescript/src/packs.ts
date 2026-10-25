/**
 * Author a `mvm.pack-spec/v1` document.
 *
 * ```ts
 * import { packs } from "@runmvm/mvm";
 *
 * const spec = packs
 *   .pack("acme/hello", "1.0.0")
 *   .target("aarch64-linux")
 *   .source(".")
 *   .package("busybox")
 *   .copy("hello.txt", "/app/hello.txt")
 *   .entrypoint("cat", "/app/hello.txt")
 *   .resources({ cpuCores: 1, memoryMib: 128 });
 * writeFileSync("pack.json", spec.toJson());
 * ```
 *
 * The builder only assembles and validates authored data. It never resolves a
 * package, reads the source tree, builds, boots or signs: `mvmctl pack lock`,
 * `mvmctl pack compile` and `mvmctl build` do that in the shared Rust
 * path, reading the bytes this emits as data. Those bytes are the canonical
 * bytes every language SDK emits for the same spec, so a lock's `spec_sha256`
 * does not depend on which language wrote it.
 *
 * A failure throws {@link PackSpecError}, whose `code` is the same stable string
 * every other language SDK reports for the same mistake.
 */

import { createHash } from "node:crypto";

/** The only authored schema this SDK writes. */
export const PACK_SPEC_SCHEMA = "mvm.pack-spec/v1";

export type PackTarget = "aarch64-linux" | "x86_64-linux";
export type PackageScope = "build" | "runtime";
export type PythonTool = "uv" | "pip_tools";
export type NodeTool = "npm" | "pnpm" | "yarn";

const TARGETS: readonly string[] = ["aarch64-linux", "x86_64-linux"];
const SCOPES: readonly string[] = ["build", "runtime"];
const PYTHON_TOOLS: readonly string[] = ["uv", "pip_tools"];
const NODE_TOOLS: readonly string[] = ["npm", "pnpm", "yarn"];

const MAX_PATH_BYTES = 4096;
const MAX_TOKEN_BYTES = 128;
const MAX_VERSION_BYTES = 128;
const MAX_CPU_CORES = 65535;
const MAX_MEMORY_MIB = 4294967295;

/**
 * An authoring mistake. `code` is shared by every language SDK; `field` names
 * the missing field when `code === "missing"`.
 */
export class PackSpecError extends Error {
  readonly code: string;
  readonly field: string | undefined;

  constructor(code: string, message: string, field?: string) {
    super(message);
    this.name = "PackSpecError";
    this.code = code;
    this.field = field;
  }
}

/** The JSON document a {@link Pack} describes. */
export interface PackSpecDocument {
  schema: typeof PACK_SPEC_SCHEMA;
  identity: { name: string; version: string };
  target: PackTarget;
  source: { kind: "local"; path: string };
  packages: { name: string; version?: string; scope: PackageScope }[];
  dependencies: (
    | { kind: "python"; tool: PythonTool; manifest: string; lockfile: string }
    | { kind: "node"; tool: NodeTool; manifest: string; lockfile: string }
  )[];
  copy: { source: string; destination: string }[];
  entrypoint: string[];
  resources: { cpu_cores: number; memory_mb: number };
}

/** Start a pack named `namespace/name` at a SemVer 2.0 `version`. */
export function pack(name: string, version: string): Pack {
  return new Pack(name, version);
}

/**
 * Fluent PackSpec builder. Adding calls append in call order; setting calls
 * replace. Every method returns the builder.
 */
export class Pack {
  private targetValue: string | undefined;
  private sourcePath: string | undefined;
  private readonly packages: { name: string; version: string | undefined; scope: string }[] = [];
  private readonly dependencyFiles: DependencyInput[] = [];
  private readonly copies: { source: string; destination: string }[] = [];
  private argv: string[] | undefined;
  private sizing: { cpuCores: number; memoryMib: number } | undefined;

  private readonly name: string;
  private readonly version: string;

  constructor(name: string, version: string) {
    this.name = name;
    this.version = version;
  }

  /** The guest target. Required; never inferred from the author's host. */
  target(target: PackTarget): this {
    this.targetValue = target;
    return this;
  }

  /** The local source tree, relative to the spec's directory (`.` for itself). */
  source(path: string): this {
    this.sourcePath = path;
    return this;
  }

  /**
   * Request a generic package. Nothing about a package implies a language
   * runtime; `version` requests an exact spelling, not a range.
   */
  package(name: string, options: { version?: string; scope?: PackageScope } = {}): this {
    this.packages.push({ name, version: options.version, scope: options.scope ?? "runtime" });
    return this;
  }

  /** A Python manifest and the lockfile `tool` produced from it. */
  dependencies(tool: PythonTool, manifest: string, lockfile: string): this {
    this.dependencyFiles.push({ kind: "python", tool, manifest, lockfile });
    return this;
  }

  /**
   * A Node package manifest and its integrity-pinned lockfile, written by
   * `tool`. No Node runtime is implied; request one with {@link package}.
   */
  nodeDependencies(tool: NodeTool, manifest: string, lockfile: string): this {
    this.dependencyFiles.push({ kind: "node", tool, manifest, lockfile });
    return this;
  }

  /** Copy a source-relative file or tree to a guest-absolute destination. */
  copy(source: string, destination: string): this {
    this.copies.push({ source, destination });
    return this;
  }

  /** Literal argv. No shell splitting or evaluation; empty later arguments are kept. */
  entrypoint(...argv: string[]): this {
    this.argv = [...argv];
    return this;
  }

  /**
   * Advisory CPU cores and binary MiB of memory (1 MiB = 1_048_576 bytes). A
   * launch's own flags and the host's ceilings still apply.
   */
  resources(sizing: { cpuCores: number; memoryMib: number }): this {
    this.sizing = { ...sizing };
    return this;
  }

  /** Assemble and validate the document. */
  toDocument(): PackSpecDocument {
    const target = required("target", this.targetValue);
    const source = required("source", this.sourcePath);
    const argv = required("entrypoint", this.argv);
    const sizing = required("resources", this.sizing);
    validateIdentity(this.name, this.version);
    if (!TARGETS.includes(target)) {
      fail("target", `unknown target ${JSON.stringify(target)}: expected one of ${TARGETS.join(", ")}`);
    }
    relativePath(source, true);
    const packages = this.packages.map(packageJson);
    const dependencies = this.dependencyFiles.map(dependencyJson);
    const copy = this.copies.map(copyJson);
    validateEntrypoint(argv);
    validateResources(sizing.cpuCores, sizing.memoryMib);
    return {
      schema: PACK_SPEC_SCHEMA,
      identity: { name: this.name, version: this.version },
      target: target as PackTarget,
      source: { kind: "local", path: source },
      packages,
      dependencies,
      copy,
      entrypoint: [...argv],
      resources: { cpu_cores: sizing.cpuCores, memory_mb: sizing.memoryMib },
    };
  }

  /** The canonical bytes: sorted keys, compact UTF-8, no trailing newline. */
  toJson(): Uint8Array {
    return canonicalJson(this.toDocument());
  }

  /** Lowercase hex SHA-256 of {@link toJson}; equals a lock's `spec_sha256`. */
  sha256(): string {
    return createHash("sha256").update(this.toJson()).digest("hex");
  }
}

/**
 * Compact JSON with every object's keys sorted and lists kept in order,
 * escaped the way the Rust contract writes it.
 */
export function canonicalJson(document: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(sortKeys(document)));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort(compareUtf8)) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}

function compareUtf8(a: string, b: string): number {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i]! - y[i]!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

function required<T>(field: string, value: T | undefined): T {
  if (value === undefined) {
    throw new PackSpecError("missing", `pack is missing required field \`${field}\``, field);
  }
  return value;
}

function fail(code: string, message: string): never {
  throw new PackSpecError(code, message);
}

function badPath(): never {
  fail("path", "unsafe path: expected normalized portable path without traversal");
}

/** UTF-8 length, refusing a lone surrogate the Rust contract could never hold. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function utf8Length(value: string, code: string, message: string): number {
  if (LONE_SURROGATE.test(value)) fail(code, message);
  return new TextEncoder().encode(value).length;
}

function isControl(code: number): boolean {
  return code < 0x20 || (code >= 0x7f && code <= 0x9f);
}

function relativePath(value: unknown, allowRoot: boolean): void {
  if (typeof value !== "string") badPath();
  if (allowRoot && value === ".") return;
  if (
    value.length === 0 ||
    utf8Length(value, "path", "unsafe path: expected valid UTF-8") > MAX_PATH_BYTES ||
    [...value].some((c) => isControl(c.codePointAt(0)!) || c === "\\" || c === ":") ||
    value.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    badPath();
  }
}

const isAsciiAlnum = (c: string): boolean => /^[A-Za-z0-9]$/.test(c);

function isToken(value: unknown): boolean {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_TOKEN_BYTES &&
    isAsciiAlnum(value[0]!) &&
    /^[A-Za-z0-9\-_.+]+$/.test(value)
  );
}

function component(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= 64 &&
    isAsciiAlnum(value[0]!) &&
    isAsciiAlnum(value[value.length - 1]!) &&
    /^[a-z0-9._-]+$/.test(value)
  );
}

const decimal = (value: string): boolean =>
  /^[0-9]+$/.test(value) && (value.length === 1 || value[0] !== "0");

const identifier = (value: string): boolean => /^[A-Za-z0-9-]+$/.test(value);

function releaseVersion(value: unknown): boolean {
  if (typeof value !== "string" || value.length > MAX_VERSION_BYTES || !/^[\x00-\x7f]*$/.test(value)) {
    return false;
  }
  const plus = value.indexOf("+");
  const version = plus < 0 ? value : value.slice(0, plus);
  if (plus >= 0 && !value.slice(plus + 1).split(".").every(identifier)) return false;
  const dash = version.indexOf("-");
  const core = dash < 0 ? version : version.slice(0, dash);
  if (
    dash >= 0 &&
    !version
      .slice(dash + 1)
      .split(".")
      .every((id) => identifier(id) && (!/^[0-9]+$/.test(id) || decimal(id)))
  ) {
    return false;
  }
  const parts = core.split(".");
  return parts.length === 3 && parts.every(decimal);
}

function validateIdentity(name: unknown, version: unknown): void {
  const slash = typeof name === "string" ? name.indexOf("/") : -1;
  const ok =
    typeof name === "string" &&
    slash >= 0 &&
    component(name.slice(0, slash)) &&
    component(name.slice(slash + 1)) &&
    releaseVersion(version);
  if (!ok) fail("identity", "invalid pack identity: expected namespace/name and SemVer 2.0 version");
}

function packageJson(p: { name: string; version: string | undefined; scope: string }): PackSpecDocument["packages"][number] {
  if (!isToken(p.name) || (p.version !== undefined && !isToken(p.version))) {
    fail("package", "invalid package name or version token");
  }
  if (!SCOPES.includes(p.scope)) {
    fail("package", `unknown package scope ${JSON.stringify(p.scope)}: expected build or runtime`);
  }
  const out: PackSpecDocument["packages"][number] = { name: p.name, scope: p.scope as PackageScope };
  if (p.version !== undefined) out.version = p.version;
  return out;
}

interface DependencyInput {
  kind: "python" | "node";
  tool: string;
  manifest: string;
  lockfile: string;
}

function dependencyJson(d: DependencyInput): PackSpecDocument["dependencies"][number] {
  const tools = d.kind === "python" ? PYTHON_TOOLS : NODE_TOOLS;
  if (!tools.includes(d.tool)) {
    fail("dependency", `unknown ${d.kind} tool ${JSON.stringify(d.tool)}: expected one of ${tools.join(", ")}`);
  }
  relativePath(d.manifest, false);
  relativePath(d.lockfile, false);
  return d.kind === "python"
    ? { kind: "python", tool: d.tool as PythonTool, manifest: d.manifest, lockfile: d.lockfile }
    : { kind: "node", tool: d.tool as NodeTool, manifest: d.manifest, lockfile: d.lockfile };
}

function copyJson(c: { source: string; destination: string }): { source: string; destination: string } {
  relativePath(c.source, true);
  if (
    typeof c.destination !== "string" ||
    utf8Length(c.destination, "path", "unsafe path: expected valid UTF-8") > MAX_PATH_BYTES ||
    !c.destination.startsWith("/")
  ) {
    badPath();
  }
  relativePath(c.destination.slice(1), false);
  return { source: c.source, destination: c.destination };
}

function validateEntrypoint(argv: unknown): void {
  const message = "entrypoint must have a nonempty executable and no NUL bytes";
  if (
    !Array.isArray(argv) ||
    argv.length === 0 ||
    !argv.every((a) => typeof a === "string") ||
    (argv[0] as string).trim() === "" ||
    argv.some((a: string) => a.includes("\0"))
  ) {
    fail("entrypoint", message);
  }
  for (const arg of argv as string[]) utf8Length(arg, "entrypoint", message);
}

function validateResources(cpuCores: unknown, memoryMib: unknown): void {
  const ok =
    Number.isInteger(cpuCores) &&
    Number.isInteger(memoryMib) &&
    (cpuCores as number) >= 1 &&
    (cpuCores as number) <= MAX_CPU_CORES &&
    (memoryMib as number) >= 1 &&
    (memoryMib as number) <= MAX_MEMORY_MIB;
  if (!ok) fail("resources", "CPU cores and memory MiB must be positive");
}
