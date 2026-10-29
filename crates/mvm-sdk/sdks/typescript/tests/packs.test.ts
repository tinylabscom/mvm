import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { packs } from "../src/index.js";
import { Pack, PackSpecError, canonicalJson, pack } from "../src/packs.js";

// The contract's shared fixtures: each is an authored document the Rust
// contract accepts. Rebuilding it through the fluent API must produce exactly
// the bytes the Rust canonical writer emits, so a lock's spec digest does not
// depend on which language wrote the spec.
const FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../mvm-contract/tests/fixtures/pack-spec-v1",
);

type Doc = any; // the fixtures are untyped JSON

function fixture(name: string): Doc {
  return JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8"));
}

function fromDocument(doc: Doc): Pack {
  const built = pack(doc.identity.name, doc.identity.version)
    .target(doc.target)
    .source(doc.source.path);
  for (const p of doc.packages) built.package(p.name, { version: p.version, scope: p.scope });
  for (const d of doc.dependencies) {
    if (d.kind === "python") built.dependencies(d.tool, d.manifest, d.lockfile);
    else built.nodeDependencies(d.tool, d.manifest, d.lockfile);
  }
  for (const c of doc.copy) built.copy(c.source, c.destination);
  return built
    .entrypoint(...doc.entrypoint)
    .resources({ cpuCores: doc.resources.cpu_cores, memoryMib: doc.resources.memory_mb });
}

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (err) {
    expect(err).toBeInstanceOf(PackSpecError);
    return (err as PackSpecError).code;
  }
  return undefined;
}

describe("PackSpec builder", () => {
  it.each(["minimal", "python", "claude-style"])(
    "rebuilds the %s fixture to its canonical bytes",
    (name) => {
      const doc = fixture(name);
      const built = fromDocument(doc);
      expect(text(built.toJson())).toBe(text(canonicalJson(doc)));
      const golden = join(FIXTURES, "canonical", `${name}.json`);
      if (existsSync(golden)) {
        expect(text(built.toJson())).toBe(readFileSync(golden, "utf8"));
        const digest = readFileSync(join(FIXTURES, "canonical", `${name}.sha256`), "utf8").trim();
        expect(built.sha256()).toBe(digest);
      }
      expect(built.sha256()).toBe(createHash("sha256").update(built.toJson()).digest("hex"));
    },
  );

  it("is reachable from the package root and reads the way the docs show", () => {
    const spec = packs
      .pack("acme/hello", "1.0.0")
      .target("aarch64-linux")
      .source(".")
      .package("busybox")
      .copy("hello.txt", "/app/hello.txt")
      .entrypoint("cat", "/app/hello.txt")
      .resources({ cpuCores: 1, memoryMib: 128 });
    expect(text(spec.toJson())).toBe(text(canonicalJson(fixture("minimal"))));
  });

  it("writes compact sorted bytes, keeps list order and omits absent versions", () => {
    const out = text(fromDocument(fixture("python")).toJson());
    expect(out.endsWith("\n")).toBe(false);
    expect(out.startsWith('{"copy":')).toBe(true);
    expect(out).toContain('["python3","/app/main.py","one argument",""]');
    expect(out).toContain('{"name":"pkg-config","scope":"build"}');
  });

  it.each(["target", "source", "entrypoint", "resources"])(
    "names the missing %s field",
    (field) => {
      const built = pack("acme/hello", "1.0.0");
      if (field !== "target") built.target("aarch64-linux");
      if (field !== "source") built.source(".");
      if (field !== "entrypoint") built.entrypoint("true");
      if (field !== "resources") built.resources({ cpuCores: 1, memoryMib: 1 });
      try {
        built.toJson();
        expect.unreachable();
      } catch (err) {
        expect((err as PackSpecError).code).toBe("missing");
        expect((err as PackSpecError).field).toBe(field);
      }
    },
  );

  it.each([
    ["hello", "1.0.0"],
    ["acme/hello/extra", "1.0.0"],
    ["Acme/hello", "1.0.0"],
    ["acme/../x", "1.0.0"],
    ["acme/hello", "1.0"],
    ["acme/hello", "01.0.0"],
    ["acme/hello", "1.0.0-01"],
    ["acme/hello", "1.0.0\n"],
  ])("refuses identity %s@%s", (name, version) => {
    const doc = fixture("minimal");
    doc.identity = { name, version };
    expect(codeOf(() => fromDocument(doc).toJson())).toBe("identity");
  });

  const mutations: [string, (p: Pack) => unknown, string][] = [
    ["parent source", (p) => p.source("../up"), "path"],
    ["absolute source", (p) => p.source("/abs"), "path"],
    ["empty segment", (p) => p.source("a//b"), "path"],
    ["backslash", (p) => p.source("a\\b"), "path"],
    ["colon", (p) => p.source("c:x"), "path"],
    ["lone surrogate", (p) => p.source("a\uD800"), "path"],
    ["root destination", (p) => p.copy("a", "/"), "path"],
    ["relative destination", (p) => p.copy("a", "relative"), "path"],
    ["traversing destination", (p) => p.copy("a", "/app/../etc"), "path"],
    ["root manifest", (p) => p.dependencies("uv", ".", "uv.lock"), "path"],
    ["unknown tool", (p) => p.dependencies("poetry" as any, "pyproject.toml", "poetry.lock"), "dependency"],
    ["unknown node tool", (p) => p.nodeDependencies("bun" as any, "package.json", "bun.lockb"), "dependency"],
    ["bad package", (p) => p.package("bad name"), "package"],
    ["bad version", (p) => p.package("ok", { version: "1 0" }), "package"],
    ["unknown scope", (p) => p.package("ok", { scope: "sometimes" as any }), "package"],
    ["blank program", (p) => p.entrypoint(" "), "entrypoint"],
    ["NUL argument", (p) => p.entrypoint("sh", "a\0b"), "entrypoint"],
    ["zero cores", (p) => p.resources({ cpuCores: 0, memoryMib: 1 }), "resources"],
    ["too much memory", (p) => p.resources({ cpuCores: 1, memoryMib: 4294967296 }), "resources"],
    ["fractional cores", (p) => p.resources({ cpuCores: 1.5, memoryMib: 1 }), "resources"],
    ["unknown target", (p) => p.target("riscv64-linux" as any), "target"],
  ];

  it.each(mutations)("refuses %s with the shared code", (_label, mutate, code) => {
    const built = fromDocument(fixture("minimal"));
    mutate(built);
    expect(codeOf(() => built.toJson())).toBe(code);
  });

  it("keeps node dependencies in their place among python ones", () => {
    const built = fromDocument(fixture("minimal"))
      .dependencies("uv", "pyproject.toml", "uv.lock")
      .nodeDependencies("npm", "package.json", "package-lock.json");
    expect(built.toDocument().dependencies).toEqual([
      { kind: "python", tool: "uv", manifest: "pyproject.toml", lockfile: "uv.lock" },
      { kind: "node", tool: "npm", manifest: "package.json", lockfile: "package-lock.json" },
    ]);
  });

  it("keeps empty later arguments", () => {
    const built = fromDocument(fixture("minimal")).entrypoint("echo", "", "x");
    expect(built.toDocument().entrypoint).toEqual(["echo", "", "x"]);
  });
});
