// Check the TypeScript examples in the documentation against the real SDK.
//
// The Python checker resolves names against the installed module. The TS SDK
// has no such luxury here: `dist/` is a build artifact that does not exist in a
// fresh worktree, and depending on it would make this gate fail for a reason
// that has nothing to do with the docs. So the export surface is resolved
// statically from `src/`, following the `export *` graph the SDK is built from.
//
// Reads a JSON array of {file, line, body} on stdin and writes a JSON array of
// findings on stdout. Exit status is 0 either way; the caller decides what a
// finding means.

import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";

const SDK_ROOT = process.env.MVM_TS_SDK_SRC;
const PACKAGE_NAME = process.env.MVM_TS_PACKAGE_NAME ?? "@runmvm/mvm";

/** Resolve a `./x.js` specifier to the `.ts` source that produces it. */
function resolveSource(fromFile, specifier) {
  if (!specifier.startsWith(".")) return null;
  const base = resolve(dirname(fromFile), specifier).replace(/\.js$/, "");
  for (const candidate of [`${base}.ts`, `${base}/index.ts`]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Every name the SDK exports, following re-exports transitively.
 *
 * Regex-driven rather than a real TS parse: the SDK's index files are plain
 * export lists, and pulling in a parser to read them would add a dependency
 * this harness does not otherwise need.
 */
function exportedNames(entry, seen = new Set()) {
  if (seen.has(entry)) return new Set();
  seen.add(entry);

  const names = new Set();
  const source = readFileSync(entry, "utf8");

  // export * from "./x.js"  — pull the whole surface of the target in.
  for (const match of source.matchAll(/export\s+\*\s+from\s+["']([^"']+)["']/g)) {
    const target = resolveSource(entry, match[1]);
    if (target) for (const name of exportedNames(target, seen)) names.add(name);
  }

  // export * as ns from "./x.js"  — the namespace itself is the export.
  for (const match of source.matchAll(
    /export\s+\*\s+as\s+(\w+)\s+from\s+["'][^"']+["']/g,
  )) {
    names.add(match[1]);
  }

  // export { a, b as c } from "./x.js"   and   export { a, b }
  for (const match of source.matchAll(/export\s+(?:type\s+)?\{([^}]*)\}/g)) {
    for (const clause of match[1].split(",")) {
      const parts = clause.trim().split(/\s+as\s+/);
      const name = (parts[1] ?? parts[0] ?? "").trim().replace(/^type\s+/, "");
      if (name) names.add(name);
    }
  }

  // export function f / const c / class C / type T / interface I / enum E
  for (const match of source.matchAll(
    /export\s+(?:declare\s+)?(?:async\s+)?(?:function|const|let|var|class|type|interface|enum)\s+(\w+)/g,
  )) {
    names.add(match[1]);
  }

  return names;
}

/** Namespace aliases bound to the SDK: `import * as mvm from "<pkg>"`. */
function namespaceAliases(body, specifiers) {
  const aliases = new Set();
  for (const match of body.matchAll(
    /import\s+\*\s+as\s+(\w+)\s+from\s+["']([^"']+)["']/g,
  )) {
    if (specifiers.has(match[2])) aliases.add(match[1]);
  }
  return aliases;
}

/** `import { a, b } from "<pkg>"` names, with the line each appears on. */
function namedImports(body, specifiers) {
  const found = [];
  for (const match of body.matchAll(
    /import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+["']([^"']+)["']/g,
  )) {
    if (!specifiers.has(match[2])) continue;
    const line = body.slice(0, match.index).split("\n").length;
    for (const clause of match[1].split(",")) {
      const name = clause.trim().split(/\s+as\s+/)[0].replace(/^type\s+/, "").trim();
      if (name) found.push([name, line]);
    }
  }
  return found;
}

/**
 * Blank out comments and string literals, preserving offsets.
 *
 * A comment mentioning `mvm.toml`, or a string containing `mvm.foo`, is prose.
 * Scanning it for member accesses invents findings — and an invented finding
 * costs more than a missed one, because it teaches the reader to ignore the
 * gate. Replacing in place rather than deleting keeps line numbers honest.
 */
function stripCommentsAndStrings(body) {
  let out = "";
  let i = 0;
  while (i < body.length) {
    const two = body.slice(i, i + 2);
    if (two === "//") {
      const end = body.indexOf("\n", i);
      const stop = end === -1 ? body.length : end;
      out += " ".repeat(stop - i);
      i = stop;
      continue;
    }
    if (two === "/*") {
      const end = body.indexOf("*/", i + 2);
      const stop = end === -1 ? body.length : end + 2;
      out += body.slice(i, stop).replace(/[^\n]/g, " ");
      i = stop;
      continue;
    }
    const ch = body[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1;
      while (j < body.length && body[j] !== ch) {
        if (body[j] === "\\") j += 1;
        j += 1;
      }
      out += body.slice(i, Math.min(j + 1, body.length)).replace(/[^\n]/g, " ");
      i = j + 1;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

/** `alias.name` property accesses, with the line each appears on. */
function memberUses(rawBody, aliases) {
  const body = stripCommentsAndStrings(rawBody);
  const found = [];
  for (const alias of aliases) {
    const pattern = new RegExp(`\\b${alias}\\.(\\w+)`, "g");
    for (const match of body.matchAll(pattern)) {
      const line = body.slice(0, match.index).split("\n").length;
      found.push([match[1], line]);
    }
  }
  return found;
}

function check(block, surface) {
  const findings = [];
  const at = (offset) => block.line + offset;
  const body = block.body;

  // Every specifier the docs use for this package, right or wrong — so a
  // snippet importing the wrong name is still analysed for its symbols.
  const specifiers = new Set([PACKAGE_NAME, "mvm-sdk", "mvm"]);

  for (const match of body.matchAll(/from\s+["'](mvm-sdk|mvm)["']/g)) {
    const line = body.slice(0, match.index).split("\n").length;
    findings.push({
      file: block.file,
      line: at(line),
      kind: "wrong-package",
      detail: `imports "${match[1]}"; the published package is "${PACKAGE_NAME}"`,
    });
  }

  const aliases = namespaceAliases(body, specifiers);
  for (const [name, line] of namedImports(body, specifiers)) {
    if (!surface.has(name)) {
      findings.push({
        file: block.file,
        line: at(line),
        kind: "missing-name",
        detail: `\`import { ${name} }\` — the SDK exports no such name`,
      });
    }
  }
  for (const [name, line] of memberUses(body, aliases)) {
    if (!surface.has(name)) {
      findings.push({
        file: block.file,
        line: at(line),
        kind: "missing-member",
        detail: `\`mvm.${name}\` does not exist in the SDK`,
      });
    }
  }

  return findings;
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const blocks = JSON.parse(Buffer.concat(chunks).toString("utf8"));

  const entry = resolve(SDK_ROOT, "index.ts");
  const surface = exportedNames(entry);
  if (surface.size < 20) {
    process.stderr.write(
      `resolved only ${surface.size} exported name(s) from ${entry}; the export ` +
        `graph walk has gone blind\n`,
    );
    process.exit(1);
  }

  const findings = blocks.flatMap((block) => check(block, surface));
  process.stdout.write(JSON.stringify(findings));
}

await main();
