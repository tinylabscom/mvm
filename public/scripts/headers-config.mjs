// Parser for the Cloudflare Pages `_headers` file that carries the deployed
// site's response headers.
//
// It is shared rather than duplicated because two consumers need to agree on
// what the deployed site will send: the static gate that checks the file
// declares cross-origin isolation everywhere it is needed, and the browser
// smoke test, which serves these headers instead of inventing its own. A
// harness that stamps its own policy proves nothing about the deployment.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// `_headers` path patterns use `*` as a splat that spans path separators and
// `:name` as a single-segment placeholder.
export function patternToRegExp(pattern) {
  let source = "";
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === "*") {
      source += ".*";
    } else if (ch === ":") {
      while (i + 1 < pattern.length && /[A-Za-z0-9_]/.test(pattern[i + 1])) i += 1;
      source += "[^/]+";
    } else {
      source += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${source}$`);
}

// A rule is an unindented path pattern followed by indented `Name: value`
// lines. Returns them in file order.
export function parseHeaders(text) {
  const rules = [];
  let current = null;
  for (const raw of text.split("\n")) {
    // `#` starts a comment only at the head of a line; a header value may
    // legitimately contain one.
    if (raw.trim().startsWith("#")) continue;
    const line = raw.replace(/\s+$/, "");
    if (line.trim() === "") continue;
    if (!/^\s/.test(line)) {
      current = { path: line.trim(), pattern: patternToRegExp(line.trim()), headers: {} };
      rules.push(current);
      continue;
    }
    const sep = line.indexOf(":");
    if (current === null || sep === -1) continue;
    current.headers[line.slice(0, sep).trim()] = line.slice(sep + 1).trim();
  }
  return rules;
}

export function loadHeaderRules(root) {
  const file = join(root, "_headers");
  if (!existsSync(file)) {
    throw new Error(`${file} not found`);
  }
  return parseHeaders(readFileSync(file, "utf8"));
}

// Every matching rule applies; a later rule wins on a repeated header name.
export function headersFor(rules, pathname) {
  const merged = {};
  for (const rule of rules) {
    if (rule.pattern.test(pathname)) Object.assign(merged, rule.headers);
  }
  return merged;
}

// The two headers a document needs to be cross-origin isolated, which is the
// only context in which browsers expose SharedArrayBuffer.
export const ISOLATION_HEADERS = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
};

// Returns the header names that are missing or wrong for `pathname`.
export function isolationGaps(rules, pathname) {
  const resolved = {};
  for (const [name, value] of Object.entries(headersFor(rules, pathname))) {
    resolved[name.toLowerCase()] = value;
  }
  return Object.entries(ISOLATION_HEADERS)
    .filter(([name, want]) => resolved[name.toLowerCase()] !== want)
    .map(([name, want]) => `${name}: ${want} (got ${resolved[name.toLowerCase()] ?? "nothing"})`);
}
