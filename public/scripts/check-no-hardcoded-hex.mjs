// Components consume role tokens, never raw colour. This keeps light mode
// working: a hex in a component is a value light mode cannot override.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..", "src");
// The terminal-dot row is deliberately theme-independent: those are macOS
// window-control colours, a product affordance rather than a theme choice.
const ALLOWED = /--color-dot-(close|minimize|expand)/;
const HEX = /#[0-9a-fA-F]{3,8}\b/;

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const failures = [];
for (const file of walk(root)) {
  if (!/\.(tsx|ts|astro|css)$/.test(file)) continue;
  readFileSync(file, "utf8").split("\n").forEach((line, i) => {
    if (HEX.test(line) && !ALLOWED.test(line)) {
      failures.push(`${file.slice(root.length + 1)}:${i + 1}: ${line.trim()}`);
    }
  });
}

if (failures.length) {
  console.error("Hardcoded colour outside the token system:\n  " + failures.join("\n  "));
  process.exit(1);
}
console.log("no hardcoded hex in components");
