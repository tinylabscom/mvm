// The WebLinux demo boots QEMU-Wasm, which uses pthreads and therefore needs
// SharedArrayBuffer. Browsers expose SharedArrayBuffer only to a
// cross-origin-isolated document, and isolation does not propagate upward from
// a frame: a page that embeds the demo in an iframe must itself be isolated or
// the embedded copy fails with "SharedArrayBuffer is not defined" while the
// standalone demo page works fine.
//
// That is exactly how it shipped once, so this gate reads the embed out of the
// component rather than trusting a hand-kept list: whatever page embeds the
// demo, and the demo document itself, must both resolve to COOP/COEP under the
// deployed `_headers`.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadHeaderRules, isolationGaps } from "./headers-config.mjs";

const publicDir = join(import.meta.dirname, "..", "public");
const teaserPath = join(import.meta.dirname, "..", "src/components/landing/DemoTeaser.tsx");

const failures = [];
const fail = (m) => failures.push(m);

let rules;
try {
  rules = loadHeaderRules(publicDir);
} catch (err) {
  console.error(`check:headers FAILED\n  - ${err.message}`);
  process.exit(1);
}

// The landing page is the top-level document a visitor loads; it is isolated
// only if `_headers` says so.
const required = new Map([["/", "landing page"]]);

const teaser = readFileSync(teaserPath, "utf8");
const embed = teaser.match(/<iframe[\s\S]*?src=\{`\$\{base\}([^`?]*)/);
if (embed === null) {
  fail(`could not find the demo iframe src in ${teaserPath}; this gate has drifted`);
} else {
  required.set(embed[1], "embedded demo document");
}

for (const [pathname, label] of required) {
  for (const gap of isolationGaps(rules, pathname)) {
    fail(`${pathname} (${label}) is missing ${gap}`);
  }
}

if (failures.length > 0) {
  console.error("check:headers FAILED");
  for (const f of failures) console.error(`  - ${f}`);
  console.error(
    "\nFix public/public/_headers so every document above resolves to\n" +
      "  Cross-Origin-Opener-Policy: same-origin\n" +
      "  Cross-Origin-Embedder-Policy: require-corp",
  );
  process.exit(1);
}

console.log(`check:headers OK (${[...required.keys()].join(", ")} are cross-origin isolated)`);
