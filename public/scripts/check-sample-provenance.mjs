// Every homepage code sample must be a verbatim slice of a real repo file.
// A sample that drifts from its source is worse than no sample: it teaches
// the reader something that does not run.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");
const samplesPath = join(import.meta.dirname, "..", "src/components/landing/samples.ts");
// samples.ts is plain data with erasable type annotations, so Node 22's
// built-in type stripping imports it directly. If that ever breaks, the
// fix is to strip types at read time — not to duplicate the samples.
const { SAMPLES } = await import(samplesPath);

const failures = [];
for (const s of SAMPLES) {
  let fileText;
  try {
    fileText = readFileSync(join(repoRoot, s.source), "utf8");
  } catch {
    failures.push(`${s.id}: source not found: ${s.source}`);
    continue;
  }
  const normalize = (t) => t.replace(/\r\n/g, "\n").trim();
  const normalizedCode = normalize(s.code);
  if (!normalizedCode) {
    failures.push(`${s.id}: code is empty or whitespace-only`);
    continue;
  }
  if (!normalize(fileText).includes(normalizedCode)) {
    failures.push(`${s.id}: code is not a verbatim slice of ${s.source}`);
  }
}

if (SAMPLES.length === 0) {
  console.error("Sample provenance failures:\n  SAMPLES is empty — the homepage must carry at least one sample");
  process.exit(1);
}
if (failures.length) {
  console.error("Sample provenance failures:\n  " + failures.join("\n  "));
  process.exit(1);
}
console.log(`sample provenance OK (${SAMPLES.length} samples)`);
