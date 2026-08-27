// The machine-readable docs index, generated from the content collection at
// build time. It replaced a hand-maintained static asset that had drifted to
// roughly a quarter of the pages and carried no descriptions, so an agent had
// to fetch every page to find the one it wanted.
import type { APIRoute } from "astro";
import {
  docUrl,
  indexSections,
  markdownTwinPath,
  requireDescription,
  ROOT_ID,
} from "../lib/docs-index";

const preamble = `# mvm Documentation Index

mvm is a security-first local microVM runtime for building and running sandboxed
workloads with signed plans, audited launches, and backend-specific snapshot
recovery.

Start at /skill.md for a single-page orientation aimed at coding agents.

Every page listed below is also served as plain markdown with no navigation
chrome: append \`.md\` to the page path with the trailing slash removed, so
/guides/builder-vm/ is also available at /guides/builder-vm.md.`;

const claimRules = `## Claim rules

- Strong claims need Shipped, Preview, Planned, or Not claimed status.
- Runtime SDK lifecycle APIs are partial until shared SDK tests cover the full lifecycle.
- OCI examples should use digest-pinned or clearly local/dev references.
- Secret examples should use references or redacted example values, not plaintext credentials.`;

export const GET: APIRoute = async () => {
  const blocks = [preamble];

  for (const section of await indexSections()) {
    const lines = section.entries.map((entry) => {
      const twin =
        entry.id === ROOT_ID ? "" : ` (markdown: /${markdownTwinPath(entry.id)})`;
      return `- [${entry.data.title}](${docUrl(entry.id)}): ${requireDescription(entry)}${twin}`;
    });
    blocks.push(`## ${section.label}\n\n${lines.join("\n")}`);
  }

  blocks.push(claimRules);

  return new Response(`${blocks.join("\n\n")}\n`, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
};
