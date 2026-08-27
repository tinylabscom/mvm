// A plain-markdown twin of every docs page: /guides/builder-vm/ is also
// /guides/builder-vm.md, with no navigation, sidebar, or search chrome for a
// reader to strip back off.
//
// This does not collide with Starlight's catch-all `[...slug]` route. Its
// paths all end in `.md`, which Starlight never emits, and a route declared in
// src/pages/ wins over an injected one regardless.
import type { APIRoute, GetStaticPaths } from "astro";
import {
  docEntries,
  docUrl,
  ROOT_ID,
  type DocEntry,
  requireDescription,
} from "../lib/docs-index";

export const getStaticPaths: GetStaticPaths = async () => {
  const entries = await docEntries();
  return entries
    // The site landing page is marketing copy with a splash hero, not
    // documentation prose; there is nothing for an agent in its markdown.
    .filter((entry) => entry.id !== ROOT_ID)
    .map((entry) => ({ params: { path: entry.id }, props: { entry } }));
};

export const GET: APIRoute = ({ props }) => {
  const entry = props.entry as DocEntry;
  const header = [
    `<!-- mvm docs. Full index of every page: /llms.txt -->`,
    `<!-- Rendered page: ${docUrl(entry.id)} -->`,
    "",
    `# ${entry.data.title}`,
    "",
    `> ${requireDescription(entry)}`,
    "",
    "---",
    "",
    "",
  ].join("\n");

  return new Response(`${header}${entry.body ?? ""}`.trimEnd() + "\n", {
    headers: { "Content-Type": "text/markdown; charset=utf-8" },
  });
};
