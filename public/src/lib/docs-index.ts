// Shared reader for the docs collection, used by the agent-facing routes
// (`/llms.txt` and the `.md` twins). Both need the same three things: every
// entry, its public URL, and the sidebar grouping — so they get them here
// rather than each growing its own copy.
import { getCollection, type CollectionEntry } from "astro:content";
import { sidebar } from "../sidebar";

export type DocEntry = CollectionEntry<"docs">;

export interface IndexSection {
  label: string;
  entries: DocEntry[];
}

/** Heading for entries the sidebar does not link. */
export const UNLISTED_SECTION = "Other pages";

/**
 * Id of the site landing page. The loader strips a trailing `/index` segment
 * from every nested id but leaves the root one as the literal `index`, so the
 * one page served from `/` is the one page whose id does not describe its URL.
 */
export const ROOT_ID = "index";

/** Public URL of a docs entry. */
export function docUrl(id: string): string {
  return id === ROOT_ID ? "/" : `/${id}/`;
}

/** Path of the plain-markdown twin. */
export function markdownTwinPath(id: string): string {
  return `${id}.md`;
}

/**
 * Body of a page, with MDX component imports removed. Roughly a sixth of the
 * docs are `.mdx` and open with a Starlight component import, which is build
 * machinery: it tells a reader nothing and the twins exist precisely so
 * nobody has to strip chrome back off. The component tags themselves stay —
 * a `<TabItem label="Python">` still says which variant follows.
 */
export function readableBody(entry: DocEntry): string {
  return (entry.body ?? "")
    .replace(/^import\s.*?from\s*["'][^"']+["'];?\s*$/gm, "")
    .replace(/^\n{2,}/, "");
}

export async function docEntries(): Promise<DocEntry[]> {
  return getCollection("docs");
}

/**
 * A page's description is what makes the generated index useful to an agent —
 * without one it has to fetch the page to learn what the page is. Refusing to
 * emit a blank clause turns that into a build failure instead of a silent
 * quality loss.
 */
export function requireDescription(entry: DocEntry): string {
  const description = entry.data.description?.trim();
  if (!description) {
    throw new Error(
      `src/content/docs/${entry.filePath?.split("src/content/docs/").pop() ?? entry.id}: ` +
        "missing frontmatter `description`. Every docs page needs one — it is the " +
        "only thing /llms.txt can tell an agent about the page without fetching it.",
    );
  }
  return description;
}

/**
 * Groups every docs entry under the sidebar headings, in sidebar order.
 * Entries the sidebar does not link land in a trailing section so a new page
 * shows up in the index the moment it exists, rather than the day someone
 * remembers to add it to the navigation.
 */
export async function indexSections(): Promise<IndexSection[]> {
  const byId = new Map((await docEntries()).map((entry) => [entry.id, entry]));
  const sections: IndexSection[] = [];
  const claimed = new Set<string>();

  for (const group of sidebar) {
    const entries: DocEntry[] = [];
    for (const item of group.items) {
      const entry = byId.get(item.slug);
      if (!entry) {
        throw new Error(
          `astro.config sidebar links "${item.slug}" (${group.label} › ${item.label}), ` +
            "but no docs page has that slug.",
        );
      }
      entries.push(entry);
      claimed.add(entry.id);
    }
    if (entries.length > 0) sections.push({ label: group.label, entries });
  }

  const unlisted = [...byId.values()]
    .filter((entry) => !claimed.has(entry.id))
    .sort((a, b) => a.id.localeCompare(b.id));
  if (unlisted.length > 0) {
    sections.push({ label: UNLISTED_SECTION, entries: unlisted });
  }

  return sections;
}
