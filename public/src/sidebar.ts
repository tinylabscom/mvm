/**
 * The small human-facing docs navigation, shared with the machine-readable index.
 * Other docs remain available by URL, search, and the "Other pages" section of
 * /llms.txt; removing a link here does not remove its page.
 */
export interface SidebarLink {
  label: string;
  slug: string;
}

export interface SidebarGroup {
  label: string;
  items: SidebarLink[];
}

export const sidebar: SidebarGroup[] = [
  {
    label: "Start here",
    items: [
      { label: "Overview", slug: "docs" },
      { label: "Installation", slug: "getting-started/installation" },
      { label: "Quickstart", slug: "getting-started/quickstart" },
    ],
  },
  {
    label: "Local CLI",
    items: [
      { label: "Machine workflows", slug: "guides/machine-use-cases" },
      { label: "Run commands", slug: "working/commands" },
      { label: "Work with files", slug: "working/filesystem" },
      { label: "Network and ports", slug: "working/network" },
      { label: "Platform support", slug: "reference/platform-support" },
    ],
  },
  {
    label: "SDK",
    items: [
      { label: "Overview", slug: "sdk" },
      { label: "Python", slug: "getting-started/python-quickstart" },
      { label: "TypeScript", slug: "getting-started/nodejs-quickstart" },
      { label: "Rust", slug: "getting-started/rust-quickstart" },
    ],
  },
  {
    label: "Guides",
    items: [
      { label: "AI agent integration", slug: "guides/ai-agent-integration" },
      { label: "Network access", slug: "guides/network-egress-policy" },
      { label: "Secrets and credentials", slug: "guides/secrets-and-credentials" },
      { label: "Troubleshooting", slug: "guides/troubleshooting" },
    ],
  },
];
