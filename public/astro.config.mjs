import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import tailwindcss from "@tailwindcss/vite";
import react from "@astrojs/react";

// Shared with src/pages/llms.txt.ts, which groups the machine-readable index
// under these headings in this order.
import { sidebar } from "./src/sidebar.ts";

export default defineConfig({
  site: "https://gomicrovm.com",
  base: "/",
  vite: {
    plugins: [tailwindcss()],
  },
  integrations: [
    starlight({
      title: "mvm",
      // Explicit .ico so the browser's automatic /favicon.ico probe is
      // served as a static asset instead of falling through to Starlight's
      // catch-all [...slug] route (which logs a getStaticPaths WARN in dev).
      favicon: "/favicon.ico",
      logo: {
        light: "./src/assets/logo-light.svg",
        dark: "./src/assets/logo-dark.svg",
        replacesTitle: true,
      },
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/tinylabscom/mvm" },
      ],
      expressiveCode: {
        themes: ["github-dark"],
        defaultProps: {
          // Long shell/CLI samples were overflowing horizontally; wrap
          // them and align wrapped continuations with the source
          // line's indentation instead of resetting to column 1.
          wrap: true,
          preserveIndent: true,
        },
        styleOverrides: {
          // A CSS var(), not a literal — Expressive Code emits this
          // straight into its generated stylesheet as --ec-brdCol, so the
          // browser resolves it against tailwind.css's --color-code-border
          // at paint time. One source of truth instead of a hex here that
          // custom.css's --ec-brdCol override then had to shadow.
          borderColor: "var(--color-code-border)",
          borderRadius: "0.75rem",
        },
      },
      customCss: ["./tailwind.css", "./src/styles/custom.css"],
      components: {
        Hero: "./src/overrides/Hero.astro",
        Header: "./src/overrides/Header.astro",
        MarkdownContent: "./src/overrides/MarkdownContent.astro",
        PageTitle: "./src/overrides/PageTitle.astro",
        Sidebar: "./src/overrides/Sidebar.astro",
      },
      // No force-theme script. Starlight's theme picker writes
      // data-theme="auto"|"light"|"dark" on <html>; tailwind.css
      // handles each via the token system documented there. The
      // previous iteration force-locked dark via this slot; the
      // new token system supports both modes natively.
      sidebar,
    }),
    react(),
  ],
});
