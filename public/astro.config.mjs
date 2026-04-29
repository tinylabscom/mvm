import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import tailwindcss from "@tailwindcss/vite";
import react from "@astrojs/react";

export default defineConfig({
  site: "https://gomicrovm.com",
  base: "/",
  vite: {
    plugins: [tailwindcss()],
  },
  integrations: [
    starlight({
      title: "mvm",
      logo: {
        light: "./src/assets/logo-light.svg",
        dark: "./src/assets/logo-dark.svg",
        replacesTitle: true,
      },
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/auser/mvm" },
      ],
      expressiveCode: {
        themes: ["github-dark"],
        styleOverrides: {
          borderColor: "#30363d", // overridden by custom.css var(--color-border)
          borderRadius: "0.75rem",
        },
      },
      customCss: ["./tailwind.css", "./src/styles/custom.css"],
      components: {
        Hero: "./src/overrides/Hero.astro",
        Header: "./src/overrides/Header.astro",
      },
      head: [
        {
          tag: "script",
          content: `document.documentElement.dataset.theme = 'dark';`,
        },
      ],
      sidebar: [
        {
          label: "Getting Started",
          items: [
            { label: "Installation", slug: "getting-started/installation" },
            { label: "Quick Start", slug: "getting-started/quickstart" },
            { label: "Nix for mvm", slug: "getting-started/nix-for-mvm" },
            { label: "Your First MicroVM", slug: "getting-started/first-microvm" },
          ],
        },
        {
          label: "Guides",
          items: [
            { label: "Writing Nix Flakes", slug: "guides/nix-flakes" },
            { label: "Templates", slug: "guides/templates" },
            { label: "Sandboxed Exec", slug: "guides/exec" },
            { label: "Config & Secrets", slug: "guides/config-secrets" },
            { label: "Networking", slug: "guides/networking" },
            { label: "Troubleshooting", slug: "guides/troubleshooting" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "CLI Commands", slug: "reference/cli-commands" },
            { label: "Architecture", slug: "reference/architecture" },
            { label: "Filesystem & Drives", slug: "reference/filesystem" },
            { label: "Guest Agent", slug: "reference/guest-agent" },
          ],
        },
        {
          label: "Contributing",
          items: [
            { label: "Development Guide", slug: "contributing/development" },
            { label: "ADR-001: Multi-Backend VMs", slug: "contributing/adr/001-multi-backend" },
          ],
        },
      ],
    }),
    react(),
  ],
});
