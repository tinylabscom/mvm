import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";
import { docsSchema } from "@astrojs/starlight/schema";
import { docsLoader } from "@astrojs/starlight/loaders";

export const collections = {
  useCases: defineCollection({
    loader: glob({ pattern: "**/*.md", base: "./src/content/use-cases" }),
    schema: z.object({
      title: z.string(),
      description: z.string(),
      team: z.string(),
      outcome: z.string(),
      order: z.number(),
      guide: z.string().startsWith("/"),
      guideLabel: z.string(),
    }),
  }),
  docs: defineCollection({
    loader: docsLoader(),
    schema: docsSchema(),
  }),
  blog: defineCollection({
    loader: glob({ pattern: "**/*.{md,mdx}", base: "./src/content/blog" }),
    schema: z.object({
      title: z.string(),
      description: z.string(),
      date: z.coerce.date(),
      shareHook: z.string().trim().min(1).max(240),
      tags: z.array(z.string()).default([]),
      heroImage: z.string(),
      heroAlt: z.string(),
    }),
  }),
};
