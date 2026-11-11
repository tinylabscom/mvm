import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";

test("blog index lists every post and exposes topic filters from post tags", async () => {
  const html = await readFile(new URL("../dist/blog/index.html", import.meta.url), "utf8");
  const files = await readdir(new URL("../src/content/blog/", import.meta.url));

  for (const file of files.filter((name) => /\.mdx?$/.test(name))) {
    const slug = file.replace(/\.mdx?$/, "");
    assert.ok(html.includes(`href="/blog/${slug}/"`), `${slug} appears in the index`);
  }

  for (const topic of ["microvm", "agent-containment", "cve-teardown", "supply-chain", "static-analysis"]) {
    assert.ok(html.includes(`data-topic="${topic}"`), `${topic} is selectable`);
    assert.ok(
      [...html.matchAll(/data-topics="([^"]*)"/g)].some(([, tags]) => tags.split(" ").includes(topic)),
      `${topic} occurs in post metadata`,
    );
  }
  for (const [slug, topic] of [
    ["secure-by-design-microvms-and-nix", "microvm"],
    ["cve-2026-8838-redshift-connector", "cve-teardown"],
  ]) {
    const tags = html.match(new RegExp(`<article[^>]*data-topics="([^"]*)"[^>]*>\\s*<a href="/blog/${slug}/"`))?.[1];
    assert.ok(tags?.split(" ").includes(topic), `${slug} appears in ${topic}`);
  }
  assert.ok(html.includes('aria-pressed="true"'), "all posts starts selected");
});
