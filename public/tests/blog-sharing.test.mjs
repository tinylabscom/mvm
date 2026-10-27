import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";

// Run after pnpm build to check the actual generated pages, not template strings.
test("every blog post renders sharing controls with its own hook and canonical URL", async () => {
  const posts = await readdir(new URL("../src/content/blog/", import.meta.url), { recursive: true });
  for (const file of posts.filter((file) => /\.mdx?$/.test(file))) {
    const slug = file.replace(/\.mdx?$/, "");
    const html = await readFile(new URL(`../dist/blog/${slug}/index.html`, import.meta.url), "utf8");
    for (const platform of ["X", "LinkedIn", "Facebook", "Reddit"]) {
      assert.ok(html.includes(`aria-label="Share on ${platform}"`), `${file}: ${platform}`);
    }
    assert.ok(html.includes(`https://runmvm.com/blog/${slug}`), `${file}: production URL`);
    const propsAttribute = html.match(/component-export="default"[^>]*props="([^"]*?&quot;hook&quot;[^"]*)"/)?.[1];
    assert.ok(propsAttribute, `${file}: sharing island receives the required hook`);
    const props = JSON.parse(propsAttribute.replaceAll("&quot;", '"').replaceAll("&amp;", "&"));
    const hook = props.hook[1];
    assert.ok(hook.trim(), `${file}: nonblank hook`);
    assert.ok(hook.length <= 240, `${file}: hook leaves room for the link`);
  }
});
