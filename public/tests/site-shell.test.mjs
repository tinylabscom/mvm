import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const publicRoot = new URL("../", import.meta.url).pathname;

function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return markdownFiles(path);
    return /\.mdx?$/.test(entry.name) ? [path] : [];
  });
}

test("shared navigation makes the blog discoverable", () => {
  const header = readFileSync(join(publicRoot, "src/overrides/Header.astro"), "utf8");

  assert.match(header, /\{ label: "Blog", href: `\$\{b\}blog\/` \}/);
});

for (const [label, relativePath] of [
  ["blog", "src/layouts/BlogLayout.astro"],
  ["pricing", "src/pages/pricing.astro"],
]) {
  test(`${label} renders the homepage header component`, () => {
    const source = readFileSync(join(publicRoot, relativePath), "utf8");

    assert.match(source, /import Header from "(?:\.\.\/){1,2}overrides\/Header\.astro";/);
    assert.match(source, /<Header forceLanding standalone\s*\/>/);
  });
}

test("homepage content renders immediately without a reveal animation", () => {
  const reveal = readFileSync(
    join(publicRoot, "src/components/landing/primitives/Reveal.tsx"),
    "utf8",
  );
  const landing = readFileSync(join(publicRoot, "src/components/landing/Landing.tsx"), "utf8");
  const header = readFileSync(join(publicRoot, "src/overrides/Header.astro"), "utf8");
  const styles = readFileSync(join(publicRoot, "src/styles/custom.css"), "utf8");

  assert.doesNotMatch(reveal, /IntersectionObserver|transitionDelay|site-reveal/);
  assert.doesNotMatch(landing, /classList\.add\("hydrated"\)/);
  assert.doesNotMatch(header, /classList\.add\("js"\)/);
  assert.doesNotMatch(styles, /html\.js .*site-reveal|site-reveal-failsafe/);
});

test("non-doc pages share one content width and responsive gutter", () => {
  const header = readFileSync(join(publicRoot, "src/overrides/Header.astro"), "utf8");
  const blogStyles = readFileSync(join(publicRoot, "src/styles/custom.css"), "utf8");
  const architecture = readFileSync(
    join(publicRoot, "src/components/architecture/Architecture.astro"),
    "utf8",
  );
  const pricing = readFileSync(join(publicRoot, "src/components/PricingContent.astro"), "utf8");
  const staticTheme = readFileSync(join(publicRoot, "public/theme.css"), "utf8");

  assert.match(blogStyles, /--site-content-width:\s*72rem/);
  assert.match(blogStyles, /--site-gutter:\s*1\.5rem/);
  assert.match(blogStyles, /--site-gutter:\s*2rem/);

  for (const source of [header, blogStyles, architecture, pricing, staticTheme]) {
    assert.match(source, /var\(--site-content-width\)/);
    assert.match(source, /var\(--site-gutter\)/);
  }
});

test("docs development clears stale content cache and uses valid code fence languages", () => {
  const packageJson = JSON.parse(readFileSync(join(publicRoot, "package.json"), "utf8"));

  assert.equal(packageJson.scripts.dev, "node scripts/clear-content-cache.mjs && astro dev");
  for (const path of markdownFiles(join(publicRoot, "src/content"))) {
    assert.doesNotMatch(readFileSync(path, "utf8"), /^```[^\s,]+,/m, path);
  }
});
