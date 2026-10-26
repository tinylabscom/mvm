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

test("blog omits the browse posts section and keeps a clear return link", () => {
  const index = readFileSync(join(publicRoot, "src/pages/blog/index.astro"), "utf8");
  const article = readFileSync(join(publicRoot, "src/pages/blog/[...slug].astro"), "utf8");
  assert.doesNotMatch(index, /blog-post-index|Browse posts/);
  assert.match(article, /href="\/blog\/">← All posts<\/a>/);
});

test("use cases are discoverable and have complete workflow content", () => {
  const header = readFileSync(join(publicRoot, "src/overrides/Header.astro"), "utf8");
  assert.match(header, /\{ label: "Use cases", href: `\$\{b\}use-cases\/` \}/);
  const files = markdownFiles(join(publicRoot, "src/content/use-cases"));
  assert.ok(files.length >= 4);
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    for (const heading of ["The situation", "A workflow with mvm", "What your team gains", "What to plan for"]) {
      assert.ok(source.includes(`## ${heading}`), `${file}: ${heading}`);
    }
    const guide = source.match(/^guide: (\/.+\/)$/m)?.[1];
    assert.ok(guide, `${file}: guide link`);
    assert.ok(markdownFiles(join(publicRoot, "src/content/docs")).some(
      path => path.replace(/\.mdx?$/, "").endsWith(guide.slice(0, -1)),
    ), `${file}: guide exists`);
  }
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

test("homepage keeps the quickstart before product details and contact", () => {
  const landing = readFileSync(join(publicRoot, "src/components/landing/Landing.tsx"), "utf8");
  const sections = ["Hero", "Quickstart", "WhyNow", "ExecutionContract", "RiskControl", "RequestAccess", "Footer"];
  const positions = sections.map(section => landing.indexOf(`<${section} />`));

  assert.ok(positions.every(position => position >= 0));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b));
  assert.doesNotMatch(landing, /<RegulatorsNow\s*\/>/);
});

test("homepage contact form preserves its endpoint and existing anchor", () => {
  const source = readFileSync(
    join(publicRoot, "src/components/landing/RequestAccess.tsx"),
    "utf8",
  );

  assert.match(source, /id="request-access"/);
  assert.match(source, /action="https:\/\/formspree\.io\/f\/xwvyllrp"/);
  assert.match(source, /method="POST"/);
  assert.match(source, /name="email"/);
  assert.match(source, /name="class"/);
});

test("architecture diagram layers retain their detail notes", () => {
  const source = readFileSync(
    join(publicRoot, "src/components/architecture/Architecture.astro"),
    "utf8",
  );
  const targets = [...source.matchAll(/data-note="([^"]+)"/g)].map(match => match[1]);

  assert.ok(targets.length > 0);
  for (const target of targets) {
    assert.ok(source.includes(`id="${target}"`), `Missing diagram note: ${target}`);
  }
  assert.match(source, /id="stack"/);
  assert.match(source, /id="company"/);
});

test("documentation code blocks provide dark and light syntax themes", () => {
  const astroConfig = readFileSync(join(publicRoot, "astro.config.mjs"), "utf8");

  assert.match(astroConfig, /themes:\s*\["github-dark",\s*"github-light"\]/);
  assert.match(astroConfig, /borderColor:\s*"var\(--color-border\)"/);
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
