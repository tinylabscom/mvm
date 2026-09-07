import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const publicRoot = new URL("../", import.meta.url).pathname;

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
