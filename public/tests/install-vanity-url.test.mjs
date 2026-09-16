import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const publicRoot = new URL("../", import.meta.url).pathname;
const repoRoot = join(publicRoot, "..");
const vanityUrl = "https://gomicrovm.com/install.sh";

test("the vanity route serves the repository installer with a shell content type", () => {
  const route = readFileSync(join(publicRoot, "src/pages/install.sh.ts"), "utf8");
  const headers = readFileSync(join(publicRoot, "public/_headers"), "utf8");

  assert.match(route, /new URL\("\.\.\/\.\.\/\.\.\/install\.sh", import\.meta\.url\)/);
  assert.match(route, /"Content-Type": "text\/x-shellscript; charset=utf-8"/);
  assert.match(route, /new Response\(installScript/);
  assert.match(headers, /\/install\.sh\n  Content-Type: text\/x-shellscript; charset=utf-8/);
});

test("all documented mvm install commands use the vanity URL", () => {
  for (const relativePath of [
    "src/content/docs/getting-started/installation.md",
    "src/content/docs/install/macos.md",
    "src/content/docs/install/linux.md",
  ]) {
    const page = readFileSync(join(publicRoot, relativePath), "utf8");

    assert.match(page, new RegExp(vanityUrl.replaceAll(".", "\\.")), relativePath);
    assert.doesNotMatch(page, /raw\.githubusercontent\.com\/tinylabscom\/mvm\/main\/install\.sh/, relativePath);
  }
});

test("the scheduled monitor checks status, content type, and the installer marker", () => {
  const workflow = readFileSync(join(repoRoot, ".github/workflows/install-url-watch.yml"), "utf8");

  assert.match(workflow, /schedule:/);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /https:\/\/gomicrovm\.com\/install\.sh/);
  assert.match(workflow, /HTTP 200/);
  assert.match(workflow, /text\/x-shellscript/);
  assert.match(workflow, /# mvmctl installer\./);
  assert.match(workflow, /gh issue create/);
});
