import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const publicRoot = new URL("../", import.meta.url).pathname;
const repoRoot = join(publicRoot, "..");
const vanityUrl = "https://runmvm.com/install.sh";

test("the vanity route serves the repository installer with a shell content type", () => {
  const route = readFileSync(join(publicRoot, "src/pages/install.sh.ts"), "utf8");
  const headers = readFileSync(join(publicRoot, "public/_headers"), "utf8");

  assert.match(route, /new URL\("\.\.\/\.\.\/\.\.\/install\.sh", import\.meta\.url\)/);
  assert.match(route, /"Content-Type": "text\/x-shellscript; charset=utf-8"/);
  assert.match(route, /new Response\(installScript/);
  assert.match(headers, /\/install\.sh\n  Content-Type: text\/x-shellscript; charset=utf-8/);
});

test("the vanity route serves the repository uninstaller with a shell content type", () => {
  const route = readFileSync(join(publicRoot, "src/pages/uninstall.sh.ts"), "utf8");
  const headers = readFileSync(join(publicRoot, "public/_headers"), "utf8");

  assert.match(route, /new URL\("\.\.\/\.\.\/\.\.\/uninstall\.sh", import\.meta\.url\)/);
  assert.match(route, /"Content-Type": "text\/x-shellscript; charset=utf-8"/);
  assert.match(route, /new Response\(uninstallScript/);
  assert.match(headers, /\/uninstall\.sh\n  Content-Type: text\/x-shellscript; charset=utf-8/);
});

test("all current mvm install commands use the production vanity URL", () => {
  for (const relativePath of [
    "../README.md",
    "src/components/landing/InstallTabs.tsx",
    "src/content/docs/getting-started/installation.md",
    "src/content/docs/install/macos.md",
    "src/content/docs/install/linux.md",
    "src/lib/agent-skill.ts",
  ]) {
    const page = readFileSync(join(publicRoot, relativePath), "utf8");

    assert.match(page, new RegExp(vanityUrl.replaceAll(".", "\\.")), relativePath);
    assert.doesNotMatch(page, /raw\.githubusercontent\.com\/tinylabscom\/mvm\/main\/install\.sh/, relativePath);
    assert.doesNotMatch(page, /https:\/\/gomicrovm\.com\/install\.sh/, relativePath);
  }
});

test("the scheduled monitor checks status, content type, and the installer marker", () => {
  const workflow = readFileSync(join(repoRoot, ".github/workflows/install-url-watch.yml"), "utf8");
  const check = readFileSync(join(repoRoot, "scripts/check-published-installer.sh"), "utf8");

  assert.match(workflow, /schedule:/);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /https:\/\/runmvm\.com\/install\.sh/);
  assert.match(workflow, /scripts\/check-published-installer\.sh/);
  assert.match(check, /expected HTTP 200/);
  assert.match(check, /text\/x-shellscript/);
  assert.match(check, /# mvmctl installer\./);
  assert.match(workflow, /gh issue create/);
});

test("site deploy verifies the installer through the production hostname", () => {
  const workflow = readFileSync(join(repoRoot, ".github/workflows/workers.yml"), "utf8");

  assert.match(workflow, /Verify the production installer/);
  assert.match(workflow, /https:\/\/runmvm\.com\/install\.sh/);
  assert.match(workflow, /scripts\/check-published-installer\.sh/);
});
