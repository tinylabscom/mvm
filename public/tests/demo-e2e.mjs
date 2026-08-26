#!/usr/bin/env node
/**
 * Smoke test for the WebLinux browser demo and the static site.
 *
 * This script starts a tiny static server from the built `public/dist`
 * directory, serving the response headers the deployed site's `_headers` file
 * declares, and uses Playwright to visit the landing page, confirm both it and
 * the demo it embeds are cross-origin isolated, and drive the /demo/weblinux
 * page through run, shell interaction, and stop.
 *
 * Prerequisites: Playwright must be installed in a discoverable Node scope.
 *   cd public && pnpm add -D playwright
 *
 * Run after building and staging the WebLinux demo assets:
 *   nix build .#qemu-wasm-smoke-pack
 *   ./web/weblinux-demo/build.sh result
 *   just docs-build
 *   node public/tests/demo-e2e.mjs
 */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
// The deployed site's response headers come from a `_headers` file that
// Cloudflare Pages reads at the site root. This harness serves that same file
// instead of stamping COOP/COEP on every response: a hard-coded blanket policy
// passes under a config that would not isolate the real site, which is how the
// landing page's embedded demo shipped without SharedArrayBuffer.
import { loadHeaderRules, headersFor } from "../scripts/headers-config.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../dist");

let chromium;
try {
  const playwright = await import("playwright");
  chromium = playwright.chromium;
} catch (err) {
  console.error("Playwright not found. Install it, e.g.:\n  cd public && pnpm add -D playwright");
  process.exit(1);
}

const mime = {
  ".html": "text/html",
  ".js": "application/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
};

function startServer(port, rules) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const pathname = decodeURIComponent(req.url.split("?")[0]);
      let file = path.join(ROOT, pathname);
      if (file.endsWith("/")) file += "index.html";
      if (!fs.existsSync(file)) file = path.join(ROOT, "index.html");
      const ext = path.extname(file);
      res.writeHead(200, {
        "Content-Type": mime[ext] || "application/octet-stream",
        ...headersFor(rules, pathname),
      });
      fs.createReadStream(file).pipe(res);
    });
    server.listen(port, () => resolve(server));
  });
}

// SharedArrayBuffer exists only in a cross-origin-isolated context, and
// isolation does not propagate upward from a frame: an embedded demo is
// isolated only when the document embedding it is isolated too. Accepts a Page
// or a Frame — both expose evaluate().
async function assertIsolated(context, label) {
  const state = await context.evaluate(() => ({
    isolated: globalThis.crossOriginIsolated === true,
    sharedArrayBuffer: typeof SharedArrayBuffer !== "undefined",
  }));
  if (!state.isolated || !state.sharedArrayBuffer) {
    throw new Error(
      `${label} is not cross-origin isolated (crossOriginIsolated=${state.isolated}, ` +
        `SharedArrayBuffer=${state.sharedArrayBuffer}); widen the COOP/COEP scope in ` +
        `public/public/_headers`,
    );
  }
}

async function openEmbeddedDemo(page, timeoutMs = 30000) {
  await page.click("button:has-text('Run demo')");
  const element = await page.waitForSelector("iframe[title='mvm WebLinux demo']", {
    timeout: timeoutMs,
  });
  const frame = await element.contentFrame();
  if (!frame) throw new Error("the demo iframe exposed no content frame");
  await frame.waitForLoadState("domcontentloaded");
  return frame;
}

async function runCommand(page, cmd) {
  await page.fill("#command", cmd);
  await page.press("#command", "Enter");
  await page.waitForTimeout(500);
}

async function waitForLog(page, needle, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const log = await page.$eval("#log", (el) => el.textContent);
    if (log.includes(needle)) return log;
    await page.waitForTimeout(500);
  }
  throw new Error(`timed out waiting for log to include: ${needle}`);
}

async function main() {
  if (!fs.existsSync(ROOT)) {
    throw new Error(`Built dist not found at ${ROOT}; run 'just docs-build' first.`);
  }

  // Built from public/public/_headers. Without it the harness would serve an
  // unisolated site and every assertion below would fail for the wrong reason,
  // so treat a missing file as a broken build rather than an empty ruleset.
  let rules;
  try {
    rules = loadHeaderRules(ROOT);
  } catch (err) {
    throw new Error(`${err.message}; rebuild the site with 'just docs-build'`);
  }

  const server = await startServer(8788, rules);
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });

  const messages = [];
  page.on("console", (msg) => messages.push({ type: msg.type(), text: msg.text() }));
  page.on("pageerror", (err) => messages.push({ type: "pageerror", text: err.message }));
  page.on("worker", (worker) => {
    worker.on("console", (msg) => console.log("[worker]", msg.type(), msg.text()));
  });

  try {
    // Smoke-check the landing page first.
    await page.goto("http://localhost:8788/", { waitUntil: "networkidle" });
    await page.waitForTimeout(500);
    await assertIsolated(page, "landing page");

    // Open the demo the way a landing-page visitor does. The frame inherits
    // isolation from this document, so it is the direct witness that the
    // embedded copy can allocate a SharedArrayBuffer. Close it again rather
    // than letting the autorun boot run alongside the standalone drive below.
    const embedded = await openEmbeddedDemo(page);
    await assertIsolated(embedded, "embedded demo iframe");
    await page.click("button[aria-label='Close demo']");
    await page.waitForTimeout(250);

    // Open the WebLinux demo with autorun so the engine starts immediately.
    await page.goto("http://localhost:8788/demo/weblinux/?autorun=1", { waitUntil: "networkidle" });

    // Wait for the worker to report ready.
    await waitForLog(page, "DEMO-RESULT: READY", 120000);

    // Run a shell command inside the guest.
    await runCommand(page, "uname -a");
    const logAfterCmd = await waitForLog(page, "Linux", 30000);
    if (!logAfterCmd.includes("qemu")) {
      // The demo's uname -a output includes "qemu" when running under QEMU-Wasm.
      throw new Error("guest uname did not look like the QEMU-Wasm Linux guest");
    }

    // Stop the VM and confirm the worker tears down cleanly.
    await page.click("#stopBtn");
    await page.waitForTimeout(1000);
    const status = await page.$eval("#status", (el) => el.textContent);
    if (!status.includes("stopped")) {
      throw new Error("demo did not report stopped status");
    }

    const relevant = messages.filter((m) => !["debug", "log", "info"].includes(m.type));
    if (relevant.length > 0) {
      relevant.forEach((m) => console.error(`[${m.type}] ${m.text}`));
      throw new Error("console warnings/errors detected");
    }

    console.log("E2E smoke test passed");
  } finally {
    await browser.close();
    server.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
