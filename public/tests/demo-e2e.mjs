#!/usr/bin/env node
/**
 * Smoke test for the browser-tier microVM demo and the static site.
 *
 * This script starts a tiny static server from the built `public/dist`
 * directory and uses Playwright to visit the landing page (to catch any
 * site-wide console errors) and then drive the /demo page through launch,
 * shell commands, allow/deny policy, and stop.
 *
 * Prerequisites: Playwright must be installed in a discoverable Node scope.
 *   cd public && pnpm add -D playwright
 *
 * Run after building the site:
 *   just demo-build
 *   just docs-build
 *   node public/tests/demo-e2e.mjs
 */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

function startServer(port) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let file = path.join(ROOT, decodeURIComponent(req.url.split("?")[0]));
      if (file.endsWith("/")) file += "index.html";
      if (!fs.existsSync(file)) file = path.join(ROOT, "index.html");
      const ext = path.extname(file);
      res.writeHead(200, { "Content-Type": mime[ext] || "application/octet-stream" });
      fs.createReadStream(file).pipe(res);
    });
    server.listen(port, () => resolve(server));
  });
}

async function runCommand(page, cmd) {
  await page.fill("#command", cmd);
  await page.press("#command", "Enter");
  await page.waitForTimeout(400);
}

async function main() {
  if (!fs.existsSync(ROOT)) {
    throw new Error(`Built dist not found at ${ROOT}; run 'just docs-build' first.`);
  }

  const server = await startServer(8788);
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

    await page.goto("http://localhost:8788/demo/", { waitUntil: "networkidle" });
    await page.waitForTimeout(1500);

    // Launch with default allowlist policy.
    await page.click("#launch");
    await page.waitForTimeout(1500);

    const consoleText = await page.$eval("#console", (el) => el.textContent);
    if (!consoleText.includes("MicroVM")) {
      throw new Error("microVM did not report as running");
    }

    await runCommand(page, "cat /etc/policy");
    const policyText = await page.$eval("#console", (el) => el.textContent);
    if (!policyText.includes('"type":"allowlist"')) {
      throw new Error("policy file not displayed");
    }

    await runCommand(page, "fetch echo.mvm.local 443");
    const allowText = await page.$eval("#console", (el) => el.textContent);
    if (!allowText.includes("fetch: allowed")) {
      throw new Error("expected allow decision for echo.mvm.local");
    }
    if (!allowText.includes("response from simulated demo destination")) {
      throw new Error("expected simulated destination response for echo.mvm.local");
    }

    // Stop and verify the first VM's audit chain.
    await page.click("#stop");
    await page.waitForTimeout(300);
    const chainAfterStop = await page.$eval("#audit-chain", (el) => el.textContent);
    if (!chainAfterStop.includes("vm.start") || !chainAfterStop.includes("egress.allow") || !chainAfterStop.includes("vm.stop")) {
      throw new Error("first audit chain missing expected events. Full chain:\n" + chainAfterStop);
    }

    // Switch to deny-all and relaunch.
    await page.waitForTimeout(500);
    await page.fill("#policy", '{"type":"allowlist","rules":[]}');
    await page.click("#launch");
    await page.waitForTimeout(1500);
    await runCommand(page, "fetch echo.mvm.local 443");
    const denyText = await page.$eval("#console", (el) => el.textContent);
    if (!denyText.includes("fetch: denied")) {
      throw new Error("expected deny decision for empty allowlist");
    }

    // The second VM's chain should contain vm.start and egress.deny.
    const auditText = await page.$eval("#audit-chain", (el) => el.textContent);
    if (!auditText.includes("vm.start") || !auditText.includes("egress.deny")) {
      throw new Error("second audit chain missing expected events");
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
