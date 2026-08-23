#!/usr/bin/env node
/**
 * Smoke test for the WebLinux browser demo and the static site.
 *
 * This script starts a tiny static server from the built `public/dist`
 * directory (with COOP/COEP headers required by SharedArrayBuffer) and uses
 * Playwright to visit the landing page and drive the /demo/weblinux page
 * through run, shell interaction, and stop.
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
      res.writeHead(200, {
        "Content-Type": mime[ext] || "application/octet-stream",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
      });
      fs.createReadStream(file).pipe(res);
    });
    server.listen(port, () => resolve(server));
  });
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
