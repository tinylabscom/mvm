import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { terminalControlBytes } from "../../web/weblinux-demo/terminal-input.mjs";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const demoDir = path.resolve(testDir, "../../web/weblinux-demo");

test("Ctrl+C maps to the terminal interrupt byte", () => {
  assert.equal(terminalControlBytes({ key: "c", ctrlKey: true }), "\x03");
});

test("Ctrl+D maps to the terminal EOF byte", () => {
  assert.equal(terminalControlBytes({ key: "d", ctrlKey: true }), "\x04");
});

test("unmodified, alternate, and command-key input remains browser input", () => {
  assert.equal(terminalControlBytes({ key: "c", ctrlKey: false }), null);
  assert.equal(terminalControlBytes({ key: "c", ctrlKey: true, altKey: true }), null);
  assert.equal(terminalControlBytes({ key: "d", ctrlKey: true, metaKey: true }), null);
});

test("control key matching is case insensitive", () => {
  assert.equal(terminalControlBytes({ key: "C", ctrlKey: true }), "\x03");
  assert.equal(terminalControlBytes({ key: "D", ctrlKey: true }), "\x04");
});

test("the page, worker, and staging script carry raw terminal input end to end", () => {
  const demo = fs.readFileSync(path.join(demoDir, "demo.js"), "utf8");
  const worker = fs.readFileSync(path.join(demoDir, "worker.js"), "utf8");
  const build = fs.readFileSync(path.join(demoDir, "build.sh"), "utf8");

  assert.match(demo, /postMessage\(\{ type: "stdin", data: controlBytes \}\)/);
  assert.match(worker, /inputCallback\(event\.data\.data\)/);
  assert.match(
    build,
    /cp "\$SCRIPT_DIR\/terminal-input\.mjs" "\$DEST_DIR\/terminal-input\.mjs"/,
  );
});

test("the active demo terminal forwards Ctrl+C and Ctrl+D to its worker", async () => {
  const listeners = new Map();
  const elements = new Map();
  const elementIds = [
    "status",
    "log",
    "runBtn",
    "stopBtn",
    "input-form",
    "command",
    "allowHost",
  ];
  for (const id of elementIds) {
    const elementListeners = new Map();
    const element = {
      addEventListener: (type, listener) => elementListeners.set(type, listener),
      className: "",
      disabled: id === "command",
      focus: () => {},
      innerHTML: "",
      scrollHeight: 0,
      scrollTop: 0,
      textContent: "",
      value: id === "allowHost" ? "demo.mvm.local" : "",
    };
    elements.set(id, element);
    listeners.set(id, elementListeners);
  }

  const workers = [];
  class FakeWorker {
    constructor(url) {
      this.url = url;
      this.messages = [];
      workers.push(this);
    }

    postMessage(message) {
      this.messages.push(message);
    }

    terminate() {}
  }

  globalThis.document = { getElementById: (id) => elements.get(id) };
  globalThis.location = { search: "" };
  globalThis.Worker = FakeWorker;

  try {
    await import(`../../web/weblinux-demo/demo.js?test=${Date.now()}`);
    listeners.get("runBtn").get("click")();
    const worker = workers[0];
    worker.onmessage({ data: { type: "ready" } });

    const controls = [
      ["c", "\x03"],
      ["d", "\x04"],
    ];
    for (const [key, data] of controls) {
      let prevented = false;
      listeners.get("command").get("keydown")({
        altKey: false,
        ctrlKey: true,
        key,
        metaKey: false,
        preventDefault: () => {
          prevented = true;
        },
      });
      assert.equal(prevented, true);
      assert.deepEqual(worker.messages.at(-1), { type: "stdin", data });
    }
  } finally {
    delete globalThis.document;
    delete globalThis.location;
    delete globalThis.Worker;
  }
});
