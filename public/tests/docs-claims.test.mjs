import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("CLI reference documents local deploy without denying it", () => {
  const reference = readFileSync(
    path.join(repo, "public/src/content/docs/reference/cli-commands.md"),
    "utf8",
  );

  assert.equal(
    reference.includes("`mvmctl deploy <ir.json> --boot-artifact <path>`"),
    true,
    "reference lists local deploy with its required boot artifact",
  );
  assert.equal(reference.includes("`mvmctl deployments ls`"), true, "reference lists inventory");
  assert.equal(
    /does not expose[^\n]*`deploy`/.test(reference),
    false,
    "reference must not deny local deploy",
  );
});

test("durable session plan describes its delivered and unfinished work", () => {
  const plan = readFileSync(
    path.join(repo, "specs/plans/2026-08-18-durable-agent-sessions.md"),
    "utf8",
  );

  assert.equal(plan.includes("**Status:** Design. Not implemented."), false, "header must reflect shipped work");
  assert.equal(
    plan.includes("**Status:** Partially implemented."),
    true,
    "header must preserve unfinished work",
  );
  assert.equal(plan.includes("- [x] **WS6 — CLI."), true, "CLI workstream is delivered");
  assert.equal(plan.includes("- [ ] **WS8 — Tests + BDD**"), true, "BDD workstream remains open");
});

test("lineage recovery has a navigable capability guide with its safety boundary", () => {
  const guide = readFileSync(
    path.join(repo, "public/src/content/docs/guides/lineage-recovery.md"),
    "utf8",
  );
  const sidebar = readFileSync(path.join(repo, "public/src/sidebar.ts"), "utf8");

  assert.match(sidebar, /slug: "guides\/lineage-recovery"/);
  for (const verb of ["timeline", "revert", "rewind", "advance"]) {
    assert.equal(guide.includes(`mvmctl machine ${verb}`), true, `${verb} is documented`);
  }
  assert.match(guide, /not an undo of external effects/i);
  assert.match(guide, /signed audit chain/i);
  assert.match(guide, /new VM identity/i);
});

test("workload provenance guide distinguishes signed evidence from an export", () => {
  const guide = readFileSync(
    path.join(repo, "public/src/content/docs/guides/workload-provenance.md"),
    "utf8",
  );
  const sidebar = readFileSync(path.join(repo, "public/src/sidebar.ts"), "utf8");

  assert.match(sidebar, /slug: "guides\/workload-provenance"/);
  assert.match(guide, /signed `ExecutionPlan`/);
  assert.match(guide, /mvmctl trust receipt verify/);
  assert.match(guide, /mvmctl trust audit verify/);
  assert.match(guide, /read-only view/);
  assert.match(guide, /not a substitute for verifying the underlying audit chain/i);
});

test("durable agent-session guide states admission and retention limits", () => {
  const guide = readFileSync(
    path.join(repo, "public/src/content/docs/guides/durable-agent-sessions.md"),
    "utf8",
  );
  const sidebar = readFileSync(path.join(repo, "public/src/sidebar.ts"), "utf8");

  assert.match(sidebar, /slug: "guides\/durable-agent-sessions"/);
  for (const verb of ["open", "park", "resume", "renew"]) {
    assert.equal(guide.includes(`mvmctl agent-session ${verb}`), true, `${verb} is documented`);
  }
  assert.match(guide, /does not boot a sandbox by default/i);
  assert.match(guide, /retention promise, not an automatic cleanup timer/i);
  assert.match(guide, /verify the audit chain separately/i);
});
