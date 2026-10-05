import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
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

test("Claude Code client guide keeps the MCP and guest boundaries distinct", () => {
  const guide = readFileSync(
    path.join(repo, "public/src/content/docs/guides/claude-code-mcp.md"),
    "utf8",
  );
  const sidebar = readFileSync(path.join(repo, "public/src/sidebar.ts"), "utf8");

  assert.match(sidebar, /slug: "guides\/claude-code-mcp"/);
  assert.match(guide, /mvmctl ops mcp stdio/);
  assert.match(guide, /CLAUDE_PROJECT_DIR/);
  assert.match(guide, /does \*\*not\*\* confine Claude Code's own/);
  assert.match(guide, /Without any `\[tools\]`\s+section, the MCP adapter has no tool gate/);
  assert.match(guide, /not a substitute for the chain-signed audit/);
});

// A profile takes its own policy under `[overrides]`; a top-level `[tools]`
// table is the group form and does not parse there. A guide that shows the
// group form for a file named by `[policy] profile` documents a server that
// refuses to start.
const readGuide = (name) =>
  readFileSync(path.join(repo, "public/src/content/docs/guides", name), "utf8");

for (const name of ["claude-code-mcp.md", "opencode-agent.md", "goose-agent.md"]) {
  test(`${name} writes the MCP tool policy in the profile form`, () => {
    const guide = readGuide(name);

    assert.match(guide, /\[overrides\.tools\]\nallow = \["mvm\.machine\.list"\]/);
    assert.doesNotMatch(guide, /^\[tools\]$/m);
    assert.match(guide, /profile = "\.\/policy\/mcp-readonly\.toml"/);
    assert.match(guide, /mvmctl ops mcp stdio/);
    assert.match(guide, /Without any `\[tools\]`\s+section, the MCP adapter has no tool gate/);
    assert.match(guide, /not a substitute for the chain-signed audit/);
  });
}

const agentPacks = [
  { file: "claude-code-mcp.md", pack: "agent/claude", secrets: ["anthropic"], needs: ["runtime/python"] },
  { file: "codex-agent.md", pack: "agent/codex", secrets: ["openai"], needs: ["runtime/node"] },
  { file: "pi-agent.md", pack: "agent/pi", secrets: ["anthropic"], needs: [] },
  { file: "opencode-agent.md", pack: "agent/opencode", secrets: ["anthropic", "openai"], needs: [] },
  { file: "goose-agent.md", pack: "agent/goose", secrets: ["anthropic", "openai"], needs: [] },
];

for (const { file, pack, secrets, needs } of agentPacks) {
  test(`${file} documents the ${pack} pack without promising an image`, () => {
    const guide = readGuide(file);
    const sidebar = readFileSync(path.join(repo, "public/src/sidebar.ts"), "utf8");
    const slug = file.replace(/\.md$/, "");

    assert.match(sidebar, new RegExp(`slug: "guides/${slug}"`));
    assert.match(guide, new RegExp(`mvmctl pull ${pack}\\n`));
    assert.match(guide, new RegExp(`mvmctl run --policy ${pack} -- `));
    // `pull` fetches one pack; a profile that includes another names it.
    for (const dependency of needs) {
      assert.match(guide, new RegExp(`mvmctl pull ${dependency}\\n`));
    }
    for (const secret of secrets) {
      assert.match(guide, new RegExp(`mvmctl secret set ${secret} --provider ${secret}`));
      assert.match(guide, new RegExp(`name = "${secret}"`));
    }
    assert.match(guide, /The pack is policy only\. It ships no image and installs nothing/);
    assert.match(guide, /no published image or\s+template\s+does/);
  });
}

test("client guides state which clients the MCP server can and cannot serve", () => {
  const codex = readGuide("codex-agent.md");
  const pi = readGuide("pi-agent.md");
  const index = readGuide("ai-agent-integration.md");

  // Codex opens with an older protocol version than the other clients; the
  // guide must name it and say the server answers it.
  assert.match(codex, /`2025-06-18`/);
  assert.match(codex, /codex mcp add mvm -- mvmctl ops mcp stdio/);
  assert.match(codex, /the MVM tools are listed under the\s+`mcp__mvm` namespace/);
  assert.match(codex, /Codex does not read `OPENAI_API_KEY`/);
  assert.match(pi, /pi has no\s+MCP client/);
  assert.match(pi, /--provider anthropic/);
  for (const slug of ["claude-code-mcp", "codex-agent", "pi-agent", "opencode-agent", "goose-agent", "pack-authoring"]) {
    assert.match(index, new RegExp(`\\(/guides/${slug}/\\)`));
  }
});

test("pack authoring guide matches the registry layout and trust model", () => {
  const guide = readGuide("pack-authoring.md");
  const policy = readGuide("policy-and-profiles.md");
  const registry = readFileSync(
    path.join(repo, "crates/mvm-core/src/registry_pack.rs"),
    "utf8",
  );
  const store = readFileSync(
    path.join(repo, "crates/mvm-core/src/registry_pack_store.rs"),
    "utf8",
  );

  // The signing identity and the two policy documents are constants in the
  // client; the guide quotes them, so a change there has to reach the guide.
  const identity = registry.match(/OFFICIAL_PACK_SIGNING_IDENTITY: &str =\s+"([^"]+)"/);
  assert.ok(identity, "official pack signing identity constant not found");
  assert.ok(guide.includes(identity[1]), "guide does not quote the official signing identity");
  for (const document of ["pack/profile.toml", "pack/group.toml"]) {
    assert.ok(store.includes(`"${document}"`), `${document} is no longer a pack policy document`);
    assert.ok(guide.includes(`\`${document}\``), `guide does not name ${document}`);
  }
  assert.match(guide, /\$MVM_HOME\/registry\/publishers\.toml/);
  assert.match(guide, /\$MVM_HOME\/registry\/packs\.lock\.toml/);
  assert.match(guide, /A published version is immutable/);
  assert.match(guide, /It cannot import local policy/);
  assert.match(guide, /follows signed profile dependencies/);
  assert.match(guide, /`--policy runtime\/node` also selects it directly/);
  assert.match(policy, /each entry is a profile or a\s+group/);
});

test("every agent-sandbox capability links to a concrete feature page", () => {
  const index = readFileSync(
    path.join(repo, "public/src/content/docs/guides/index.md"),
    "utf8",
  );
  const pages = new Map([
    ["Isolation", "security/matryoshka.md"],
    ["Undo, redo, and replay", "guides/lineage-recovery.md"],
    ["Audit trail", "guides/audit-and-receipts.md"],
    ["Provenance", "guides/workload-provenance.md"],
    ["Runtime approvals", "guides/runtime-approvals.md"],
    ["Network filtering", "guides/network-egress-policy.mdx"],
    ["Credential injection", "guides/secrets-and-credentials.mdx"],
    ["Sessions", "guides/durable-agent-sessions.md"],
  ]);

  for (const [capability, source] of pages) {
    const route = source.replace(/\.(md|mdx)$/, "");
    assert.equal(existsSync(path.join(repo, "public/src/content/docs", source)), true, `${capability} page exists`);
    assert.equal(
      index.includes(`| ${capability} | [Feature page](/${route}/) |`),
      true,
      `${capability} appears in the capability map`,
    );
  }
  assert.match(index, /external side effects are not undone/i);
});
