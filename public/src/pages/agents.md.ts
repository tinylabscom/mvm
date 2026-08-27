// The same body as /skill.md. Agents look for one name or the other, and
// which one is a coin flip that should not decide whether they find mvm.
import type { APIRoute } from "astro";
import { AGENT_SKILL } from "../lib/agent-skill";

export const GET: APIRoute = () =>
  new Response(AGENT_SKILL, {
    headers: { "Content-Type": "text/markdown; charset=utf-8" },
  });
