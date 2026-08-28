import type { APIRoute } from "astro";
import { AGENT_SKILL } from "../lib/agent-skill";

export const GET: APIRoute = () =>
  new Response(AGENT_SKILL, {
    headers: { "Content-Type": "text/markdown; charset=utf-8" },
  });
