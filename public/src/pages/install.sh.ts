import { readFileSync } from "node:fs";
import type { APIRoute } from "astro";

const installScript = readFileSync(
  new URL("../../../install.sh", import.meta.url),
  "utf8",
);

export const GET: APIRoute = () =>
  new Response(installScript, {
    headers: { "Content-Type": "text/x-shellscript; charset=utf-8" },
  });
