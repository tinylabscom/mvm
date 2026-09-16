import { readFileSync } from "node:fs";
import type { APIRoute } from "astro";

const uninstallScript = readFileSync(
  new URL("../../../uninstall.sh", import.meta.url),
  "utf8",
);

export const GET: APIRoute = () =>
  new Response(uninstallScript, {
    headers: { "Content-Type": "text/x-shellscript; charset=utf-8" },
  });
