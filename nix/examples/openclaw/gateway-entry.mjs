// Entry point wrapper for OpenClaw gateway in mvm microVMs.
// Fixes the double-start bug: runGatewayLoop fires two concurrent
// startGatewayServer() calls; the loser's lock check calls process.exit(1),
// killing the working server. We detect the conflict and suppress the exit.
//
// IMPORT_PATH is replaced at build time with the actual openclaw module path.
import { runCli } from "IMPORT_PATH";

process.env.OPENCLAW_NODE_OPTIONS_READY = "1";

const realExit = process.exit;
let lockConflict = false;

for (const stream of [process.stdout, process.stderr]) {
  const orig = stream.write.bind(stream);
  stream.write = function (chunk, ...args) {
    if (
      typeof chunk === "string" &&
      !lockConflict &&
      (chunk.includes("already running") ||
        chunk.includes("already listening") ||
        chunk.includes("already in use"))
    ) {
      lockConflict = true;
    }
    return orig(chunk, ...args);
  };
}

process.exit = (code) => {
  if (code !== 0 && lockConflict) return;
  realExit(code);
};

runCli(process.argv).catch((err) => {
  if (!lockConflict) realExit(1);
});
