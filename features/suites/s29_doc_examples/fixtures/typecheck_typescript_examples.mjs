// Typecheck the documentation's TypeScript examples against the local SDK.
//
// The sibling `check_typescript_examples.mjs` resolves *names* from the SDK's
// export graph. That catches a symbol that does not exist; it cannot catch a
// call with the right name and the wrong argument shape. This runs the real
// compiler over the same blocks, with `@runmvm/mvm` mapped to the checkout's
// `src/index.ts` — so the examples are checked against the SDK in this tree,
// not against whatever version is published.
//
// Requires the SDK's dev toolchain (`just sdk-ts-install`). When it is absent
// the caller is told so and skips, rather than failing for a reason that has
// nothing to do with the docs.
//
// Reads a JSON array of {file, line, body} on stdin; writes a JSON array of
// findings on stdout.

import { mkdtempSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";

const SDK = process.env.MVM_TS_SDK_ROOT;

function findings(list) {
  process.stdout.write(JSON.stringify(list));
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const blocks = JSON.parse(Buffer.concat(chunks).toString("utf8"));

  const tsc = resolve(SDK, "node_modules/.bin/tsc");
  if (!existsSync(tsc)) {
    process.stderr.write("MVM_TS_TOOLCHAIN_ABSENT\n");
    process.exit(3);
  }

  const dir = mkdtempSync(join(tmpdir(), "mvm-doc-ts-"));
  try {
    // One file per block. `allowJs` off, `noEmit` on; the point is the types.
    const index = [];
    blocks.forEach((block, i) => {
      const name = `example_${i}.ts`;
      // Without an import or export a .ts file is a script, not a module:
      // two blocks declaring `const result` would collide, and top-level
      // `await` would be rejected. Force module scope.
      writeFileSync(join(dir, name), `${block.body}\nexport {};\n`);
      index.push({ name, file: block.file, line: block.line });
    });

    writeFileSync(
      join(dir, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          noEmit: true,
          strict: false,
          skipLibCheck: true,
          module: "esnext",
          target: "es2022",
          moduleResolution: "bundler",
          // The whole point: the docs' import specifier resolves to this
          // checkout's SDK source.
          paths: { "@runmvm/mvm": [resolve(SDK, "src/index.ts")] },
          types: ["node"],
          typeRoots: [resolve(SDK, "node_modules/@types")],
        },
        include: index.map((entry) => entry.name),
      }),
    );

    let output = "";
    try {
      execFileSync(tsc, ["-p", dir], { encoding: "utf8", stdio: "pipe" });
    } catch (error) {
      output = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    }

    // A config-level failure (an unresolvable typeRoot, a bad option) makes tsc
    // check nothing while still exiting non-zero. The per-file regex below then
    // matches nothing and the caller sees a clean run — the worst possible
    // outcome for a gate. Any `error TS` line that does not belong to a block
    // is therefore a harness failure, not a doc finding.
    const unattributed = output
      .split("\n")
      .filter((line) => /error TS\d+/.test(line))
      .filter((line) => !/(?:^|[/\\])example_\d+\.ts\(/.test(line));
    if (unattributed.length > 0) {
      process.stderr.write(
        `typechecker produced ${unattributed.length} error(s) not attributable to ` +
          `any example — the run checked nothing:\n${unattributed.join("\n")}\n`,
      );
      process.exit(4);
    }

    const found = [];
    for (const line of output.split("\n")) {
      // tsc prefixes the path when `-p` is absolute, so the filename is not
      // necessarily at the start of the line:
      //   tmp/x/example_3.ts(7,22): error TS2554: Expected 3 arguments, but got 2.
      const match = line.match(
        /(?:^|[/\\])example_(\d+)\.ts\((\d+),\d+\): error (\S+): (.+)$/,
      );
      if (!match) continue;
      const entry = index[Number(match[1])];
      if (!entry) continue;
      found.push({
        file: entry.file,
        // +1: the block body starts one line after its opening fence.
        line: entry.line + Number(match[2]),
        kind: match[3].replace(":", ""),
        detail: match[4],
      });
    }
    findings(found);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

await main();
