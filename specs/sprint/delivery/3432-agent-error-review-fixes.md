# Agent-facing failures: the six review fixes

The review of the agent-facing error work asked for six changes that did not
land with it.

The misplaced-image-reference refusal ran last in `resolve_run_source`, after
the manifest walk-up and runtime detection, so `mvmctl run -- node:22 index.js`
next to a `package.json` booted the detected node runtime and ran `node:22` as
its command. The refusal now runs before any inference, including the
`mvm.toml` walk-up: inference is not the user choosing a source. A word that
names an existing path relative to the working directory is never refused,
whether it reads like a registry host (`app.d/run`) or a tag (`bin/run:dev`),
and the error names the `./` escape for a local path.

The flag-after-`--` refusal moved out of the shared resolver and into each
verb. `run` and `machine run` each check against their own subcommand in the
real, built clap command tree, which includes the global flags clap passes down
to it. So `machine run -- --name web`, `run -- --mode live` and
`run -- --verbose` are refused, along with every alias (visible or hidden, long
or short, such as `--volume`), the `--flag=value` spelling, short flags (`-m`),
short clusters (`-it`, `-ih`), and short flags with an attached value
(`-p8080:80`, `-dp8080:80`). A cluster containing a character that is not one of
the verb's short flags is left alone. A standalone `--help` or `-h` is
excluded, since a workload may forward it to its own program. `--version` and
`-V` pass because neither subcommand has them, not because of an exclusion. The
error names the subcommand and says whether the flag is a global one. On `run`
the check runs before SDK-mode dispatch as well, because that mode's first word
is a script path, which a flag-shaped word never is.

In `mvm-mcp`, `capabilities()` keeps the typed error. `tools/list` and
`tools/call` return it as a `-32603` JSON-RPC error whose `data` carries the
same `code`/`retryable` pair a tool result's `_meta` does. The message is fixed
text; the backend's own error text is not included. A failed tool call still
carries the backend's own message, which is often what the caller needs, capped
at 512 characters like every tool error. The two serialization paths (the
result of a client call, and the final tool output) return `INTERNAL`, not
retryable, and output that is too large returns `OUTPUT_TOO_LARGE`. The uncoded
builder is gone: `tool_error` always takes a code.

The tool-server tests assert literal code strings rather than `error.code()`.
The `MvmError` tests pin each variant's code and retryability in a `match` with
no wildcard arm, so a new variant does not compile until its strings are
written down. The list of variants the tests iterate is produced by a second
wildcard-free `match` that names each variant's successor, so a new variant
also needs an arm there. The walk must reach `PINNED_VARIANTS` variants, the
count of `pinned`'s arms, and must include the retryable `Unavailable`. So a
walk that stops early fails, as long as that count is updated with the new arm.
These tests live behind `mvm-core`'s `client` feature; the workspace test run
enables it, and a single-crate run needs `--features client`.

Tests:

- `mvm-mcp`: two `capabilities()` classification tests, one per call site, that
  also check the backend's error text does not reach the caller. Literal codes
  on the seven per-variant tool tests and on the input-error and
  output-too-large paths. A test that a long backend message reaches the caller
  capped at 512 characters, and a unit test that a serialization failure maps
  to `INTERNAL`, not retryable.
- `mvm-core`: the variant walk visits each variant once.
- Resolver: refusal inside a detected project and beside an `mvm.toml`, the
  path-existence guard for both the registry and the tag marker, and positive
  and negative image-reference words.
- Flag refusal, through the two per-verb entry points the verbs call: each verb
  refuses the flag only it declares and passes the other's. Plus shared
  spellings, global flags, short clusters and attached values, `-ih`, unknown
  clusters, a standalone `--help`/`--version` passing through, flags deeper in
  argv, and the verb and flag kind in the message. A synthetic command covers
  hidden long and short aliases, since no `mvmctl` flag has one today.
- Three binary-level CLI tests:
  - `machine run -- --name web` and `run -- --image=alpine sh`: each verb
    refuses the flag.
  - `run --mode live -- --image=alpine`: the check runs before SDK dispatch.
  - `run -- node:22 index.js` beside a `package.json`: the image-reference
    refusal wins over detection.

Neither `INTERNAL` path can be reached end to end. Every client DTO derives
`Serialize` with string map keys, so `serde_json::to_value` of a client result
cannot fail. `serde_json::to_string` of the final `Value` cannot fail either.
The mapping from a client-result serialization failure to `INTERNAL` is
unit-tested; the `tool_success` branch for the final output has no test.
