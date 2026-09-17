# Agent-facing failures: stable error codes, and a misplaced-image-reference hint

The MCP tool server reported every failure as plain text; an automated caller
had to parse English to know whether a request was worth retrying.
`MvmError` now carries its own classification (`code() -> &'static str`,
`retryable() -> bool`), one mapping shared by every surface: `NOT_FOUND`,
`INVALID_SPEC`, `BACKEND_ERROR`, `UNAUTHORIZED`, `CONFLICT`, `REJECTED` are
not retryable; `UNAVAILABLE` is. `mvm-mcp`'s `ToolFailure::Backend` now
carries the typed error instead of a pre-formatted string, so `tool_error`'s
`_meta` gains `code` and `retryable` alongside the existing server keys.
Failures that never reach an `MvmError` — bad tool arguments, an unknown tool
— get the documented generic `INVALID_INPUT` / non-retryable pair instead of
going unclassified.

Separately, `mvmctl machine run app:1.0 -- sh` treated the image reference as
the guest's command with no hint, because `RunArgs`'s trailing-var-arg argv
never gets reinterpreted once resolution falls through to the bundled
default. `resolve_run_source` (shared by `run` and `machine run`) now refuses
a first argv word that reads as an OCI image reference — a tag or digest
colon, or an explicit registry host before a `/`, and not a path — once no
source flag was given and nothing was detected, naming `--image <ref>` as the
fix. The same function also refuses a known `RunArgs` flag (`--image`,
`--net`, …) placed as the very first word after `--`, reading the flag list
from clap's own `Command` definition rather than a hand-kept copy; only
position 0 is checked, so a workload legitimately forwarding a same-named
flag deeper in its own argv is untouched.

Tests: seven MCP tool-server tests (one per `MvmError` variant) plus one for
the generic input-error code; two `MvmError::code`/`retryable` unit tests; ten
CLI unit tests covering the image-reference hint (positive, full-inference
fallback, an explicit-source bypass, and a four-command negative list) and
the flag-after-`--` refusal (positive, a deeper-argv non-trigger, and an
unrecognised flag-shaped word). Full `mvm-core`, `mvm-mcp`, `mvm-cli`, and
root `mvmctl` suites pass (4,626 tests), along with `cargo fmt --all`,
`cargo clippy --workspace --all-targets -- -D warnings`, and doctests for the
touched crates.
