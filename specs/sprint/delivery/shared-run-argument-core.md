# One argument core behind `run` and `machine run`

**Plan:** `specs/plans/329-run-first-cli-and-upstream-adoption.md`, Phase 1.

## What was wrong

The two run verbs each declared their own argument struct and `machine run`
converted into the other by hand. Twenty-one flags were spelled twice, and they
had drifted:

- `--profile` defaulted to `dev` on `machine run` and `standard` on `run`.
- `--agent-verb` and `--hypervisor` were real flags on `machine run` and
  `#[arg(skip)]` internals on `run`.
- `--flake`, `--flake-profile`, `--deployment` and `--runtime-pack` existed only
  on `machine run`; `--prod` — which selects production OCI policy, not just an
  SDK mode — existed only on `run`, so the beginner verb could not ask for a
  digest-pinned, verified image.

## The shape

`RunArgs` holds the 26 shared execution flags and is flattened into both verbs.
`run` adds `SdkTransportArgs` (`--mode`, `--dev`, `--ack-divergence`);
`machine run` adds the lifecycle flags (`--name`, `-d`, `--port`, `--ttl`,
`--tty`, `--entrypoint`, the healthcheck family, …).

This deviates from Plan 329's literal "one consolidated struct" wording, and the
plan now records why: a single struct hands `run` the whole lifecycle surface
and makes it a synonym for `machine run`, which contradicts the same plan's
"flagship one-shot" and re-creates the second-name-for-one-operation ADR-027
exists to forbid.

## Behaviour changes

- **`--profile` defaults to `standard` on `machine run`** (was `dev`). On the
  persistent machine-spec path `dev` admitted a writable `:rw` host share; the
  default now refuses at spec time with a message naming `--profile dev`. It
  fails closed and loudly rather than silently handing the guest a read-only
  mount it would fail to write to later. The transient path was already
  read-only under both profiles.
- **`machine run` gains** `--prod`, `--launch-plan`, `-m` as a `--manifest`
  short, and `--mount`'s `--volume` alias is now on both verbs.
- **`run` gains** `--flake`, `--flake-profile`, `--deployment`,
  `--runtime-pack`, `--agent-verb`, `--hypervisor`.
- **A bare `mvmctl run` now refuses at runtime, not at parse time.** `argv`'s
  `required_unless_present_any` could not survive the flatten: `machine run -d`
  legitimately boots with no command, and the attribute named `mode`/`dev`,
  which do not exist on the `machine` side. `run_transient` checks it and says
  what to type instead.

## Witnesses

`parsed_defaults_match_the_default_impl` and
`machine_run_parsed_defaults_match_the_default_impl` parse a bare invocation of
each verb and compare field by field against the hand-written `Default`, which
is what stops the impl and the `#[arg(default_value)]` attributes drifting. The
second also asserts the two verbs agree on `--profile`. Confirmed red by moving
the impl's `cpus` to 4.
