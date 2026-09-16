# Claude Code as an mvm workload

Backing: preview
Validation: none

Run an instance of Claude Code (Anthropic's CLI coding agent) inside an mvm
microVM: interactively for a sandboxed dev workbench, and headlessly as a
sealed batch workload. This plan is a design; nothing in it is enforced yet.

## Why this is close, and where it is not

Most of the substrate already exists and was verified against the tree on
2026-09-15:

- `public/src/content/docs/guides/nix-flakes.md` §"Running an LLM agent
  inside a microVM" already sketches a `mkGuest` flake with
  `entrypoint.command = [ "${pkgs.claude-code}/bin/claude" ... ]`, and
  `public/src/content/docs/tutorials/coding-agent.md` walks the
  build/run/exec loop.
- The guest environment is already TUI-ready: the agent console is a real
  `openpty(3)` PTY over vsock with SIGWINCH resize forwarding and
  `TERM=xterm-256color` (`crates/mvm-agentd/src/console.rs`,
  `crates/mvm-cli/src/commands/vm/console.rs`).
- Egress env is already injected Node-aware: `HTTPS_PROXY`/`ALL_PROXY` at the
  in-guest loopback proxy (`crates/mvm-core/src/guest_netd.rs`), and
  `NODE_EXTRA_CA_CERTS` when a per-VM egress CA is provisioned
  (`crates/mvm-cli/src/commands/vm/invoke.rs`). Claude Code documents support
  for exactly these variables (HTTP CONNECT proxying, custom CAs).
- `api.anthropic.com` is already first-class: the `anthropic` secret provider
  binding (`crates/mvm-contract/src/service_catalog.rs`), the AI meter's
  Anthropic usage parsing (`crates/mvm-hostd/src/supervisor/ai_meter.rs`), and
  the `Dev` network preset's allow entry
  (`crates/mvm-contract/src/policy/network_policy.rs`).
- Claude Code itself needs little: the native distribution is a
  self-contained binary (arm64 and x64, musl builds exist), headless auth is
  `ANTHROPIC_API_KEY` with no browser, and every non-API endpoint
  (telemetry, updater, plugins) is optional and disable-able by env var. The
  minimum egress is one host: `api.anthropic.com:443`.

Three constraints shape everything below. They are facts of the current
tree, not choices this plan gets to make:

1. **No writable host-directory share exists.** A transient run refuses
   `--mount HOST:GUEST:rw` on a directory
   (`crates/mvm-cli/src/commands/vm/exec.rs`, the transient-snapshot bail),
   a persistent machine refuses directory shares outright
   (`crates/mvm-cli/src/commands/machine/mod.rs`,
   `build_machine_volume_cfg`), and virtio-fs is being removed
   (`specs/plans/2026-08-31-remove-virtio-fs.md`,
   `specs/plans/2026-09-02-retire-dirshare.md`). The workspace Claude Code
   edits must live on a sized ext4 disk volume (`HOST:/GUEST:SIZE:rw`) or a
   managed machine volume, with `machine cp` / `machine fs` for host-side
   round-trips.
2. **The API key is in guest memory, for now.** Egress-substitution fires
   only on typed absolute-form HTTP through the forward proxy; a stock HTTPS
   client's `CONNECT` is opaque TCP relay with TLS end-to-end, so no shipping
   path injects the Anthropic header host-side
   (`public/src/content/docs/guides/config-secrets.md`: "Guest HTTPS CONNECT
   egress is not a substitution path"; ADR-023's transparent terminator is
   unwired — `terminator_listen` is `None` at every production call site).
   The interim posture is the documented manual pattern: key file mounted
   read-only, guest holds it. Getting the key out of the guest is in scope —
   it is W5, and it lands after the workload itself runs, not before.
3. **Interactive means dev-tier, by construction.** Console/exec/fs verbs are
   `RequestClass::DevOnly` and `enforce_accessible_gate` refuses a sealed
   image with no `--force` bypass (claim 15). An interactive Claude Code VM
   is an accessible, `--profile dev` artifact; the sealed lane is headless
   `claude -p` only. The plan treats these as two deliberate lanes rather
   than fighting the gate.

## Design

One example flake, two profiles off it, shipped as an example first and a
remote template second.

### Lane A — interactive workbench (accessible, dev-tier)

- `mkGuest` with `entrypoint.shell`, run as `machine run --flake . --name
  claude -d --profile dev`, attach with `mvmctl machine console claude` (or
  `machine exec claude -it -- claude`). `machine run -it` is foreground-only
  and one console session exists per VM; the persistent `-d` + console shape
  is the primary UX.
- Claude Code binary baked at image build (see "Packaging"), launched inside
  the console session so it inherits the PTY, `TERM`, and the injected proxy
  env.
- Workspace: a sized rw disk volume mounted at `/data/work`; agent state
  (`~/.claude`) persisted by pointing `CLAUDE_CONFIG_DIR` at a directory on
  the same volume, because guest `$HOME` is tmpfs and vanishes on stop
  (`crates/mvm-agentd/src/guest_mount.rs`).
- Network: `--allow-host api.anthropic.com:443` plus
  `platform.claude.com:443` (the interactive mode's startup key check —
  W0 finding). The image sets
  `DISABLE_AUTOUPDATER=1`, `DISABLE_TELEMETRY=1`,
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` so nothing wants the
  endpoints we refuse, instead of widening the allow-list. Optional wider
  variant (npm registry, github) documented for users who ask Claude Code to
  install packages, following the obscura example's fail-loud proxy guard
  (`examples/obscura/flake.nix`).
- Key, interim: `--mount ~/.mvm/config/secrets/anthropic:/data/secrets:ro`
  and `ANTHROPIC_API_KEY` read from that file by the entrypoint wrapper —
  the pattern the nix-flakes guide already documents, stated honestly as
  guest-held. Key, destination: the W5 placeholder posture below; the
  example README labels which mode a given invocation is using.
- Metering for free: `[network.ai] metering = true` in `mvm.toml`; the AI
  meter already recognises Anthropic on the typed path, and token budget
  refusal semantics come with it.

### Lane B — headless batch (sealed-capable)

- Same flake, second profile: `entrypoint.command` wrapping
  `claude --bare -p --output-format stream-json`, task text delivered via
  `machine run --entrypoint --stdin -` (the claim-17 input plane; stdin is a
  byte pipe, which is exactly what `-p` mode wants — no TTY needed).
- `--bare` skips discovery and never touches OAuth/keychain, so the only
  inputs are the key file, the stdin task, and the workspace volume; output
  leaves via the console log and the exit-code path.
- This lane is the one that can eventually run `--prod` (digest-pinned,
  sealed, claim 8/15 clean). Resource bounds via `--cpu-limit` / `--memory`
  ride the existing preview-claim-18 admission ceiling unchanged.

### Packaging

Priority order, resolved by the W0 spike:

1. `pkgs.claude-code` from the pinned `nixos-25.11` — if it evaluates and is
   current enough, the entrypoint is one line.
2. The native-installer binary fetched as a fixed-output derivation +
   `autoPatchelfHook` (the obscura example is the model for third-party
   binaries).
3. `buildNpmPackage` + `importNpmLock` over a two-line `package.json`
   pinning `@anthropic-ai/claude-code`, the same mechanism
   `crates/mvm-sdk/src/compile/flake.rs` emits. If this path is taken,
   shebangs must be stamped to store paths — the workload rootfs has no
   `/usr/bin/env` (`nix/lib/factories/languages/registry.nix` records why).

Runtime deps in `packages`: `bash`, `ripgrep`, `libgcc`/`libstdc++` per
Claude Code's Alpine notes, and git — **which is the likeliest build-time
failure**: `mkGuest`'s transitive closure grep refuses anything matching the
SSH needle set (`nix/lib/mk-guest.nix`, `assertNoSshClosureScript`), and
nixpkgs `git` plausibly carries `openssh` for the `git+ssh://` transport.
W0 settles this with `nix why-depends`; the fallback ladder is `gitMinimal`,
an override severing the ssh transport, or shipping HTTPS-only git and
saying so.

The SDK-compile path (`mvmctl build compile`) is explicitly not used: its
`mkFunctionService` shape is a module+function RPC contract with a 1 MiB
stdin cap, structurally wrong for a long-lived CLI. Its npm plumbing is
reused via mechanism 3 only.

### Distribution

`examples/claude-code/` (flake + `mvm.toml` + README) lands in-repo first,
under the same doc-example gates as the existing examples. Once stable, a
`claude-code` entry goes to the `tinylabscom/mvm-templates` remote registry
(`crates/mvm-cli/src/template_registry.rs`) — the intended extension point,
no mvmctl code change, scaffolded by `mvmctl init <DIR> --catalog` users
notwithstanding (the bundled catalog and runtime catalog stay untouched; a
security-relevant default should not gain entries casually, per the runtime
catalog's own header note).

## Workstreams

### W0 — spike and de-risk (no shipped artifacts)

- [x] Zero-authoring smoke: `mvmctl run --runtime node --allow-host
      api.anthropic.com:443 -- npx @anthropic-ai/claude-code --bare -p "…"`
      (node:22-alpine is musl; Claude Code documents musl support). Records:
      does the CONNECT tunnel carry the API traffic, does the `standard`
      seccomp/profile tier admit Node + the agent, what breaks. All ran on
      real HVF VMs — see findings below.
- [x] git↔openssh against the `nixos-25.11` pin (settled by source
      inspection at the locked rev — host nix absent); pick the git
      mitigation. See findings below.
- [x] Resolve packaging option 1 vs 2 vs 3 (does `pkgs.claude-code` exist in
      the pin, and does the npm package's platform-binary layout survive
      `importNpmLock`). See findings below.
- [x] Interactive smoke: TUI (raw mode, resize, colors), Ctrl-C forwarded
      as a byte, a real API turn — passed by hand on 2026-09-15 via
      `machine run -it` on the npx lane (see findings). Still open, folded
      into the W2 live scenario: the same checks under `machine console`
      on a persistent machine, and idle-reaper interplay — a long
      "thinking" pause under an attached console must not trip
      `MVM_TIMEOUT`/`--ttl` teardown
      (`crates/mvm-hostd/src/supervisor/reaper.rs`, `touch_activity`).
- [x] Findings recorded as `.agent-memory/notes/` entries plus a short
      findings section appended to this plan (interactive-console smoke
      still open above — it needs a human terminal).

#### W0 findings, research half (2026-09-15)

Environment: the flake pins `nixos-25.11`, locked rev `8fd9daa3db09`
(2026-05-06). Detail lives in `.agent-memory/notes/` (local); the
load-bearing conclusions:

- **Git needs no mitigation.** At the pin, git's derivation takes
  `withSsh ? false` and only `gitFull` turns it on — `pkgs.git` and
  `gitMinimal` carry no openssh runtime reference, so the closure ban is
  not in play. Use `gitMinimal` (also drops perl/manual/pcre2). curl's
  `scpSupport` puts `libssh2` in the closure, and that matches neither ban
  arm: the closure regex anchors right after the store hash
  (`-(openssh|dropbear|ssh|...)(-|$)`) so `-libssh2-` does not match, and
  the eval-time "ssh" substring check reads declared package labels, not
  the closure.
- **Packaging verdict: option 2, the fixed-output native binary,
  `linux-arm64-musl`.** `downloads.claude.ai/claude-code-releases/` serves
  `{latest|stable}` → version, `{version}/manifest.json` → first-party
  SHA-256 + size per platform, `{version}/{platform}/claude` → the binary;
  live-verified for 2.1.273. The musl artifact is a dynamically linked
  aarch64 ELF whose only need is musl's own loader
  (`/lib/ld-musl-aarch64.so.1`, supplied by `pkgs.musl` or patchelf) — no
  glibc, no nodejs in the image closure. Pin version + checksum in-repo.
- **Option 1 exists but is stale**: `pkgs.claude-code` at the pin packages
  2.1.81 (2026-03-20) against a `latest` of 2.1.273 (2026-09-15), is
  unfree (the consuming flake's pkgs import needs `allowUnfree` — guest
  `packages` come from the user flake's own pkgs, so the switch goes
  there), and drags nodejs into the closure. `pkgs.claude-code-bin` at the
  pin fetches the **glibc** arm64 artifact, same stale version. Acceptable
  fallback, not the default.
- **Option 3 (`importNpmLock`) is the fragile path**: the current npm
  package is a thin installer — empty deps, a `postinstall` that runs
  `install.cjs`, per-platform binaries as libc-filtered
  `optionalDependencies` — exactly the shape npm-lock-based Nix builds
  handle worst. Avoid.

#### W0 findings, smoke half (2026-09-15)

All on real HVF VMs on macOS 26 Apple Silicon, `--runtime node`
(node:22-alpine, v22.23.2). Detail in
`.agent-memory/notes/node-runtime-anthropic-egress-smoke.md` (local).

- **Allowlisted connectivity holds, with one required env var.** Node's
  fetch (undici) ignores the injected `HTTPS_PROXY` by default and dials
  direct (`ENETUNREACH` — vsock-only guest, no route). With
  `NODE_USE_ENV_PROXY=1` (honored by node ≥22.18) the same fetch returns
  STATUS 401 `authentication_error: x-api-key header is required` from
  `api.anthropic.com` — DNS, CONNECT tunnel, and TLS all carried through
  the egress gate. The example flake must bake `NODE_USE_ENV_PROXY=1`
  alongside the telemetry-disable vars.
- **Default-deny surfaces as policy, immediately.** A non-allowlisted
  fetch gets `403 Forbidden` from the proxy with no timeout. Undici
  renders it opaquely as `Request was cancelled` — a UX caveat for the
  README, not a blocker.
- **The zero-authoring npx lane works end to end.** With
  `registry.npmjs.org:443` added, `npx -y @anthropic-ai/claude-code@latest
  --version` prints `2.1.273 (Claude Code)` in 27s including boot and the
  ~221 MB musl platform package (npm honors the injected proxy natively;
  the install needed no `downloads.claude.ai`). `--bare -p "say hi"` exits
  1 with `Not logged in` — the expected no-credential refusal, no hang.
  Used `--memory 2G`: the npx cache lives on tmpfs and the default 512M
  is plausibly too small (floor unprobed). The two-host allow-list is
  sufficient for this lane.
- **No `standard`-tier seccomp refusals** were hit by node, npm, or the
  Bun-compiled Claude Code binary; no `--profile dev` delta to report.
- **W5-relevant**: `NODE_EXTRA_CA_CERTS` is unset on this path — no
  per-VM egress CA was provisioned because no substitution service was
  assembled. The terminator option's guest-trust half is therefore only
  present when secrets are actually bound.
- **Interactive TUI: passed by hand** (2026-09-15, `machine run -it`,
  npx lane, real API key). Rendering, resize reflow, Ctrl-C-as-keystroke,
  and a live API turn all behaved. One more endpoint surfaced: the
  interactive mode checks the key against the Console at startup, and the
  refused host renders in-UI as "Unable to connect to Anthropic services
  … Status 403" — so the interactive lane's minimum allow-list is
  **three** hosts (`api.anthropic.com:443`, `platform.claude.com:443`,
  plus `registry.npmjs.org:443` for the npx lane only), with
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` baked in so optional
  traffic never hits the deny wall. The headless `--bare -p` lane was not
  observed needing the Console host; verify before widening Lane B.
- Transient runs self-cleaned (no stray VM state, supervisors, or
  endpoints). Host setup friction worth knowing: a rebuilt `mvmctl` needs
  `mvmctl env sign` before HVF boots it, and `just toolchain-embed`'s
  `rustup target add` step can fail under mise-managed rustup (manual
  re-run worked). Cold first run ~6m (Stage 0 + supervisor build); warm
  runs ~1s.

### W1 — the example flake

- [x] `examples/claude-code/` with one flake, two profiles (interactive
      shell entrypoint; headless `--bare -p` command entrypoint), the
      obscura-style `${ALL_PROXY:?...}` fail-loud guard, the
      telemetry-disable env baked in, and `mvm.toml` carrying the
      three-host allow-list + `[network.ai] metering = true`. Both
      profiles built through the builder VM on 2026-09-15; the sidecars
      came out to spec (interactive: accessible shell tier; headless:
      `sealed: true`, `accessible: false`, recorded `claude --bare -p`
      argv).
- [x] README covering: launch both lanes, workspace-volume recipe,
      key-file mount, state persistence via `CLAUDE_CONFIG_DIR`, getting
      results out (`machine cp`), and the honest secrets posture (guest
      holds the key; the plan's W5 is the destination state).
- [x] Whatever gate covers examples today covers this one: `examples/`
      markdown is inside the s29 doc-example corpus, so every README
      command is parse-gated against the real clap tree and recorded in
      `docs_coverage.toml`; the mkGuest-attribute scenario checks the
      flake's call. (Image builds stay local/live-lane; the hermetic suite
      does not build flakes.)

#### W1 findings (2026-09-15)

- A non-default flake profile is addressed as `packages.<system>.
  tenant-<name>` (`mvm_build::pipeline::dev_build`); only `default` is
  bare. The example's headless output is `tenant-headless`, selected as
  `--profile headless` / `--flake-profile headless`.
- The doc-example coverage ledger
  (`features/suites/s29_doc_examples/docs_coverage.toml`) is regenerated,
  not hand-edited: any doc change that adds an `mvmctl` command needs
  `MVM_UPDATE_DOCS_COVERAGE=1` through the conformance suite in the same
  change.

### W2 — runnable end-to-end tests

Per AGENTS.md, no workstream is done without tests. The mounted-PTY plan
(`specs/plans/2026-09-01-mounted-pty-image-environment.md`) is the model:

- [x] A live BDD scenario (opt-in lane, like the Rust-image PTY scenario):
      boot the example, attach the console, run a command that touches the
      workspace volume, assert egress to a non-allow-listed host is refused
      as policy (not unreachable), assert `api.anthropic.com:443` is
      admitted at the gate (stub upstream; no real API call in CI).
      Landed as `features/suites/s34_claude_code/claude_code_workbench.feature`
      (steps in `crates/mvm-conformance/tests/steps/claude_code.rs`);
      see the W2 findings for what the console/reaper half became.
- [x] A non-live test for the headless lane: sealed-profile admission of the
      command entrypoint with `--stdin`, and refusal of the console on the
      sealed variant (rides the existing claim-15 witnesses; add coverage
      only where this example's shape isn't already covered).
      `a_sealed_sidecar_recording_the_headless_agent_argv_admits_the_stdin_route`
      (`crates/mvm-cli/src/commands/vm/up/admission.rs`) and
      `console_refused_on_a_sealed_sidecar_derived_meta`
      (`crates/mvm-cli/src/commands/vm/console.rs`).

#### W2 findings (2026-09-15)

- **Egress assertions ride raw `CONNECT` against the guest's loopback
  proxy** (`bash` `/dev/tcp`, no curl in the image closure). The FlowMux
  egress proxy answers a policy-refused target `403 Forbidden` and an
  admitted-but-unreachable upstream `502 Bad Gateway`
  (`crates/mvm-agentd/src/flowmux_egress.rs`), so the two failure shapes
  are distinguishable on the first response line — `403` is the refusal
  shape asserted, `200 Connection established` is admitted-at-the-gate
  with the upstream connect completed and no API byte sent. No credential
  is involved anywhere in the scenario.
- **The idle-reaper interplay cannot be a live assertion.** The reaper
  (`crates/mvm-hostd/src/supervisor/reaper.rs`) is an unconsumed primitive
  in local `mvmctl` — nothing outside tests constructs one, so no process
  exists whose (non-)teardown a live scenario could observe. What the code
  does support: a console attach calls `touch_activity`, which stamps
  `last_active` on the name-registry entry — the exact input
  `idle_elapsed` prefers — and the "recent activity is not idle" half is
  already unit-covered (`sweep_does_not_sleep_when_not_yet_idle`,
  `idle_elapsed_prefers_last_active_then_registered_at`,
  `touch_activity_refreshes_last_active_for_registered_vm`). The live
  scenario asserts the remaining wiring: a real console attach on the
  workbench machine refreshes the registry stamp. Caveat worth carrying to
  any future resident reaper: `touch_activity` fires once at attach, not
  during a quiet attached session, so a long "thinking" pause would still
  age past an idle timeout under a consumer that arms one.
- **The console leg is the one-shot form** (`machine console <name>
  --command`), which shares the accessible gate, transport pick, and
  activity touch with the PTY loop; the interactive PTY loop itself blocks
  on a terminal and stays hand-validated (W0) plus covered by the
  `machine run -it` PTY scenarios in s31.
- **The sidecar→gate chain had no witness.** The input-grant tests
  hand-build `ResolvedEntrypoint` and the claim-15 tests hand-write
  `VmRuntimeMeta`, so a break in `GuestSidecar` → `resolve_for_rootfs` /
  `from_sidecar` → gate was invisible to all of them. The two new tests
  run the example's exact artifact shape (sealed sidecar, recorded
  `claude --bare -p` argv) through those chains. Known limit, restated
  from claim 17's ledger row: the recorded argv names the `claude`
  wrapper, which is a shell script inside an ext4 the host never opens;
  classification sees only the argv basename (`shebang` is always `None`
  from the sidecar resolver), so admission rests on "argv is not
  shell-shaped", not on what the wrapper execs.

### W3 — doc repairs this work uncovered

- [x] `public/src/content/docs/guides/nix-flakes.md` LLM-agent section: the
      `--mount "$PWD:/work:rw"` recipe cannot work (directory `:rw` is
      refused); rewritten onto a registered secrets volume + sized
      workspace disk.
- [x] `public/src/content/docs/guides/config-secrets.md`: the persistent
      `--mount …:ro` directory example hits the same persistent-machine
      bail; rewritten onto a transient run plus the two working
      persistent shapes.
- [ ] `crates/mvm-contract/src/policy/network_policy.rs` `agent_rules()` doc
      comment cites `nix/images/examples/llm-agent/`, which does not exist;
      point it at `examples/claude-code/` once W1 lands (keeping the
      no-spec-refs-in-source-comments lint happy).
- [ ] `public/src/content/docs/tutorials/coding-agent.md` gains the
      interactive lane and links the example.

### W4 — remote template

- [ ] `claude-code` entry in `tinylabscom/mvm-templates` (`template.toml`,
      `flake.nix`, `index.json` row with an `mvm_version` floor), mirroring
      the shipped example.
- [ ] Note for the security backlog: template fetch is unsigned text
      download (`fetch_and_cache_remote_template`); this plan does not fix
      that, but shipping a credential-adjacent template makes it worth a
      line in the open-work register.

### W5 — the guest never holds the key

Goal: `ANTHROPIC_API_KEY` inside the guest is a minted `mvm-secret-<hex>`
placeholder; the real key exists only in the per-VM `mvm-network-endpoint`
(already built as the single plaintext-secret holder, Landlock/seccomp
self-confined) and is inserted host-side on the way out. Starts after W0;
does not block W1–W3, which ship on the interim key-file posture.

The pieces that already exist, which is why this is wiring rather than new
architecture:

- The endpoint mints placeholders and hands `(guest_var, placeholder)` pairs
  back for launch-env injection
  (`crates/mvm-hostd/src/bin/mvm-network-endpoint.rs`), and
  `refuse_secrets_without_substitution` fails closed.
- Substitution fires on typed HTTP flows: absolute-form requests into the
  in-guest forward proxy (`crates/mvm-agentd/src/forward_proxy.rs`), host
  originates the real upstream TLS.
- The `anthropic` provider binding ships
  (`mvmctl secret set NAME --provider anthropic` →
  `api.anthropic.com`, bearer).
- Claude Code honors `ANTHROPIC_BASE_URL` and standard proxy env, so its
  API traffic can be steered onto the typed path without patching it.

Work:

- [ ] A reachable CLI surface binding a managed secret to a run: `--secret
      NAME` exists only on the unreachable `up::Args`
      (`crates/mvm-cli/src/commands/vm/up/mod.rs`); land it on the reachable
      `RunArgs` surface (move, don't fork) with the same
      destination-binding semantics.
- [ ] Steer Claude Code onto the typed path: guest env `ANTHROPIC_BASE_URL`
      plus proxy env aimed at the loopback forward proxy so requests arrive
      absolute-form, with `ANTHROPIC_API_KEY` set to the placeholder.
      Verify substitution replaces the placeholder in the header position
      Claude Code sends (`x-api-key` / `Authorization`), not only in
      catalog-templated positions.
- [ ] Streaming: Claude Code consumes SSE responses. The AI meter parses
      Anthropic `message_delta` events on this path
      (`crates/mvm-hostd/src/supervisor/ai_meter.rs`), which points to the
      typed flow carrying streamed bodies — verify end-to-end latency and
      incremental delivery through the substitution relay
      (`crates/mvm-agentd/src/substitution_client.rs`), and fix if the wire
      shape buffers whole bodies.
- [ ] Fallback, only if the typed path cannot carry this traffic: wire
      ADR-023's TLS terminator for CONNECT flows at the endpoint (the guest
      already trusts the per-VM egress CA via the injected
      `NODE_EXTRA_CA_CERTS`; the ADR's nft-redirect premise is stale now
      that guests have no NIC, so the endpoint's CONNECT handler is the
      interception point). Decide one mechanism; do not build both.
- [ ] Tests: the guest launch env carries the placeholder shape and never
      the raw key; an unbound destination is refused at the endpoint; a
      request to a bound destination completes with the substituted header;
      the live scenario finishes a real API turn with the raw key absent
      from guest env, the workspace volume, and the console log. Extends
      the claim-13 witness family; the ADR-001 row is not renamed here.
- [ ] Ledger note: claim 13's row covers the broker channel; this lane
      widens practical containment to the workload's own API traffic.
      Whether that becomes new ledger prose is a maintainer decision —
      raise it, do not edit ADR-001's table unilaterally.
- [ ] Once landed: flip the example + template default to the placeholder
      posture, demote the key-file mount to a documented offline fallback,
      and update the W3 doc touchpoints in the same change.

## Acceptance

- `mvmctl machine run --flake examples/claude-code --name claude -d
  --profile dev --allow-host api.anthropic.com:443 --mount
  workspace.img:/data/work:8G:rw --mount <keyfile>:/data/secrets:ro` boots;
  `mvmctl machine console claude` yields a working Claude Code TUI that can
  edit files on the workspace volume and complete a real API turn.
- The headless profile completes a `--stdin`-fed task under a sealed image
  and exits with the task's status; the console verb on that VM is refused.
- Egress to any host outside the allow-list surfaces as a policy refusal.
- With W5 landed: the same interactive session completes an API turn while
  the guest env holds only the placeholder, and `mvmctl machine exec` +
  `machine fs` sweeps of env, volume, and console log find no raw key
  material.
- `just ci` green, the live scenario green in its opt-in lane, doc gates
  (`check-doc-claims`, `check-declared-backing`, `check-plan-names`) green.

## Out of scope, named so nobody trips on it

- **Durable agent sessions integration**: `mvmctl agent-session
  park/resume`, checkpoints, and warm claims are natural follow-ons for
  long-lived Claude Code sessions but are bookkeeping-only today; nothing
  here depends on them.
- **Fleet/mvmd**: single-host `mvmctl` only.
- **Auto-detection**: no runtime-catalog or bundled-catalog entry; explicit
  flake/template invocation only.
