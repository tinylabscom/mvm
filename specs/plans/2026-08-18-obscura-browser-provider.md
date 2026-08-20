# Obscura browser workload and SDK provider

Backing: shipped-source
Validation: check-sprint-append

**Status:** OPT-IN PILOT IMPLEMENTED — LIVE PROOF DEFERRED

Owner direction on 2026-08-18 first retained the plan only, then authorized the
pilot implementation on an isolated feature branch and draft PR. The provider
is not enabled by default and Chromium behavior remains unchanged.

## Goal

Evaluate [Obscura](https://github.com/h4ckf0r0day/obscura) as an optional
browser-automation runtime inside an mvm microVM, then—if the acceptance gates
are met—expose it through the Python and TypeScript `BrowserSandbox` helpers.

Obscura is not proposed as another host-side mvm utility. It is a guest
workload and CDP-speaking browser provider:

- Obscura and its V8 worker execute only inside the microVM.
- The host reaches CDP through mvm's loopback port-forwarding boundary.
- Browser egress remains subordinate to mvm's allowlist and audit path.
- Chromium remains the default. Obscura is explicit opt-in and never a silent
  fallback.

## Why consider it

Obscura offers a compact, browser-automation-oriented CDP service and is
packaged upstream for both supported Linux architectures. It may become useful
for isolated agent browsing where its smaller API surface and process model are
a better fit than a full Chromium image.

The tradeoff is compatibility. Obscura is experimental and is not a drop-in
implementation of every Chromium, Playwright, or Puppeteer behavior. The
integration must therefore be proven against real workflows before it becomes
more than an optional provider.

## Upstream pins

The researched pilot version is Obscura `v0.2.0`. Any future implementation
must re-verify these values against upstream before use.

| Artifact | URL/reference | SHA-256 |
| --- | --- | --- |
| `aarch64-linux` release | `https://github.com/h4ckf0r0day/obscura/releases/download/v0.2.0/obscura-aarch64-linux.tar.gz` | `8ac11fb7db704d2a5acfd917804e066b8f9a102f2f0a8eaef110322848e12565` |
| `x86_64-linux` release | `https://github.com/h4ckf0r0day/obscura/releases/download/v0.2.0/obscura-x86_64-linux.tar.gz` | `d601f4f542319c3b9fa8dca9f5ccfc134a2ca001648da528db5f03c9e6c2599b` |
| Multi-architecture OCI index | `docker.io/h4ckf0r0day/obscura` | `sha256:78c99ac89d010d444d96d85c183a2db912c41f807b7807d697df98ab7e4bd3c2` |

The release archives contain `obscura` and `obscura-worker`. Both are
dynamically linked glibc executables, so a Nix package must patch their
interpreters and include their runtime closure.

## Research findings

### Runtime posture

- Upstream's container command starts `obscura serve` on port `9222` and
  binds a wildcard address. An mvm integration must override this with
  `--host 127.0.0.1 --port 9222`.
- Obscura supports an explicit `--proxy` option (and its own proxy setting),
  but does not generally honor `HTTP_PROXY`, `HTTPS_PROXY`, or
  `ALL_PROXY`. The mvm guest proxy must therefore be passed explicitly.
- The researched command is:

  ```text
  /obscura --proxy http://127.0.0.1:1080 serve --host 127.0.0.1 --port 9222
  ```

- Caller command overrides must be rejected for this provider; otherwise a
  caller could restore the upstream wildcard bind or bypass the explicit proxy.
- Obscura's private-network override must remain disabled.
- Stealth mode is out of scope. This work is about isolation and browser
  automation, not evading anti-bot controls.

### mvm SDK prerequisites

The exploratory prototype found that the current live sandbox SDK cannot add an
OCI-backed provider honestly without first closing these general SDK gaps:

- A source string is treated as a manifest/template even when the caller means
  an OCI image. Live transports need a typed manifest-versus-image source.
- Accepted create options can be silently lost on the way to
  `mvmctl machine run`. Literal environment values and egress allowlists can
  be lowered; every unsupported field must fail before boot.
- Resource declarations cannot be partially lowered: the SDK resource type
  requires `rootfs_size_mb`, while the live CLI has no equivalent. Applying
  only CPU and memory would still be dishonest, so the whole resource option
  must fail in live mode until the surfaces converge.
- Secret-reference environment values must not be converted to plaintext CLI
  arguments.
- A provider needs an explicit boot command and a bounded CDP readiness
  contract. Timeout or startup failure must close the forwarder and stop the VM.
- Python and TypeScript should share a golden live argv fixture so their
  security posture cannot drift.

These are reusable live-SDK corrections, not Obscura-specific exceptions.

### Environment limits observed during research

- The available Linux builder VM was `aarch64` and had no `/dev/kvm`.
  It could evaluate and build the package/guest but could not produce a real
  Firecracker CDP lifecycle witness.
- Host Clippy and Linux cross-target checks completed, but the final
  builder-VM `cargo clippy --workspace --all-targets -- -D warnings` run was
  not completed. The minimal builder image intentionally omits Cargo; its
  on-demand Nix Rust/Clippy environment remained compute-bound for more than
  twenty minutes and was stopped.

## Proposed architecture

The intended data path is:

```text
host SDK/client
  -> mvm loopback port forward
  -> guest 127.0.0.1:9222 (Obscura CDP)
  -> Obscura explicit guest proxy
  -> mvm admitted egress gate
  -> allowlisted remote origin
```

There is no guest NIC bypass, wildcard CDP listener, host-loaded browser
library, or automatic Chromium fallback.

Two distribution paths are useful:

1. A Nix `mkGuest` example built from the architecture-specific release
   archives. This is the auditable workload path.
2. An SDK provider using the digest-pinned multi-architecture OCI index. This
   is the live-development convenience path.

They share an upstream version and security posture, but not identical artifact
bytes. Documentation must not imply otherwise.

## Proposed work

### WS0 — Research and decision record

- [x] Audit the upstream `v0.2.0` release archives, OCI image, default serve
      command, proxy behavior, license, and supported architectures.
- [x] Record immutable release hashes and the OCI index digest.
- [x] Prototype the guest workload and both SDK surfaces to expose integration
      gaps and collect validation evidence.
- [x] Remove the prototype at owner direction and retain this plan only.
- [x] Restore the pilot at owner direction as an explicit opt-in feature branch.

### WS1 — Reproducible guest workload

- [x] Add failing regression coverage for the version, architecture hashes,
      loopback CDP bind, explicit mvm proxy, private-network deny, and
      non-stealth posture.
- [x] Add `examples/obscura/` with a cross-architecture Nix package,
      `mkGuest` image, deny-by-default manifest, and focused README.
- [x] Evaluate and build the package and complete guest for each available
      Linux builder architecture.
- [ ] Boot on a real backend, complete `/json/version` through mvm forwarding,
      and prove teardown closes the host listener.

### WS2 — Honest live SDK execution

- [x] Add failing Python and TypeScript tests for manifest-versus-image
      selection and accepted-but-unrepresentable create options.
- [x] Introduce a typed boot-source representation at the live transport
      boundary.
- [x] Lower literal environment values and granular host allowlists through the
      existing CLI.
- [x] Reject secret refs, resources, and unsupported network/include/tag
      fields before any CLI process starts.
- [x] Add explicit boot-command support in record and live modes.
- [x] Add equivalent cross-language live argv tests.

### WS3 — Opt-in Obscura provider

- [x] Export one public constant for the digest-pinned OCI reference in each
      SDK.
- [x] Add explicit `obscura` provider selection with port `9222` and the
      fixed loopback/proxy command.
- [x] Reject caller command overrides before boot.
- [x] Add bounded, monotonic CDP readiness checks against
      `/json/version`; validate `webSocketDebuggerUrl`.
- [x] Tear down the VM and forwarder on startup failure or readiness timeout.
- [x] Preserve Chromium's existing source selection, behavior, and default.
- [x] Add provider tests for source selection, endpoint construction, option
      propagation, unknown provider, startup failure, timeout, and cleanup.

### WS4 — Live policy and compatibility proof

- [ ] Launch Obscura, create a CDP target, evaluate JavaScript, perform an
      allowed fetch, and capture a screenshot.
- [ ] Prove an unadmitted host is denied.
- [ ] Prove a private-network target is denied.
- [ ] Exercise malformed CDP traffic and a browser process that exits during
      startup.
- [ ] Run a small Playwright/Puppeteer corpus against both Obscura and
      Chromium; record unsupported behavior.
- [ ] Measure cold start, idle RSS, first page, and deterministic teardown.

### WS5 — Documentation and release gates

- [x] Document the trust boundary, upstream pin, compatibility limits,
      explicit opt-in, proxy path, egress policy, CDP exposure, and
      Apache-2.0 notices.
- [ ] Run formatting, workspace tests/check, Python tests, TypeScript
      tests/build/typecheck, gated target checks, and Linux all-target Clippy.
- [ ] Run Nix evaluation/package/guest builds for the supported architecture
      matrix.
- [ ] Run the real-backend positive and negative BDD scenarios.
- [ ] Update this plan, `specs/SPRINT.md`, and
      `specs/REFACTOR-STATUS.md` only as tested implementation lands.

## Pilot evidence

The restored pilot has current branch coverage for its packaging, SDK, and
lowering boundaries:

- Nix flake evaluation, pinned Obscura package, and complete `aarch64-linux`
  guest build: passed in the project builder VM.
- Python SDK: 229 passed, 7 skipped.
- TypeScript SDK: 149 passed; build passed.
- Rust SDK: 282 unit tests plus integration and documentation tests passed.
- Obscura example contract: 3 passed.
- Host `mvm-sdk` + `mvm-cli` all-target Clippy with warnings denied: passed.
- Linux/BDD feature-gated cross-target checks: passed.
- Workspace test run reached one unrelated parallel environment race in
  `doctor::toolchain::tests::check_cmd_rustup_on_host`; the failing test passed
  when rerun in isolation.
- Linux builder-VM all-target Clippy: not completed for the environment reason
  recorded above.
- Real microVM/CDP policy witness: not run because the available builder VM had
  no `/dev/kvm`.

The real-backend, compatibility corpus, complete workspace, Nix matrix, and
native Linux all-target gates remain intentionally open. This pilot must not be
presented as production-ready until those witnesses exist.

## Security acceptance criteria

- The host never loads or executes Obscura, V8, or an Obscura extension.
- CDP binds guest loopback and is forwarded only to host loopback.
- Browser traffic uses the explicit guest proxy and mvm's admitted egress gate.
- No private-network override or stealth behavior is enabled.
- The provider image is immutable by digest; mutable tags are refused.
- Unknown sources, unsupported live options, command overrides, missing proxy
  configuration, and readiness failures fail closed before exposure.
- Logs and errors contain no page content, cookies, authorization headers,
  proxy credentials, secrets, or CDP payloads.
- Timeout and startup failure leave no VM or forwarding process behind.

## Definition of done

- Both SDKs expose equivalent opt-in semantics and Chromium remains unchanged.
- The pinned guest builds for supported architectures.
- Positive and negative policy scenarios pass on a real mvm backend.
- The compatibility corpus is documented without silent fallback.
- Workspace, SDK, gated-target, Nix, BDD, formatting, and Linux all-target
  Clippy gates are green.
- Sprint and refactor rollups are updated in the same tested implementation
  change.

## Resume decision

The pilot may be reviewed and iterated on this feature branch. Do not promote
Obscura beyond explicit experimental opt-in until an approved real backend
produces the CDP/policy witness, the compatibility corpus is recorded, and the
complete Linux/Nix gates pass.
