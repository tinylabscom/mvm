# #3713 — `--secret` on the run surface, scoped per binding

Part of PS-03 (`specs/plans/2026-09-25-agent-sandbox-product-surface.md`).
Supersedes draft #3333, whose first commit this ports onto current main.

## What was already there

The decision recorded for PS-03 was host TLS termination for plan-bound
destinations only. Most of that had already shipped while #3333 sat in draft:
CONNECT termination to a bound host (#3338), the per-VM name-constrained CA
delivered on the identity drive, and deletion of the listener-driven
terminator whose NIC and nftables premise no longer held (#3347). ADR-023's
mechanism section already described the vsock path. What was missing was a
way to reach it from the command line, and a guarantee that a placeholder is
good only where its own binding says.

## What landed

- **`--secret NAME[:HOST,...]`** on the shared `RunArgs`, so `mvmctl run`,
  `mvmctl machine run` (transient, persistent, and `--entrypoint`) all take
  it. The dead `up::Args` field is gone. Resolution lives in
  `mvm_client::admission::run_secrets` and reads metadata only: an unknown
  secret, a value-only secret, a destination outside the stored allow-list,
  two secrets handing over one variable, a flag shadowing a workload-declared
  variable, and a malformed spec (empty name or host, a port, a URL) all
  refuse before anything boots. A persistent machine records the references
  beside its spec and re-validates them on every start.
- **Guest variable naming** from a new `env_var` field on the service catalog
  (`anthropic` → `ANTHROPIC_API_KEY`, `openai`, `github`, `stripe`); an
  uncatalogued binding folds its own name. `mvmctl secret providers` shows it.
- **Destinations in the signed plan.** `SecretBinding` gained `destinations`
  (empty → the stored allow-list; non-empty narrows it and can never widen
  it). `mvm_core::crypto::secret_binding::plan_binding_hosts` is the one
  narrowing, and the substitution registry, the per-VM CA's name constraints
  and the checkpoint-fork audit all go through it. Before this, the host list
  a caller passed was checked at admission and then dropped: enforcement read
  the stored allow-list, so a narrowed run was not narrowed on the wire.
  Workload IR's own `allowed_hosts` now ride into the plan the same way.
- **A transient run's command now receives its placeholders.** The argv path
  built its environment before boot, and placeholders are minted at boot, so
  `run -- CMD` on a secret-bearing plan handed the command no placeholder and
  no trust-bundle variables at all (observed live: an empty variable). The
  command's environment now takes the host-provisioned egress environment
  (`mvm_hostd::workload_env::workload_egress_env`) once the endpoint has a
  session, ahead of the caller's explicit `--env`.
- **A body placeholder on a terminated flow is refused before the forward leg
  exists.** The terminator already holds the whole body; checking it there
  removes the window the streaming path has, where headers carrying the
  substituted credential can leave before the body scan trips.

## Witnesses

- `crates/mvm-hostd/src/supervisor/terminator/flow/tests/destination_scope.rs`:
  each destination receives only its own credential; a placeholder presented
  to another bound destination is refused and recorded as
  `secret.placeholder_dropped` with nothing forwarded; a placeholder in the
  URL (`placeholder_in_url`) or body (`placeholder_in_body`) is refused before
  forwarding; `x-api-key` is substituted like `authorization`; and, over the
  production forwarder against a real local TLS server, a verified upstream
  receives the real credential while one whose certificate does not chain to
  the trusted anchor receives not one request byte and the guest gets a 502.
- `keyholder::admission` tests: one placeholder per binding, each scoped to its
  own destinations; a widening plan binding refuses assembly.
- `secret_binding` tests: narrowing, refusal to widen, and the CA host set
  following the narrowing.
- `mvm-client` `admission::run_secrets` tests and the root `tests/cli.rs`
  integration tests for the pre-boot refusals and the help text.
- Unchanged and still covering the rest: an unbound CONNECT is spliced
  without termination (`an_unbound_connect_is_spliced_without_termination`),
  and a bound destination with no per-VM CA is refused rather than relayed.

## Live verification (macOS 26, HVF, 2026-09-25)

With two dummy secrets bound to `postman-echo.com` and `httpbin.org`,
`mvmctl run --image curlimages/curl:latest --secret … --allow-host … -- sh -c …`:

- the guest variable held `mvm-secret-<48 hex>`, and `SSL_CERT_FILE`,
  `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` were set;
- an unmodified `curl` to `https://postman-echo.com/headers` with its own
  placeholder got `200`, and the destination received the real dummy value;
- the same request with the other binding's placeholder got `502` —
  `destination postman-echo.com is not in the secret's allowed_hosts` — and the
  chain recorded `secret.placeholder_dropped`;
- a placeholder in the URL got `502` and `secret.flow_refused
  reason=placeholder_in_url`;
- `httpbin.org` failed closed with `502`: it does not offer TLS 1.3, which the
  forward leg requires;
- the chain carried `secret.substituted` / `secret.forward_outcome` for each
  send, and none of the entries contained the value.

One finding the change does not fix: the echo endpoint reflected the real
value back in its response body, so it reached the guest. That is recorded as
an open PS-03 box and as a stated limit in the agent-sandbox guide.

## Not in this change

Secret source references (`env://`, `file://`, `keychain://`, `op://`,
`bw://`), the provider route catalogue beyond variable names, `[secrets]` in
`mvm.toml`, and OAuth2 remain open under PS-03.
