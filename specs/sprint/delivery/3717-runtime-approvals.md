# #3717 — runtime approvals: `ask` held at the endpoint, answered by the operator

PS-07 (`specs/plans/2026-09-25-agent-sandbox-product-surface.md`). It builds on
the endpoint routes of PS-02, whose `ask` outcome refused until now.

## What landed

- **The supervisor lives in the endpoint.** `mvm_hostd::supervisor::runtime_approval`
  replaces the refusing egress approver. `ApprovalSupervisor` holds the flow,
  records the request in the contract's `ApprovalLedger` (one operator, the
  broker; capability `NetworkConnect` or `AgentInvoke`), asks the broker, and
  settles the ledger. Timeout (120 s), no broker, a broker error, a mismatched
  answer and a ledger refusal all deny. A prompt limiter lets at most 10
  questions a minute reach the broker; the rest deny `rate_limited` unasked.
  Session approvals are held in memory for 15 minutes, keyed by the question
  (for egress: route, rule, destination and method, not the path).
- **Audit.** A new `approval` recorder category chain-signs
  `approval.requested`, `approval.granted` (scope and answering backend),
  `approval.denied` (reason) and `approval.timed_out`, each with the request
  id. Guest-derived fields are length-bounded; the path is never recorded.
- **Secret use.** `SecretBindingMeta.approve` (`never` by default, omitted when
  `never`), set by `mvmctl secret set --approve ask` and shown by `secret ls`.
  The endpoint asks before substituting a header placeholder of such a
  secret toward a bound destination.
- **Broker transport.** The wire types (`ApprovalSubject`, `ApprovalPrompt`,
  `ApprovalAnswer`, `display_safe`) are in `mvm_contract::policy::approval_prompt`.
  The endpoint connects to `approval.sock` in the VM's socket directory
  (`mvm_core::config::vm_approval_socket_at`); the spawner passes the path,
  and Landlock grants the directory, since the broker binds after the endpoint
  confines itself.
- **Backends** (`mvm_client::approval_broker`): `ApprovalServer` (mode 0600,
  one prompt at a time, bounded lines), `DenyBackend`, `WebhookBackend`
  (HTTPS or loopback HTTP, never follows redirects, 4 KiB reply cap, timeout),
  `ChainBackend` (`all` / `any`), and `CallbackBackend` for an SDK callback.
  The terminal backend is in `mvm-cli` (`approval::tty`): `/dev/tty` opened
  `O_NOCTTY`, input flushed before and after an arming window, guest text made
  display-safe, `y` / `s` approve, anything else or silence denies, no TTY
  denies, an `-it` run denies `tty_busy`. `PromptRenderer` is the seam PS-04's
  live denials can share.
- **Surface.** `--approval tty|deny|webhook=URL` (repeatable) and
  `--approval-mode all|any` on `run` and `machine run`; `[approval]` in
  `mvm.toml`. The flag replaces the manifest; with neither, the terminal when
  an operator is at one, deny otherwise. The broker is bound for the
  foreground run (`crate::exec` after boot, and around an `--entrypoint`
  dispatch) and removed at teardown.
- **Docs.** New guide `guides/runtime-approvals`; the egress-policy and
  secrets guides, the CLI reference and ADR-003 updated.

## Tests

Supervisor: session TTL expiry, once scope, rate limit, timeout expiring the
ledger request, answer mismatch, field bounding, session-id legality, audit
entries. Terminal: arming-window and type-ahead discard, control/ANSI/OSC
stripping, empty / other / silent answers deny, no TTY and busy TTY deny.
Webhook: redirect, oversize reply, non-HTTPS, malformed and non-2xx replies,
silence past the timeout. Chain `all` / `any`, the broker socket lifecycle,
flag / manifest / default resolution, `[approval]` parsing, `secret set
--approve ask`, and endpoint route and secret-use approvals end to end through
the terminated-flow harness.

## Live verification (macOS 26, HVF)

- A `[[network.routes]]` rule `{ method = "POST", path = "/post", outcome = "ask" }`
  on `postman-echo.com`, answered by a loopback webhook that approves: `GET
  /get` (allow rule) 200, `POST /post` asked once and 200, `PUT /put`
  (otherwise) refused, with `curl -x socks5h://127.0.0.1:1080` (see Open).
  The webhook received one `egress` prompt carrying the
  route, `rule-2`, destination, method and path.
- A secret set with `--approve ask`: an approving webhook got one
  `secret_use` prompt and the destination received the real value; a denying
  webhook, and the non-interactive default with no `--approval`, both refused
  the request (502 to the guest). The chain carries `approval.requested`
  followed by `approval.granted` (`reason=webhook`) or `approval.denied`
  (`reason=webhook`, `reason=approval_policy_deny`).

## Open

- PS-13 tool calls: the `tool_call` subject exists; nothing asks it yet.
- SDK callback through hostlib: `CallbackBackend` is the type. Still needed: a
  hostlib ABI entry to register it, a broker per machine hostlib launches (a
  hostlib launch binds none today, so its asks deny), and the SDK facades.
- Detached and persistent machines have no broker, so their asks deny.
- When PS-02's injection modes land, secret-use approval must cover the new
  placeholder positions (query, path, basic auth), not only headers.
- Found while verifying, not caused here: a `--manifest` run whose manifest
  names an OCI `image` gets no guest proxy environment
  (`oci_vsock_proxy_env_for_backend` keys on `--image` only), so an unmodified
  client cannot reach an admitted route. The route test above passed the
  proxy to `curl` explicitly.
