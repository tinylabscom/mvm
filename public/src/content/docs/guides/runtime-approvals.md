---
title: Runtime approvals
description: How an endpoint rule or a secret binding set to `ask` pauses a request until you approve it — on your terminal, through a webhook, or not at all — and what is recorded.
---

Some requests should be neither always allowed nor always refused. An endpoint
rule whose outcome is `ask`, or a secret bound with `--approve ask`, holds the
request on the host until someone answers. The guest waits on an open
connection; it is never told there is a question, and it cannot answer one.

```toml
# A route in mvm.toml: reads are fine, filing an issue needs a yes.
[[network.routes]]
id = "github"
host = "api.github.com"
intercept = true
rules = [
  { method = "GET", path = "/repos/my-org/**", outcome = "allow" },
  { method = "POST", path = "/repos/my-org/*/issues", outcome = "ask" },
]
```

```sh
mvmctl run --manifest ./mvm.toml -- ./triage.sh
```

```text
── mvm: approval needed (egress) ──
  request   POST api.github.com:443/repos/my-org/app/issues
  route     github (rule-2)
  expires   in 120s
Allow? [y] once, [s] this session, [N] no:
```

## Where the question is asked

The per-VM network endpoint makes the decision. When a rule says `ask` it holds
the flow and puts the question to the approval socket in the VM's socket
directory. The `mvmctl` that launched the run listens on that socket for as long
as the run is in the foreground, and answers with the backends you chose:

| Backend | `--approval` | What it does |
| --- | --- | --- |
| Terminal | `tty` | Asks on the controlling terminal (`/dev/tty`) of the `mvmctl` process. |
| Webhook | `webhook=URL` | POSTs the question as JSON and reads the answer. |
| Deny | `deny` | Refuses every question. |

Choose with `--approval` on `mvmctl run` or `mvmctl machine run` (repeatable),
or in the project manifest:

```toml
[approval]
backends = ["tty", "webhook=https://approvals.example.com/mvm"]
mode = "any"
```

The flag replaces the manifest's list. With neither, the terminal is used when
an operator is at one (standard error is a terminal and `/dev/tty` opens) and
everything is denied otherwise — so a CI job, a pipe, or a background process
never hangs on a question nobody will see.

Several backends combine under `--approval-mode` (or `[approval] mode`):

- `all` (the default): every backend must approve, asked in order; the first
  refusal stops. A session approval holds only if every backend gave one.
- `any`: one approval is enough, asked in order; the first approval stops.

## The terminal

The terminal backend is written to be hard to fool:

- It reads the controlling terminal, never standard input. Standard input may
  be the workload's.
- Anything typed before the prompt is drawn, and during a short arming window
  after it, is discarded. A key already on its way cannot answer a question it
  was not typed for.
- Every field that came from the guest — the path, the method, the
  destination — is shown with control characters, ANSI and OSC sequences
  replaced by `?`, and is length-capped. A request path cannot move the cursor,
  recolour the prompt, or redraw it to ask something else.
- `y` approves this request, `s` approves it for the session, and anything
  else — an empty line, any other text, no answer before it expires — is a
  denial.
- A run started with `-it` is already reading your terminal for the workload.
  The terminal backend does not race it for keystrokes: it denies with the
  reason `tty_busy`. Use a webhook for an interactive run that needs approvals.
- No controlling terminal is a denial (`no_tty`).

## The webhook

The webhook receives a POST whose body is the question:

```json
{
  "request_id": "appr-…",
  "subject": {
    "kind": "egress",
    "route_id": "github",
    "rule": "rule-2",
    "destination": "api.github.com:443",
    "method": "POST",
    "path": "/repos/my-org/app/issues"
  },
  "expires_in_ms": 120000
}
```

A secret use has `"kind": "secret_use"` with `secret` and `destination`. The
reply approves or denies:

```json
{ "outcome": "approved", "scope": "session" }
```

`scope` is `once` (the default) or `session`. The reply is refused, and the
request denied, if the URL is not `https://` (plain `http://` is accepted only
to a loopback host), if the server answers with a redirect (redirects are never
followed), a non-2xx status, more than 4 KiB, or anything that does not parse,
or if it does not answer before the question expires.

The path is guest-controlled text. Treat it as untrusted wherever your webhook
displays it.

## Secrets that ask

```sh
mvmctl secret set deploy-token --host api.example.com --type bearer --approve ask
```

A run that uses the secret toward a bound destination holds that request and
asks, with the secret's name and the destination. Approving it for the session
covers later uses of the same secret toward the same destination. The guest
still holds only a placeholder; the value is substituted after the approval,
exactly as for any bound secret. `mvmctl secret ls` shows `approve=ask` on the
binding.

Approval covers placeholders carried in request headers, which is where the
endpoint substitutes today.

## What the endpoint enforces

The backends only answer. Everything else is the endpoint's, and none of it can
be changed from the guest:

- **Timeout.** A question not answered in 120 seconds is denied
  (`timed_out`), and the request is refused.
- **Fail closed.** No broker listening, an unreachable socket, a malformed or
  mismatched answer, a backend error — every one is a denial.
- **Rate limit.** At most 10 questions per minute per VM reach a backend. The
  rest are denied without asking (`rate_limited`), so a workload cannot flood
  your terminal.
- **Scope.** `once` covers the one request. `session` covers the same
  question — for egress the route, rule, destination and method, not the
  path — for 15 minutes or until the run ends, whichever is first. Session
  approvals live in the endpoint's memory and are recorded in its approval
  ledger; nothing is written to your profile, to `mvm.toml`, or to disk to be
  reused by a later run.
- **Audit.** Every step is a chain-signed entry in the tenant's audit log,
  carrying the request id: `approval.requested`, then `approval.granted` (with
  its scope and which backend answered), `approval.denied` (with a reason), or
  `approval.timed_out`. A request answered from a session approval is recorded
  as `approval.granted` with the reason `session_grant`. The request path is
  never recorded. The route decision itself is still a `host.route.decided`
  entry.

## Limits

- Approvals are answered by a foreground `mvmctl`. A detached or persistent
  machine (`machine run -d`, `machine start`) has nobody listening, so its
  questions are denied. `machine run --entrypoint -d` answers during the call
  and denies after it, while the machine keeps running.
- Tool calls have an approval subject (`tool_call`) and the same supervisor,
  but no tool gate asks it yet.
- A machine launched through the host library (the Python and TypeScript
  SDKs) has no broker yet, so its questions are denied, and an embedding
  application cannot yet supply its own approval callback.
