---
title: Agent sandbox
description: How an agent in a microVM calls a model API without holding the API key — the placeholder the guest receives, the host-side substitution and destination check, the egress policy around it, what the audit chain records, and the limits of each.
---

An agent that calls a model API needs a credential, and an agent that runs
generated code should not be trusted with one. mvm resolves that by keeping the
credential on the host. The guest holds a random placeholder, and the host
substitutes the real value into outbound requests to the destinations the
secret is bound to.

This page describes what that mechanism does, how to reach it, and where it
stops. For the image side, see
[Running an LLM agent inside a microVM](/guides/nix-flakes/#running-an-llm-agent-inside-a-microvm).

## What the guest receives

For each secret the run binds, the guest gets one environment variable whose
value is an opaque token: `mvm-secret-` followed by 48 hex characters, minted
from the OS random source when the VM boots. Two bindings never share a token,
and the token says nothing about the value it stands for. Each token is valid
only for the destinations its own binding names: presented to any other host,
it is refused.

Alongside the placeholders, the entrypoint gets:

- `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` set to
  `http://127.0.0.1:1080`, and `ALL_PROXY` / `all_proxy` to
  `socks5h://127.0.0.1:1080` — the same in-guest listener, which dispatches on
  the first byte. `NO_PROXY` covers loopback.
- `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` and
  `NODE_EXTRA_CA_CERTS` pointing at the guest's trust bundle, which carries the
  image's own roots plus this VM's egress CA certificate.

The entrypoint is launched with an otherwise empty environment. The real secret
value is never written to the rootfs, the kernel command line, a drive, or the
guest's environment — and neither is the egress CA's private key, which stays
in the host process that terminates.

## What the host does

Every workload VM gets its own `mvm-network-endpoint` process on the host; it
carries all of the guest's egress. Declaring secrets adds a placeholder
registry to that process, and it is the only process that reads a secret value
in the clear.

1. **At boot**, the endpoint reads the secret bindings from the signed
   execution plan, looks up each one's destination list and auth type in the
   local binding store, narrows that list to the destinations the plan binding
   names (when it names any), mints the placeholders, and hands them back to be
   injected into the entrypoint's environment. A secret with no binding, or a
   plan binding naming a destination outside the stored list, fails the boot
   rather than handing the guest a placeholder nothing can resolve.
2. **Per connection**, the in-guest proxy relays the tunnel to the endpoint over
   the VM's authenticated vsock channel. The endpoint checks the destination
   against the VM's network policy first. If a secret is bound to that
   destination, it terminates the tunnel under this VM's egress CA and reads the
   request; otherwise it relays the bytes untouched and never sees inside them.
3. **Per request in a terminated tunnel**, for each header carrying a
   placeholder, the endpoint checks the destination host against that secret's
   bound hosts. The value is resolved only after both checks pass. A request
   whose `Host` disagrees with the tunnel it arrived in is refused.
4. **The endpoint originates the request itself**, including the TLS
   connection to the destination, validated against the host's system roots.
   The guest's TLS session is with the host, never with the model provider. A
   destination whose certificate does not validate gets nothing — the guest
   gets a `502` — and there is no fallback to relaying the guest's own bytes.
5. **When it hands the request to the forward leg**, the endpoint appends a
   `secret.substituted` entry for each secret it substituted into that request
   to the host's chain-signed audit log. When the forward ends, it appends one
   `secret.forward_outcome` entry saying how.

The substitution is recorded before the request is sent, not after the response
arrives, because from that point the destination may have the key whether or
not a response ever comes back. A forward that fails after sending (an upstream
reset, a timeout, a response over the size cap) therefore still leaves a
`secret.substituted` entry, followed by an outcome naming the failure. The
entry also appears for a forward that failed before anything was sent, such as
a connection refused, so the log can over-report a send but does not
under-report one.

A placeholder that the endpoint did not mint, or a request to a host the
secret is not bound to, is refused before any value is read, and the guest gets
a `502` with the reason in the body.

Substitution looks only at request **headers**. Put the placeholder where the
client sends its credential header. A request that carries a placeholder in its
URL or its body is refused and recorded rather than sent to the destination
with the token in place of the key. In a tunnel the host terminated, the whole
body is read before anything is forwarded, so that refusal comes before the
forward leg exists. On the typed HTTP path, where a body can stream, the
refusal comes before any byte of the placeholder is sent, but the request
headers, carrying the substituted credential, may already have gone out.

## Setting it up

Two pieces: the host secret and its binding, and a run that binds it.

**1. Store the secret and bind it.** `mvmctl secret set` stores the value and
records where it may be sent and how it authenticates:

```sh
mvmctl secret set anthropic --provider anthropic
```

`mvmctl secret providers` lists the built-in catalog; the `anthropic` entry
binds to `api.anthropic.com`. For a destination not in the catalog, name it
directly:

```sh
mvmctl secret set my-api --host api.example.com --type bearer
```

With no `--value` or `--value-file`, the command prompts on a terminal or reads
a pipe, so the value does not land in shell history or the process table. The
binding recorded here is the one the host enforces.

**2. Bind it to the run with `--secret`.** `run` and `machine run` both take
`--secret NAME[:HOST,...]`, repeatable:

```sh
mvmctl run --image curlimages/curl:latest --secret anthropic \
  --allow-host api.anthropic.com -- \
  sh -c 'curl -sS https://api.anthropic.com/v1/models -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01"'
```

Inside the guest `$ANTHROPIC_API_KEY` is the placeholder; `curl` tunnels
through the proxy environment, the host terminates that tunnel and sends the
request on with the real key. The host's connection to the destination
requires TLS 1.3; a destination that offers only older versions is refused
with a `502` rather than contacted over a weaker protocol.

The guest variable comes from the provider the secret was bound with
(`anthropic` hands over `ANTHROPIC_API_KEY`, `openai` `OPENAI_API_KEY`,
`github` `GITHUB_TOKEN`, `stripe` `STRIPE_API_KEY`); a secret bound with
`--host` hands over its own name, uppercased, with `-` folded to `_`. The
optional host list narrows where this run's placeholder is valid:
`--secret anthropic:api.anthropic.com` binds only that host even if the
stored binding admits more. It can only narrow — a host the stored binding
does not admit refuses the run. An unknown secret, a secret with no binding,
two secrets handing over the same variable, or a malformed spec (an empty
name or host, or a host with a port) all refuse before anything boots.

A persistent machine (`machine run --name NAME -d --secret ...`) records the
binding beside its spec and re-validates it on every start, and
`mvmctl secret rm` refuses while a machine still names the secret.

**Or declare it in Workload IR.** The host also reads secret declarations
from a Workload IR file, passed with `--from-workload-ir`. There are two ways
to produce one:

- From an SDK function workload: declare the variable with
  `mvm.secret("anthropic", type="bearer", hosts=["api.anthropic.com"], var="ANTHROPIC_API_KEY")`
  in the app's `env` and run `mvmctl build compile app.py --out ./out`. That
  writes the flake and `./out/workload.json`, and strips the secret
  declaration out of the image.
- For a hand-written flake: write `workload.json` yourself. The
  [Nix flakes guide](/guides/nix-flakes/#running-an-llm-agent-inside-a-microvm)
  has a complete example.

`mvm.toml` has no secret declaration.

**Running an IR-declared entrypoint.** A compiled
function workload reads its call arguments from stdin as a JSON
`[args, kwargs]` array; plain text is a decode error in the guest. With no
stdin, the call gets `[[], {}]`.

```sh
echo '[["Summarize this repository."], {}]' | mvmctl machine run --flake ./out --entrypoint \
  --from-workload-ir ./out/workload.json \
  --allow-host api.anthropic.com \
  --timeout 120
```

`--timeout` bounds the whole call, boot excluded, and defaults to 30 seconds.
A call that outlives it exits with status 124.

## Which runs receive the placeholder

`--secret` and `--from-workload-ir PATH` resolve the same plan-bound secret
metadata on every launch shape, and can be combined as long as they do not
bind the same guest variable. The substitution endpoint mints opaque environment placeholders
before boot, and PID 1 exports them before it starts the image workload. Raw
secret values remain host-only. `--manifest PATH` works in place of `--flake
PATH`.

```sh
mvmctl machine run --flake PATH --entrypoint --from-workload-ir PATH
```

| Invocation | Placeholder injected |
| --- | --- |
| `run --secret NAME -- argv` | Yes |
| `machine run --flake PATH --entrypoint --from-workload-ir PATH` | Yes |
| `machine run --flake PATH --entrypoint --secret NAME` | Yes |
| `machine run --entrypoint` without `--secret` or `--from-workload-ir` | No: the plan carries no secrets |
| `machine run --flake PATH --from-workload-ir PATH -- argv` | Yes |
| `machine run --name NAME -d --secret NAME` or `--from-workload-ir PATH` | Yes; references persist beside the machine spec and are revalidated on restart |
| `machine run` without `--secret` or `--from-workload-ir` | No |
| `machine session start TEMPLATE --from-workload-ir PATH` | Yes |
| `machine session attach SESSION_ID` | Yes, if the session was booted with secrets |
| In-process `mvm-client` launch with typed secret references | Yes |

An explicit `--name` is preserved for a kept-alive secret-bearing entrypoint
run. Attach by that name or use the session id printed on stderr as `Session
kept alive: <id>`:

```sh
echo '[["Next question."], {}]' | mvmctl machine session attach <id> --stdin - --timeout 120
```

Both forms reuse the placeholders minted at boot and admit nothing new.
`--stdin -` is required to send piped input: without `--stdin`,
`machine session attach` ignores its stdin and calls the entrypoint with
`[[], {}]`.

The entrypoint itself must be a per-call entrypoint: an image whose PID 1
idles and whose `/etc/mvm/entrypoint` is a wrapper the guest agent runs on each
call. Function workloads from `mvmctl build compile` have that shape. Command
workloads from `mvmctl build compile`, and plain mkGuest `entrypoint.command`
images, do not: their program is PID 1, which never receives a placeholder.

## What the agent's HTTP client must do

An ordinary HTTP client that reads the proxy environment works. It tunnels an
`https://` URL through the in-guest listener with `CONNECT`, the host terminates
that tunnel for a destination the secret is bound to, substitutes into the
request headers and originates the upstream connection itself. The guest's TLS
session is with the host, under this VM's egress CA — which is why the trust
bundle matters, and why a client that ignores `SSL_CERT_FILE` and carries its
own compiled-in root store will reject the connection.

Things still worth knowing:

- **The placeholder goes in a header**, where the credential goes: `x-api-key:
  $ANTHROPIC_API_KEY` or `Authorization: Bearer $API_KEY`. Substitution reads
  request headers only. A placeholder in a request URL or body is refused.
- **`HTTPS_PROXY` applies to all of the process's HTTPS traffic**, not only the
  requests carrying a placeholder. A destination the network policy does not
  admit is refused whether or not a secret is involved. Node's built-in `fetch`
  does not read `HTTPS_PROXY` by default and connects directly, which has no
  route out of a guest with no NIC.
- **A tunnel to a destination no secret is bound to is relayed, not
  terminated.** The host does not sit inside TLS it has no reason to open, so
  those connections are end-to-end with the destination and no substitution
  happens in them. A placeholder sent down such a tunnel reaches that
  destination as the meaningless token it is, never as the key. A tunnel to a
  destination bound to a *different* secret is terminated, and a placeholder
  that is not valid there is refused and recorded as
  `secret.placeholder_dropped`.
- **Requests are not pipelined.** Bytes that arrive past the declared
  `Content-Length` are refused rather than served, and a `Transfer-Encoding:
  chunked` request body is refused with a `501`.
- **Gets a response started within 30 seconds, and never stalls for 30.** The
  upstream response head must arrive within 30 seconds of the request being
  sent. After that, each side gives up after 30 seconds with no data read. A
  request and a response are each capped at 16 MiB. The whole entrypoint call
  is separately bounded by `machine run --timeout`, which defaults to 30
  seconds.

## Egress

Egress is denied by default. A bound secret does not open a destination; the
network policy has to admit it too, and the endpoint refuses a request the
policy does not admit before it looks at any placeholder.

| Flag | Policy |
| --- | --- |
| (none) | Deny all outbound traffic |
| `--allow-host HOST[:PORT]` | Allow only the listed destinations; the port defaults to 443. Repeatable |
| `--net` | The `dev` preset: package registries, `github.com`, `api.github.com`, `api.openai.com`, `api.anthropic.com` |

For an agent, prefer `--allow-host` with exactly the model API host. The
network policy also defines a narrower `agent` preset (the two model APIs plus
GitHub), but no `machine run` flag selects it today.

Every microVM backend boots the workload with a vsock device and no network
interface, so the endpoint is the only way out of the guest. The same endpoint
enforces the same policy on each backend.

## Token budget

None on this path. The endpoint can meter model API traffic against a token
budget, but `machine run --entrypoint` builds its network policy from
`--allow-host` and `--net` only, and neither attaches a budget. Bound spend at
the provider, for example with a key that has a usage limit.

## What the audit chain records

Admission and substitution entries go to the chain-signed log for the `local`
tenant, `~/.mvm/audit/local.jsonl`, signed with the host key at
`~/.mvm/keys/host-signer.ed25519`:

| Event | When | Labels |
| --- | --- | --- |
| `plan.admitted` | The signed plan, including its secret bindings, was admitted | plan identity |
| `plan.launched` / `plan.failed` | The VM started, or failed to | plan identity |
| `secret.substituted` | A request carrying a substituted secret was handed to the forward leg, before any response | `name`, `destination`, `auth_type` |
| `secret.forward_outcome` | A forward that carried a substituted secret ended: `completed`, `upstream_failed`, `request_failed`, `response_failed`, `response_refused` (a fail-closed transform refused the response) or `canceled` (the workload stopped reading) | `destination`, `outcome` |
| `secret.redacted` | Secret-shaped or PII content was masked out of an outbound request, or a request failed or was refused fail-closed | `destination`, rule categories or reason |
| `secret.placeholder_dropped` | A placeholder was found where it may not travel and was dropped | `destination` |
| `secret.flow_refused` | A request was refused before anything was forwarded: the network policy does not admit its destination (`policy_denied`), it names a peer (`peer_destination`), its URL has no host and port (`malformed`), it carries a placeholder outside a header (`placeholder_in_url`, `placeholder_in_body`), or, on a connection the host intercepted, it was addressed to a different host than the connection or could not be framed | `destination`, `reason` |

No entry carries a secret value, a request body, or a header value.

Read and verify the chain:

```sh
mvmctl trust audit tail --chain
mvmctl trust audit verify
```

`verify` exits nonzero if a signature or chain link does not check out,
including across rotated segments. It cannot detect entries removed from the
end of the log.

## What this does not protect against

- **Use of the credential through the placeholder.** A compromised agent can
  send any request it likes to a bound host, and the host will attach the real
  key. Substitution keeps the key from being copied out of the VM; it does not
  limit what the key is used for at the provider. Bind the narrowest key you
  can.
- **Data the agent sends to allowed hosts.** Anything the agent can read, it
  can put in a request to an admitted destination.
- **A destination that echoes the credential back.** Responses are relayed to
  the guest as the destination sent them. An endpoint that reflects request
  headers in its body — a debugging echo service, for one — hands the guest
  the real value it was sent. Bind secrets only to destinations that do not.
- **Credentials that are not HTTP headers.** A database password or a TLS
  client key cannot be substituted. If you give one to a guest, the guest holds
  the real value.
- **A malicious host.** The host holds the secret store, the signing key, and
  the hypervisor.

## Related pages

- [Secrets and credentials](/guides/secrets-and-credentials/)
- [Network egress policy](/guides/network-egress-policy/)
- [Audit and receipts](/guides/audit-and-receipts/)
- [Agent tool contract](/guides/agent-tool-contract/)
- [Workload input](/guides/workload-input/)
