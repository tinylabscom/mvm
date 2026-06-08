# secret-egress (Python)

Egress-secret substitution — **Plan 129 / ADR-067**. The workload declares a
secret with `mvm.secret(name, type=..., hosts=[...])`; the host substitutes the
real credential on outbound requests and **the raw secret never enters the
guest**.

Demonstrates:

- `mvm.secret("echo-key", type="bearer", hosts=["postman-echo.com"], var="API_KEY")`
  — the egress binding. `type` is how the credential authenticates
  (`bearer` / `basic` / `sigv4` / `hmac`); `hosts` is the claim-12 allow-list of
  destinations it may reach (`*.` subdomain wildcards supported).
- In the guest, `os.environ["API_KEY"]` is an opaque placeholder
  (`mvm-secret-<hex>`), not the real value.
- The request is routed through `HTTP_PROXY` (set by the host) → the in-guest
  forward proxy → the host substitution endpoint, which injects the real
  `Authorization: Bearer <value>` and makes the real TLS to the bound host.

## How the secret reaches the host (not the guest)

1. **Host stores it** — `mvmctl secret set echo-key --host postman-echo.com
   --type bearer --value -` writes the encrypted value + its binding into
   `~/.mvm` (never the guest).
2. **Boot** — `mvmctl up` spawns the per-VM substitution endpoint (the only
   process holding the value in the clear), which mints the placeholder.
3. **Invoke** — the host injects `HTTP_PROXY` + the placeholder env var; the
   workload's request carries the placeholder; the endpoint substitutes the
   real credential on egress.

## How to run it

First, store the secret + its egress binding on the host (the value is piped,
never on argv):

```sh
printf '%s' "$REAL_KEY" | mvmctl secret set echo-key \
    --host postman-echo.com --type bearer --value -
```

A workload that references a **managed** secret is admitted through the
**deploy / plan (admission) flow** — that path synthesizes a signed
`ExecutionPlan` carrying the secret binding, which is what spawns the per-VM
substitution endpoint at boot. `mvmctl compile` (which emits *local* boot
artifacts with no admission) deliberately **refuses** managed secret refs:

```text
$ mvmctl compile examples/python/secret-egress/app.py --out /tmp/x
Error: managed secret refs are not supported by `mvmctl compile` local boot
artifacts yet ... Use deploy/plan flows for managed refs ...
```

So drive this example through the admission/deploy flow (the fleet path —
`mvmd`), not `compile`. The runtime substitution itself is exercised on a
`/dev/kvm` host per the boot-e2e runbook in `specs/plans/129-secrets-subsystem.md`.

`postman-echo.com/get` reflects the request headers, so the returned JSON shows
the substituted credential reached the destination — proving the guest only
ever held the placeholder. A request to any host **not** in `hosts=[...]` is
refused before it leaves the host (claim 12).
