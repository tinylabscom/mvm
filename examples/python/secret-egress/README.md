# secret-egress (Python)

Egress-secret substitution — **Plan 129 / ADR-023**. The workload declares a
secret with `mvm.secret(name, type=..., hosts=[...])`; the host substitutes the
real credential on outbound requests and **the raw secret never enters the
guest**.

Demonstrates:

- `mvm.secret("echo-key", type="bearer", hosts=["httpbin.org"], var="API_KEY")`
  — the egress binding. `type` is how the credential authenticates
  (`bearer` / `basic` / `sigv4` / `hmac`); `hosts` is the claim-12 allow-list of
  destinations it may reach (`*.` subdomain wildcards supported).
- In the guest, `os.environ["API_KEY"]` is an opaque placeholder
  (`mvm-secret-<hex>`), not the real value.
- The request is routed through `HTTP_PROXY` (set by the host) → the guest's
  loopback egress proxy → the host endpoint, which injects the real
  `Authorization: Bearer <value>` and originates the request to the bound host
  itself. This example uses plain `http://`, so that upstream leg is
  cleartext. An `https://` URL takes the same route: the client tunnels with
  `CONNECT`, and because the destination carries a binding the host terminates
  the tunnel under this VM's egress CA, substitutes, and re-originates real TLS
  upstream. An unbound destination is passed through untouched.

## How the secret reaches the host (not the guest)

1. **Host stores it** — `mvmctl secret set echo-key --host httpbin.org
   --type bearer --value -` writes the encrypted value + its binding into
   `~/.mvm` (never the guest).
2. **Boot** — `mvmctl machine run --entrypoint --from-workload-ir` admits the
   secret and spawns the per-VM substitution endpoint (the only process
   holding the value in the clear), which mints the placeholder.
3. **Invoke** — the host injects `HTTP_PROXY` + the placeholder env var; the
   workload's request carries the placeholder; the endpoint substitutes the
   real credential on egress.

## How to run it

First, store the secret + its egress binding on the host (the value is piped,
never on argv):

```sh
printf '%s' "$REAL_KEY" | mvmctl secret set echo-key \
    --host httpbin.org --type bearer --value -
```

Compile the app to local boot artifacts, then boot it on a `/dev/kvm` host:

```sh
mvmctl build compile examples/python/secret-egress/app.py --out /tmp/secret-egress
mvmctl machine run --flake /tmp/secret-egress --entrypoint \
    --from-workload-ir /tmp/secret-egress/workload.json \
    --allow-host httpbin.org:80
```

`mvmctl build compile` strips the managed `SecretRef` out of the baked image — the
rootfs is secret-free by construction — and writes the binding into
`workload.json`, the admission input. Nothing discovers that file on its own:
`--from-workload-ir` (which requires `--entrypoint`) lowers its `SecretRef`
into a signed `ExecutionPlan.secrets` and admits it, which is what gives the
per-call entrypoint its placeholder and proxy env. A plain
`mvmctl machine run --flake /tmp/secret-egress` runs with no placeholder.
`--allow-host httpbin.org:80` admits the destination; egress is denied by
default, and the example calls plain `http://`. Deploying to a multi-tenant
fleet is a separate `mvmd` concern; this is the local dev/test path. The
runtime substitution is exercised per the boot-e2e runbook in
`129-secrets-subsystem`.

`httpbin.org/get` reflects the request headers, so the returned JSON shows
the substituted credential reached the destination — proving the guest only
ever held the placeholder. A request to any host **not** in `hosts=[...]` is
refused before it leaves the host (claim 12).
