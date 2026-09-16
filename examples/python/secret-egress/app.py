"""Egress-secret example — Plan 129 / ADR-023.

Declares a **bearer** secret bound to a single destination host. The guest
never sees the real credential: `mvm.secret(...)` only puts an opaque
placeholder (`mvm-secret-<hex>`) into the `API_KEY` env var. On an outbound
request carrying that placeholder, the host substitution endpoint swaps in the
real value and originates the upstream request itself — and refuses any
destination not in `hosts=[...]` (claim 12). The raw secret stays on the host,
in one process.

Set the secret on the host first (the value is piped, never on argv):

    printf '%s' "$REAL_KEY" | mvmctl secret set echo-key \
        --host httpbin.org --type bearer --value -

Run it locally on a /dev/kvm host:

    mvmctl build compile examples/python/secret-egress/app.py --out /tmp/secret-egress
    mvmctl machine run --flake /tmp/secret-egress --entrypoint \
        --from-workload-ir /tmp/secret-egress/workload.json \
        --allow-host httpbin.org:80

`compile` strips the managed `SecretRef` out of the baked image (secret-free
rootfs) and records it in `workload.json`. Nothing discovers that file on its
own: `--entrypoint --from-workload-ir` is what lowers it into a signed
`ExecutionPlan.secrets`, admits it, and injects the placeholder into the
per-call entrypoint. A plain `machine run --flake` runs with no placeholder.
`--allow-host` admits the destination; egress is denied by default. `httpbin.org/get` reflects the request headers, so the
response shows the **real** credential reached the destination while the
workload only ever held the placeholder; any host not in `hosts=[...]` is
refused (claim 12).
"""

import os
import urllib.request

import mvm


@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256, rootfs_size_mb=512),
    env={
        # The guest receives an opaque placeholder here — never the value.
        # `hosts` + `type` are the egress binding (claim 12): the host only
        # substitutes toward httpbin.org, and only as a Bearer token.
        "API_KEY": mvm.secret(
            "echo-key",
            type="bearer",
            hosts=["httpbin.org"],
            var="API_KEY",
        ),
    },
)
def call_api() -> str:
    # `API_KEY` holds the opaque placeholder, not the real key. `HTTP_PROXY` is
    # set by the host to the guest's loopback egress proxy; the request reaches
    # the host endpoint, which substitutes the real Bearer credential before
    # making the real request to the bound host.
    #
    # An `https://` URL takes the same route with no change here: urllib issues
    # a `CONNECT` tunnel, and because the destination carries a binding the host
    # terminates that tunnel under this VM's egress CA and substitutes inside
    # it. This example stays on plain `http://` only to keep the upstream leg
    # readable.
    placeholder = os.environ["API_KEY"]
    request = urllib.request.Request(
        "http://httpbin.org/get",
        headers={
            "Authorization": f"Bearer {placeholder}",
            # An explicit User-Agent — must NOT contain the reserved
            # `mvm-secret-` placeholder prefix, or the host endpoint would treat
            # this header as a placeholder too and refuse the request.
            "User-Agent": "mvm-egress-example/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        # Surface the body, not just the status line: when the host substitution
        # endpoint refuses/fails the forward it returns the reason as the 502
        # body (`WireResponse::Refused`), which is otherwise lost.
        body = exc.read().decode("utf-8", "replace")
        return f"HTTP {exc.code}: {body}"
