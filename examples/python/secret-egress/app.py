"""Egress-secret example — Plan 129 / ADR-067.

Declares a **bearer** secret bound to a single destination host. The guest
never sees the real credential: `mvm.secret(...)` only puts an opaque
placeholder (`mvm-secret-<hex>`) into the `API_KEY` env var. On an outbound
request carrying that placeholder, the host substitution endpoint swaps in the
real value and makes the real TLS — and refuses any destination not in
`hosts=[...]` (claim 12). The raw secret stays on the host, in one process.

Set the secret on the host first (the value is piped, never on argv):

    printf '%s' "$REAL_KEY" | mvmctl secret set echo-key \
        --host postman-echo.com --type bearer --value -

A workload referencing a *managed* secret is admitted through the deploy/plan
(admission) flow, which synthesizes the signed plan that spawns the per-VM
substitution endpoint at boot. `mvmctl compile` (local boot artifacts, no
admission) refuses managed secret refs by design — see the README for the run
flow. `postman-echo.com/get` reflects the request headers, so the response
shows the **real** credential reached the destination while the workload only
ever held the placeholder; any host not in `hosts=[...]` is refused (claim 12).
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
        # substitutes toward postman-echo.com, and only as a Bearer token.
        "API_KEY": mvm.secret(
            "echo-key",
            type="bearer",
            hosts=["postman-echo.com"],
            var="API_KEY",
        ),
    },
)
def call_api() -> str:
    # `API_KEY` holds the opaque placeholder, not the real key. `HTTP_PROXY` is
    # set by the host to the in-guest forward proxy; the request is relayed to
    # the host endpoint, which substitutes the real Bearer credential before
    # making the real request to the bound host.
    placeholder = os.environ["API_KEY"]
    request = urllib.request.Request(
        "https://postman-echo.com/get",
        headers={"Authorization": f"Bearer {placeholder}"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
        return response.read().decode("utf-8")
