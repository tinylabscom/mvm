"""Egress-secret example — Plan 129 / ADR-067.

Declares a **bearer** secret bound to a single destination host. The guest
never sees the real credential: `mvm.secret(...)` only puts an opaque
placeholder (`mvm-secret-<hex>`) into the `API_KEY` env var. On an outbound
request carrying that placeholder, the host substitution endpoint swaps in the
real value and makes the real TLS — and refuses any destination not in
`hosts=[...]` (claim 12). The raw secret stays on the host, in one process.

Set the secret on the host first (the value is piped, never on argv):

    printf '%s' "$REAL_KEY" | mvmctl secret set echo-key \
        --host httpbin.org --type bearer --value -

Run it locally on a /dev/kvm host:

    mvmctl build compile examples/python/secret-egress/app.py --out /tmp/secret-egress
    mvmctl up --flake /tmp/secret-egress

`compile` strips the managed `SecretRef` out of the baked image (secret-free
rootfs) and records it in `workload.json`; `up` lowers that into a signed
`ExecutionPlan.secrets` and admits it, spawning the per-VM substitution
endpoint at boot. `httpbin.org/get` reflects the request headers, so the
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
    # set by the host to the in-guest forward proxy; the request is relayed to
    # the host endpoint, which substitutes the real Bearer credential before
    # making the real request to the bound host.
    #
    # The request is plain `http://` so urllib sends it to the proxy in
    # absolute-form (`GET http://httpbin.org/get HTTP/1.1` + headers) — the
    # form the forward proxy parses to read the placeholder. (An `https://` URL
    # via HTTP_PROXY makes urllib issue a `CONNECT` tunnel instead, which hides
    # the headers from the proxy; SDK-configured clients that send absolute-form
    # are the path to credential substitution on TLS destinations.)
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
