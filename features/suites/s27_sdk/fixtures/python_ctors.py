"""Tier A constructor fixture (Python).

Twin of `typescript_ctors.mjs`: calls every generated constructor with
the same inputs and emits one normalized JSON document, so the scenario
can compare both languages against a single golden file.

Both the valid results and the refusal messages are emitted. The
messages are the part a signature-level comparison cannot see, and the
part that would silently diverge if one language's generator drifted.
"""

import dataclasses
import enum
import json
import sys

import mvm


def norm(value):
    """Normalize to plain JSON, dropping the generated dataclass's name.

    `datamodel-codegen` renumbers the variant classes on every
    regeneration, so the class identity is deliberately not compared —
    only the field content, which is what the IR actually carries.
    """
    if dataclasses.is_dataclass(value):
        # Drop absent fields. Every optional field in the IR carries
        # `skip_serializing_if = "Option::is_none"`, so `None` and absent are
        # the same thing on the wire — and Python spells absence as a `None`
        # attribute where JSON.stringify simply omits the key. Comparing the
        # wire form keeps the golden document about content rather than about
        # how each language spells "not set".
        return {
            f.name: norm(getattr(value, f.name))
            for f in sorted(dataclasses.fields(value), key=lambda f: f.name)
            if getattr(value, f.name) is not None
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, list):
        return [norm(v) for v in value]
    return value


def refusal(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - the message is the assertion
        return {"error": type(exc).__name__, "message": str(exc)}
    return {"error": None, "message": None}


built = {
    "host_port": norm(mvm.host_port("example.com", 443)),
    "host_port_low": norm(mvm.host_port("example.com", 1)),
    "host_port_high": norm(mvm.host_port("example.com", 65535)),
    "egress": norm(mvm.egress([mvm.host_port("a.example", 443), mvm.host_port("b.example", 80)])),
    "egress_empty": norm(mvm.egress([])),
    "dns_none": norm(mvm.dns_none()),
    "dns_system": norm(mvm.dns_system()),
    "dns_resolver_default_port": norm(mvm.dns_resolver("1.1.1.1")),
    "dns_resolver_explicit_port": norm(mvm.dns_resolver("1.1.1.1", 5353)),
    "no_deps": norm(mvm.no_deps()),
    "python_deps_default_tool": norm(mvm.python_deps(lockfile="uv.lock")),
    "python_deps_alias": norm(mvm.python_deps(lockfile="r.txt", tool="pip-tools")),
    "python_deps_canonical": norm(mvm.python_deps(lockfile="r.txt", tool="pip_tools")),
    "node_deps_default_tool": norm(mvm.node_deps(lockfile="pnpm-lock.yaml")),
    "node_deps_npm": norm(mvm.node_deps(lockfile="package-lock.json", tool="npm")),
    # Tier B.
    "warm_process_defaults": norm(mvm.warm_process(max_calls_per_worker=1000, max_rss_mb=256)),
    "warm_process_tuned": norm(
        mvm.warm_process(
            max_calls_per_worker=500,
            max_rss_mb=128,
            pool_size=4,
            in_process="concurrent",
            max_queue_depth=32,
        )
    ),
    "addon_use_registry": norm(mvm.addon_use("postgres", version="16", alias="db")),
    "addon_use_local": norm(mvm.addon_use("my-db", path="./addons/my-db")),
}

refusals = {
    "host_port_empty_host": refusal(mvm.host_port, "", 443),
    "host_port_port_zero": refusal(mvm.host_port, "example.com", 0),
    "host_port_port_too_high": refusal(mvm.host_port, "example.com", 65536),
    "dns_resolver_empty_host": refusal(mvm.dns_resolver, ""),
    "python_deps_empty_lockfile": refusal(mvm.python_deps, lockfile="", tool="uv"),
    "python_deps_unknown_tool": refusal(mvm.python_deps, lockfile="uv.lock", tool="poetry"),
    "node_deps_empty_lockfile": refusal(mvm.node_deps, lockfile=""),
    "node_deps_unknown_tool": refusal(mvm.node_deps, lockfile="x", tool="bun"),
    "warm_process_bad_mode": refusal(
        mvm.warm_process, max_calls_per_worker=1000, max_rss_mb=256, in_process="parallel"
    ),
    "addon_use_both_refs": refusal(mvm.addon_use, "x", version="1", path="./x"),
    "addon_use_neither_ref": refusal(mvm.addon_use, "x"),
}

json.dump({"built": built, "refusals": refusals}, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
