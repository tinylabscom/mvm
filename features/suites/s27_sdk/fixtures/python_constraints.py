"""Python half of the shared network-constructor verdict corpus.

Walks ``network_constraints.json`` and, for each case, tries to build a
workload through the public Python DSL. It reports what Python did — refused
at the constructor, or emitted a document — and the calling step validates
whatever came back. That split is the point: the corpus states the verdict on
the *document*, and each surface is free to reach it at whichever seam its
language makes natural, as long as it reaches the same one.
"""

import json
import pathlib
import sys

import mvm

CORPUS = pathlib.Path(__file__).with_name("network_constraints.json")


def build(case: dict) -> dict:
    """Emit the case's workload document, or say the constructor refused."""
    mvm.reset()
    mvm.workload(id="constraints")
    try:
        if case["ctor"] == "host_port":
            net = mvm.network(
                mode="bridge",
                egress=mvm.egress([mvm.host_port(case["host"], case["port"])]),
            )
        elif case["ctor"] == "dns_resolver":
            net = mvm.network(
                mode="bridge",
                dns=mvm.dns_resolver(case["host"], case["port"]),
            )
        else:
            raise AssertionError(f"corpus names constructor {case['ctor']!r}")
    except (ValueError, TypeError) as exc:
        return {"refused": True, "detail": str(exc)}

    @mvm.app(
        name="constraints",
        source=mvm.local_path("."),
        image=mvm.nix_packages(["python312"]),
        entrypoint=mvm.entrypoint(command=["true"]),
        resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        network=net,
    )
    def _constraints() -> None:
        pass

    return {"refused": False, "document": json.loads(mvm.emit_json())}


def main() -> int:
    corpus = json.loads(CORPUS.read_text())
    print(json.dumps({case["id"]: build(case) for case in corpus["cases"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
