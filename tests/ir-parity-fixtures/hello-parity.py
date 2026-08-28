# Shared cross-language parity workload — Python SDK.
#
# The identical workload is declared in `hello-parity.ts` and in the Rust
# conformance test (`crates/mvm-sdk/tests/ir_address_parity.rs`). All three
# must resolve to one `mvm_core::workload_address` — the pinned golden the
# test asserts. Emitting to stdout lets `xtask gen-ir-parity`/`check-ir-parity`
# regenerate `hello-parity.python.ir.json` and diff it for drift.
#
# Keep this meaning-identical to the sibling TS/Rust declarations: any field
# change here without the same change there breaks the parity assertion.
import sys

import mvm

mvm.reset()
mvm.workload(id="hello-parity")


@mvm.app(
    name="greeter",
    source=mvm.local_path("."),
    image=mvm.nix_packages(["python312"]),
    entrypoint=mvm.entrypoint(command=["python", "-m", "greeter"]),
    resources=mvm.resources(cpu_cores=2, memory_mb=512, rootfs_size_mb=1024),
    env={"GREETING": mvm.literal("hello")},
)
def greeter():
    pass


sys.stdout.write(mvm.emit_json())
