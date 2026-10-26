# Manual native NVIDIA witness

This harness addresses the native-backend acceptance slice of issue #3560.
It does not establish microVM/vsock, graphs, fork-memory handoff, or MLX
support. No NVIDIA hardware result is recorded by this change. The missing
witness is a successful run on an authorized Linux NVIDIA host and a retained
JSON record for each tested GPU/driver combination.

## CPU-only validation

From the repository root:

```sh
python3 -B tests/test_native_gpu_witness.py
```

This compiles the C probe with warnings as errors and tests invalid arguments,
transport refusal, missing libraries, and mocked orchestration (identity policy,
diagnostics, readiness, deadlines, cleanup, and success evidence). It does not build Rust, install
anything, start the endpoint, invoke `nvidia-smi`, or access a GPU.

## Prepare artifacts explicitly

Use the project builder VM for Linux compilation. Do not run Linux builds or
Linux runtime operations on the macOS host. A real witness requires an
operator-authorized NVIDIA Linux execution environment consistent with
`AGENTS.md`; this harness does not provision one or authorize cloud spending.
It requires Python 3.9+, a C compiler, the installed NVIDIA driver, and host
`nvidia-smi`. CUDA SDK headers and `nvcc` are not required.

Inside the builder, from the repository root:

```sh
cargo build -p mvm-gpu \
  -p mvm-gpu-cuda-shim -p mvm-gpu-nvml-shim
cc -std=c11 -Wall -Wextra -Werror crates/mvm-gpu/tests/native_witness.c \
  -ldl -o /tmp/mvm-native-witness
```

Use artifacts matching the execution host architecture/libc. Transfer to a
separate host only with operator permission. Run from the root of that checkout
after setting `CARGO_TARGET_DIR` to its actual build output directory:

```sh
test -n "$CARGO_TARGET_DIR"
python3 scripts/native-gpu-witness.py \
  --endpoint "$CARGO_TARGET_DIR/debug/mvm-gpu-endpoint" \
  --probe /tmp/mvm-native-witness \
  --cuda-shim "$CARGO_TARGET_DIR/debug/libmvm_gpu_cuda_shim.so" \
  --nvml-shim "$CARGO_TARGET_DIR/debug/libmvm_gpu_nvml_shim.so" \
  --timeout 60 > /tmp/mvm-native-witness.json
```

All four artifact paths must be absolute existing files. The runner always
spawns its own `--backend native` endpoint on a private temporary Unix socket
and sets `MVM_GPU_RPC=unix:...` for the C program. It never connects to an
operator's endpoint, pins a GPU, selects auto/stub, installs drivers, or runs
automatically in CI. It removes `LD_LIBRARY_PATH` and `LD_PRELOAD` so the host
endpoint resolves installed vendor libraries, not guest shims. Run with normal
host ordinal visibility. The current shim does not expose CUDA UUID/PCI identity;
no protocol extension is introduced. Only a single physical GPU is supported:
the runner requires one host index-zero `GPU-` UUID, MIG mode Disabled or N/A,
and rejects any set `CUDA_VISIBLE_DEVICES`, `CUDA_DEVICE_ORDER`, or
`NVIDIA_VISIBLE_DEVICES` (even empty). Unknown MIG status fails closed. The probe
requires exactly one CUDA device before creating a context, and the runner
requires exactly one NVML device. Only under these restrictions are CUDA zero,
NVML zero, and the host GPU attributed together. Multi-GPU and MIG hosts are
unsupported, not evidence of success.

The total operational deadline is 60 seconds (configurable from 1 to 300).
Startup observes the existing endpoint log event; because that line precedes
listen, a maximum of five bounded compatibility connection checks follows.
A post-listen readiness event would replace those checks. The runner kills
and attempts to reap only its owned endpoint, including on exceptions and interruption;
each probe/subcommand is bounded by the remaining deadline. Do not kill the
runner with SIGKILL if cleanup is required.
After SIGKILL, endpoint reaping has a separate five-second budget. On expiry the
runner fails with the PID and reports uncertain cleanup; a driver-blocked process
may remain in uninterruptible kernel sleep despite SIGKILL and require operator
investigation. Success JSON is emitted only after confirmed endpoint teardown.
Endpoint stderr is continuously drained after readiness and retains its last
64 KiB; command failures/timeouts include the last 64 KiB of captured stderr.

## Acceptance and evidence

Accept a run only when the command exits zero and its JSON has `passed: true`:

| Requirement | Witness |
| --- | --- |
| Built shim ABI | C `dlopen` of the exact CUDA and NVML artifact paths |
| PTX/module/function | Embedded PTX 6.0, `sm_50`, module load and function lookup |
| HtoD, real launch, DtoH | Copy 105, launch increment-by-37, synchronize, require 142 |
| NVML versus host | Single-physical-GPU policy above, exact name and driver string, and device-count comparison against host `nvidia-smi` |
| Driver/GPU/version matrix | JSON includes CUDA driver API version, NVML driver/name/count, all host GPU indices/UUIDs/names/driver versions, platform and artifact paths |
| Owned lifecycle | Private socket directory; endpoint killed and reaped on exit |

The kernel transforms its input: a stub/no-op launch cannot satisfy correctness.
NVML utilization and free memory are intentionally not compared because they
change between samples. Exit failure, timeout, missing libraries/hardware,
unsupported PTX, or inconsistent enumeration is a failed witness, not a skip
or evidence of native success. Preserve stderr when diagnosing failures.

Attach successful JSON, checkout revision, exact build/run commands, and build
profile to the PR/issue verification record. Repeat per driver/GPU combination;
one run is not a compatibility matrix. Do not mark the native issue acceptance
complete until that hardware evidence is reviewed. Graph/fork and MLX acceptance
remain separate and unimplemented by this harness.
