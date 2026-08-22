"""mvm — Python SDK for declaring microVM workloads.

Public surface re-exported from the private ``_dsl`` module. The SDK has two
layers (per ADR-0003 / ADR-0004):

- ``mvm._ir``: generated lower-layer dataclasses (internal, no stability
  guarantee — may change in any minor ``mvm`` release).
- ``mvm._dsl``: the hand-authored upper-layer DSL implementation.
- ``mvm``: this module — re-exports the public surface.

Per ADR-0003, the v0 DSL uses keyword-argument style on a decorator. User code
registers a single-app workload and emits IR via ``mvm.emit_json()`` (or
by running ``mvm emit entry.py`` from the host, which honors ADR-0002's
subprocess contract).

Plan 60 Phase 5 Slice D1: the declarative DSL + ``@mvm.func`` decorator
+ ``RemoteFunction`` invoke path are wired here. The libkrun-shaped
``Sandbox.create()`` lifecycle wrapper and the fluent
``WorkloadBuilder`` are deferred to Slice D2.
"""

from mvm._dsl import (
    SCHEMA_VERSION,
    EmittingContextError,
    MsgpackUnavailable,
    MvmTransportError,
    NoVmIntrospectionError,
    PayloadTooLarge,
    RemoteError,
    RemoteFunction,
    SecretInArgError,
    SecretInArgWarning,
    Session,
    WorkloadRef,
    addon_use,
    ai_budget,
    ai_policy,
    app,
    derive_schema,
    dns_none,
    dns_resolver,
    dns_system,
    egress,
    emit_json,
    entrypoint,
    entrypoint_function,
    func,
    hook,
    host_port,
    literal,
    local_path,
    network,
    nix_packages,
    no_deps,
    node_deps,
    node_image,
    python_deps,
    python_image,
    reset,
    resources,
    secret,
    session,
    warm_process,
    workload,
    workload_ref,
)

# In-guest host-services surface: `mvm.audit.emit(...)`, `mvm.host.time()`,
# `mvm.host.cost()`. These speak vsock to the per-VM broker from inside a
# microVM; on the host they raise a clear transport error. Imported here so
# `mvm.audit` / `mvm.host` resolve as attributes (no connection at import).
from mvm import audit, host

# The typed failures `mvm.audit.emit(...)` / `mvm.host.time()` raise. They live
# in a private module, but a caller has to be able to name what it catches, so
# they belong on the public surface — as they already are in TypeScript.
from mvm._hostsvc import (
    BadRequestError,
    HostServiceError,
    InvalidInputError,
    NotBoundError,
    RateLimitedError,
    ServiceError,
    TransportError,
    UnavailableError,
    VerbNotImplementedError,
)
from mvm._helpers import (
    OBSCURA_IMAGE,
    BrowserReadyError,
    BrowserSandbox,
    CodeError,
    CodeSandbox,
)

# Rust-owned env-var names (crates/mvm-sdk/src/env.rs), generated into
# `_env/vars.py`. MVM_SDK_MODE_ENV / MVM_SDK_OUT_PATH_ENV were already
# defined and read by `_sandbox`, but never re-exported here — which is
# the whole of the 'absent from Python' divergence the TypeScript SDK
# recorded against them.
from mvm._env import MVM_SDK_MODE_ENV, MVM_SDK_OUT_PATH_ENV
from mvm._machine import (
    MVM_MACHINE_MAX_OUTPUT_ENV,
    MVM_MACHINE_TIMEOUT_ENV,
    Machine,
    MachineError,
    MachineResult,
)
from mvm._sandbox import (
    DEFAULT_TTL_SECONDS,
    MVM_CLI_BIN_ENV,
    ExecResult,
    FsEntry,
    FsStat,
    ProcessHandle,
    ProcessResult,
    ProcessStreamEvent,
    RecordingNotActiveError,
    Sandbox,
    SandboxDevOnly,
    SandboxInfo,
    SandboxLiveError,
    SandboxModeError,
    current_recording,
    emit_recording_json,
    reset_recording,
)
from mvm._session import current_session_id
from mvm._runtime.runtime import (
    Runtime,
    RuntimeFsEntry,
    RuntimeFsStat,
    RuntimeProcessEvent,
    RuntimeProcessResult,
)

# In-guest host-services runtime surface (`mvm.audit.emit`, `mvm.host.time()`).
# Submodules, so `import mvm; mvm.audit.emit(...)` works inside a booted
# workload. Importing them is cheap — the shared object is loaded lazily on
# first call, never at import — so this stays inert in host authoring use.
from mvm import audit, host

__all__ = [
    "audit",
    "host",
    "DEFAULT_TTL_SECONDS",
    "MVM_CLI_BIN_ENV",
    "MVM_MACHINE_MAX_OUTPUT_ENV",
    "MVM_MACHINE_TIMEOUT_ENV",
    "MVM_SDK_MODE_ENV",
    "MVM_SDK_OUT_PATH_ENV",
    "SCHEMA_VERSION",
    "BadRequestError",
    "BrowserSandbox",
    "BrowserReadyError",
    "CodeError",
    "CodeSandbox",
    "OBSCURA_IMAGE",
    "HostServiceError",
    "InvalidInputError",
    "NotBoundError",
    "RateLimitedError",
    "ServiceError",
    "TransportError",
    "UnavailableError",
    "VerbNotImplementedError",
    "EmittingContextError",
    "ExecResult",
    "FsEntry",
    "FsStat",
    "Machine",
    "MachineError",
    "MachineResult",
    "MsgpackUnavailable",
    "MvmTransportError",
    "NoVmIntrospectionError",
    "PayloadTooLarge",
    "ProcessHandle",
    "ProcessResult",
    "ProcessStreamEvent",
    "RecordingNotActiveError",
    "RemoteError",
    "RemoteFunction",
    "Runtime",
    "RuntimeFsEntry",
    "RuntimeFsStat",
    "RuntimeProcessEvent",
    "RuntimeProcessResult",
    "Sandbox",
    "SandboxDevOnly",
    "SandboxInfo",
    "SandboxLiveError",
    "SandboxModeError",
    "SecretInArgError",
    "SecretInArgWarning",
    "Session",
    "WorkloadRef",
    "addon_use",
    "ai_budget",
    "ai_policy",
    "app",
    "audit",
    "current_recording",
    "current_session_id",
    "derive_schema",
    "dns_none",
    "dns_resolver",
    "dns_system",
    "egress",
    "emit_json",
    "emit_recording_json",
    "entrypoint",
    "entrypoint_function",
    "func",
    "hook",
    "host",
    "host_port",
    "literal",
    "local_path",
    "network",
    "nix_packages",
    "no_deps",
    "node_deps",
    "node_image",
    "python_deps",
    "python_image",
    "reset",
    "reset_recording",
    "resources",
    "secret",
    "session",
    "warm_process",
    "workload",
    "workload_ref",
]
