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
+ ``RemoteFunction`` invoke path are wired here. The microsandbox-shaped
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
from mvm._sandbox import (
    DEFAULT_TTL_SECONDS,
    RecordingNotActiveError,
    Sandbox,
    SandboxModeError,
    current_recording_dict,
    emit_recording_json,
    reset_recording,
)
from mvm._session import current_session_id

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "SCHEMA_VERSION",
    "EmittingContextError",
    "MsgpackUnavailable",
    "MvmTransportError",
    "NoVmIntrospectionError",
    "PayloadTooLarge",
    "RecordingNotActiveError",
    "RemoteError",
    "RemoteFunction",
    "Sandbox",
    "SandboxModeError",
    "SecretInArgError",
    "SecretInArgWarning",
    "Session",
    "WorkloadRef",
    "addon_use",
    "app",
    "current_recording_dict",
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
