"""mvm — Python SDK for declaring microVM workloads.

The SDK has two layers (per ADR-0003):

- ``mvm._ir``: generated lower-layer dataclasses (internal, no stability
  guarantee — may change in any minor ``mvm`` release).
- ``mvm``: the hand-authored upper-layer DSL exposed here.

Per ADR-0003, the v0 DSL uses keyword-argument style on a decorator. User code
registers a single-app workload and emits IR via ``mvm.emit_json()`` (or
by running ``mvm emit entry.py`` from the host, which honors ADR-0002's
subprocess contract).
"""

from __future__ import annotations

import dataclasses
import json
import typing
from enum import Enum
from typing import Any, Callable

from mvm._ir import workload as _ir
# Tier A constructors are generated from the Rust registry
# (crates/mvm-sdk/src/ctor_registry.rs) into `_ctors/generated.py`.
# Re-exported here so `mvm._dsl.<name>` keeps resolving.
from mvm._ctors.generated import (  # noqa: F401
    dns_none,
    dns_resolver,
    dns_system,
    egress,
    host_port,
    no_deps,
    node_deps,
    python_deps,
    warm_process,
)


def _kind_value(dataclass_cls: type, value: str) -> Any:
    """Look up the right ``KindN`` enum for a generated dataclass and
    construct an instance with ``value``.

    The codegen tool (``datamodel-codegen``) numbers enum classes in the
    order they appear in the schema, which shifts whenever a new
    variant lands. Looking up the enum class via the dataclass's type
    hints means our hand-authored DSL keeps working across regenerations.
    """
    hints = typing.get_type_hints(dataclass_cls)
    return hints["kind"](value)
from mvm._remote import (
    EmittingContextError,
    MsgpackUnavailable,
    MvmTransportError,
    NoVmIntrospectionError,
    PayloadTooLarge,
    RemoteError,
    RemoteFunction,
    SecretInArgError,
    SecretInArgWarning,
    WorkloadRef,
    workload_ref,
)
from mvm._session import Session, session

__all__ = [
    "SCHEMA_VERSION",
    "workload",
    "app",
    "func",
    "local_path",
    "nix_packages",
    "python_image",
    "node_image",
    "hook",
    "secret",
    "literal",
    "entrypoint",
    "entrypoint_function",
    "resources",
    "python_deps",
    "node_deps",
    "no_deps",
    "host_port",
    "network",
    "egress",
    "dns_none",
    "dns_system",
    "dns_resolver",
    "derive_schema",
    "emit_json",
    "reset",
    "session",
    "RemoteFunction",
    "RemoteError",
    "MvmTransportError",
    "MsgpackUnavailable",
    "PayloadTooLarge",
    "SecretInArgError",
    "SecretInArgWarning",
    "EmittingContextError",
    "NoVmIntrospectionError",
    "Session",
    "WorkloadRef",
    "workload_ref",
]

SCHEMA_VERSION = "0.1"

_state: dict[str, Any] = {
    "workload_id": None,
    "apps": [],
}


def reset() -> None:
    """Reset SDK module state. Exposed for tests; production code should not call this."""
    _state["workload_id"] = None
    _state["apps"] = []


def workload(*, id: str) -> None:
    """Declare the workload identity. Must be called exactly once per emit."""
    if _state["workload_id"] is not None:
        raise RuntimeError("workload(id=...) called twice")
    if not id:
        raise ValueError("workload id must be a non-empty string")
    _state["workload_id"] = id


def _resolve_network_with_depends_on(
    network: _ir.Network | None,
    depends_on: list[WorkloadRef] | None,
) -> _ir.Network | None:
    """Merge `depends_on=[...]` declarations into `network.peers`.

    If `depends_on` is empty/None and `network` is None, returns None
    (no network declaration). If only `depends_on` is set, synthesizes
    a `mode="none"` network with the peers populated. If both are set,
    appends the depends_on workload ids to `network.peers` (de-duplicated,
    preserving the user-declared order first, then any newly referenced
    workloads).
    """
    if not depends_on:
        return network
    extra = [ref.id for ref in depends_on if isinstance(ref, WorkloadRef)]
    invalid = [ref for ref in depends_on if not isinstance(ref, WorkloadRef)]
    if invalid:
        raise TypeError(
            f"depends_on entries must be WorkloadRef instances; got "
            f"{[type(r).__name__ for r in invalid]!r}. Hint: use "
            "`mv.workload_ref('id')` for each declared dependency."
        )
    if network is None:
        return globals()["network"](mode="none", peers=extra)
    # Append novel ids while preserving the existing peers' order.
    seen = set(network.peers)
    merged = list(network.peers)
    for pid in extra:
        if pid not in seen:
            merged.append(pid)
            seen.add(pid)
    return _ir.Network(
        mode=network.mode,
        ports=list(network.ports),
        egress=network.egress,
        peers=merged,
        dns=network.dns,
    )


def app(
    *,
    name: str,
    source: _ir.Source1,
    image: _ir.Image1,
    entrypoint: _ir.Entrypoint | None = None,
    entrypoints: list[_ir.Entrypoint] | None = None,
    resources: _ir.Resources,
    env: dict[str, Any] | None = None,
    mounts: list[_ir.Mount] | None = None,
    network: _ir.Network | None = None,
    dependencies: _ir.Dependencies | None = None,
    depends_on: list[WorkloadRef] | None = None,
    addons: list[_ir.AddonUse] | None = None,
    threat_tier: _ir.ThreatTier | str | None = None,
    before_build: str | list[str] | _ir.HookCmd | list[_ir.HookCmd] | None = None,
    before_start: str | list[str] | _ir.HookCmd | list[_ir.HookCmd] | None = None,
    after_start: str | list[str] | _ir.HookCmd | list[_ir.HookCmd] | None = None,
    before_stop: str | list[str] | _ir.HookCmd | list[_ir.HookCmd] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register an app in the current workload. Used as a decorator.

    Single-entrypoint shape (legacy + most common case)::

        @mvm.app(
            name="hello",
            source=mvm.local_path("."),
            image=mvm.nix_packages(["python312"]),
            entrypoint=mvm.entrypoint(command=["python", "-m", "hello"]),
            resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
        )
        def hello():
            pass

    Multi-function shape (ADR-0014 Phase 2)::

        @mvm.app(
            name="math-svc",
            source=mvm.local_path("."),
            image=...,
            resources=...,
            dependencies=mvm.no_deps(),
            entrypoints=[
                mvm.entrypoint_function(module="math", function="add", primary=True),
                mvm.entrypoint_function(module="math", function="mul"),
            ],
        )

    Cross-workload dependencies declare which other workloads this app
    is allowed to call (per ADR-0014). Each entry populates
    ``network.peers``::

        math = mvm.workload_ref("math-svc")

        @mvm.app(..., depends_on=[math])
        def my_app(): ...
    """
    if entrypoint is not None and entrypoints is not None:
        raise ValueError(
            "mv.app(): pass `entrypoint=` (single) OR `entrypoints=` (list); not both."
        )
    if entrypoint is None and entrypoints is None:
        raise ValueError(
            "mv.app(): one of `entrypoint=` or `entrypoints=` is required."
        )
    resolved_entrypoints = (
        list(entrypoints) if entrypoints is not None else [entrypoint]  # type: ignore[list-item]
    )
    resolved_network = _resolve_network_with_depends_on(network, depends_on)
    resolved_threat_tier: _ir.ThreatTier | None
    if isinstance(threat_tier, str):
        # Accept the string form for ergonomics. The lower-layer
        # `ThreatTier` is a Union of single-variant enums (one per
        # value) — `_resolve_union_member` walks the variants and
        # returns the matching one.
        resolved_threat_tier = _resolve_union_member(_ir.ThreatTier, threat_tier)
    else:
        resolved_threat_tier = threat_tier
    resolved_hooks: _ir.Hooks | None = None
    bb = _resolve_hook_kwarg(before_build, "before_build")
    bs = _resolve_hook_kwarg(before_start, "before_start")
    af = _resolve_hook_kwarg(after_start, "after_start")
    bp = _resolve_hook_kwarg(before_stop, "before_stop")
    if any(phase is not None for phase in (bb, bs, af, bp)):
        resolved_hooks = _ir.Hooks(
            before_build=bb,
            before_start=bs,
            after_start=af,
            before_stop=bp,
        )

    record = _ir.App(
        entrypoints=resolved_entrypoints,
        image=image,
        name=name,
        resources=resources,
        source=source,
        env=env if env is not None else {},
        mounts=mounts if mounts is not None else [],
        network=resolved_network,
        dependencies=dependencies,
        addons=list(addons) if addons else None,
        threat_tier=resolved_threat_tier,
        hooks=resolved_hooks,
    )
    _state["apps"].append(record)

    workload_id = _state["workload_id"]
    primary_entry = next(
        (
            ep
            for ep in resolved_entrypoints
            if isinstance(ep, _ir.Entrypoint2)
            and getattr(ep, "primary", False)
        ),
        None,
    )
    if primary_entry is None:
        # Fall back to the first function entry (single-entrypoint
        # apps don't need to set `primary=True` explicitly).
        primary_entry = next(
            (ep for ep in resolved_entrypoints if isinstance(ep, _ir.Entrypoint2)),
            None,
        )
    is_function = primary_entry is not None
    fmt = primary_entry.format.value if is_function else None

    def _wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
        if is_function and workload_id is not None:
            return RemoteFunction(fn, workload_id=workload_id, format=fmt)
        return fn

    return _wrap


def local_path(
    path: str,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> _ir.Source1:
    """Declare a local source tree to copy into the VM."""
    return _ir.Source1(
        kind=_kind_value(_ir.Source1, "local_path"),
        path=path,
        include=include if include is not None else ["**"],
        exclude=exclude if exclude is not None else [],
    )


def nix_packages(packages: list[str]) -> _ir.Image1:
    """Declare a nixpkgs-based image."""
    return _ir.Image1(
        kind=_kind_value(_ir.Image1, "nix_packages"),
        packages=list(packages),
    )


def python_image(
    *,
    python: str = "3.12",
    packages: list[str] | None = None,
) -> _ir.Image1:
    """Convenience over :func:`nix_packages` — start with the Python
    interpreter at the requested minor version (``python3.12`` → nix
    attribute ``python312``) and add any extra system packages.

    Mirrors the ``mvm.python_image`` helper recognized by the host-side
    static decorator parser (Phase 4) so the same call site validates
    under both the in-process SDK and the AST-walking compiler.
    """
    pkgs = [f"python{python.replace('.', '')}"]
    pkgs.extend(packages or [])
    return nix_packages(pkgs)


def node_image(
    *,
    node: str = "22",
    packages: list[str] | None = None,
) -> _ir.Image1:
    """Convenience over :func:`nix_packages` — start with the Node.js
    interpreter at the requested major version (``node="22"`` → nix
    attribute ``nodejs_22``) and add any extra system packages.
    """
    pkgs = [f"nodejs_{node}"]
    pkgs.extend(packages or [])
    return nix_packages(pkgs)


def hook(cmd: str | list[str]) -> _ir.HookCmd:
    """Build a lifecycle-hook command.

    Pass a string for a shell line (``mvm.hook("echo hi")``) or a list
    of strings for an exec-style argv (``mvm.hook(["python", "-m",
    "migrate"])``). The result slots into ``before_build`` /
    ``before_start`` / ``after_start`` / ``before_stop`` kwargs on
    :func:`app`. The host-side parser (Phase 4) recognizes the same
    surface so a literal ``mvm.hook(...)`` call site round-trips
    cleanly through both routes.
    """
    if isinstance(cmd, str):
        return _ir.HookCmd1(
            kind=_kind_value(_ir.HookCmd1, "shell"),
            line=cmd,
        )
    if isinstance(cmd, list) and all(isinstance(s, str) for s in cmd):
        return _ir.HookCmd2(
            argv=list(cmd),
            kind=_kind_value(_ir.HookCmd2, "argv"),
        )
    raise TypeError(
        f"mvm.hook expects a string (shell) or list[str] (argv); got {type(cmd).__name__}"
    )


def literal(value: str) -> _ir.EnvValue1:
    """Wrap a string as an explicit literal env value. Equivalent to
    passing the string directly in an ``env={...}`` mapping — the
    wrapper exists for parity with :func:`secret` and for callers that
    want to be unambiguous.
    """
    return _ir.EnvValue1(
        kind=_kind_value(_ir.EnvValue1, "literal"),
        value=value,
    )


def secret(
    name: str,
    *,
    type: str,
    hosts: list[str],
    var: str | None = None,
) -> _ir.EnvValue2:
    """Reference a named secret from the host keystore for egress
    substitution (ADR-023 / Plan 129). The guest only ever receives an
    opaque placeholder in the env var ``var`` (defaults to ``name``); the
    host substitution endpoint injects/signs the real credential on
    outbound requests and never lets it enter the guest.

    ``type`` is how the credential authenticates the request — one of
    ``bearer`` / ``basic`` / ``sigv4`` / ``hmac``. ``hosts`` is the
    allow-list of destinations the substituted credential may reach
    (claim 12); ``*.`` subdomain wildcards are supported. Both are
    required — an egress secret with no declared destination or auth
    type can't be bound, and the resolver fails closed on an empty host
    list.
    """
    try:
        auth = _ir.AuthType(type)
    except ValueError:
        allowed = ", ".join(t.value for t in _ir.AuthType)
        raise ValueError(f"secret type must be one of {{{allowed}}}, got {type!r}") from None
    if not hosts:
        raise ValueError("secret hosts must be non-empty (claim 12: a secret must be bound to a destination)")
    return _ir.EnvValue2(
        kind=_kind_value(_ir.EnvValue2, "secret_ref"),
        ref=_ir.SecretRef(
            allowed_hosts=list(hosts),
            auth_type=auth,
            mount=_ir.SecretMount1(
                kind=_kind_value(_ir.SecretMount1, "env"),
                var=var if var is not None else name,
            ),
            name=name,
        ),
    )


def _resolve_hook_kwarg(
    raw: str | list[str] | _ir.HookCmd | list[_ir.HookCmd] | None,
    phase: str,
) -> list[_ir.HookCmd] | None:
    """Normalize the four hook-kwargs into the IR's ``Hooks.<phase>``
    shape. Accepts:

    - ``None`` → no commands for this phase.
    - A string → single Shell command.
    - A flat list of strings → single Argv command (one argv-style
      invocation; mirrors the host-side parser rule).
    - A single :class:`HookCmd` (from :func:`hook`) → length-1 list.
    - A list of :class:`HookCmd` → passed through as-is. Bare strings
      inside the list are lowered to Shell commands so users can mix
      shorthand with explicit :func:`hook` calls.
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        return [hook(raw)]
    if isinstance(raw, list):
        if all(isinstance(s, str) for s in raw):
            return [hook(list(raw))]
        out: list[_ir.HookCmd] = []
        for item in raw:
            if isinstance(item, str):
                out.append(hook(item))
            elif isinstance(item, list):
                out.append(hook(item))
            elif isinstance(item, (_ir.HookCmd1, _ir.HookCmd2)):
                out.append(item)
            else:
                raise TypeError(
                    f"app({phase}=...): list elements must be str, list[str], or mvm.hook(...); "
                    f"got {type(item).__name__}"
                )
        return out
    if isinstance(raw, (_ir.HookCmd1, _ir.HookCmd2)):
        return [raw]
    raise TypeError(
        f"app({phase}=...): expected str, list, or mvm.hook(...); got {type(raw).__name__}"
    )


def entrypoint(
    *,
    command: list[str],
    working_dir: str = "/app",
    env: dict[str, Any] | None = None,
) -> _ir.Entrypoint:
    """Declare a command-style app entrypoint (legacy / non-function shape).

    The wrapper exec's ``command`` once at boot. For function-call workloads
    (plan 0003 / ADR-0009), use :func:`entrypoint_function` instead.
    """
    if not command:
        raise ValueError("entrypoint command must have at least one element")
    return _ir.Entrypoint1(
        command=list(command),
        kind=_kind_value(_ir.Entrypoint1, "command"),
        env=env if env is not None else {},
        working_dir=working_dir,
    )


def entrypoint_function(
    *,
    module: str,
    function: str,
    language: str = "python",
    format: str = "json",
    working_dir: str = "/app",
    env: dict[str, Any] | None = None,
    args_schema: dict[str, Any] | None = None,
    return_schema: dict[str, Any] | None = None,
    extra_imports: list[str] | None = None,
    primary: bool = False,
    concurrency: _ir.Concurrency | None = None,
) -> _ir.Entrypoint:
    """Declare a function-call entrypoint (plan 0003 / ADR-0009).

    The image bakes ``mvm-runtime`` at ``/usr/lib/mvm/wrappers/runner``
    (with ``/etc/mvm/entrypoint`` pointing at it). At call time the runtime
    reads stdin, dispatches ``module:function`` per the declared ``format``,
    and writes the return on stdout. The host SDK calls
    ``mvmctl invoke <workload> --stdin <encoded>``.

    ``language`` selects which Nix factory mvm dispatches to when
    compiling the entrypoint into a rootfs derivation (per ADR-0010 §4).
    Defaults to ``"python"`` since this is the Python SDK; override
    explicitly when using this SDK as a manifest-authoring tool to
    produce a workload in a different language. The host validator
    rejects unknown values with ``E_UNSUPPORTED_LANGUAGE``.

    ``format`` is the wire format for stdin/stdout: ``"json"`` (default,
    debugs cleanly with ``cat``) or ``"msgpack"`` (opt-in, byte-/float-
    fidelity). Code-executing serializer formats are forbidden by ADR-0009.
    """
    if not module:
        raise ValueError("entrypoint_function module must be a non-empty string")
    if not function:
        raise ValueError("entrypoint_function function must be a non-empty string")
    if format not in ("json", "msgpack"):
        raise ValueError(
            f"entrypoint_function format must be 'json' or 'msgpack', got {format!r}"
        )
    # Format is a Union of single-variant enums; resolve the right member
    # by walking union members and picking the one that accepts our value.
    # ``language`` is a plain string passed through; the host validator
    # checks it against the supported-language allowlist.
    fmt_enum = _resolve_union_member(_ir.Format, format)
    ep = _ir.Entrypoint2(
        format=fmt_enum,
        function=function,
        kind=_kind_value(_ir.Entrypoint2, "function"),
        language=language,
        module=module,
        env=env if env is not None else {},
        working_dir=working_dir,
        extra_imports=list(extra_imports) if extra_imports else [],
        primary=primary,
        concurrency=concurrency,
    )
    # The generated `JsonSchemaShape` lower-layer type is an open
    # object. Assign raw dicts directly — `_to_plain` walks them
    # natively, and the canonical-IR layer handles them as
    # serde_json::Map on the Rust side.
    if args_schema is not None:
        ep.args_schema = args_schema  # type: ignore[assignment]
    if return_schema is not None:
        ep.return_schema = return_schema  # type: ignore[assignment]
    return ep


def _resolve_union_member(union_alias: Any, value: str) -> Any:
    """Construct a member of a ``Union[Enum, Enum, ...]`` from a string.

    Each generated single-variant enum accepts only its specific value.
    We walk the union members and pick the one whose constructor accepts
    ``value``. Handles the codegen pattern where a closed enum becomes
    `Union[FormatN, FormatM, ...]`.
    """
    args = typing.get_args(union_alias)
    for member in args:
        try:
            return member(value)
        except (ValueError, KeyError):
            continue
    raise ValueError(
        f"value {value!r} did not match any member of {union_alias!r}"
    )


def resources(*, cpu_cores: int, memory_mb: int, rootfs_size_mb: int) -> _ir.Resources:
    """Declare app resource requirements."""
    return _ir.Resources(
        cpu_cores=cpu_cores,
        memory_mb=memory_mb,
        rootfs_size_mb=rootfs_size_mb,
    )





# The placeholder `sha256` an unlocked addon use carries until
# `mvm addon lock` resolves it. Mirrored by `UNRESOLVED_SHA256` in the
# Rust ctor and the TypeScript `_addon.ts`; the s27 golden IR document
# pins all three against each other.
_UNRESOLVED_SHA256 = "0" * 64


def addon_use(
    name: str,
    *,
    version: str | None = None,
    path: str | None = None,
    alias: str | None = None,
    sha256: str | None = None,
    params: dict[str, Any] | None = None,
    tier: str = "separate",
) -> _ir.AddonUse:
    """Declare a use of a published addon (ADR-0018).

    Pass either ``version=`` for a registry-resolved addon::

        mvm.addon_use("postgres", version="16", alias="db")

    or ``path=`` for a local-path addon during development::

        mvm.addon_use("my-db", path="./addons/my-db", alias="db")

    ``sha256`` is optional at SDK time; the canonical placeholder
    (64 zero hex chars) is replaced by ``mvm addon lock`` when the
    consumer runs the resolver. Until then, downstream tooling uses the
    placeholder as a marker for "needs locking."
    """
    if (version is None) == (path is None):
        raise ValueError(
            "mv.addon_use(): pass exactly one of `version=` (registry) "
            "or `path=` (local-path)"
        )
    if version is not None:
        ref: _ir.AddonRef = _ir.AddonRef1(
            kind=_kind_value(_ir.AddonRef1, "registry"),
            url=f"addons.mvm.io/{name}",
            version=version,
        )
    else:
        ref = _ir.AddonRef2(
            kind=_kind_value(_ir.AddonRef2, "local"),
            path=path,  # type: ignore[arg-type]
        )
    return _ir.AddonUse(
        name=name,
        alias=alias,
        tier=_ir.AddonTier(tier),
        ref=ref,
        sha256=sha256 if sha256 is not None else _UNRESOLVED_SHA256,
        params=dict(params) if params else None,
    )



def derive_schema(
    fn: Callable[..., Any],
    *,
    return_only: bool = False,
) -> dict[str, Any]:
    """Derive a JSON Schema from a function's type hints (plan-0009 v2).

    Requires the ``schema`` extra installed (``pip install
    'mvm[schema]'``). Returns a JSON-Schema-shaped dict suitable
    for ``args_schema=`` or ``return_schema=`` on
    :func:`entrypoint_function`.

    By default, derives from the *parameter* signature: every
    annotated parameter becomes a property of an object schema, with
    `required` set to those without defaults. Pass ``return_only=True``
    to derive from the return annotation instead.

    Type hints supported (via pydantic): primitives, ``list[T]``,
    ``dict[str, T]``, ``Optional[T]``, ``Literal[...]``, ``Union[...]``,
    pydantic ``BaseModel`` subclasses, dataclasses, and ``TypedDict``.
    Anything pydantic can ``TypeAdapter`` will work; everything else
    raises a clear error.
    """
    try:
        import pydantic
    except ImportError as exc:
        raise ImportError(
            "mvm.derive_schema requires pydantic; install with "
            "`pip install 'mvm[schema]'` or pass an explicit "
            "args_schema=/return_schema= dict instead."
        ) from exc

    import inspect

    sig = inspect.signature(fn)
    if return_only:
        ret = sig.return_annotation
        if ret is inspect.Signature.empty:
            raise TypeError(
                f"{fn.__qualname__} has no return annotation; "
                "annotate the return type or pass an explicit return_schema= dict."
            )
        adapter = pydantic.TypeAdapter(ret)
        return adapter.json_schema()

    fields: dict[str, Any] = {}
    required: list[str] = []
    for name, param in sig.parameters.items():
        if param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            raise TypeError(
                f"{fn.__qualname__} uses *args / **kwargs which can't be "
                "expressed in a closed schema; pass an explicit args_schema= dict."
            )
        if param.annotation is inspect.Parameter.empty:
            raise TypeError(
                f"{fn.__qualname__} parameter {name!r} has no type annotation; "
                "annotate it or pass an explicit args_schema= dict."
            )
        adapter = pydantic.TypeAdapter(param.annotation)
        fields[name] = adapter.json_schema()
        if param.default is inspect.Parameter.empty:
            required.append(name)
    schema: dict[str, Any] = {"type": "object", "properties": fields}
    if required:
        schema["required"] = required
    schema["additionalProperties"] = False
    return schema


def ai_budget(
    *,
    max_input_tokens: int | None = None,
    max_output_tokens: int | None = None,
    max_total_tokens: int | None = None,
) -> _ir.AiBudget:
    """Token budget for AI egress metering.

    Each limit is independent. A `None` field means no limit for that
    category. The budget is enforced best-effort at response time: the
    request that crosses the threshold is still allowed through and
    recorded, and the *next* AI request is refused.
    """
    return _ir.AiBudget(
        max_input_tokens=max_input_tokens,
        max_output_tokens=max_output_tokens,
        max_total_tokens=max_total_tokens,
    )


def ai_policy(
    *,
    metering: bool = True,
    budget: _ir.AiBudget | None = None,
) -> _ir.AiPolicy:
    """AI egress metering/budget policy for `mvm.network(...)`.

    `metering` enables per-VM token counting for known AI providers.
    `budget` optionally refuses further AI requests once exceeded.
    """
    return _ir.AiPolicy(metering=metering, budget=budget)


def network(
    *,
    mode: str = "none",
    ports: list[_ir.PortForward] | None = None,
    egress: _ir.NetworkEgress | None = None,
    peers: list[str] | None = None,
    dns: _ir.NetworkDns | None = None,
    ai: _ir.AiPolicy | None = None,
) -> _ir.Network:
    """Declare an app's network posture (plan-0004 §Phase 5).

    `mode` is the high-level toggle: `"none"`, `"bridge"`, or
    `"host"` (host is rejected for function-entrypoint workloads).
    `egress` / `peers` / `dns` layer granular grants on top. Applications
    use the guest loopback HTTP proxy, SOCKS5h/UDP, controlled DNS, mediated
    ping, or typed connectors; direct raw networking is unsupported.

    `ai` attaches an optional AI egress metering and budget policy to the
    network posture. When set, the host records token usage for known AI
    providers and refuses further AI requests once the budget is exceeded.
    """
    # `NetworkMode` is `Union[NetworkMode1, NetworkMode2]`, and a Union is
    # not callable — constructing it raised TypeError for every caller.
    # Resolve against the enum arm rather than the union: `NetworkMode2` is
    # a dataclass, so it would accept any string positionally and turn a
    # typo into a `custom` provider instead of the error promised below.
    try:
        mode_enum = _ir.NetworkMode1(mode)
    except ValueError as exc:
        raise ValueError(
            f"network mode must be 'none' / 'bridge' / 'host', got {mode!r}"
        ) from exc
    return _ir.Network(
        mode=mode_enum,
        ports=ports if ports is not None else [],
        egress=egress,
        peers=list(peers) if peers else [],
        dns=dns,
        ai=ai,
    )


_DEFAULT_PYTHON_IMAGE_PACKAGES: tuple[str, ...] = ("python312",)
_DEFAULT_RESOURCES = (1, 256, 512)  # cpu_cores, memory_mb, rootfs_size_mb
# Captured at module-load time so the kwarg `resources=` in `func()`
# below doesn't shadow the function-name lookup.
_make_resources = resources


def func(
    *,
    name: str,
    image: _ir.Image1 | None = None,
    resources: _ir.Resources | None = None,
    module: str | None = None,
    function: str | None = None,
    language: str = "python",
    format: str = "json",
    source: _ir.Source1 | None = None,
    working_dir: str = "/app",
    env: dict[str, Any] | None = None,
    network: _ir.Network | None = None,
    mounts: list[_ir.Mount] | None = None,
    dependencies: _ir.Dependencies | None = None,
    args_schema: dict[str, Any] | None = None,
    return_schema: dict[str, Any] | None = None,
    extra_imports: list[str] | None = None,
    depends_on: list[WorkloadRef] | None = None,
    primary: bool | None = None,
    concurrency: _ir.Concurrency | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Workload + app + function-entrypoint shortcut (plan-0010 phase A + W14).

    Single decorator factory that registers the workload identity, the
    single-app, and the function entrypoint in one call. The minimum
    viable shape is a single kwarg::

        @mv.func(name="adder")
        async def add(a: int, b: int) -> int:
            return a + b

        await add(2, 3)      # remote dispatch
        add.local(2, 3)      # in-process body
        add.sync(2, 3)       # sync escape

    Defaults (per W14 — every kwarg below has a sane fallback so a
    starter workload is one decorator + one function body):

    - ``image`` — ``nix_packages(["python312"])``. Override for older
      Python or to add extra system packages
      (e.g. ``mv.nix_packages(["python312", "ffmpeg"])``).
    - ``resources`` — ``resources(cpu_cores=1, memory_mb=256,
      rootfs_size_mb=512)``. Bump for memory-hungry workloads.
    - ``module`` — inferred from ``fn.__module__``. Rejected if the entry
      runs as ``__main__`` (running ``python entry.py`` vs
      ``python -m pkg.entry`` would otherwise drift the IR; pass
      ``module=`` explicitly to keep emit deterministic).
    - ``function`` — inferred from ``fn.__name__``.
    - ``language`` — ``"python"`` (this SDK). Override for cross-language
      manifest authoring.
    - ``source`` — ``local_path(".")``. The host resolves this against
      the manifest file's directory at compile time, so the bundled tree
      is the entry module's directory (NOT cwd).
    - ``dependencies`` — ``no_deps()``. Override with
      ``mv.python_deps(lockfile="uv.lock")`` for non-stdlib workloads.

    For multi-app workloads or finer-grained control, use the long form:
    ``workload({id}) + app({...}, entrypoint=entrypoint_function(...))``.
    """

    def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        resolved_module = module
        if resolved_module is None:
            inferred = fn.__module__
            if inferred == "__main__":
                raise ValueError(
                    "mv.func: cannot auto-infer `module` because fn.__module__ "
                    "is '__main__'. Pass `module=` explicitly so the emitted IR "
                    "is deterministic across `python entry.py` and "
                    "`python -m pkg.entry` invocation styles."
                )
            resolved_module = inferred

        resolved_function = function or getattr(fn, "__name__", "")
        if not resolved_function:
            raise ValueError(
                "mv.func: cannot auto-infer `function` from the local fn; "
                "pass `function=` explicitly."
            )

        # Default source: the entry module's directory (host resolves
        # `.` relative to manifest_dir at compile time, which IS the
        # entry module's directory). This avoids the cwd-as-source
        # foot-gun where running from $HOME would scope $HOME.
        resolved_source = source if source is not None else local_path(".")
        resolved_deps = dependencies if dependencies is not None else no_deps()
        resolved_image = (
            image
            if image is not None
            else nix_packages(list(_DEFAULT_PYTHON_IMAGE_PACKAGES))
        )
        if resources is None:
            cpu, mem, rootfs = _DEFAULT_RESOURCES
            resolved_resources = _make_resources(
                cpu_cores=cpu, memory_mb=mem, rootfs_size_mb=rootfs
            )
        else:
            resolved_resources = resources

        # Register the workload identity if the user hasn't already.
        if _state["workload_id"] is None:
            workload(id=name)

        # ADR-0014 Phase 2: a second `@mv.func(name="X", ...)` against
        # a workload whose app `name` already exists extends the
        # existing app's `entrypoints` list rather than registering a
        # new app. This is how multi-function workloads are authored.
        existing_app = next(
            (a for a in _state["apps"] if a.name == name),
            None,
        )
        # Default `primary`: the first entrypoint declared for an app
        # is primary; subsequent ones are not (unless explicitly
        # overridden). User-supplied `primary=` always wins.
        if primary is None:
            resolved_primary = existing_app is None or not any(
                isinstance(ep, _ir.Entrypoint2) and getattr(ep, "primary", False)
                for ep in (existing_app.entrypoints if existing_app else [])
            )
        else:
            resolved_primary = primary

        ep = entrypoint_function(
            module=resolved_module,
            function=resolved_function,
            language=language,
            format=format,
            working_dir=working_dir,
            env=env,
            args_schema=args_schema,
            return_schema=return_schema,
            extra_imports=extra_imports,
            primary=resolved_primary,
            concurrency=concurrency,
        )

        if existing_app is not None:
            # Extend the existing app's entrypoints. Image / resources /
            # source / network / dependencies are inherited from the
            # first registration; passing them again on subsequent
            # decorations is rejected so the user can't "split" an app
            # across mismatched declarations.
            for label, value in (
                ("image", image),
                ("resources", resources),
                ("source", source),
                ("dependencies", dependencies),
                ("env", env),
                ("mounts", mounts),
                ("network", network),
                ("depends_on", depends_on),
            ):
                if value is not None:
                    raise ValueError(
                        f"mv.func(name={name!r}, ...): app already registered "
                        f"in this workload — repeated decoration may only add "
                        f"new entrypoints. Drop `{label}=` from this call (or "
                        f"the previous `mv.func` call). Authored shape: app-"
                        f"level config goes on the FIRST decoration; subsequent "
                        f"decorations contribute additional entrypoints."
                    )
            existing_app.entrypoints.append(ep)
            # Inherit format from primary; if a non-primary entrypoint
            # has a different format that's a real conflict (the
            # wrapper can only speak one wire format).
            primary_fmt = next(
                (
                    e.format.value
                    for e in existing_app.entrypoints
                    if isinstance(e, _ir.Entrypoint2) and getattr(e, "primary", False)
                ),
                ep.format.value,
            )
            return RemoteFunction(fn, workload_id=name, format=primary_fmt)

        # First decoration for this app — full app() registration.
        decorator = app(
            name=name,
            source=resolved_source,
            image=resolved_image,
            entrypoint=ep,
            resources=resolved_resources,
            env=env,
            mounts=mounts,
            network=network,
            dependencies=resolved_deps,
            depends_on=depends_on,
        )
        return decorator(fn)

    return _decorator


def _build_workload() -> _ir.Workload:
    if _state["workload_id"] is None:
        raise RuntimeError("workload(id=...) must be called before emit")
    if not _state["apps"]:
        raise RuntimeError("at least one @app(...) registration is required")
    return _ir.Workload(
        apps=list(_state["apps"]),
        id=_state["workload_id"],
        schema_version=SCHEMA_VERSION,
        extensions={},
        volumes=[],
    )


def _to_plain(obj: Any) -> Any:
    """Recursively convert a lower-layer IR tree to JSON-native Python values.

    Enums unwrap to their string value. Dataclasses unwrap to dicts. This is
    the bridge between dataclass instances and ``json.dumps``.

    Fields in :data:`_SKIP_IF_NONE_FIELDS` are omitted entirely when their
    value is ``None``. Mirrors the Rust IR's ``#[serde(skip_serializing_if =
    "Option::is_none")]`` for additive fields whose absence preserves
    byte-identity with legacy IR (ADR-0018: ``addons`` + ``threat_tier``).
    """
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            value = getattr(obj, f.name)
            if value is None and f.name in _SKIP_IF_NONE_FIELDS:
                continue
            out[f.name] = _to_plain(value)
        return out
    if isinstance(obj, dict):
        return {k: _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_plain(x) for x in obj]
    return obj


# Fields the Rust IR skip-serializes when empty/absent (skip-if-none /
# skip-if-empty). Emitting them as JSON ``null`` is not equivalent: the Rust
# `Workload` deserializer rejects ``null`` for the non-`Option` fields
# (``hooks`` is a struct, ``files`` a list), so a null here makes the emitted
# IR fail to round-trip through the host. Omitting them when unset keeps
# ``emit_json`` deserializable and canonical — the same content identity a
# TypeScript- or Rust-emitted document resolves to. ``alias``/``params``
# belong to AddonUse.
_SKIP_IF_NONE_FIELDS: frozenset[str] = frozenset(
    {
        "addons",
        "threat_tier",
        "hooks",
        "files",
        "health_check",
        "alias",
        "params",
    }
)


def emit_json() -> str:
    """Return the currently-registered workload serialized as canonical JSON.

    Output follows RFC 8785 for the integer-only v0 IR (sorted keys, no
    whitespace, standard string escaping). The host re-canonicalizes on
    receipt (per ADR-0002), so this matches host output byte-for-byte.
    """
    workload = _build_workload()
    plain = _to_plain(workload)
    return json.dumps(plain, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
