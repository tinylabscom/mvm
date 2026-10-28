"""Author a ``mvm.pack-spec/v1`` document.

```python
from mvm.packs import pack

spec = (
    pack("acme/hello", "1.0.0")
    .target("aarch64-linux")
    .source(".")
    .package("busybox")
    .copy("hello.txt", "/app/hello.txt")
    .entrypoint("cat", "/app/hello.txt")
    .resources(cpu_cores=1, memory_mib=128)
)
spec.write("pack.json")
```

The builder only assembles and validates authored data. It never resolves a
package, reads the source tree, builds, boots or signs: ``mvmctl pack lock``,
``mvmctl pack compile`` and ``mvmctl build`` do that in the shared Rust
path, reading the file this writes as data. The bytes :meth:`Pack.to_json`
returns are the same canonical bytes every language SDK emits for the same
spec, so a lock's ``spec_sha256`` does not depend on which language wrote it.

A failure raises :class:`PackSpecError`, whose ``code`` is the same stable
string every other language SDK reports for the same mistake.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Optional

#: The only authored schema this SDK writes.
PACK_SPEC_SCHEMA = "mvm.pack-spec/v1"

TARGETS = ("aarch64-linux", "x86_64-linux")
SCOPES = ("build", "runtime")
PYTHON_TOOLS = ("uv", "pip_tools")
NODE_TOOLS = ("npm", "pnpm", "yarn")

_MAX_PATH_BYTES = 4096
_MAX_TOKEN_BYTES = 128
_MAX_VERSION_BYTES = 128
_MAX_CPU_CORES = 65535
_MAX_MEMORY_MIB = 4294967295
_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_COMPONENT = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
_DIGITS = frozenset("0123456789")


class PackSpecError(ValueError):
    """An authoring mistake. ``code`` is shared by every language SDK; ``field``
    names the missing field for ``code == "missing"``."""

    def __init__(self, code: str, message: str, field: Optional[str] = None) -> None:
        super().__init__(message)
        self.code = code
        self.field = field


def pack(name: str, version: str) -> "Pack":
    """Start a pack named ``namespace/name`` at a SemVer 2.0 ``version``."""
    return Pack(name, version)


@dataclass(frozen=True)
class _Package:
    name: str
    version: Optional[str]
    scope: str


@dataclass(frozen=True)
class _DependencyFiles:
    kind: str
    tool: str
    manifest: str
    lockfile: str


class Pack:
    """Fluent PackSpec builder. Adding calls append in call order; setting
    calls replace. Every method returns the builder."""

    def __init__(self, name: str, version: str) -> None:
        self._name = name
        self._version = version
        self._target: Optional[str] = None
        self._source: Optional[str] = None
        self._packages: list[_Package] = []
        self._dependencies: list[_DependencyFiles] = []
        self._copy: list[tuple[str, str]] = []
        self._entrypoint: Optional[list[str]] = None
        self._resources: Optional[tuple[int, int]] = None

    def target(self, target: str) -> "Pack":
        """The guest target: ``aarch64-linux`` or ``x86_64-linux``. Required;
        never inferred from the author's host."""
        self._target = target
        return self

    def source(self, path: str) -> "Pack":
        """The local source tree, relative to the spec's directory (``.`` for
        that directory itself)."""
        self._source = path
        return self

    def package(self, name: str, version: Optional[str] = None, scope: str = "runtime") -> "Pack":
        """Request a generic package. Nothing about a package implies a language
        runtime; ``version`` requests an exact spelling, not a range."""
        self._packages.append(_Package(name, version, scope))
        return self

    def dependencies(self, tool: str, manifest: str, lockfile: str) -> "Pack":
        """A Python manifest and the lockfile ``tool`` (``uv`` or
        ``pip_tools``) produced from it, both relative to the source tree."""
        self._dependencies.append(_DependencyFiles("python", tool, manifest, lockfile))
        return self

    def node_dependencies(self, tool: str, manifest: str, lockfile: str) -> "Pack":
        """A Node package manifest and its integrity-pinned lockfile, written
        by ``tool`` (``npm``, ``pnpm`` or ``yarn``). No Node runtime is
        implied; request one with :meth:`package`."""
        self._dependencies.append(_DependencyFiles("node", tool, manifest, lockfile))
        return self

    def copy(self, source: str, destination: str) -> "Pack":
        """Copy a source-relative file or tree to a guest-absolute destination."""
        self._copy.append((source, destination))
        return self

    def entrypoint(self, *argv: str) -> "Pack":
        """Literal argv. No shell splitting or evaluation; empty later arguments
        are kept."""
        if len(argv) == 1 and isinstance(argv[0], (list, tuple)):
            argv = tuple(argv[0])
        self._entrypoint = list(argv)
        return self

    def resources(self, *, cpu_cores: int, memory_mib: int) -> "Pack":
        """Advisory CPU cores and binary MiB of memory (1 MiB = 1_048_576
        bytes). A launch's own flags and the host's ceilings still apply."""
        self._resources = (cpu_cores, memory_mib)
        return self

    def to_dict(self) -> dict[str, Any]:
        """Assemble and validate the document."""
        target = self._required("target", self._target)
        source = self._required("source", self._source)
        entrypoint = self._required("entrypoint", self._entrypoint)
        cpu_cores, memory_mib = self._required("resources", self._resources)
        _validate_identity(self._name, self._version)
        if target not in TARGETS:
            _fail("target", f"unknown target {target!r}: expected one of {', '.join(TARGETS)}")
        _relative_path(source, allow_root=True)
        packages = [_package_json(p) for p in self._packages]
        dependencies = [_dependency_json(d) for d in self._dependencies]
        copy = [_copy_json(s, d) for s, d in self._copy]
        _validate_entrypoint(entrypoint)
        _validate_resources(cpu_cores, memory_mib)
        return {
            "schema": PACK_SPEC_SCHEMA,
            "identity": {"name": self._name, "version": self._version},
            "target": target,
            "source": {"kind": "local", "path": source},
            "packages": packages,
            "dependencies": dependencies,
            "copy": copy,
            "entrypoint": list(entrypoint),
            "resources": {"cpu_cores": cpu_cores, "memory_mb": memory_mib},
        }

    def to_json(self) -> bytes:
        """The canonical bytes: sorted keys, compact UTF-8, no trailing newline."""
        return canonical_json(self.to_dict())

    def sha256(self) -> str:
        """Lowercase hex SHA-256 of :meth:`to_json`; equals a lock's
        ``spec_sha256``."""
        return hashlib.sha256(self.to_json()).hexdigest()

    def write(self, path: "str | os.PathLike[str]") -> str:
        """Write :meth:`to_json` to ``path`` and return the digest written."""
        data = self.to_json()
        with open(path, "wb") as out:
            out.write(data)
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _required(field: str, value: Any) -> Any:
        if value is None:
            raise PackSpecError("missing", f"pack is missing required field `{field}`", field)
        return value


def canonical_json(document: dict[str, Any]) -> bytes:
    """Compact JSON with every object's keys sorted and lists kept in order,
    escaped the way the Rust contract writes it."""
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _fail(code: str, message: str) -> None:
    raise PackSpecError(code, message)


def _utf8_len(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        _fail("path", "unsafe path: expected valid UTF-8")
        raise AssertionError("unreachable")


def _bad_path() -> None:
    _fail("path", "unsafe path: expected normalized portable path without traversal")


def _relative_path(value: Any, *, allow_root: bool) -> None:
    if not isinstance(value, str):
        _bad_path()
    if allow_root and value == ".":
        return
    if (
        not value
        or _utf8_len(value) > _MAX_PATH_BYTES
        or any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F or c in "\\:" for c in value)
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        _bad_path()


def _is_token(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_TOKEN_BYTES
        and value.isascii()
        and value[0] in _ALNUM
        and all(c in _ALNUM or c in "-_.+" for c in value)
    )


def _component(value: str) -> bool:
    return (
        1 <= len(value) <= 64
        and value[0] in _ALNUM
        and value[-1] in _ALNUM
        and all(c in _COMPONENT for c in value)
    )


def _decimal(value: str) -> bool:
    return bool(value) and (len(value) == 1 or value[0] != "0") and all(c in _DIGITS for c in value)


def _identifier(value: str) -> bool:
    return bool(value) and all(c in _ALNUM or c == "-" for c in value)


def _release_version(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > _MAX_VERSION_BYTES or not value.isascii():
        return False
    version, plus, build = value.partition("+")
    if plus and not all(_identifier(i) for i in build.split(".")):
        return False
    core, dash, prerelease = version.partition("-")
    if dash and not all(
        _identifier(i) and (not all(c in _DIGITS for c in i) or _decimal(i))
        for i in prerelease.split(".")
    ):
        return False
    parts = core.split(".")
    return len(parts) == 3 and all(_decimal(p) for p in parts)


def _validate_identity(name: Any, version: Any) -> None:
    namespace, slash, rest = name.partition("/") if isinstance(name, str) else ("", "", "")
    if not (slash and _component(namespace) and _component(rest)) or not _release_version(version):
        _fail("identity", "invalid pack identity: expected namespace/name and SemVer 2.0 version")


def _package_json(package: _Package) -> dict[str, Any]:
    if not _is_token(package.name) or (package.version is not None and not _is_token(package.version)):
        _fail("package", "invalid package name or version token")
    if package.scope not in SCOPES:
        _fail("package", f"unknown package scope {package.scope!r}: expected build or runtime")
    out: dict[str, Any] = {"name": package.name, "scope": package.scope}
    if package.version is not None:
        out["version"] = package.version
    return out


def _dependency_json(dependency: _DependencyFiles) -> dict[str, Any]:
    tools = PYTHON_TOOLS if dependency.kind == "python" else NODE_TOOLS
    if dependency.tool not in tools:
        _fail(
            "dependency",
            f"unknown {dependency.kind} tool {dependency.tool!r}: expected one of {', '.join(tools)}",
        )
    _relative_path(dependency.manifest, allow_root=False)
    _relative_path(dependency.lockfile, allow_root=False)
    return {
        "kind": dependency.kind,
        "tool": dependency.tool,
        "manifest": dependency.manifest,
        "lockfile": dependency.lockfile,
    }


def _copy_json(source: Any, destination: Any) -> dict[str, str]:
    _relative_path(source, allow_root=True)
    if (
        not isinstance(destination, str)
        or _utf8_len(destination) > _MAX_PATH_BYTES
        or not destination.startswith("/")
    ):
        _bad_path()
    _relative_path(destination[1:], allow_root=False)
    return {"source": source, "destination": destination}


def _validate_entrypoint(argv: Any) -> None:
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(a, str) for a in argv)
        or not argv[0].strip()
        or any("\0" in a for a in argv)
    ):
        _fail("entrypoint", "entrypoint must have a nonempty executable and no NUL bytes")
    for arg in argv:
        _utf8_len(arg)


def _validate_resources(cpu_cores: Any, memory_mib: Any) -> None:
    def integer(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    if not (
        integer(cpu_cores)
        and integer(memory_mib)
        and 1 <= cpu_cores <= _MAX_CPU_CORES
        and 1 <= memory_mib <= _MAX_MEMORY_MIB
    ):
        _fail("resources", "CPU cores and memory MiB must be positive")


__all__ = ["PACK_SPEC_SCHEMA", "Pack", "PackSpecError", "canonical_json", "pack"]
