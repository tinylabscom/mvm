"""Check the Python examples in the documentation against the real SDK.

A Python snippet in the docs is an API claim in exactly the way a Rust snippet
is, but nothing type-checks it. The compiler equivalent here is two questions,
both answerable without running the reader's code:

  1. does it parse, and
  2. does every ``mvm`` attribute it names actually exist on the module?

Attribute resolution is alias-aware (``import mvm as mv``) and covers
``from mvm import ...`` too. Argument *names* are checked for the decorators
that take keyword-only declarations, because a renamed keyword is the drift
that silently produces a wrong workload rather than an error.

Reads a JSON array of ``{file, line, body}`` on stdin and writes a JSON array
of findings on stdout. Exit status is 0 whether or not there are findings; the
caller decides what a finding means.
"""

from __future__ import annotations

import ast
import inspect
import json
import sys

import mvm


def module_aliases(tree: ast.AST) -> set[str]:
    """Names that refer to the ``mvm`` module inside this snippet."""
    aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "mvm":
                    aliases.add(alias.asname or "mvm")
    return aliases


def direct_imports(tree: ast.AST) -> list[tuple[str, int]]:
    """``from mvm import X`` names, with the line each appears on."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "mvm":
            for alias in node.names:
                if alias.name != "*":
                    found.append((alias.name, node.lineno))
    return found


def attribute_uses(tree: ast.AST, aliases: set[str]) -> list[tuple[str, int]]:
    """``mvm.X`` / ``mv.X`` accesses, with the line each appears on."""
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in aliases
        ):
            found.append((node.attr, node.lineno))
    return found


def calls(tree: ast.AST, aliases: set[str]) -> list[tuple[str, ast.Call, int]]:
    """``mvm.<callable>(...)`` call sites, with the line each appears on."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in aliases
        ):
            found.append((func.attr, node, node.lineno))
    return found


def missing_required(target, call: ast.Call) -> list[str]:
    """Required keyword-only parameters the call site never supplies.

    Only meaningful when the call passes no positional arguments and no
    ``**kwargs``; otherwise the missing name may well be supplied and this
    would invent a finding.
    """
    if call.args or any(k.arg is None for k in call.keywords):
        return []
    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        return []
    supplied = {k.arg for k in call.keywords}
    missing = []
    for parameter in signature.parameters.values():
        if parameter.default is not inspect.Parameter.empty:
            continue
        if parameter.kind not in (
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            continue
        if parameter.name not in supplied:
            missing.append(parameter.name)
    return missing


def keyword_uses(tree: ast.AST, aliases: set[str]) -> list[tuple[str, str, int]]:
    """Keyword arguments passed to an ``mvm.<callable>(...)`` call."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Unwrap `@mvm.app(...)` used as a decorator factory.
        if not (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in aliases
        ):
            continue
        for keyword in node.keywords:
            if keyword.arg:
                found.append((func.attr, keyword.arg, node.lineno))
    return found


def accepts_keyword(target, name: str) -> bool:
    """Whether ``target`` accepts ``name`` as a keyword argument."""
    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        return True  # Not introspectable; do not invent a finding.
    for parameter in signature.parameters.values():
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            return True
        if parameter.name == name and parameter.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            return True
    return False


def check(block: dict) -> list[dict]:
    findings = []
    # A snippet's own line numbers are relative to the block; the block starts
    # one line after its opening fence.
    base = block["line"]

    def at(offset: int) -> int:
        return base + offset

    try:
        tree = ast.parse(block["body"])
    except SyntaxError as error:
        return [
            {
                "file": block["file"],
                "line": at(error.lineno or 1),
                "kind": "syntax",
                "detail": str(error.msg),
            }
        ]

    aliases = module_aliases(tree)
    if not aliases and not direct_imports(tree):
        return findings  # Not an SDK snippet; parsing is all we can assert.

    for name, line in direct_imports(tree):
        if not hasattr(mvm, name):
            findings.append(
                {
                    "file": block["file"],
                    "line": at(line),
                    "kind": "missing-name",
                    "detail": f"`from mvm import {name}` — no such name in the SDK",
                }
            )

    for name, line in attribute_uses(tree, aliases):
        if not hasattr(mvm, name):
            findings.append(
                {
                    "file": block["file"],
                    "line": at(line),
                    "kind": "missing-attribute",
                    "detail": f"`mvm.{name}` does not exist in the SDK",
                }
            )

    for callee, call, line in calls(tree, aliases):
        target = getattr(mvm, callee, None)
        if target is None:
            continue  # Already reported as a missing attribute.
        absent = missing_required(target, call)
        if absent:
            listed = ", ".join(f"{name}=" for name in absent)
            findings.append(
                {
                    "file": block["file"],
                    "line": at(line),
                    "kind": "missing-argument",
                    "detail": f"`mvm.{callee}(...)` requires {listed}",
                }
            )

    for callee, keyword, line in keyword_uses(tree, aliases):
        target = getattr(mvm, callee, None)
        if target is None:
            continue  # Already reported as a missing attribute.
        if not accepts_keyword(target, keyword):
            findings.append(
                {
                    "file": block["file"],
                    "line": at(line),
                    "kind": "unknown-keyword",
                    "detail": f"`mvm.{callee}(...)` takes no `{keyword}=` argument",
                }
            )

    return findings


def main() -> int:
    blocks = json.load(sys.stdin)
    findings = []
    for block in blocks:
        findings.extend(check(block))
    json.dump(findings, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
