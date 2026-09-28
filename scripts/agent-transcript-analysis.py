#!/usr/bin/env python3
"""Quantified cross-agent transcript analysis.

Samples N transcripts from each of the three agent stores
(~/.claude/projects, ~/.codex/sessions, ~/.kimi/sessions) and reports:
tool-call volume, tool failure rate, back-to-back duplicate-call retry
loops, session sizes, and per-session command repetition.

Read-only: never writes outside stdout. Used to baseline and re-measure
the agent-efficiency plan (specs/plans/2026-09-28-agent-efficiency-overhaul.md).

Usage: python3 agent-transcript-analysis.py [N]   (default N=40)
"""

import collections
import json
import os
import random
import re
import statistics
import sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 40
random.seed(42)

ERR_RE = re.compile(r"\b(error|failed|failure|panic|exception)\b", re.I)
EXIT_RE = re.compile(r"exited with code ([1-9]\d*)")


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "n/a"


def sample_files(root, n):
    files = []
    for dp, _, fns in os.walk(os.path.expanduser(root)):
        for fn in fns:
            if fn.endswith(".jsonl"):
                files.append(os.path.join(dp, fn))
    random.shuffle(files)
    return files[:n]


def analyze_claude():
    sample = sample_files("~/.claude/projects", N)
    st = collections.Counter()
    tool_names = collections.Counter()
    retry_sessions = 0
    compact_sessions = 0
    ws_mentions = 0
    ws_sessions = 0
    for f in sample:
        try:
            lines = open(f, errors="replace").readlines()
        except OSError:
            continue
        st["sessions"] += 1
        tools, results = [], []
        for line in lines:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = d.get("type")
            if t == "assistant":
                for c in d.get("message", {}).get("content", []):
                    if c.get("type") == "tool_use":
                        tools.append(c.get("name", "?"))
            elif t == "user":
                content = d.get("message", {}).get("content")
                if isinstance(content, list):
                    for c in content:
                        if c.get("type") == "tool_result":
                            results.append(json.dumps(c.get("content", "")))
            if t == "system" and isinstance(d.get("content"), str) and "compact" in d["content"].lower():
                compact_sessions += 1
        st["tool_calls"] += len(tools)
        tool_names.update(tools)
        st["errors"] += sum(1 for r in results if ERR_RE.search(r))
        prev = None
        dups = 0
        for line in lines:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") == "assistant":
                for c in d.get("message", {}).get("content", []):
                    if c.get("type") == "tool_use" and c.get("name") == "Bash":
                        cmd = c.get("input", {}).get("command", "")
                        if cmd and cmd == prev:
                            dups += 1
                        prev = cmd
        if dups >= 2:
            retry_sessions += 1
        st["dups"] += dups
        ws = sum(1 for l in lines if "cargo test --workspace" in l)
        if ws:
            ws_sessions += 1
        ws_mentions += ws
    print("=== CLAUDE ===")
    print(f"sessions: {st['sessions']}, tool calls: {st['tool_calls']}, "
          f"avg {st['tool_calls'] / max(1, st['sessions']):.1f}/session")
    print(f"tool results w/ error keywords: {st['errors']} ({pct(st['errors'], st['tool_calls'])})")
    print(f"sessions w/ >=2 back-to-back duplicate Bash cmds: {retry_sessions} "
          f"({pct(retry_sessions, st['sessions'])}), dups total: {st['dups']}")
    print(f"sessions mentioning compaction: {compact_sessions}")
    print(f"'cargo test --workspace' mentions: {ws_mentions} in {ws_sessions} sessions")
    print("top tools:", tool_names.most_common(8))


def analyze_codex():
    sample = sample_files("~/.codex/sessions", N)
    st = collections.Counter()
    tool_names = collections.Counter()
    retry_sessions = 0
    reasoning = 0
    sizes = []
    for f in sample:
        try:
            sz = os.path.getsize(f)
            fh = open(f, errors="replace")
        except OSError:
            continue
        st["sessions"] += 1
        sizes.append(sz)
        calls = errs = 0
        last_args = None
        dups = 0
        for line in fh:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") != "response_item":
                continue
            p = d.get("payload", {})
            t = p.get("type")
            if t in ("function_call", "custom_tool_call", "web_search_call"):
                calls += 1
                tool_names[p.get("name", t)] += 1
                args = p.get("arguments", "")
                if args == last_args and len(args) > 10:
                    dups += 1
                last_args = args
            elif t in ("function_call_output", "custom_tool_call_output"):
                out = str(p.get("output", ""))
                if EXIT_RE.search(out) or ERR_RE.search(out):
                    errs += 1
            elif t == "reasoning":
                reasoning += 1
        fh.close()
        st["tool_calls"] += calls
        st["errors"] += errs
        st["dups"] += dups
        if dups >= 2:
            retry_sessions += 1
    print("=== CODEX ===")
    print(f"sessions: {st['sessions']}, tool calls: {st['tool_calls']}, "
          f"avg {st['tool_calls'] / max(1, st['sessions']):.1f}/session")
    print(f"tool outputs w/ errors: {st['errors']} ({pct(st['errors'], st['tool_calls'])})")
    print(f"sessions w/ >=2 back-to-back identical calls: {retry_sessions} "
          f"({pct(retry_sessions, st['sessions'])}), dups total: {st['dups']}")
    print(f"reasoning items: {reasoning} (avg {reasoning / max(1, st['sessions']):.0f}/session)")
    if sizes:
        print(f"median size {statistics.median(sizes) / 1e6:.2f} MB, "
              f"max {max(sizes) / 1e6:.1f} MB, >5MB: {sum(1 for s in sizes if s > 5e6)}")
    print("top tools:", tool_names.most_common(10))


def analyze_kimi():
    root = os.path.expanduser("~/.kimi/sessions")
    wires = []
    for dp, _, fns in os.walk(root):
        if "subagents" in dp:
            continue
        for fn in fns:
            if fn == "wire.jsonl":
                wires.append(os.path.join(dp, fn))
    random.shuffle(wires)
    sample = wires[:N]
    st = collections.Counter()
    tool_names = collections.Counter()
    retry_sessions = 0
    for f in sample:
        try:
            fh = open(f, errors="replace")
        except OSError:
            continue
        st["sessions"] += 1
        calls = errs = 0
        last_args = None
        dups = 0
        for line in fh:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            m = d.get("message", {})
            if not isinstance(m, dict):
                continue
            t = m.get("type")
            p = m.get("payload", {})
            if t == "ToolCall":
                calls += 1
                fn = p.get("function", {})
                tool_names[fn.get("name", "?")] += 1
                args = fn.get("arguments", "")
                if args == last_args and len(args) > 10:
                    dups += 1
                last_args = args
            elif t == "ToolResult":
                rv = p.get("return_value", {})
                if isinstance(rv, dict) and rv.get("is_error"):
                    errs += 1
        fh.close()
        st["tool_calls"] += calls
        st["errors"] += errs
        st["dups"] += dups
        if dups >= 2:
            retry_sessions += 1
    print("=== KIMI ===")
    print(f"wires: {st['sessions']}, tool calls: {st['tool_calls']}, "
          f"avg {st['tool_calls'] / max(1, st['sessions']):.1f}/session")
    print(f"tool errors: {st['errors']} ({pct(st['errors'], st['tool_calls'])})")
    print(f"sessions w/ >=2 back-to-back identical calls: {retry_sessions} "
          f"({pct(retry_sessions, st['sessions'])}), dups total: {st['dups']}")
    print("top tools:", tool_names.most_common(10))


analyze_claude()
analyze_codex()
analyze_kimi()
