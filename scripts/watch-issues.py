#!/usr/bin/env python3
"""Read-only terminal view of unchecked GitHub issue tasks."""

import argparse
import json
import re
import subprocess
import sys
import time


DEFAULT_ISSUES = ("tinylabscom/mvm#3731", "tinylabscom/mvm#4839")
ITEM = re.compile(r"^(\s*)(?:[-+*]|\d+[.)])\s+(.*)$")
TASK = re.compile(r"^\[([ xX])\](?:\s+|$)(.*)$")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")


def plain(text):
    """Do not let remote Markdown inject terminal control sequences."""
    return "".join(c for c in text if c in "\n\t" or c.isprintable())


def unchecked_tasks(body):
    # Keep source order, selecting headings and parent items only when needed.
    lines = []
    selected = set()
    parents = []
    headings = []
    current = None
    fence = None
    for line in plain(body).expandtabs(4).splitlines():
        marker = FENCE.match(line)
        if fence:
            if (marker and marker[1][0] == fence[0]
                    and len(marker[1]) >= len(fence) and not marker[2].strip()):
                fence = None
            continue
        if marker:
            fence = marker[1]
            continue
        heading = re.match(r"^(#{1,6})\s+", line)
        if heading:
            level = len(heading[1])
            headings = [(n, i) for n, i in headings if n < level]
            headings.append((level, len(lines)))
            lines.append(line)
            parents = []
            current = None
            continue
        item = ITEM.match(line)
        if item:
            indent = len(item[1])
            parents = [(n, i) for n, i in parents if n < indent]
            task = TASK.match(item[2])
            current = len(lines)
            # A checked ancestor is context, never another open checkbox.
            lines.append(
                f"{item[1]}- {task[2]} (context)"
                if task and task[1] != " " else line
            )
            parents.append((indent, current))
            if task and task[1] == " ":
                selected.update(i for _, i in headings + parents)
            continue
        if current is not None and line.strip():
            lines[current] += "\n" + line
        elif not line.strip():
            current = None
    return "\n".join(line for i, line in enumerate(lines) if i in selected)


def issue_ref(value):
    if value.isdecimal() and int(value) > 0:
        return f"tinylabscom/mvm#{int(value)}"
    match = re.fullmatch(
        r"(?:https://github\.com/)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
        r"(?:#|/issues/)([1-9][0-9]*)", value
    )
    if not match:
        raise argparse.ArgumentTypeError(
            "use an issue number, owner/repo#number, or GitHub issue URL"
        )
    return f"{match[1]}#{match[2]}"


def fetch_issue(ref):
    repo, number = ref.split("#")
    try:
        result = subprocess.run(
            ["gh", "issue", "view", number, "--repo", repo,
             "--json", "title,body,state"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=15, check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("gh CLI not found; install it before using this command") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("gh timed out after 15 seconds") from None
    except OSError:
        raise RuntimeError("could not execute gh") from None
    if result.returncode:
        # Never echo raw diagnostics: gh debug output can contain credentials.
        status = re.search(r"\bHTTP (\d{3})\b", result.stderr)
        detail = f", HTTP {status[1]}" if status else ""
        auth = "; authentication required" if result.returncode == 4 else ""
        raise RuntimeError(
            f"gh failed (exit {result.returncode}{detail}){auth}; "
            "check GitHub access and gh authentication"
        )
    try:
        issue = json.loads(result.stdout)
        if (not isinstance(issue, dict)
                or not all(isinstance(issue.get(k), str) for k in ("title", "body", "state"))):
            raise ValueError
        return issue
    except (ValueError, TypeError):
        raise RuntimeError("gh returned an invalid issue response") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="print once, even on a terminal")
    parser.add_argument("issues", nargs="*", type=issue_ref, help="additional issue refs")
    args = parser.parse_args(argv)
    refs = list(dict.fromkeys((*DEFAULT_ISSUES, *args.issues)))
    interactive = sys.stdout.isatty()
    watch = interactive and not args.once
    try:
        while True:
            sections = []
            failed = False
            for ref in refs:
                try:
                    issue = fetch_issue(ref)
                    tasks = unchecked_tasks(issue["body"])
                    sections.append(
                        f"{ref} — {plain(issue['title'])} [{plain(issue['state'])}]\n"
                        f"{tasks or 'No unchecked task items.'}"
                    )
                except RuntimeError as exc:
                    failed = True
                    sections.append(f"{ref}\nERROR: {exc}")
            if watch:
                print("\033[2J\033[H", end="")
            print("\n\n".join(sections), flush=True)
            if not watch:
                return int(failed)
            print("\nRefreshes every 30s after fetching. Ctrl+C to exit.", flush=True)
            time.sleep(30)
    except KeyboardInterrupt:
        if interactive:
            print()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
