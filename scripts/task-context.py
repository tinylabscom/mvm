#!/usr/bin/env python3
"""Generate a disposable issue → durable context → Graft briefing."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


DOCUMENT_RE = re.compile(r"(?:^|[(`/])((?:specs/)?(?:adrs|contracts)/[^)\s`]+\.md)")
ADR_RE = re.compile(r"\bADR[- ]0*(\d{1,3})\b", re.IGNORECASE)


def run(*args: str) -> str:
    completed = subprocess.run(args, check=True, text=True, capture_output=True)
    return completed.stdout.strip()


def linked_documents(body: str, root: Path) -> list[str]:
    found: set[str] = set()
    for match in DOCUMENT_RE.finditer(body):
        path = match.group(1)
        if not path.startswith("specs/"):
            path = f"specs/{path}"
        if (root / path).is_file():
            found.add(path)
    for match in ADR_RE.finditer(body):
        prefix = f"{int(match.group(1)):03d}-"
        found.update(
            str(path.relative_to(root))
            for path in (root / "specs/adrs").glob(f"{prefix}*.md")
        )
    return sorted(found)


def render(issue: dict[str, object], documents: list[str], prs: list[dict[str, object]], graft: str) -> str:
    labels = ", ".join(label["name"] for label in issue["labels"]) or "none"
    assignees = ", ".join(assignee["login"] for assignee in issue["assignees"]) or "unassigned"
    lines = [
        f"# Task #{issue['number']}: {issue['title']}",
        "",
        "## Authoritative work state",
        f"- Issue: {issue['url']}",
        f"- Assignee: {assignees}",
        f"- Labels: {labels}",
        "",
        "## Durable context linked by the issue",
    ]
    lines.extend(f"- `{path}`" for path in documents)
    if not documents:
        lines.append("- None linked; do not infer architecture from unrelated plans.")
    lines.extend(["", "## Related open pull requests"])
    lines.extend(f"- #{pr['number']}: {pr['title']} ({pr['url']})" for pr in prs)
    if not prs:
        lines.append("- None found.")
    lines.extend(["", "## Graft orientation", graft or "No Graft result.", ""])
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not argv[1].isdigit():
        print("usage: task-context.py <issue-number>", file=sys.stderr)
        return 2
    number = argv[1]
    root = Path(__file__).resolve().parent.parent
    issue = json.loads(
        run(
            "gh",
            "issue",
            "view",
            number,
            "--json",
            "number,title,body,url,labels,assignees",
        )
    )
    documents = linked_documents(str(issue["body"]), root)
    prs = json.loads(
        run(
            "gh",
            "pr",
            "list",
            "--state",
            "open",
            "--search",
            f"#{number}",
            "--json",
            "number,title,url",
        )
    )
    query = f"GitHub issue #{number}: {issue['title']}. {str(issue['body'])[:1500]}"
    graft = run("graft", "ask", query, "--source")
    print(render(issue, documents, prs, graft))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
