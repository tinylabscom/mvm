#!/usr/bin/env python3
"""Retry a zero-job merge-group failure once and report a stalled queue head."""

import datetime as dt
import json
import os
import urllib.parse
import urllib.request

REPO = "tinylabscom/mvm"
TITLE = "Merge queue stalled"
STALE_AFTER = dt.timedelta(minutes=30)
QUERY = """
query {
  repository(owner: "tinylabscom", name: "mvm") {
    mergeQueue(branch: "main") {
      entries(first: 1) {
        nodes { position state enqueuedAt headCommit { oid } pullRequest { number } }
      }
    }
  }
}
"""


def api(path, payload=None, method=None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        data=data,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        method=method or ("POST" if data is not None else "GET"),
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read()
    return json.loads(body) if body else None


def queue_head(call):
    result = call("graphql", {"query": QUERY})
    if result.get("errors"):
        raise ValueError("GitHub could not read the merge queue")
    entries = result["data"]["repository"]["mergeQueue"]["entries"]["nodes"]
    return entries[0] if entries else None


def ci_run(call, sha):
    path = f"repos/{REPO}/actions/workflows/ci.yml/runs?" + urllib.parse.urlencode(
        {"event": "merge_group", "head_sha": sha, "per_page": 100}
    )
    runs = call(path)["workflow_runs"]
    matching = [
        run for run in runs
        if run["head_sha"] == sha and run["event"] == "merge_group"
        and run["path"] == ".github/workflows/ci.yml"
    ]
    return max(matching, key=lambda run: run["id"]) if matching else None


def retry_zero_job_failure(call, head, run):
    if not run or run["status"] != "completed" or run["conclusion"] != "failure":
        return False
    if run["run_attempt"] != 1 or run["head_sha"] != head["headCommit"]["oid"]:
        return False
    path = f"repos/{REPO}/actions/runs/{run['id']}"
    jobs = call(path + "/attempts/1/jobs?per_page=1")
    if jobs["total_count"] != 0:
        return False
    # The workflow_run and scheduled triggers can both see the same failure.
    # Re-read the run before mutating it; the workflow also serializes itself.
    current = call(path)
    if (current["head_sha"] != run["head_sha"] or current["run_attempt"] != 1
            or current["status"] != "completed" or current["conclusion"] != "failure"):
        return False
    call(path + "/rerun", {})
    print(f"Re-ran zero-job merge-group failure {run['html_url']} once")
    return True


def alert_if_stalled(call, head, run, now):
    entered = dt.datetime.fromisoformat(head["enqueuedAt"].replace("Z", "+00:00"))
    if now - entered < STALE_AFTER:
        return False
    number = head["pullRequest"]["number"]
    url = f"https://github.com/{REPO}/pull/{number}"
    run_url = run["html_url"] if run else "No merge-group CI run found"
    body = (
        f"PR: {url}\n"
        f"Queue head since: {head['enqueuedAt']}\n"
        f"Queue state: {head['state']}\n"
        f"Merge-group CI: {run_url}\n\n"
        "The head has exceeded 30 minutes. Inspect the queue checks and recover "
        "manually if the one permitted zero-job retry did not help."
    )
    search = urllib.parse.urlencode(
        {"q": f'repo:{REPO} is:issue is:open in:title "{TITLE}"', "per_page": 20}
    )
    existing = next(
        (item for item in call("search/issues?" + search)["items"]
         if item["title"] == TITLE),
        None,
    )
    if existing is None:
        call(f"repos/{REPO}/issues", {"title": TITLE, "body": body})
    elif existing["body"] != body:
        call(f"repos/{REPO}/issues/{existing['number']}", {"body": body}, method="PATCH")
    print(f"Merge queue stalled: {url} ({head['state']}); {run_url}")
    return True


def watch(call=api, now=None):
    head = queue_head(call)
    if not head:
        print("Merge queue is empty")
        return
    run = ci_run(call, head["headCommit"]["oid"])
    retry_zero_job_failure(call, head, run)
    alert_if_stalled(call, head, run, now or dt.datetime.now(dt.timezone.utc))


if __name__ == "__main__":
    if os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise SystemExit("merge-queue watch runs only in tinylabscom/mvm")
    watch()
