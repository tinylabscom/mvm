import datetime as dt
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "merge_queue_watch", Path(__file__).with_name("merge-queue-watch.py")
)
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)
NOW = dt.datetime(2026, 11, 9, 19, 0, tzinfo=dt.timezone.utc)
SHA = "a" * 40
HEAD = {
    "position": 1, "state": "AWAITING_CHECKS",
    "enqueuedAt": "2026-11-09T18:20:00Z",
    "headCommit": {"oid": SHA}, "pullRequest": {"number": 5246},
}
RUN = {
    "id": 42, "head_sha": SHA, "event": "merge_group",
    "path": ".github/workflows/ci.yml", "status": "completed",
    "conclusion": "failure", "run_attempt": 1,
    "html_url": "https://github.com/tinylabscom/mvm/actions/runs/42",
}


class FakeApi:
    def __init__(self, head=HEAD, run=RUN, jobs=0, current=None, issue=None):
        self.head, self.run, self.jobs = head, run, jobs
        self.current = current or run
        self.issue = issue
        self.writes = []

    def __call__(self, path, payload=None, method=None):
        if path == "graphql":
            return {"data": {"repository": {"mergeQueue": {"entries": {
                "nodes": [self.head] if self.head else []
            }}}}}
        if path.startswith("repos/") and "/workflows/ci.yml/runs?" in path:
            return {"workflow_runs": [self.run] if self.run else []}
        if path.endswith("/attempts/1/jobs?per_page=1"):
            return {"total_count": self.jobs}
        if path.endswith("/actions/runs/42") and payload is None:
            return self.current
        if path.startswith("search/issues?"):
            return {"items": [self.issue] if self.issue else []}
        if payload is not None:
            self.writes.append((path, payload, method))
            return {}
        raise AssertionError(path)


class MergeQueueWatchTests(unittest.TestCase):
    def test_zero_job_failure_is_retried_once_and_stall_is_reported(self):
        api = FakeApi()
        watch.watch(api, NOW)
        self.assertEqual([path for path, _, _ in api.writes], [
            "repos/tinylabscom/mvm/actions/runs/42/rerun",
            "repos/tinylabscom/mvm/issues",
        ])
        self.assertIn("/pull/5246", api.writes[1][1]["body"])

    def test_real_failure_and_rerun_do_not_retry(self):
        for api in (FakeApi(jobs=1), FakeApi(run={**RUN, "run_attempt": 2})):
            watch.watch(api, NOW)
            self.assertFalse(any(path.endswith("/rerun") for path, _, _ in api.writes))

    def test_recent_zero_job_failure_retries_without_alerting(self):
        api = FakeApi(head={**HEAD, "enqueuedAt": "2026-11-09T18:45:00Z"})
        watch.watch(api, NOW)
        self.assertEqual([path for path, _, _ in api.writes], [
            "repos/tinylabscom/mvm/actions/runs/42/rerun"
        ])

    def test_run_changed_before_retry_is_not_retried(self):
        api = FakeApi(current={**RUN, "run_attempt": 2})
        watch.watch(api, NOW)
        self.assertFalse(any(path.endswith("/rerun") for path, _, _ in api.writes))

    def test_no_head_or_recent_head_causes_no_alert(self):
        for api in (
            FakeApi(head=None),
            FakeApi(head={**HEAD, "enqueuedAt": "2026-11-09T18:45:00Z"},
                    run={**RUN, "status": "in_progress", "conclusion": None}),
        ):
            watch.watch(api, NOW)
            self.assertEqual(api.writes, [])

    def test_missing_run_still_alerts_on_stale_queue(self):
        api = FakeApi(run=None)
        watch.watch(api, NOW)
        self.assertEqual(api.writes[0][0], "repos/tinylabscom/mvm/issues")

    def test_existing_alert_is_updated_only_when_it_changes(self):
        issue = {"number": 17, "title": watch.TITLE, "body": "old"}
        api = FakeApi(run={**RUN, "run_attempt": 2}, issue=issue)
        watch.watch(api, NOW)
        self.assertEqual(api.writes[0][0], "repos/tinylabscom/mvm/issues/17")
        self.assertEqual(api.writes[0][2], "PATCH")
        api.issue["body"] = api.writes[0][1]["body"]
        api.writes.clear()
        watch.watch(api, NOW)
        self.assertEqual(api.writes, [])


if __name__ == "__main__":
    unittest.main()
