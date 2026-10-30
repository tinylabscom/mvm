import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "watch_issues", Path(__file__).with_name("watch-issues.py")
)
WATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WATCH)


class WatchIssuesTests(unittest.TestCase):
    def test_unchecked_and_nested_context(self):
        body = """# Delivery
- [x] Finished
- [X] Parent
  details for parent
  - [ ] Child
    continuation
    - [ ] Grandchild
  - [x] Done child
## Next
1. [ ] Another
* [X] Done
+ [ ] Last
"""
        self.assertEqual(WATCH.unchecked_tasks(body), """# Delivery
- Parent (context)
  details for parent
  - [ ] Child
    continuation
    - [ ] Grandchild
## Next
1. [ ] Another
+ [ ] Last""")

    def test_fenced_examples_and_empty_lists(self):
        for body in ("", "- [x] Done", "No tasks", """```markdown
- [ ] Example
```
~~~text
- [ ] Another example
~~~
"""):
            with self.subTest(body=body):
                self.assertEqual(WATCH.unchecked_tasks(body), "")
        self.assertEqual(WATCH.unchecked_tasks("""- [ ] Real
  ````markdown
  - [ ] Example
  ```
  ````
  more details
- [ ] Next
"""), "- [ ] Real\n  more details\n- [ ] Next")

    def test_plain_output_removes_controls(self):
        self.assertNotIn("\033", WATCH.unchecked_tasks("- [ ] \033[2JTask"))

    def test_refs(self):
        for value in ("3731", "tinylabscom/mvm#3731",
                      "https://github.com/tinylabscom/mvm/issues/3731"):
            self.assertEqual(WATCH.issue_ref(value), WATCH.DEFAULT_ISSUES[0])
        with self.assertRaises(WATCH.argparse.ArgumentTypeError):
            WATCH.issue_ref("--repo=other")

    def test_fetch_errors_are_bounded_and_do_not_echo_diagnostics(self):
        failures = (
            (FileNotFoundError(), "not found"),
            (subprocess.TimeoutExpired("gh", 15), "timed out"),
            (subprocess.CompletedProcess([], 4, "", "private diagnostic"), "authentication required"),
            (subprocess.CompletedProcess([], 1, "", "HTTP 403 private diagnostic"), "HTTP 403"),
            (subprocess.CompletedProcess([], 0, "private diagnostic", ""), "invalid issue"),
            (subprocess.CompletedProcess([], 0, "[]", ""), "invalid issue"),
        )
        for failure, message in failures:
            with self.subTest(message=message), patch.object(WATCH.subprocess, "run") as run:
                if isinstance(failure, Exception):
                    run.side_effect = failure
                else:
                    run.return_value = failure
                with self.assertRaisesRegex(RuntimeError, message) as raised:
                    WATCH.fetch_issue(WATCH.DEFAULT_ISSUES[0])
                self.assertNotIn("private diagnostic", str(raised.exception))
                self.assertEqual(run.call_args.kwargs["timeout"], 15)
                self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_fetch_success(self):
        with patch.object(WATCH.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, '{"title":"Work","body":"- [ ] Task","state":"OPEN"}', ""
        )):
            self.assertEqual(WATCH.fetch_issue(WATCH.DEFAULT_ISSUES[0])["body"], "- [ ] Task")

    def test_once_and_non_tty_do_not_sleep_or_clear(self):
        for tty, argv in ((True, ["--once"]), (False, [])):
            output = io.StringIO()
            with (self.subTest(tty=tty), contextlib.redirect_stdout(output),
                  patch.object(output, "isatty", return_value=tty),
                  patch.object(WATCH, "fetch_issue", return_value={
                      "title": "Work", "body": "", "state": "OPEN",
                  }) as fetch, patch.object(WATCH.time, "sleep") as sleep):
                self.assertEqual(WATCH.main(argv), 0)
                self.assertEqual(fetch.call_count, 2)
                sleep.assert_not_called()
                self.assertNotIn("\033", output.getvalue())
                self.assertIn("No unchecked task items.", output.getvalue())

    def test_partial_error_is_visible_and_fails_one_shot(self):
        output = io.StringIO()
        with (contextlib.redirect_stdout(output),
              patch.object(WATCH, "fetch_issue", side_effect=[
                  RuntimeError("gh failed"), {"title": "Other", "body": "- [ ] Task", "state": "OPEN"}
              ])):
            self.assertEqual(WATCH.main(["--once"]), 1)
        self.assertIn("ERROR: gh failed", output.getvalue())
        self.assertIn("- [ ] Task", output.getvalue())

    def test_watch_refreshes_and_interrupts_cleanly(self):
        output = io.StringIO()
        with (contextlib.redirect_stdout(output),
              patch.object(output, "isatty", return_value=True),
              patch.object(WATCH, "fetch_issue", return_value={
                  "title": "Work", "body": "- [ ] Task", "state": "OPEN",
              }) as fetch,
              patch.object(WATCH.time, "sleep", side_effect=[None, KeyboardInterrupt]) as sleep):
            self.assertEqual(WATCH.main(["99"]), 0)
            self.assertEqual(fetch.call_count, 6)
            sleep.assert_called_with(30)
        self.assertEqual(output.getvalue().count("\033[2J\033[H"), 2)


if __name__ == "__main__":
    unittest.main()
