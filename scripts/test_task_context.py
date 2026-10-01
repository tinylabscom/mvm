#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "task_context", Path(__file__).with_name("task-context.py")
)
assert SPEC and SPEC.loader
TASK_CONTEXT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TASK_CONTEXT)


class TaskContextTests(unittest.TestCase):
    def test_linked_documents_are_existing_durable_specs_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "specs/adrs").mkdir(parents=True)
            (root / "specs/contracts").mkdir(parents=True)
            (root / "specs/adrs/042-network.md").write_text("decision")
            (root / "specs/contracts/agent-v1.md").write_text("contract")

            found = TASK_CONTEXT.linked_documents(
                "Use ADR-042 and `specs/contracts/agent-v1.md`; ignore plans/x.md.",
                root,
            )

            self.assertEqual(
                found,
                ["specs/adrs/042-network.md", "specs/contracts/agent-v1.md"],
            )

    def test_render_marks_missing_links_instead_of_guessing(self):
        issue = {
            "number": 7,
            "title": "Example",
            "url": "https://example.test/issues/7",
            "labels": [],
            "assignees": [],
        }

        output = TASK_CONTEXT.render(issue, [], [], "one source span")

        self.assertIn("None linked; do not infer architecture", output)
        self.assertIn("one source span", output)


if __name__ == "__main__":
    unittest.main()
