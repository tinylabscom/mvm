"""Source contracts only: no network, tool installation, or workflow execution."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKOUT = "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"


def read(path):
    return (ROOT / path).read_text()


def job(source, name):
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:|\Z)",
        source, re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing job: {name}")
    return match.group(1)


def step_script(source, name):
    rest = source.split(f"- name: {name}\n", 1)[1].split("        run: |\n", 1)[1]
    lines = []
    for line in rest.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:] if line else "")
    return "\n".join(lines)


class SupplyChainWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.gate = read(".github/workflows/supply-chain.yml")
        self.security = read(".github/workflows/security.yml")
        self.action = read(".github/actions/supply-chain-check/action.yml")
        self.ci = read(".github/workflows/ci.yml")

    def test_ci_calls_input_free_gate_for_dependency_changes(self):
        self.assertIn("\n  workflow_call:\n", self.gate)
        self.assertNotIn("pull_request_target", self.gate)
        self.assertNotRegex(self.gate, r"(?m)^\s+(inputs|secrets|ref|repository):")
        scope = job(self.ci, "scope")
        self.assertIn(f"uses: {CHECKOUT}", scope)
        self.assertIn("persist-credentials: false", scope)
        lane = job(self.ci, "supply-chain")
        self.assertIn("needs: [scope]", lane)
        self.assertIn("if: ${{ needs.scope.outputs.dependencies == 'true' }}", lane)
        self.assertIn("uses: ./.github/workflows/supply-chain.yml", lane)
        aggregate = job(self.ci, "test")
        self.assertIn("test-workspace, supply-chain]", aggregate)
        self.assertIn("DEPENDENCIES: ${{ needs.scope.outputs.dependencies }}", aggregate)
        self.assertIn("DEPENDENCIES_RESULT: ${{ needs.supply-chain.result }}", aggregate)

    def test_dependency_path_classifier(self):
        script = step_script(self.ci, "Classify changed paths")
        self.assertIn("git diff --name-only -z --no-renames", script)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_git = root / "git"
            fake_git.write_text(
                '#!/bin/sh\ncase "$1" in\n'
                'merge-base) printf "base\\n" ;;\n'
                'diff) cat "$TEST_PATHS" ;;\n'
                '*) exit 1 ;;\nesac\n'
            )
            fake_git.chmod(0o755)
            env = {
                "PATH": str(root) + os.pathsep + os.defpath,
                "HOME": str(root), "TMPDIR": str(root),
                "EVENT": "pull_request", "PR_BASE": "base", "PR_HEAD": "head",
                "TEST_PATHS": str(root / "paths"), "GITHUB_OUTPUT": str(root / "output"),
            }
            for path, expected in (
                ("Cargo.toml", True), ("Cargo.lock", True),
                ("crates/client/Cargo.toml", True), ("crates/client/Cargo.lock", True),
                ("deny.toml", True), ("audit.toml", True), ("rust-toolchain.toml", True),
                ("third_party/library/src/lib.rs", True),
                (".cargo/config.toml", True), ("crates/client/.cargo/config.toml", True),
                (".github/workflows/release.yml", True),
                (".github/actions/supply-chain-check/action.yml", True),
                ("tests/test_supply_chain_workflow.py", True),
                ("public/src/content/docs/guide.md", False), ("src/main.rs", False),
            ):
                with self.subTest(path=path):
                    (root / "paths").write_bytes(path.encode() + b"\0")
                    (root / "output").write_text("")
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"dependencies={str(expected).lower()}\n",
                                  (root / "output").read_text())
            for event in ("push", "workflow_dispatch"):
                (root / "output").write_text("")
                subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                               env={**env, "EVENT": event}, check=True, capture_output=True)
                self.assertIn("dependencies=true\n", (root / "output").read_text())

    def test_required_test_result_refuses_failed_or_skipped_required_checks(self):
        script = step_script(self.ci, "Require every validation lane to pass")
        for scope in ("true", "false", "", "invalid"):
            for result in ("success", "skipped", "failure", "cancelled", ""):
                with self.subTest(scope=scope, result=result):
                    env = {
                        "PATH": os.defpath, "BAD": "false", "DOCS": "false",
                        "DOCS_RESULT": "skipped", "LEDGER": "false",
                        "LEDGER_RESULT": "skipped", "DEPENDENCIES": scope,
                        "DEPENDENCIES_RESULT": result, "GITHUB_EVENT_NAME": "pull_request",
                    }
                    verdict = subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                                             env=env, capture_output=True)
                    expected = ((scope == "true" and result == "success")
                                or (scope == "false" and result in ("success", "skipped")))
                    self.assertEqual(verdict.returncode == 0, expected)

    def test_read_only_authority_and_same_revision(self):
        for workflow in (self.gate, self.security):
            self.assertIn("\npermissions:\n  contents: read\n", workflow)
            for checker in ("deny", "audit"):
                lane = job(workflow, f"cargo-{checker}")
                self.assertIn(f"uses: {CHECKOUT}", lane)
                self.assertIn("persist-credentials: false", lane)
                self.assertNotRegex(lane, r"(?m)^\s+(ref|repository|permissions|env):")
                self.assertIn("runs-on: ubuntu-24.04", lane)
                self.assertIn("timeout-minutes: 20", lane)
        self.assertNotRegex(self.gate + self.action, r"\b(write|id-token):")
        self.assertNotIn("secrets.", self.gate + self.action)

    def test_both_entrypoints_share_unconditional_checkers(self):
        for workflow in (self.gate, self.security):
            for checker in ("deny", "audit"):
                lane = job(workflow, f"cargo-{checker}")
                self.assertIn("uses: ./.github/actions/supply-chain-check", lane)
                self.assertIn(f"checker: {checker}", lane)
                self.assertNotIn("cargo install", lane)
                self.assertNotRegex(lane, r"(?m)^\s+(if|continue-on-error):")
        self.assertNotRegex(self.gate, r"(?m)^\s+(if|continue-on-error):")

    def test_exact_tools_and_fail_closed_commands(self):
        for required in (
            'RUSTUP_TOOLCHAIN: "1.97.1"',
            "deny) package=cargo-deny; version=0.20.2 ;;",
            "audit) package=cargo-audit; version=0.23.0 ;;",
            '*) echo "checker must be deny or audit" >&2; exit 1 ;;',
            "set -euo pipefail",
            "test -f Cargo.lock",
            "test -f deny.toml",
            'rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --no-self-update',
            'cargo install --locked --version "=$version" "$package"',
            "deny) cargo deny --locked --workspace --config deny.toml check ;;",
            "audit) cargo audit --file Cargo.lock ;;",
        ):
            self.assertIn(required, self.action)
        for forbidden in (
            "continue-on-error", "|| true", "--ignore", "--no-fetch",
            "--stale", "--no-yanked", "nightly", "curl ", "secrets.",
        ):
            self.assertNotIn(forbidden, self.action)
        self.assertNotRegex(self.action, r"(?m)^\s+if:")
        self.assertLess(self.action.index('case "$CHECKER"'), self.action.index("cargo install"))


if __name__ == "__main__":
    unittest.main()
