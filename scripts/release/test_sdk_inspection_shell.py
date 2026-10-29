"""Exercise SDK inspection commands under the system Bash, including nounset."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SdkInspectionShellTests(unittest.TestCase):
    def test_optional_notarization_arguments(self):
        cases = (
            ("publish-pypi.yml", "Inspect final macOS wheel bytes",
             "dist/example.whl", "pypi"),
            ("publish-npm.yml", "Inspect actual packed Darwin npm bytes",
             "npm-dist/runmvm-mvm-darwin-arm64-1.0.0.tgz", "npm"),
        )
        for workflow, step, archive, kind in cases:
            text = (ROOT / ".github" / "workflows" / workflow).read_text()
            body = text.split(f"      - name: {step}\n", 1)[1]
            body = body.split("\n      - name:", 1)[0]
            body = body.split("        run: |\n", 1)[1]
            script = "\n".join(line[10:] for line in body.splitlines())
            for notarized in (False, True):
                with self.subTest(workflow=workflow, notarized=notarized):
                    with tempfile.TemporaryDirectory(prefix="sdk inspection ") as tmp:
                        root = Path(tmp)
                        artifact = root / archive
                        artifact.parent.mkdir(parents=True)
                        artifact.write_bytes(b"test archive")
                        binary_dir = root / "bin"
                        binary_dir.mkdir()
                        capture = root / "arguments"
                        python = binary_dir / "python3"
                        python.write_text(
                            '#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\n'
                            'exit "${VERIFIER_EXIT:-0}"\n'
                        )
                        python.chmod(0o700)
                        env = dict(
                            os.environ,
                            PATH=f"{binary_dir}{os.pathsep}{os.environ['PATH']}",
                            CAPTURE=str(capture),
                            RUNNER_TEMP=str(root),
                            VERIFIER_EXIT="0",
                        )
                        command = script.replace(
                            "${{ !inputs.dry_run || github.ref_type == 'tag' }}",
                            str(notarized).lower(),
                        )
                        result = subprocess.run(
                            ["/bin/bash", "-c", command],
                            cwd=root, env=env, capture_output=True, text=True,
                            check=False, timeout=10,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        args = capture.read_text().splitlines()
                        self.assertEqual(args[0], "scripts/release/verify_macos_package.py")
                        self.assertEqual(args[args.index("--archive") + 1], archive)
                        self.assertIn("--sdk-layout", args)
                        producer = (
                            str(root / "pypi-producer-signing.json")
                            if kind == "pypi"
                            else "signing-reports/npm-producer-signing.json"
                        )
                        self.assertEqual(
                            args[args.index("--producer-report") + 1], producer
                        )
                        if kind == "npm":
                            self.assertEqual(args[args.index("--envelope") + 1], "package")
                        self.assertEqual("--notary-report" in args, notarized)
                        if notarized:
                            expected = (
                                str(root / "pypi-notarization.json")
                                if kind == "pypi"
                                else "signing-reports/npm-notarization.json"
                            )
                            self.assertEqual(args[args.index("--notary-report") + 1], expected)
                        self.assertEqual(
                            args[args.index("--report") + 1],
                            str(root / f"{kind}-final-package.json"),
                        )
                        env["VERIFIER_EXIT"] = "7"
                        refused = subprocess.run(
                            ["/bin/bash", "-c", command],
                            cwd=root, env=env, capture_output=True, text=True,
                            check=False, timeout=10,
                        )
                        self.assertEqual(refused.returncode, 7, refused.stderr)


if __name__ == "__main__":
    unittest.main()
