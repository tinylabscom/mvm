"""Exercise the signing smoke's image-set shell fixture without signing or booting."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/pack-signing-smoke.yml"


def smoke_script():
    body = WORKFLOW.read_text().split("        run: |\n", 1)[1]
    return "\n".join(line[10:] for line in body.splitlines())


class PackSigningSmokeTests(unittest.TestCase):
    def generate(self, root, reference, contract):
        scripts = root / "scripts"
        scripts.mkdir()
        shutil.copy(ROOT / "scripts/locked-image-tag.sh", scripts)
        lock = root / "crates/mvm-core/images.lock"
        lock.parent.mkdir(parents=True)
        source = (ROOT / "crates/mvm-core/images.lock").read_text()
        if contract is not None:
            source = re.sub(
                r"^builder_cache_contract = \d+$",
                f"builder_cache_contract = {contract}", source, flags=re.MULTILINE,
            )
            lock.write_text(source)
        inputs = root / "smoke/inputs"
        inputs.mkdir(parents=True)
        (inputs / "vmlinux").write_bytes(b"dummy-kernel")
        (root / "smoke/image-set").mkdir()
        script = smoke_script().split("# Step 3:", 1)[1]
        script = script.split("if [[", 1)[1]
        script = "set -euo pipefail\nif [[" + script.split("cosign sign-blob", 1)[0]
        script += '\nprintf "%s\\n" "$expected_stage"\n'
        env = dict(
            os.environ, REF=reference, REF_NAME=reference.rsplit("/", 1)[1],
            REPOSITORY="tinylabscom/mvm", GITHUB_SHA="a" * 40,
        )
        return subprocess.run(
            ["/bin/bash", "-c", script], cwd=root, env=env,
            capture_output=True, text=True, check=False, timeout=10,
        )

    def test_image_set_uses_canonical_contract_and_keeps_identity_binding(self):
        for reference, stage in [
            ("refs/tags/v0.24.0", "none"), ("refs/heads/main", "signature"),
        ]:
            for contract in (5, 37):
                with self.subTest(reference=reference, contract=contract):
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        result = self.generate(root, reference, contract)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), stage)
                        manifest = json.loads((root / "smoke/image-set.json").read_text())
                        self.assertEqual(
                            manifest["compatibility"]["builder_cache_contract"], contract,
                        )
                        tag = "v0.24.0" if stage == "none" else "v0.0.0-smoke"
                        self.assertEqual(manifest["producer"]["release_tag"], tag)
                        self.assertEqual(
                            manifest["producer"]["workflow"],
                            ".github/workflows/pack-signing-smoke.yml",
                        )
                        self.assertEqual(manifest["producer"]["source_commit"], "a" * 40)
                        self.assertEqual(manifest["members"][0]["artifacts"][0]["size"], 12)

    def test_missing_contract_source_fails_before_manifest_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.generate(root, "refs/tags/v0.24.0", None)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "smoke/image-set.json").exists())

    def test_verdict_gate_requires_status_and_exact_stage(self):
        function = smoke_script().split("expect() {", 1)[1].split(
            '\nexpect "${expected_stage}"', 1,
        )[0]
        for wanted, status, verdict, accepted in [
            ("none", 0, {"verified": True}, True),
            ("none", 1, {"verified": True}, False),
            ("none", 0, {"verified": False}, False),
            ("signature", 1, {"verified": False, "stage": "signature"}, True),
            ("signature", 0, {"verified": False, "stage": "signature"}, False),
            ("signature", 1, {"verified": False, "stage": "protocol-compatibility"}, False),
            ("artifacts", 1, {"verified": False, "stage": "artifacts"}, True),
            ("artifacts", 1, {"verified": True, "stage": "artifacts"}, False),
        ]:
            with self.subTest(wanted=wanted, status=status, verdict=verdict):
                env = dict(
                    os.environ, VERDICT=json.dumps(verdict),
                    STATUS=str(status), WANTED=wanted,
                )
                result = subprocess.run(
                    ["/bin/bash", "-c",
                     'set -euo pipefail\nverify() { printf "%s\\n" "$VERDICT"; '
                     'return "$STATUS"; }\nexpect() {' + function + '\nexpect "$WANTED"'],
                    env=env, capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)


if __name__ == "__main__":
    unittest.main()
