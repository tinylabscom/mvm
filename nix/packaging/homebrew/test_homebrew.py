"""Host-only rendering, installation and authentication-boundary fixtures."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
TARGETS = ["aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
MANIFEST = "".join(f"{'a' * 64}  mvmctl-{target}.tar.gz\n" for target in TARGETS)


class HomebrewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="homebrew-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "checksums"
        self.manifest.write_text(MANIFEST)
        self.output = self.root / "mvmctl.rb"

    def render(self, version="1.2.3"):
        return subprocess.run(
            ["sh", HERE / "render-formula.sh", version, self.manifest, self.output],
            text=True, capture_output=True,
        )

    def test_render_and_install_all_platform_layouts(self):
        self.assertEqual(self.render().returncode, 0)
        self.assertNotIn("@@", self.output.read_text())
        subprocess.run(["ruby", "-c", self.output], check=True)
        for platform in ["mac", "linux"]:
            subprocess.run(
                ["ruby", HERE / "test-install.rb", self.output], check=True,
                env={**os.environ, "FIXTURE_OS": platform},
            )

    def test_invalid_versions(self):
        for version in ["v1.2.3", "1.2.3-rc.1", "01.2.3", "1.2.3\nbad", "1/2/3", "$(id)"]:
            with self.subTest(version=version):
                self.assertNotEqual(self.render(version).returncode, 0)
                self.assertFalse(self.output.exists())

    def test_manifest_missing_duplicate_malformed(self):
        for manifest in [
            "", MANIFEST + MANIFEST.splitlines()[0] + "\n",
            MANIFEST.replace("a" * 64, "a" * 63),
            MANIFEST.replace("a" * 64, "g" * 64),
            MANIFEST.replace(".tar.gz", ".tar.gz trailing", 1),
        ]:
            with self.subTest(manifest=manifest):
                self.manifest.write_text(manifest)
                self.assertNotEqual(self.render().returncode, 0)
                self.assertFalse(self.output.exists())

    def prepare(self, *, tag="v1.2.3", metadata=None, reject=False):
        tools = self.root / "tools"
        tools.mkdir(exist_ok=True)
        metadata = metadata or {
            "tag_name": tag, "draft": False, "prerelease": False,
            "published_at": "2026-10-01T00:00:00Z",
        }
        (self.root / "metadata").write_text(json.dumps(metadata))
        gh = tools / "gh"
        gh.write_text("""#!/bin/sh
set -eu
if [ "$1" = api ]; then cat "$FIXTURE_ROOT/metadata"; exit; fi
while [ "$1" != --dir ]; do shift; done
cp "$FIXTURE_ROOT/checksums" "$2/checksums-sha256.txt"
printf 'fixture bundle' > "$2/checksums-sha256.txt.bundle"
""")
        cosign = tools / "cosign"
        cosign.write_text("""#!/bin/sh
set -eu
printf '%s\\n' "$@" > "$FIXTURE_ROOT/cosign-args"
[ "$REJECT" = 0 ]
""")
        gh.chmod(0o755)
        cosign.chmod(0o755)
        return subprocess.run(
            ["bash", HERE / "prepare-formula.sh", tag, self.root / "prepared"],
            env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                 "FIXTURE_ROOT": str(self.root), "REJECT": str(int(reject))},
            text=True, capture_output=True,
        )

    def test_exact_tag_authentication_before_render(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = (self.root / "cosign-args").read_text().splitlines()
        self.assertIn("--certificate-identity", args)
        self.assertIn("https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v1.2.3", args)
        self.assertIn("https://token.actions.githubusercontent.com", args)
        self.assertNotIn("--certificate-identity-regexp", args)
        self.assertTrue((self.root / "prepared/mvmctl.rb").exists())

    def test_signature_failure_never_renders(self):
        self.assertNotEqual(self.prepare(reject=True).returncode, 0)
        self.assertFalse((self.root / "prepared/mvmctl.rb").exists())

    def test_unpromoted_wrong_tag_and_non_cli_rejected(self):
        for change in [{"draft": True}, {"prerelease": True}, {"published_at": None},
                       {"tag_name": "v9.9.9"}]:
            metadata = {"tag_name": "v1.2.3", "draft": False, "prerelease": False,
                        "published_at": "2026-10-01", **change}
            self.assertNotEqual(self.prepare(metadata=metadata).returncode, 0)
            self.assertFalse((self.root / "cosign-args").exists())
        for tag in ["images-v1.2.3", "v1.2.3-rc.1", "v1.2.3\nbad"]:
            self.assertNotEqual(self.prepare(tag=tag).returncode, 0)
            self.assertFalse((self.root / "prepared/mvmctl.rb").exists())


if __name__ == "__main__":
    unittest.main()
