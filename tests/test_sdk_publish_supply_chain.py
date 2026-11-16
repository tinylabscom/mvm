"""Keep SDK packaging outside signing jobs and pin publisher container bytes."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "411241df99067c98b6d08fd8e26d14e86740a22460599c2af571e6dc26e27ffc"


class PublisherTests(unittest.TestCase):
    def test_rehearsal_cannot_displace_a_pending_release(self):
        workflow = (ROOT / ".github/workflows/publish-sdk.yml").read_text()
        self.assertIn(
            "github.event_name == 'release' && 'publish-sdk' || "
            "format('publish-sdk-rehearsal-{0}', github.ref)", workflow
        )
        preflight = workflow.split("\n  preflight:\n", 1)[1].split(
            "\n  publish_pypi_release:\n", 1
        )[0]
        permissions = preflight.split("    permissions:\n", 1)[1].split(
            "    steps:\n", 1
        )[0]
        self.assertNotIn("id-token:", permissions)
        self.assertIn("contents: read", permissions)

    def test_pypi_publisher_uses_exact_upstream_container_bytes(self):
        action = (ROOT / ".github/actions/publish-pypi/action.yml").read_text()
        self.assertIn("using: docker", action)
        self.assertIn(
            f"image: docker://ghcr.io/pypa/gh-action-pypi-publish@sha256:{DIGEST}", action
        )
        self.assertNotIn("entrypoint:", action)
        self.assertNotIn("args:", action)
        for name, value in {
            "user": "__token__", "password": "''",
            "repository-url": "https://upload.pypi.org/legacy/",
            "packages-dir": "dist", "verify-metadata": "'true'",
            "skip-existing": "'false'", "verbose": "'true'",
            "print-hash": "'true'", "attestations": "'true'",
        }.items():
            # Descriptions/required/default lines are four-space indented.
            block = action.split(f"  {name}:\n", 1)[1]
            lines = []
            for line in block.splitlines():
                if line and not line.startswith("    "):
                    break
                lines.append(line)
            self.assertIn(f"    default: {value}", lines, name)

    def test_local_publisher_has_trusted_checkout_and_no_build_step(self):
        workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text()
        publish = workflow.split("\n  publish:\n", 1)[1]
        for value in (
            "environment: pypi", "id-token: write", "runs-on: ubuntu-latest",
            "ref: ${{ github.sha }}", "persist-credentials: false",
            "uses: ./.github/actions/publish-pypi",
            "packages-dir: dist", "skip-existing: true",
        ):
            self.assertIn(value, publish)
        for command in ("pip install", "python -m build", "cargo ", "npm "):
            self.assertNotIn(command, publish)

    def test_sdk_packaging_depends_on_separate_macos_signer(self):
        for channel in ("npm", "pypi"):
            workflow = (ROOT / f".github/workflows/publish-{channel}.yml").read_text()
            # Slice at the next job, not the indented attributes of this job.
            call = workflow.split("\n  macos-hostlib:\n", 1)[1]
            call = call.split("\n  hostlib:\n", 1)[0].split("\n  build:\n", 1)[0]
            self.assertIn("uses: ./.github/workflows/sdk-macos-hostlib.yml", call)
            self.assertIn(f"channel: {channel}", call)
            self.assertIn("actions: read", call)
            build = workflow.split("\n  build:\n", 1)[1]
            self.assertIn("macos-hostlib", build.split("    steps:\n", 1)[0])
            self.assertNotIn("sign_macos.py", workflow)
            self.assertNotIn("secrets.APPLE_", build)
        pypi = (ROOT / ".github/workflows/publish-pypi.yml").read_text()
        self.assertIn("artifact-ids: ${{ needs.macos-hostlib.outputs.artifact-id }}", pypi)
        self.assertIn("name: pypi-producer-signing-${{ matrix.platform }}", pypi)
        self.assertIn("name: pypi-notarization-${{ matrix.platform }}", pypi)


if __name__ == "__main__":
    unittest.main()
