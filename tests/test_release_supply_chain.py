"""Release source contracts; these tests never sign, download, or publish."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def job(source, name):
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:|\Z)",
        source, re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing job {name}")
    return match[1]


def local_inputs(root):
    pending = [root / ".github/workflows/release.yml"]
    sources = {}
    while pending:
        path = pending.pop()
        if path in sources:
            continue
        if not path.resolve().is_relative_to(root.resolve()):
            raise AssertionError(f"local action escapes checkout: {path}")
        sources[path] = path.read_text()
        for reference in re.findall(r"(?m)^\s+(?:- )?uses: ([^\s#]+)", sources[path]):
            if reference.startswith("./"):
                child = root / reference[2:]
                if child.is_dir():
                    child = next((child / name for name in ("action.yml", "action.yaml")
                                  if (child / name).is_file()), child / "action.yml")
                pending.append(child)
    return sources


def action_steps(source):
    lines = source.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"\s+(?:- )?uses: ([^\s#]+)", line)
        if match is None:
            continue
        following = []
        for next_line in lines[index + 1:]:
            if next_line.strip().startswith("- "):
                break
            following.append(next_line)
        yield match[1], "\n".join(following)


class ReleaseSupplyChainTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/release.yml").read_text()

    def test_builders_do_not_inherit_signing_or_publication_permissions(self):
        permissions = self.workflow.split("\npermissions:\n", 1)[1].split("\nenv:", 1)[0]
        self.assertEqual(permissions.strip(), "contents: read")
        for name in ("build", "sbom", "bdd", "guest-runtime", "archive-install-smoke"):
            block = job(self.workflow, name)
            self.assertNotRegex(block, r"(?:id-token|contents|attestations|actions): write")
            self.assertNotIn("secrets: inherit", block)
        for name in ("release", "runtime-proof-candidate"):
            block = job(self.workflow, name)
            self.assertIn("environment: release-signing", block)
            self.assertIn("id-token: write", block)

    def test_supply_chain_success_is_required_before_signing_and_publication(self):
        gate = job(self.workflow, "supply-chain")
        self.assertIn("uses: ./.github/workflows/supply-chain.yml", gate)
        self.assertNotRegex(gate, r"(?m)^\s+(if|continue-on-error):")
        for name in ("release", "runtime-proof-candidate"):
            block = job(self.workflow, name)
            needs = re.search(r"^    needs: \[([^]]+)\]", block, re.MULTILINE)[1].split(", ")
            self.assertIn("supply-chain", needs)
            self.assertIn("needs.supply-chain.result == 'success'", block)
        self.assertIn("needs.sbom.result == 'success'", job(self.workflow, "release"))

    def test_sbom_production_has_no_signing_authority(self):
        producer = job(self.workflow, "sbom")
        signer = job(self.workflow, "release")
        self.assertIn("contents: read", producer)
        self.assertIn("cargo +1.97.1 install cargo-cyclonedx --version '=0.5.10' --locked", producer)
        self.assertIn("git diff --exit-code -- Cargo.lock", producer)
        self.assertIn("path: sbom.cdx.json", producer)
        self.assertIn("if-no-files-found: error", producer)
        for forbidden in ("cargo install", "cargo +", "cargo cyclonedx", "rustup ",
                          "uses: dtolnay/rust-toolchain", "uses: ./.github/actions/rust-cache"):
            self.assertNotIn(forbidden, signer)
        for required in (
            "fetch-sbom", "${{ needs.sbom.outputs.artifact_id }}",
            "${{ needs.sbom.outputs.artifact_digest }}",
            "${{ needs.sbom.outputs.content_sha256 }}",
            '--artifact-id "$SBOM_ID" --artifact-digest "$SBOM_DIGEST"',
            '--content-sha256 "$SBOM_SHA256"',
        ):
            self.assertIn(required, signer)
        self.assertLess(signer.index("fetch-sbom"), signer.index("cosign sign-blob"))

    def test_external_actions_and_cosign_versions_are_pinned(self):
        actions = re.findall(r"(?m)^\s+(?:- )?uses: ([^\s#]+)", self.workflow)
        self.assertTrue(actions)
        for action in actions:
            if not action.startswith("./"):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        installers = self.workflow.count("uses: sigstore/cosign-installer@")
        self.assertGreater(installers, 0)
        self.assertEqual(self.workflow.count("cosign-release: v2.5.2"), installers)
        for name in ("build", "sbom", "release", "runtime-proof-candidate"):
            self.assertIn("persist-credentials: false", job(self.workflow, name))

    def test_nested_release_actions_and_installed_tools_are_pinned(self):
        sources = local_inputs(ROOT)
        self.assertIn(ROOT / ".github/actions/rust-cache/action.yml", sources)
        self.assertIn(ROOT / ".github/actions/fetch-runtime-candidate/action.yml", sources)
        for path, source in sources.items():
            for reference, step in action_steps(source):
                with self.subTest(path=path, reference=reference):
                    if reference.startswith("./"):
                        continue
                    self.assertRegex(reference, r"^[^@]+@[0-9a-f]{40}$")
                    action = reference.split("@", 1)[0]
                    key = {
                        "dtolnay/rust-toolchain": "toolchain",
                        "actions/setup-node": "node-version",
                        "actions/setup-python": "python-version",
                        "astral-sh/setup-uv": "version",
                        "sigstore/cosign-installer": "cosign-release",
                        "taiki-e/install-action": "tool",
                    }.get(action)
                    if key is None:
                        continue
                    value = re.search(rf"(?m)^\s+{key}: (.+)$", step)
                    self.assertIsNotNone(value, f"{action} lacks {key}")
                    version = value[1].strip("\"'")
                    if action == "taiki-e/install-action":
                        self.assertRegex(version, r"^[\w-]+@\d+\.\d+\.\d+$")
                    else:
                        self.assertRegex(version, r"^v?\d+\.\d+\.\d+$")
        python = sources[ROOT / ".github/actions/python3-via-uv/action.yml"]
        self.assertIn("uv python install 3.12.14", python)
        self.assertIn("uv python find 3.12.14", python)


if __name__ == "__main__":
    unittest.main()
