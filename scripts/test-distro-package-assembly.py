#!/usr/bin/env python3
"""PR-only packaging mechanics witness; its runtime is synthetic, never publishable.

The host archive is authenticated by the workflow before invoking this harness.
Only runtime signature verification is stubbed, inside one subprocess. Production
assembly has no verifier override or unsigned mode. Tag runs never invoke this.
"""

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main():
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        raise SystemExit("synthetic package assembly is restricted to pull-request tests")
    if len(sys.argv) != 5:
        raise SystemExit("usage: test-distro-package-assembly.py HOST_ARCHIVE TARGET VERSION OUTPUT")
    host, target, version, output = sys.argv[1:]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version):
        raise SystemExit("fixture version must be a bare release version")
    with tempfile.TemporaryDirectory(prefix="mvm-package-fixture-") as temporary:
        root = Path(temporary)
        runtime = root / "runtime"
        runtime.mkdir()
        archive = runtime / f"mvm-guest-bins-v{version}.tar.gz"
        archive.write_bytes(gzip.compress(b"Synthetic package-layout fixture; cannot boot a guest.\n"))
        checksum = Path(str(archive) + ".sha256")
        checksum.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        for path in (archive, checksum):
            Path(str(path) + ".bundle").write_text("Synthetic verifier fixture, not a signature.\n")
        tools = root / "tools"
        tools.mkdir()
        verifier = tools / "cosign"
        # Confine the fake verifier to these two generated files and the exact
        # expected identity/issuer. It cannot bless a host archive or package.
        verifier.write_text(
            "#!/usr/bin/env python3\nimport pathlib, sys\n"
            "def need(condition):\n"
            "    if not condition: raise SystemExit('not a runtime signature fixture')\n"
            f"allowed = {json.dumps([str(archive), str(checksum)])}\n"
            f"identity = {json.dumps('https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v' + version)}\n"
            "args = sys.argv[1:]\n"
            "need(args[0] == 'verify-blob' and args[-1] in allowed)\n"
            "need(args[args.index('--certificate-identity') + 1] == identity)\n"
            "need(args[args.index('--certificate-oidc-issuer') + 1] == 'https://token.actions.githubusercontent.com')\n"
            "need(args[args.index('--bundle') + 1] == args[-1] + '.bundle')\n"
            "need(pathlib.Path(args[-1] + '.bundle').read_text() == 'Synthetic verifier fixture, not a signature.\\n')\n"
            "print('PR fixture only: runtime signature is stubbed', file=sys.stderr)\n"
        )
        verifier.chmod(0o755)
        env = dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}")
        subprocess.run(
            ["bash", str(Path(__file__).with_name("build-distro-packages.sh")),
             host, target, version, output, str(runtime)],
            env=env, check=True,
        )


if __name__ == "__main__":
    main()
