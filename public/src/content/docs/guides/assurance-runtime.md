---
title: Runtime selection for assurance campaigns
description: Configure signed external guest runtimes for an operator-owned assurance provider without treating cache metadata as authority.
---

# Runtime selection for assurance campaigns

An operator-configured assurance provider reads `boot-config.json` from its
configured state directory. Its schema is
`mvm.assurance.provider-boot-config/v1`. The configuration must be a private,
regular, non-symlink file. Runtime selection belongs inside `workload`; it does
not replace the workload image digest, kernel digest, extension trust policy,
destination restrictions, or campaign authority checks.

## External runtime selection

When the workload uses an external runtime, configure all of these fields:

| `workload` field | Meaning |
| --- | --- |
| `runtime_overlay_path` | Absolute path to the selected runtime overlay image. |
| `runtime_overlay_verity_path` | Absolute path to its verity tree. |
| `runtime_overlay_roothash` | Root hash from the signed runtime declaration. |
| `runtime_overlay_version` | Version of the selected runtime release. |
| `initrd_path` | Absolute path to the selected runtime initramfs. |
| `runtime_release_proof` | Release inputs described below, independently verified by the host. |

`runtime_release_proof` has these fields:

| Field | Meaning |
| --- | --- |
| `archive` | Absolute path to the guest-runtime release archive. |
| `checksum` | Absolute path to the release checksum file. |
| `signature_bundle` | Absolute path to the release signature bundle. |
| `archive_sha256` | Lowercase hexadecimal SHA-256 of the archive, without a `sha256:` prefix. |
| `version` | Exact release version expected from the authenticated archive. |
| `arch` | Selected guest architecture: `aarch64` or `x86_64`. It must match the host. |

These are **untrusted verification inputs**, not a statement that verification
has already succeeded. A checksum alone, a cache fingerprint, a protocol number,
or a JSON field claiming `verified: true` does not authorize the runtime.
Unknown fields are rejected. Before granting assurance admission, the host verifies
release provenance and compares the selected overlay, verity tree, and initramfs
hashes against the authenticated declaration. It rechecks the selection before
launch; the runtime separately binds private artifact snapshots to the launch.
Verification does not by itself prove execution
or the outcome of an assurance trial.

### Generate a configuration from operator-selected paths

The following Python 3 command prints an updated **existing** provider
configuration. It does not download artifacts, build a runtime, verify a
signature, or overwrite the installed configuration.

Set these environment variables to your actual selections before running it:

- `MVM_ASSURANCE_BOOT_CONFIG`: existing complete provider configuration.
- `MVM_RUNTIME_ARCHIVE`, `MVM_RUNTIME_CHECKSUM`, `MVM_RUNTIME_SIGNATURE_BUNDLE`:
  downloaded release files.
- `MVM_RUNTIME_OVERLAY`, `MVM_RUNTIME_VERITY`, `MVM_RUNTIME_INITRAMFS`:
  selected boot artifacts.
- `MVM_RUNTIME_ROOT_HASH`: the runtime's declared verity root.
- `MVM_RUNTIME_VERSION`: the selected release version.
- `MVM_RUNTIME_ARCH`: `aarch64` or `x86_64`.

The command refuses unset variables and non-absolute or missing file paths.
It computes the archive digest from the supplied bytes rather than inventing
an example digest.

```bash
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

def required(name):
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Set {name} to your actual operator selection")
    return value

def file_path(name):
    path = Path(required(name))
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise SystemExit(f"{name} must name an absolute regular non-symlink file")
    return str(path)

config = json.loads(Path(file_path("MVM_ASSURANCE_BOOT_CONFIG")).read_text())
if config.get("schema") != "mvm.assurance.provider-boot-config/v1":
    raise SystemExit("Unsupported provider configuration schema")
archive = file_path("MVM_RUNTIME_ARCHIVE")
digest = hashlib.sha256()
with open(archive, "rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
arch = required("MVM_RUNTIME_ARCH")
if arch not in ("aarch64", "x86_64"):
    raise SystemExit("MVM_RUNTIME_ARCH must be aarch64 or x86_64")
version = required("MVM_RUNTIME_VERSION")
config["workload"].update({
    "runtime_overlay_path": file_path("MVM_RUNTIME_OVERLAY"),
    "runtime_overlay_verity_path": file_path("MVM_RUNTIME_VERITY"),
    "runtime_overlay_roothash": required("MVM_RUNTIME_ROOT_HASH"),
    "runtime_overlay_version": version,
    "initrd_path": file_path("MVM_RUNTIME_INITRAMFS"),
    "runtime_release_proof": {
        "archive": archive,
        "checksum": file_path("MVM_RUNTIME_CHECKSUM"),
        "signature_bundle": file_path("MVM_RUNTIME_SIGNATURE_BUNDLE"),
        "archive_sha256": digest.hexdigest(),
        "version": version,
        "arch": arch,
    },
})
print(json.dumps(config, indent=2))
PY
```

Review the output and install it through your normal operator configuration
deployment, preserving private permissions. The provider still rejects
untrusted signatures, mismatched versions or architectures, incompatible guest
RPC protocols, and changed artifacts; generating JSON is not an acceptance test.

## Baked agents and contributor runtimes

A genuinely baked, compatible guest agent can continue using the existing
image admission path without an external-runtime proof. This fallback requires
metadata identifying a real baked agent, a non-runtime-lean image, and a
supported guest RPC protocol, with the rootfs bound to the admitted image digest.
Selecting an external overlay or initramfs cannot borrow that image's protocol
number as evidence for the selected runtime.

A runtime-lean base, an image with no agent, or a `cli-initramfs` base reporting
protocol zero needs the external runtime and its release proof. Do not change
the base's protocol number to make it appear to contain a guest agent.

Ordinary contributor launches can use independently checked source runtimes
under the binary's compiled source-channel policy, including sealed workloads.
That source-channel permission does **not** authorize an assurance runtime.
Assurance rejects source runtimes regardless of workload variant or a caller's
unsigned-development flag. An ordinary admission that never checked an
assurance-compatible runtime cannot later be promoted into a campaign.

Campaign opening also requires the session's VM name to match the runtime-bound
launch name. An admitted runtime for one VM cannot authorize a session for
another. This is **admission evidence**: it records which image and runtime
selection passed the checks. It is not **execution evidence** that a VM consumed
those bytes, completed a probe, or produced an attested result. The runtime
launch path binds actual artifact snapshots separately, and trial outcomes
require their own observations and receipts.
