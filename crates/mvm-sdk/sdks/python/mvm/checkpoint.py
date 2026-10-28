"""Complete checkpoint metadata as JSON mappings, not verification results."""

from typing import List, Literal, TypedDict, Union, cast

from mvm import _hostlib
from mvm._hostabi.methods import CHECKPOINT_LIST

CheckpointClass = Literal["fs_quick", "vm_full"]
CheckpointProtection = Literal["unprotected", "sealed_v1"]
GuestArch = Literal["x86_64", "aarch64"]


class ContentBlob(TypedDict):
    name: str
    sha256: str


class RuntimeReleaseProof(TypedDict):
    archive: str
    checksum: str
    signature_bundle: str
    archive_sha256: str
    version: str
    arch: GuestArch


class ReleaseProvenance(TypedDict):
    kind: Literal["release"]
    proof: RuntimeReleaseProof


class SourceProvenance(TypedDict):
    kind: Literal["source"]
    version: str
    arch: GuestArch
    archive_sha256: str


RuntimeBindingProvenance = Union[ReleaseProvenance, SourceProvenance]


class CliRuntimeLaunchBinding(TypedDict):
    runtime: Literal["cli_assembly"]
    provenance: RuntimeBindingProvenance
    overlay_path: str
    overlay_verity_path: str
    initramfs_path: str
    overlay_roothash: str


class PlanArtifact(TypedDict):
    bundle_sha256: str
    manifest_sig_base64: str
    key_id: str


class LegacyBundleRuntimeProof(TypedDict):
    archive: str
    pin: PlanArtifact


class LegacyPortableRuntimeProof(LegacyBundleRuntimeProof):
    manifest_sha256: str
    arch: GuestArch


class LegacyBundleLaunchBinding(TypedDict):
    runtime: Literal["legacy_bundle"]
    proof: LegacyBundleRuntimeProof
    rootfs_path: str
    initramfs_path: str | None


class LegacyPortableLaunchBinding(TypedDict):
    runtime: Literal["legacy_portable"]
    proof: LegacyPortableRuntimeProof
    rootfs_path: str
    kernel_path: str
    overlay_path: str
    overlay_verity_path: str
    initramfs_path: str
    overlay_roothash: str
    version: str


RuntimeLaunchBinding = Union[
    CliRuntimeLaunchBinding, LegacyBundleLaunchBinding, LegacyPortableLaunchBinding
]


class CpuShareGrant(TypedDict):
    unit: Literal["share"]
    millicores: int


class CpuFuelGrant(TypedDict):
    unit: Literal["fuel"]
    instructions: int


CpuGrant = Union[CpuShareGrant, CpuFuelGrant]


class UnboundedWallClockGrant(TypedDict):
    kind: Literal["unbounded"]


class SecondsWallClockGrant(TypedDict):
    kind: Literal["secs"]
    secs: int


WallClockGrant = Union[UnboundedWallClockGrant, SecondsWallClockGrant]


class HostPort(TypedDict):
    host: str
    port: int


class EgressGrant(TypedDict):
    allow: List[HostPort]


class DriveGrant(TypedDict):
    workspace_roots: List[str]
    program_id: str
    max_bytes_in: int
    max_bytes_out: int
    ttl: int


class DisplayClipboardGrant(TypedDict):
    max_paste_bytes: int


class HumanCredentialGrant(TypedDict):
    destinations: List[HostPort]


class DisplayInputGrant(TypedDict, total=False):
    attended: bool
    clipboard: DisplayClipboardGrant
    human_credential: HumanCredentialGrant


class ApplicationTerminalGrant(TypedDict):
    argv: List[str]


class Grants(TypedDict, total=False):
    cpu: CpuGrant
    wall_clock: WallClockGrant
    egress: EgressGrant
    drive: DriveGrant
    display_input: DisplayInputGrant
    application_terminal: ApplicationTerminalGrant


class _SessionBindingRequired(TypedDict):
    session_id: str
    generation: int
    journal_cursor: int
    approval_head: str


class SessionBinding(_SessionBindingRequired, total=False):
    replay_input_digest: str


# Functional syntax preserves the wire key `class`, a Python keyword.
_CheckpointMetaRequired = TypedDict("_CheckpointMetaRequired", {
    "id": str,
    "class": CheckpointClass,
    "vm_name": str,
    "tag": str | None,
    "parent": str | None,
    "created_unix": int,
    "content": List[ContentBlob],
    "supervisor_config_digest": str,
    "meta_digest": str,
    "audit_ref": str | None,
})


class CheckpointMeta(_CheckpointMetaRequired, total=False):
    """Serialized metadata; omitted defaults remain absent, not synthesized.

    ``tag``, ``parent`` and ``audit_ref`` are required nullable keys. These
    optional keys, in contrast, are absent rather than null when unset.
    """

    key_domain: str
    protection: CheckpointProtection
    runtime_overlay_version: str
    runtime_launch_binding: RuntimeLaunchBinding
    snapshot_id: str
    grants: Grants
    session: SessionBinding
    machine_input_cursor: int


CheckpointListReply = List[CheckpointMeta]


def list() -> CheckpointListReply:
    """List complete records in host-provided lexicographic ID order.

    This is inspection, not verification or restore authority. Digests, nulls,
    and omitted fields are returned unchanged.
    """
    return cast(CheckpointListReply, _hostlib.call(CHECKPOINT_LIST, {}))
