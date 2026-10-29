"""Offline canonical revocation administration, with no acquisition or trust override."""

from typing import TypedDict, cast

from mvm import _hostlib
from mvm._hostabi.methods import IMAGE_REVOCATIONS_STATUS, IMAGE_REVOCATIONS_UPDATE


class CheckpointReport(TypedDict):
    publication: int
    issued_at: str
    sha256: str


class StatusReport(CheckpointReport):
    signer_identity: str
    not_after: str
    entries: int


def update(document_path: str, bundle_path: str) -> CheckpointReport:
    """Apply signed files; refusal may still initialize private store infrastructure."""
    return cast(CheckpointReport, _hostlib.call(
        IMAGE_REVOCATIONS_UPDATE,
        {"document_path": document_path, "bundle_path": bundle_path},
    ))


def status() -> StatusReport:
    """Reauthenticate applied state; absence may initialize the private root/lock."""
    return cast(StatusReport, _hostlib.call(IMAGE_REVOCATIONS_STATUS, {}))
