"""Host identity data. A valid v0 signature is not measured-boot evidence."""

from typing import Literal, TypedDict, Union, cast

from mvm import _hostlib
from mvm._hostabi.methods import ATTESTATION_EXPORT, ATTESTATION_STATUS, ATTESTATION_VERIFY


class SelfIdentity(TypedDict):
    kind: Literal["self_identity"]


class PublicKeyFile(TypedDict):
    kind: Literal["public_key_file"]
    path: str


Trust = Union[SelfIdentity, PublicKeyFile]


class ReportData(TypedDict):
    payload: list[int]
    signature: list[int]
    signer_id: str


class HardwareMeasurementData(TypedDict):
    provider: str
    measurement_hex: str


class BodyData(TypedDict):
    schema_version: int
    boot_measurement: str
    identity_pubkey_hex: str
    nonce_hex: str
    hw_measurement: HardwareMeasurementData | None


class VerificationData(TypedDict):
    signer_id: str
    body: BodyData
    trust: Trust


class ProviderData(TypedDict):
    name: str
    feature: str
    compiled: bool


class StatusData(TypedDict):
    signer_id: str
    pubkey_hex: str
    secret_path: str
    public_path: str
    providers: list[ProviderData]


def export() -> ReportData:
    """Export v0 data; may initialize identity, never returns secret key bytes."""
    return cast(ReportData, _hostlib.call(ATTESTATION_EXPORT, {}))


def verify(report_path: str, *, trust: Trust) -> VerificationData:
    """Verify a report file with explicit trust, not embedded-key authority."""
    return cast(VerificationData, _hostlib.call(
        ATTESTATION_VERIFY, {"report_path": report_path, "trust": trust}
    ))


def status() -> StatusData:
    """Inspect metadata, initializing identity if needed. Paths are not capabilities."""
    return cast(StatusData, _hostlib.call(ATTESTATION_STATUS, {}))
