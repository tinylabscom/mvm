"""Depth-one workload actors through the admitted, encrypted lifecycle channel.

Templates, not caller-supplied VM configuration, determine what a child runs.
Task messages use the child's canonical mailbox, separately from lifecycle
operations. An uncertain outcome is never automatically retried or reported as
released; callers retain the original idempotency key when reconciling it.
"""

from copy import deepcopy
from dataclasses import dataclass
from typing import Union

from mvm import _hostsvc

_TIMEOUT_SECS = 60.0
_MAILBOX_FIELDS = {"tenant", "authorization_domain", "mailbox", "recipient"}
_REFUSALS = {
    "not_bound", "unauthorized", "stale_controller", "expired", "unknown_template",
    "template_mismatch", "request_conflict", "capacity", "unsupported", "unavailable",
}


def _fixed_id(value: object) -> bytes:
    if (
        not isinstance(value, list)
        or len(value) != 32
        or any(type(byte) is not int or not 0 <= byte <= 255 for byte in value)
    ):
        raise ValueError("invalid actor identity")
    return bytes(value)


class ActorHandle:
    """An opaque lifecycle capability and the child's one mailbox address.

    The token is intentionally excluded from representations. Copying a handle
    does not grant another workload authority: the host binds it to the
    original controller's authenticated boot.
    """

    __slots__ = ("__token", "__mailbox")

    def __init__(self, token: list[int], mailbox: dict):
        self.__token = _fixed_id(token)
        if not isinstance(mailbox, dict) or set(mailbox) != _MAILBOX_FIELDS:
            raise ValueError("invalid actor mailbox")
        for identity in mailbox.values():
            _fixed_id(identity)
        self.__mailbox = deepcopy(mailbox)

    def __repr__(self) -> str:
        return "ActorHandle(token=<redacted>)"

    @property
    def mailbox(self) -> dict:
        """Return the canonical mailbox address, not a host route or permission."""
        return deepcopy(self.__mailbox)

    def _wire(self) -> dict:
        return {"token": list(self.__token), "mailbox": self.mailbox}


@dataclass(frozen=True)
class Pending:
    """Durable intent exists, but launch has not produced a completed result."""

    request_id: str


@dataclass(frozen=True)
class Running:
    """The host confirmed the admitted child is running."""

    handle: ActorHandle


@dataclass(frozen=True)
class Released:
    """The host confirmed child death, resource cleanup and terminal evidence."""

    request_id: str


@dataclass(frozen=True)
class Refused:
    """The host refused the operation without granting new authority."""

    code: str


@dataclass(frozen=True)
class Unknown:
    """Dispatch occurred but the result is uncertain; capacity remains held."""

    request_id: str


ActorOutcome = Union[Pending, Running, Released, Refused, Unknown]


def _outcome(response: dict) -> ActorOutcome:
    if (
        not isinstance(response, dict)
        or set(response) != {"version", "outcome"}
        or type(response["version"]) is not int
        or response["version"] != 1
    ):
        raise ValueError("unsupported actor response")
    outcome = response["outcome"]
    if not isinstance(outcome, dict):
        raise ValueError("invalid actor outcome")
    status = outcome.get("status")
    if not isinstance(status, str):
        raise ValueError("invalid actor status")
    if status == "running" and set(outcome) == {"status", "handle"}:
        handle = outcome["handle"]
        if not isinstance(handle, dict) or set(handle) != {"token", "mailbox"}:
            raise ValueError("invalid actor handle")
        return Running(ActorHandle(handle["token"], handle["mailbox"]))
    if status == "refused" and set(outcome) == {"status", "code"}:
        if not isinstance(outcome["code"], str) or outcome["code"] not in _REFUSALS:
            raise ValueError("unsupported actor refusal")
        return Refused(outcome["code"])
    classes = {"pending": Pending, "released": Released, "unknown": Unknown}
    if status in classes and set(outcome) == {"status", "request_id"}:
        request_id = outcome["request_id"]
        if not isinstance(request_id, str) or not request_id or len(request_id.encode()) > 128:
            raise ValueError("invalid actor request identity")
        return classes[status](request_id)
    raise ValueError("unsupported actor outcome")


def _call(operation: dict, timeout_secs: float) -> ActorOutcome:
    return _outcome(_hostsvc.call(
        "host.actor.call",
        {"version": 1, "operation": operation},
        timeout_secs=timeout_secs,
    ))


def launch_child(
    grant_id: str,
    template_id: str,
    *,
    idempotency_key: str,
    timeout_secs: float = _TIMEOUT_SECS,
) -> ActorOutcome:
    """Launch one exact admitted template. Reconcile retries with the same key."""
    return _call({
        "operation": "launch",
        "grant_id": grant_id,
        "template_id": template_id,
        "idempotency_key": idempotency_key,
    }, timeout_secs)


def observe_child(handle: ActorHandle, *, timeout_secs: float = _TIMEOUT_SECS) -> ActorOutcome:
    """Observe only the child named by this controller's opaque handle."""
    return _call({"operation": "observe_child", "handle": handle._wire()}, timeout_secs)


def release_child(
    handle: ActorHandle,
    *,
    idempotency_key: str,
    timeout_secs: float = _TIMEOUT_SECS,
) -> ActorOutcome:
    """Request destruction; only a Released outcome confirms completed cleanup."""
    return _call({
        "operation": "release_child",
        "handle": handle._wire(),
        "idempotency_key": idempotency_key,
    }, timeout_secs)
