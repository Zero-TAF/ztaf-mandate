"""Revocation status lists.

Registered method ``status-list`` (mandate format document section 5): a
signed, versioned structure the verifier fetches and caches within bounded
windows. Revoking a mandate invalidates all descendants by chain position —
the decision point checks every link (SEC-7).
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from .canonical import digest
from .keys import verify

VALID, REVOKED = "valid", "revoked"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def body_of(status_list: dict) -> dict:
    return {k: v for k, v in status_list.items() if k != "issuer_signature"}


def verify_status_list(status_list: dict, public_raw: bytes) -> bool:
    return verify(public_raw, digest(body_of(status_list)),
                  base64.b64decode(status_list.get("issuer_signature", "")))


class StatusChecker:
    """A revocation checker bound to one verified status list.

    Implements the ``Callable[[str], bool]`` revocation interface used by
    chain verification: returns True when the mandate is *revoked*. Raises
    when the list is stale beyond *max_age* or fails verification — callers
    must treat any exception as deny (ENF-3).
    """

    def __init__(
        self,
        status_list: dict,
        public_raw: bytes,
        now: datetime,
        max_age: timedelta = timedelta(hours=24),
    ):
        if not verify_status_list(status_list, public_raw):
            raise ValueError("status list signature verification failed")
        updated = parse_time(status_list["updated"])
        if now - updated > max_age:
            raise ValueError("status list is stale beyond the bounded window")
        self._entries = status_list["entries"]

    def __call__(self, mandate_id: str) -> bool:
        return self._entries.get(mandate_id, VALID) == REVOKED


def null_checker(mandate_id: str) -> bool:
    """A checker for deployments with no revocation infrastructure.

    Permitted only for offline vectors and tests; a production deployment
    MUST check revocation state (MAN-6, SEC-7).
    """
    return False
