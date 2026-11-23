"""Chain verification — the reference implementation of MAN-5.

Given a chain M1 (root) ... Mn (held by the acting agent), ordered root to
leaf, verification succeeds only for the whole chain; any failure denies
(ENF-3, SEC-6).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional

from .constraints import check_attenuation, grade_rank
from .keys import KeyProvider, verify
from .mandate import body_of, mandate_hash, verify_signature
from .revocation import parse_time

# A RevocationChecker returns True when the mandate is revoked.
RevocationChecker = Callable[[str], bool]


@dataclass
class ChainResult:
    ok: bool
    reason: Optional[str] = None
    leaf_hash: Optional[str] = None


def verify_chain(
    mandates: List[dict],
    keys: KeyProvider,
    now: datetime,
    revocation: RevocationChecker,
    subject: Optional[str] = None,
) -> ChainResult:
    if not mandates:
        return ChainResult(False, "empty chain")

    for i, mandate in enumerate(mandates):
        body = body_of(mandate)

        # 1. Signature (MAN-5 step 1).
        try:
            public_raw = keys.get(body["issuer_key_id"])
        except KeyError as exc:
            return ChainResult(False, f"key lookup failed: {exc}")
        if not verify_signature(mandate, public_raw):
            return ChainResult(False, "signature verification failed", f"link {i}")

        # 2. Validity window (MAN-5 step 2).
        validity = body["validity"]
        if not (parse_time(validity["not_before"]) <= now <= parse_time(validity["not_after"])):
            return ChainResult(False, f"validity window failure at link {i}")

        if i == 0:
            if "parent" in body:
                return ChainResult(False, "chain root must not carry a parent link")
            continue

        parent = mandates[i - 1]
        parent_body = body_of(parent)

        # Chain integrity: the child's parent hash must match the recomputed
        # parent hash (MAN-5 step 4).
        if body["parent"]["mandate_id"] != parent_body["mandate_id"]:
            return ChainResult(False, f"parent id mismatch at link {i}")
        if body["parent"]["mandate_hash"] != mandate_hash(parent):
            return ChainResult(False, f"parent hash mismatch at link {i}")

        # Validity containment (MAN-4).
        pv, cv = parent_body["validity"], body["validity"]
        if parse_time(cv["not_before"]) < parse_time(pv["not_before"]):
            return ChainResult(False, f"validity containment failure (not_before) at link {i}")
        if parse_time(cv["not_after"]) > parse_time(pv["not_after"]):
            return ChainResult(False, f"validity containment failure (not_after) at link {i}")

        # Attenuation: constraints (MAN-4, spec section 3a) and grades.
        ok, reason = check_attenuation(parent_body["constraints"], body["constraints"])
        if not ok:
            return ChainResult(False, reason, f"link {i}")
        if grade_rank(body["required_grade"]) < grade_rank(parent_body["required_grade"]):
            return ChainResult(False, f"grade descent at link {i}: "
                                      f"{parent_body['required_grade']} -> {body['required_grade']}")

    # Revocation, every link (MAN-5 step 5, SEC-7).
    for i, mandate in enumerate(mandates):
        try:
            if revocation(body_of(mandate)["mandate_id"]):
                return ChainResult(False, f"revoked at link {i}")
        except Exception as exc:  # stale list, bad signature: fail closed
            return ChainResult(False, f"revocation check failed: {exc}")

    # Subject binding (MAN-5 step 6, IDE-1).
    leaf = body_of(mandates[-1])
    if subject is not None and leaf["subject"] != subject:
        return ChainResult(False, f"subject mismatch: mandate subject {leaf['subject']!r} "
                                  f"!= presented subject {subject!r}")

    return ChainResult(True, None, mandate_hash(mandates[-1]))
