"""Mandate construction, minting, and single-mandate verification.

A mandate instance on the wire is its body plus one field::

    {... body ..., "issuer_signature": "<base64 of Ed25519 sig over digest>"}

The ``mandate_hash`` referenced by children and decision records is the
canonical hash of the body *without* the signature field, so the chain
reference is signature-independent.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_bytes, canonical_hash, digest
from .keys import sign

REQUIRED_FIELDS = [
    "zt_mandate_version",
    "mandate_id",
    "mandate_version",
    "issuer",
    "issuer_key_id",
    "subject",
    "outcomes",
    "constraints",
    "escalation",
    "validity",
    "required_grade",
    "revocation",
]


def body_of(mandate: dict) -> dict:
    """Return the unsigned body of a mandate instance."""
    return {k: v for k, v in mandate.items() if k != "issuer_signature"}


def validate_body(body: dict) -> None:
    missing = [f for f in REQUIRED_FIELDS if f not in body]
    if missing:
        raise ValueError(f"mandate body missing required fields: {missing}")
    if not body["outcomes"] or not isinstance(body["outcomes"], list):
        raise ValueError("outcomes must be a non-empty list")
    if not body["constraints"] or not isinstance(body["constraints"], list):
        raise ValueError("constraints must be a non-empty list")
    if "parent" not in body and not body.get("originator"):
        raise ValueError("a chain root MUST name its originator")


def mandate_hash(mandate: dict) -> str:
    return canonical_hash(body_of(mandate))


def mint(
    private: Ed25519PrivateKey,
    body: dict,
) -> dict:
    """Sign *body* and return the full mandate instance."""
    validate_body(body)
    signature = sign(private, digest(body))
    mandate = dict(body)
    mandate["issuer_signature"] = base64.b64encode(signature).decode("ascii")
    return mandate


def verify_signature(mandate: dict, public_raw: bytes) -> bool:
    from .keys import verify

    return verify(public_raw, digest(body_of(mandate)),
                  base64.b64decode(mandate.get("issuer_signature", "")))
