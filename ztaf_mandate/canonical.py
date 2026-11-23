"""Canonical serialisation and hashing.

The canonical form of a mandate body is: UTF-8 JSON with object keys sorted
lexicographically, no insignificant whitespace, and non-ASCII characters
unescaped. The mandate hash is the SHA-256 of the canonical bytes, prefixed
``zt-sha256:``. Children reference parents by this hash and decision records
bind to it (ztaf-spec, mandate format document section 2); changing the
canonical form is a format-version change.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

HASH_PREFIX = "zt-sha256:"


def canonical_bytes(obj: Any) -> bytes:
    """Return the canonical serialisation of *obj*."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    """Return the ``zt-sha256:``-prefixed hash of the canonical bytes."""
    return HASH_PREFIX + hashlib.sha256(canonical_bytes(obj)).hexdigest()


def digest(obj: Any) -> bytes:
    """Return the raw 32-byte SHA-256 digest of the canonical bytes.

    Signatures are computed over this digest (mandate format document,
    section 2: "signed by the issuer").
    """
    return hashlib.sha256(canonical_bytes(obj)).digest()
