"""Key handling for mandate issuers.

Ed25519 keys only, per the mandate format document. Production deployments
obtain public keys through the registry by ``issuer_key_id``; the reference
implementation takes any callable ``KeyProvider`` (``kid -> raw public
bytes``) and ships a dict-backed one for tests and vectors.
"""

from __future__ import annotations

from typing import Callable, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# A KeyProvider maps issuer_key_id -> raw 32-byte Ed25519 public key.
KeyProvider = Callable[[str], bytes]


class DictKeyProvider:
    """A KeyProvider backed by a dict of ``kid -> raw public bytes``."""

    def __init__(self, keys: Dict[str, bytes]):
        self._keys = dict(keys)

    def get(self, kid: str) -> bytes:
        if kid not in self._keys:
            raise KeyError(f"unknown issuer_key_id: {kid}")
        return self._keys[kid]


def generate_key(seed: bytes | None = None) -> tuple[Ed25519PrivateKey, bytes]:
    """Return (private key, raw public bytes). A 32-byte *seed* makes the key
    deterministic, which the golden vectors rely on."""
    if seed is None:
        private = Ed25519PrivateKey.generate()
    else:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        private = Ed25519PrivateKey.from_private_bytes(seed)
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public_raw


def sign(private: Ed25519PrivateKey, digest_bytes: bytes) -> bytes:
    """Sign a 32-byte digest (the raw canonical digest of a mandate body)."""
    return private.sign(digest_bytes)


def verify(public_raw: bytes, digest_bytes: bytes, signature: bytes) -> bool:
    """Verify a signature over a digest with a raw public key."""
    try:
        public = Ed25519PublicKey.from_public_bytes(public_raw)
        public.verify(signature, digest_bytes)
        return True
    except Exception:
        return False
