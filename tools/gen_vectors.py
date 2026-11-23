#!/usr/bin/env python
"""Generate the golden test vectors deterministically.

Run from the repository root with an environment that has ``cryptography``::

    python tools/gen_vectors.py

The seeds are fixed constants, so the vectors regenerate byte-identically.
Each vector is self-describing: keys (seed + raw public), mandates with
signatures, an optional status list, the verification time, the presented
subject, and the expected result. tests/test_vectors.py replays them.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from ztaf_mandate.canonical import canonical_hash
from ztaf_mandate.keys import generate_key
from ztaf_mandate.mandate import body_of, mandate_hash, mint, verify_signature
from ztaf_mandate.revocation import REVOKED, VALID, body_of as sl_body_of, verify_status_list
from ztaf_mandate.canonical import digest
from ztaf_mandate.keys import sign

ROOT_SEED = bytes.fromhex("a1" * 32)
MID_SEED = bytes.fromhex("b2" * 32)
LEAF_SEED = bytes.fromhex("c3" * 32)

ROOT_KID = "ztaf-vector-root-issuer"
MID_KID = "ztaf-vector-intermediate-issuer"

NOW = "2026-11-23T00:00:00Z"
V0 = "2026-01-01T00:00:00Z"
V1 = "2027-01-01T00:00:00Z"


def _mint(private, body):
    return mint(private, body)


def build_chain():
    """The valid three-link chain used by V-01 and derived failures."""
    root_private, _ = generate_key(ROOT_SEED)
    mid_private, _ = generate_key(MID_SEED)

    root = _mint(root_private, {
        "zt_mandate_version": "0.1.0",
        "mandate_id": "ZT-MND-VEC-0001",
        "mandate_version": 1,
        "issuer": "operations-director",
        "issuer_key_id": ROOT_KID,
        "subject": "payments-desk",
        "originator": "Emmanuel A. Otchere (operations principal)",
        "outcomes": ["issue a customer refund within policy"],
        "constraints": [
            {"type": "outcome-scope", "value": ["refund-issue"]},
            {"type": "resource-scope", "value": ["payments-api"]},
            {"type": "budget", "value": {"unit": "EUR", "amount": 5000}},
        ],
        "escalation": {"threshold": "single refund above EUR 500", "channel": "oversight-desk"},
        "validity": {"not_before": V0, "not_after": V1},
        "required_grade": "TG-2",
        "revocation": {"method": "status-list", "endpoint": "https://vector.invalid/status"},
    })

    root_hash = mandate_hash(root)
    child = _mint(mid_private, {
        "zt_mandate_version": "0.1.0",
        "mandate_id": "ZT-MND-VEC-0002",
        "mandate_version": 1,
        "issuer": "payments-desk",
        "issuer_key_id": MID_KID,
        "subject": "refund-agent-fleet",
        "parent": {"mandate_id": "ZT-MND-VEC-0001", "mandate_hash": root_hash},
        "outcomes": ["issue a customer refund within policy"],
        "constraints": [
            {"type": "outcome-scope", "value": ["refund-issue"]},
            {"type": "resource-scope", "value": ["payments-api"]},
            {"type": "budget", "value": {"unit": "EUR", "amount": 1000}},
        ],
        "escalation": {"threshold": "single refund above EUR 500", "channel": "oversight-desk"},
        "validity": {"not_before": "2026-06-01T00:00:00Z", "not_after": "2026-12-31T00:00:00Z"},
        "required_grade": "TG-2",
        "revocation": {"method": "status-list", "endpoint": "https://vector.invalid/status"},
    })

    child_hash = mandate_hash(child)
    leaf = _mint(mid_private, {
        "zt_mandate_version": "0.1.0",
        "mandate_id": "ZT-MND-VEC-0003",
        "mandate_version": 1,
        "issuer": "payments-desk",
        "issuer_key_id": MID_KID,
        "subject": "refund-agent-42",
        "parent": {"mandate_id": "ZT-MND-VEC-0002", "mandate_hash": child_hash},
        "outcomes": ["issue a customer refund within policy"],
        "constraints": [
            {"type": "outcome-scope", "value": ["refund-issue"]},
            {"type": "resource-scope", "value": ["payments-api"]},
            {"type": "budget", "value": {"unit": "EUR", "amount": 200}},
        ],
        "escalation": {"threshold": "single refund above EUR 200", "channel": "oversight-desk"},
        "validity": {"not_before": "2026-11-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z"},
        "required_grade": "TG-2",
        "revocation": {"method": "status-list", "endpoint": "https://vector.invalid/status"},
    })
    return root, child, leaf


def make_status_list(revoked_ids):
    """A signed status list; the root issuer signs it."""
    _, root_public = generate_key(ROOT_SEED)
    entries = {m: REVOKED for m in revoked_ids}
    body = {
        "zt_status_version": "0.1.0",
        "updated": "2026-11-22T12:00:00Z",
        "entries": entries,
        "issuer_key_id": ROOT_KID,
    }
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private = Ed25519PrivateKey.from_private_bytes(ROOT_SEED)
    signature = sign(private, digest(body))
    return {**body, "issuer_signature": base64.b64encode(signature).decode("ascii")}, root_public


def keys_block():
    out = {}
    for kid, seed in ((ROOT_KID, ROOT_SEED), (MID_KID, MID_SEED)):
        _, public = generate_key(seed)
        out[kid] = {"seed_hex": seed.hex(), "public_hex": public.hex()}
    return out


def write_vector(directory: Path, name: str, vector: dict):
    path = directory / f"vector-{name}.json"
    path.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n")
    return path.name


def main():
    directory = Path(__file__).resolve().parents[1] / "vectors"
    directory.mkdir(exist_ok=True)
    keys = keys_block()
    root, child, leaf = build_chain()
    good = [root, child, leaf]
    written = []

    # V-01: the valid chain.
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "01-valid-chain", {
        "vector_id": "V-01", "description": "valid three-link chain verifies",
        "keys": keys, "mandates": good, "status_list": sl,
        "now": NOW, "subject": "refund-agent-42", "expect": {"result": "ok"},
    }))

    # V-02: tampered body, original signature.
    tampered = json.loads(json.dumps(leaf))
    tampered["subject"] = "refund-agent-evil"
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "02-broken-signature", {
        "vector_id": "V-02", "description": "body tampered after signing: signature fails",
        "keys": keys, "mandates": [root, child, tampered], "status_list": sl,
        "now": NOW, "subject": "refund-agent-evil", "expect": {"result": "fail", "reason_contains": "signature"},
    }))

    # V-03: child validity escapes the parent's window.
    bad = json.loads(json.dumps(child))
    bad["validity"]["not_after"] = "2028-01-01T00:00:00Z"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    bad = mint(Ed25519PrivateKey.from_private_bytes(MID_SEED), body_of(bad))
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "03-validity-escapes-parent", {
        "vector_id": "V-03", "description": "child validity window escapes parent: containment failure",
        "keys": keys, "mandates": [root, bad, leaf], "status_list": sl,
        "now": NOW, "subject": "refund-agent-42", "expect": {"result": "fail", "reason_contains": "validity"},
    }))

    # V-04: attenuation violation - child budget looser than parent.
    bad = json.loads(json.dumps(child))
    bad["constraints"][2]["value"]["amount"] = 10000
    bad = mint(Ed25519PrivateKey.from_private_bytes(MID_SEED), body_of(bad))
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "04-loose-budget", {
        "vector_id": "V-04", "description": "child budget exceeds parent budget: attenuation violation",
        "keys": keys, "mandates": [root, bad, leaf], "status_list": sl,
        "now": NOW, "subject": "refund-agent-42", "expect": {"result": "fail", "reason_contains": "attenuation"},
    }))

    # V-05: the intermediate mandate is revoked.
    sl, _ = make_status_list(["ZT-MND-VEC-0002"])
    written.append(write_vector(directory, "05-revoked-intermediate", {
        "vector_id": "V-05", "description": "intermediate mandate revoked: revocation propagates down-chain",
        "keys": keys, "mandates": good, "status_list": sl,
        "now": NOW, "subject": "refund-agent-42", "expect": {"result": "fail", "reason_contains": "revoked"},
    }))

    # V-06: grade descent - leaf requires less than its parent.
    bad = json.loads(json.dumps(leaf))
    bad["required_grade"] = "TG-1"
    bad = mint(Ed25519PrivateKey.from_private_bytes(MID_SEED), body_of(bad))
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "06-grade-descent", {
        "vector_id": "V-06", "description": "leaf required_grade below parent: grade descent",
        "keys": keys, "mandates": [root, child, bad], "status_list": sl,
        "now": NOW, "subject": "refund-agent-42", "expect": {"result": "fail", "reason_contains": "grade"},
    }))

    # V-07: parent hash mismatch - chain integrity failure.
    bad = json.loads(json.dumps(leaf))
    bad["parent"]["mandate_hash"] = canonical_hash({"tampered": True})
    bad = mint(Ed25519PrivateKey.from_private_bytes(MID_SEED), body_of(bad))
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "07-parent-hash-mismatch", {
        "vector_id": "V-07", "description": "parent hash reference does not match the recomputed parent hash",
        "keys": keys, "mandates": [root, child, bad], "status_list": sl,
        "now": NOW, "subject": "refund-agent-42", "expect": {"result": "fail", "reason_contains": "parent hash"},
    }))

    # V-08: unknown constraint type - fail closed.
    bad = json.loads(json.dumps(child))
    bad["constraints"].append({"type": "teleport", "value": ["anywhere"]})
    bad = mint(Ed25519PrivateKey.from_private_bytes(MID_SEED), body_of(bad))
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "08-unknown-constraint-type", {
        "vector_id": "V-08", "description": "unregistered constraint type: verifier rejects (fail closed)",
        "keys": keys, "mandates": [root, bad, leaf], "status_list": sl,
        "now": NOW, "subject": "refund-agent-42", "expect": {"result": "fail", "reason_contains": "constraint"},
    }))

    # V-09: subject mismatch on the presented identity.
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "09-subject-mismatch", {
        "vector_id": "V-09", "description": "presented subject is not the leaf mandate's subject",
        "keys": keys, "mandates": good, "status_list": sl,
        "now": NOW, "subject": "refund-agent-99", "expect": {"result": "fail", "reason_contains": "subject"},
    }))

    # V-10: parent constraint type dropped by the child.
    bad = json.loads(json.dumps(child))
    bad["constraints"] = [c for c in bad["constraints"] if c["type"] != "budget"]
    bad = mint(Ed25519PrivateKey.from_private_bytes(MID_SEED), body_of(bad))
    sl, _ = make_status_list([])
    written.append(write_vector(directory, "10-dropped-parent-constraint", {
        "vector_id": "V-10", "description": "child drops a parent constraint type: attenuation violation",
        "keys": keys, "mandates": [root, bad, leaf], "status_list": sl,
        "now": NOW, "subject": "refund-agent-42", "expect": {"result": "fail", "reason_contains": "attenuation"},
    }))

    (directory / "index.json").write_text(json.dumps({
        "vectors": written,
        "now": NOW,
        "note": "Seeds are fixed constants; regenerate byte-identically with tools/gen_vectors.py.",
    }, indent=2) + "\n")
    print(f"wrote {len(written)} vectors + index.json to {directory}")


if __name__ == "__main__":
    main()
